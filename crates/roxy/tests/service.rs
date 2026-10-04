//! End-to-end tests of service layers: `roxy run` with `kind: service`
//! addons whose exchanges stream through an in-test service over
//! `roxy.layer.v2`. The service's behaviour is picked by its URL path (one
//! per connection), and for `/mixed` by the request's path (per stream).

mod support;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{Value, json};
use support::{Harness, Opts, fnv};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{Notify, mpsc};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

const ALLOW_UPSTREAM: &str = r#"
  - id: upstream
    when: host == "upstream.test"
    then: { allow: { private_ok: true } }
"#;

/// Each stream's starting credit, each way.
const WINDOW: u64 = 256 * 1024;

/// Extra credit granted to an observe stream as it opens, so roxy can
/// send the copies on without waiting (an observer that falls behind is
/// cut).
const OBSERVE_CREDIT: u64 = 16 * 1024 * 1024;

#[derive(Default)]
struct SvcState {
    /// The handshake headers of every connection.
    connections: Mutex<Vec<Vec<(String, String)>>>,
    /// Every `open` message, with the index of its connection as `conn_index`.
    opens: Mutex<Vec<Value>>,
    /// Streams roxy reset: (connection index, stream id, message).
    resets: Mutex<Vec<(usize, u64, String)>>,
    /// Connections that ended, by index.
    closed: Mutex<Vec<usize>>,
    /// `/echo` streams that saw the whole exchange through.
    echoed: Mutex<Vec<u64>>,
    /// Lets `/mixed` streams that wait for it go on.
    release: Notify,
    changed: Notify,
}

impl SvcState {
    fn connections(&self) -> Vec<Vec<(String, String)>> {
        self.connections.lock().unwrap().clone()
    }

    fn opens(&self) -> Vec<Value> {
        self.opens.lock().unwrap().clone()
    }

    async fn until(&self, what: &str, f: impl Fn(&Self) -> bool) {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let changed = self.changed.notified();
                if f(self) {
                    return;
                }
                changed.await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
    }
}

/// The next message on a stream.
enum Got {
    Ctl(Value),
    Bytes(Vec<u8>),
    End,
}

/// What a connection's streams share: the way out, and roxy's credit.
struct ConnOut {
    tx: mpsc::UnboundedSender<Message>,
    credit: Mutex<HashMap<u64, u64>>,
    more: Notify,
    kill: Notify,
}

/// One stream, from the service's side. It grants roxy credit for bytes
/// as they are read, and waits for credit before sending bytes.
struct Sess {
    id: u64,
    rx: mpsc::UnboundedReceiver<Got>,
    out: Arc<ConnOut>,
    st: Arc<SvcState>,
}

impl Sess {
    async fn recv(&mut self) -> Got {
        let g = self.rx.recv().await.unwrap_or(Got::End);
        if let Got::Bytes(b) = &g {
            self.send(json!({"type": "credit", "bytes": b.len()}));
        }
        g
    }

    fn send(&self, mut v: Value) {
        v["stream"] = self.id.into();
        let _ = self.out.tx.send(Message::text(v.to_string()));
    }

    fn raw(&self, m: Message) {
        let _ = self.out.tx.send(m);
    }

    fn frame(&self, b: &[u8]) -> Message {
        let mut f = u32::try_from(self.id).unwrap().to_be_bytes().to_vec();
        f.extend_from_slice(b);
        Message::binary(f)
    }

    /// Sends body bytes as roxy's credit allows.
    async fn send_bytes(&self, mut b: &[u8]) {
        while !b.is_empty() {
            let more = self.out.more.notified();
            let n = {
                let mut c = self.out.credit.lock().unwrap();
                let have = c.entry(self.id).or_insert(WINDOW);
                let n = usize::try_from(*have).unwrap().min(b.len()).min(32 * 1024);
                *have -= n as u64;
                n
            };
            if n == 0 {
                more.await;
                continue;
            }
            self.raw(self.frame(&b[..n]));
            b = &b[n..];
        }
    }

    /// Ends the whole connection.
    fn kill(&self) {
        self.out.kill.notify_one();
    }
}

/// Reads one whole message (head, body, end).
async fn whole(s: &mut Sess) -> (Value, Vec<u8>) {
    let Got::Ctl(head) = s.recv().await else {
        panic!("expected a head");
    };
    let mut body = Vec::new();
    loop {
        match s.recv().await {
            Got::Bytes(b) => body.extend(b),
            Got::Ctl(_) => return (head, body),
            Got::End => panic!("closed mid-message"),
        }
    }
}

/// Sends a whole message back: head, body (if any), end.
async fn send_whole(s: &Sess, head: Value, body: &[u8], end: &str) {
    s.send(head);
    s.send_bytes(body).await;
    s.send(json!({ "type": end }));
}

/// Forwards every message as it arrives, applying `f` to heads and `g` to
/// response bytes. True if it got through to the response's end.
async fn relay(s: &mut Sess, f: impl Fn(Value) -> Value, g: impl Fn(Vec<u8>) -> Vec<u8>) -> bool {
    let mut in_response = false;
    loop {
        match s.recv().await {
            Got::Ctl(v) => {
                if v["type"] == "response" {
                    in_response = true;
                }
                let end = v["type"] == "response_end";
                s.send(f(v));
                if end {
                    return true;
                }
            }
            Got::Bytes(b) => {
                let b = if in_response { g(b) } else { b };
                s.send_bytes(&b).await;
            }
            Got::End => return false,
        }
    }
}

async fn session(path: &str, mut s: Sess) {
    match path {
        "/echo" => {
            if relay(&mut s, |v| v, |b| b).await {
                s.st.echoed.lock().unwrap().push(s.id);
                s.st.changed.notify_waiters();
            }
        }
        "/rewrite" => {
            let _ = relay(
                &mut s,
                |mut v| {
                    if v["type"] == "request" {
                        let url = v["url"].as_str().unwrap().replace("/fine", "/rewritten");
                        v["url"] = url.into();
                    }
                    v
                },
                |b| b.to_ascii_uppercase(),
            )
            .await;
        }
        "/deny" => {
            let _ = s.recv().await;
            s.send(json!({"type": "deny", "status": 451, "message": "the service said no"}));
        }
        "/deny-response" => {
            let (head, body) = whole(&mut s).await;
            send_whole(&s, head, &body, "request_end").await;
            let _ = whole(&mut s).await;
            s.send(json!({"type": "deny", "message": "not this answer"}));
        }
        "/respond" => {
            let _ = s.recv().await;
            let head =
                json!({"type": "response", "status": 200, "headers": [["x-from", "service"]]});
            send_whole(&s, head, b"made up", "response_end").await;
        }
        // Broken framing: fails the connection.
        "/garbage" => {
            let _ = s.recv().await;
            s.raw(Message::text("not json"));
        }
        "/out-of-order" => {
            let _ = s.recv().await;
            s.raw(s.frame(b"bytes first"));
        }
        "/bad-head" => {
            let _ = s.recv().await;
            s.send(json!({"type": "request", "method": "GET",
                "url": "http://upstream.test/", "headers": [["bad header", "x"]]}));
        }
        // Forwards a request with framing fields a client could not send.
        "/smuggle" => {
            let _ = whole(&mut s).await;
            let head = json!({"type": "request", "method": "POST", "url": "http://upstream.test/x",
                "headers": [["content-length", "3"], ["transfer-encoding", "chunked"]]});
            send_whole(&s, head, b"abc", "request_end").await;
        }
        "/slow" => tokio::time::sleep(Duration::from_secs(5)).await,
        // roxy refuses the handshake (no subprotocol); nothing to do.
        "/no-protocol" => {}
        // Forwards the request head and part of a body, then the
        // connection goes away.
        "/drop" => {
            let Got::Ctl(mut head) = s.recv().await else {
                return;
            };
            // Undeclared length, so only the lost connection is wrong.
            head["headers"] = json!([]);
            s.send(head);
            s.send_bytes(b"partial").await;
            tokio::time::sleep(Duration::from_millis(200)).await;
            s.kill();
        }
        // Declares a length, then sends more than that.
        "/too-long" => {
            let (mut head, _) = whole(&mut s).await;
            head["headers"] = json!([["content-length", "3"]]);
            send_whole(&s, head, b"too long", "request_end").await;
        }
        // Passes the request on, then cuts the response short.
        "/drop-response" => {
            let (head, body) = whole(&mut s).await;
            send_whole(&s, head, &body, "request_end").await;
            let Got::Ctl(head) = s.recv().await else {
                return;
            };
            s.send(head);
            s.send_bytes(b"{\"partial\":").await;
            tokio::time::sleep(Duration::from_millis(200)).await;
            s.kill();
        }
        "/mixed" => mixed(s).await,
        p => panic!("unknown service path {p}"),
    }
}

/// Per stream, by the request's path: `/hold…` waits for `release`, then
/// echoes; `/bad…` sends an invalid head; `/kill` ends the connection;
/// `/hang` never answers; `/big` answers with 1 MiB; `/flood` sends four
/// windows on credit; `/overrun` sends past its credit; anything else
/// echoes.
async fn mixed(mut s: Sess) {
    let Got::Ctl(head) = s.recv().await else {
        return;
    };
    let url = head["url"].as_str().unwrap_or_default().to_owned();
    let after_scheme = url.split_once("://").map_or("", |(_, r)| r);
    let path = after_scheme
        .find('/')
        .map_or("", |i| &after_scheme[i..])
        .to_owned();
    if path.starts_with("/hold") {
        s.st.release.notified().await;
    }
    if path.starts_with("/bad") {
        s.send(json!({"type": "request", "method": "GET",
            "url": "http://upstream.test/", "headers": [["bad header", "x"]]}));
        return;
    }
    match path.as_str() {
        "/kill" => {
            tokio::time::sleep(Duration::from_millis(100)).await;
            s.kill();
        }
        "/hang" => std::future::pending().await,
        "/big" => {
            let head = json!({"type": "response", "status": 200,
                "headers": [["content-length", "1048576"]]});
            send_whole(&s, head, &vec![b'x'; 1 << 20], "response_end").await;
        }
        // Sends four windows' worth, on credit, then says so.
        "/flood" => {
            s.send(json!({"type": "response", "status": 200}));
            s.send_bytes(&vec![b'f'; 4 * usize::try_from(WINDOW).unwrap()])
                .await;
            s.send(json!({"type": "response_end"}));
            s.st.echoed.lock().unwrap().push(s.id);
            s.st.changed.notify_waiters();
        }
        "/overrun" => {
            s.send(json!({"type": "response", "status": 200}));
            // One frame larger than the whole window.
            s.raw(s.frame(&vec![b'x'; usize::try_from(WINDOW).unwrap() + 1]));
            s.send(json!({"type": "response_end"}));
        }
        _ => {
            s.send(head);
            let _ = relay(&mut s, |v| v, |b| b).await;
        }
    }
}

/// Accepts the handshake, recording it. Returns the connection's path
/// and index.
async fn handshake<S>(io: S, st: &Arc<SvcState>) -> Option<(WebSocketStream<S>, String, usize)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let seen = Arc::new(Mutex::new((String::new(), 0)));
    let record = seen.clone();
    let state = st.clone();
    // The handshake callback's error type is tungstenite's.
    #[allow(clippy::result_large_err)]
    let callback = move |req: &Request, mut res: Response| {
        let path = req.uri().path().to_owned();
        let mut conns = state.connections.lock().unwrap();
        if path != "/no-protocol" {
            res.headers_mut()
                .insert("sec-websocket-protocol", "roxy.layer.v2".parse().unwrap());
        }
        *record.lock().unwrap() = (path, conns.len());
        conns.push(
            req.headers()
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_str().unwrap_or("").to_owned()))
                .collect(),
        );
        Ok(res)
    };
    let ws = tokio_tungstenite::accept_hdr_async(io, callback)
        .await
        .ok()?;
    st.changed.notify_waiters();
    let (path, index) = seen.lock().unwrap().clone();
    Some((ws, path, index))
}

/// One connection's streams, from the service's side.
struct Demux {
    st: Arc<SvcState>,
    out: Arc<ConnOut>,
    path: String,
    index: usize,
    streams: HashMap<u64, mpsc::UnboundedSender<Got>>,
}

impl Demux {
    fn bytes(&self, b: &[u8]) {
        let id = u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
        if let Some(tx) = self.streams.get(&id) {
            let _ = tx.send(Got::Bytes(b[4..].to_vec()));
        }
    }

    fn control(&mut self, v: Value) {
        let id = v["stream"].as_u64().unwrap();
        match v["type"].as_str().unwrap() {
            "open" => {
                let mut o = v.clone();
                o["conn_index"] = self.index.into();
                self.st.opens.lock().unwrap().push(o);
                self.st.changed.notify_waiters();
                if v["mode"] == "observe" {
                    let grant = json!({"type": "credit", "stream": id, "bytes": OBSERVE_CREDIT});
                    let _ = self.out.tx.send(Message::text(grant.to_string()));
                }
                let (tx, rx) = mpsc::unbounded_channel();
                self.streams.insert(id, tx);
                let sess = Sess {
                    id,
                    rx,
                    out: self.out.clone(),
                    st: self.st.clone(),
                };
                let path = self.path.clone();
                tokio::spawn(async move { session(&path, sess).await });
            }
            "credit" => {
                let n = v["bytes"].as_u64().unwrap();
                *self.out.credit.lock().unwrap().entry(id).or_insert(WINDOW) += n;
                self.out.more.notify_waiters();
            }
            "reset" => {
                let msg = v["message"].as_str().unwrap_or_default().to_owned();
                self.st.resets.lock().unwrap().push((self.index, id, msg));
                self.st.changed.notify_waiters();
                if let Some(tx) = self.streams.remove(&id) {
                    let _ = tx.send(Got::End);
                }
            }
            _ => {
                if let Some(tx) = self.streams.get(&id) {
                    let _ = tx.send(Got::Ctl(v));
                }
            }
        }
    }
}

/// Serves one connection: demultiplexes roxy's streams into sessions.
async fn connection<S>(io: S, st: Arc<SvcState>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Some((ws, path, index)) = handshake(io, &st).await else {
        return;
    };
    let (mut sink, mut stream) = ws.split();
    let (tx, mut out_rx) = mpsc::unbounded_channel::<Message>();
    let writer = tokio::spawn(async move {
        while let Some(m) = out_rx.recv().await {
            if sink.send(m).await.is_err() {
                return;
            }
        }
    });
    let out = Arc::new(ConnOut {
        tx,
        credit: Mutex::new(HashMap::new()),
        more: Notify::new(),
        kill: Notify::new(),
    });
    let mut demux = Demux {
        st: st.clone(),
        out: out.clone(),
        path,
        index,
        streams: HashMap::new(),
    };
    loop {
        let m = tokio::select! {
            m = stream.next() => m,
            () = out.kill.notified() => break,
        };
        match m {
            None | Some(Err(_) | Ok(Message::Close(_))) => break,
            Some(Ok(Message::Binary(b))) => demux.bytes(&b),
            Some(Ok(Message::Text(t))) => demux.control(serde_json::from_str(&t).unwrap()),
            Some(Ok(_)) => {}
        }
    }
    writer.abort();
    st.closed.lock().unwrap().push(index);
    st.changed.notify_waiters();
}

/// A plain `ws://` service.
async fn start_service() -> (std::net::SocketAddr, Arc<SvcState>) {
    let st = Arc::new(SvcState::default());
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let s = st.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = l.accept().await {
            tokio::spawn(connection(tcp, s.clone()));
        }
    });
    (addr, st)
}

/// The TLS config of a `wss://` service, set once it is known (the test
/// CA is made when the harness starts, after the URL is configured).
type TlsSlot = Arc<OnceLock<Arc<rustls::ServerConfig>>>;

/// A `wss://` service.
async fn start_tls_service() -> (std::net::SocketAddr, Arc<SvcState>, TlsSlot) {
    let st = Arc::new(SvcState::default());
    let slot = TlsSlot::default();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let s = st.clone();
    let tls = slot.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = l.accept().await {
            let acceptor = TlsAcceptor::from(tls.get().expect("TLS config set").clone());
            let s = s.clone();
            tokio::spawn(async move {
                if let Ok(io) = acceptor.accept(tcp).await {
                    connection(io, s).await;
                }
            });
        }
    });
    (addr, st, slot)
}

/// A server config whose certificate no trusted CA signed.
fn self_signed() -> Arc<rustls::ServerConfig> {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["upstream.test".to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let mut cfg = rustls::ServerConfig::builder_with_provider(support::provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key)
        .unwrap();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(cfg)
}

/// roxy with service layer `s` on a `wss://` service at
/// `upstream.test:<port>/echo`.
async fn start_tls(private_ok: bool, trusted: bool) -> (Harness, Arc<SvcState>) {
    let (addr, st, slot) = start_tls_service().await;
    let url = format!("https://upstream.test:{}/echo", addr.port());
    let mut yaml = addon("s", &url, "");
    if !private_ok {
        yaml = yaml.replace("        private_ok: true\n", "");
    }
    let addons = format!("addons:\n{yaml}");
    let h = Harness::start_with(Opts {
        rules: ALLOW_UPSTREAM,
        extra: &addons,
        ..Opts::default()
    })
    .await;
    let cfg = if trusted {
        h.test_ca.ws_server()
    } else {
        self_signed()
    };
    slot.set(cfg).unwrap();
    (h, st)
}

/// An addon `name` streaming through the in-test service at `url`.
fn addon(name: &str, url: &str, extra: &str) -> String {
    format!(
        "  - name: {name}\n    kind: service\n    endpoint: svc\n    endpoints:\n      \
         svc:\n        url: {url}\n        private_ok: true\n        \
         headers: {{ x-svc-key: \"${{secret:token}}\" }}\n{extra}"
    )
}

/// roxy with one service layer `s` at `path` on the in-test service.
async fn start(path: &str, extra: &str, rules: &str) -> (Harness, Arc<SvcState>) {
    let (addr, st) = start_service().await;
    let addons = format!(
        "addons:\n{}",
        addon("s", &format!("http://{addr}{path}"), extra)
    );
    let h = Harness::start_with(Opts {
        rules,
        extra: &addons,
        ..Opts::default()
    })
    .await;
    (h, st)
}

fn header<'a>(hs: &'a [(String, String)], n: &str) -> &'a str {
    hs.iter()
        .find(|(k, _)| k == n)
        .map_or("", |(_, v)| v.as_str())
}

fn json_of(b: &[u8]) -> Value {
    serde_json::from_slice(b)
        .unwrap_or_else(|e| panic!("not JSON ({e}): {}", String::from_utf8_lossy(b)))
}

#[tokio::test(flavor = "multi_thread")]
async fn pass_through_is_byte_identical() {
    let (h, st) = start("/echo", "", ALLOW_UPSTREAM).await;
    // Several times the credit window, so it streams on credit both ways.
    let body: Vec<u8> = (0..1_000_000u32).map(|i| (i % 251) as u8).collect();
    let res = h
        .client()
        .post(h.https_url("/echo-me?q=1"))
        .header("x-thing", "kept")
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let v = json_of(&res.bytes().await.unwrap());
    assert_eq!(v["path"], "/echo-me?q=1");
    assert_eq!(v["body_len"], 1_000_000);
    assert_eq!(v["body_hash"], fnv(&body));
    assert_eq!(v["headers"]["x-thing"], "kept");

    // The endpoint's credential on the handshake; the flow metadata on the
    // stream's `open`.
    let conns = st.connections();
    assert_eq!(conns.len(), 1, "{conns:?}");
    assert_eq!(header(&conns[0], "x-svc-key"), support::SECRET);
    assert_eq!(header(&conns[0], "roxy-flow-id"), "");
    let opens = st.opens();
    assert_eq!(opens.len(), 1, "{opens:?}");
    let o = &opens[0];
    assert_eq!(o["stream"], 1);
    assert_eq!(o["layer"], "s");
    assert_eq!(o["mode"], "enforce");
    assert_eq!(o["client_ip"], "127.0.0.1");
    assert_eq!(o["listener"], "proxy");
    assert_eq!(o["sni"], "upstream.test");
    let ev = h.wait_events("request", 1).await;
    assert_eq!(o["flow"], ev[0]["flow"]);
    assert_eq!(ev[0]["decision"], "allow");
    assert_eq!(ev[0]["addons"], json!(["s"]));
    let calls = h.wait_events("endpoint_call", 1).await;
    assert_eq!(calls[0]["endpoint"], "svc");
    assert_eq!(calls[0]["status"], 101);
    h.stop().await;
}

/// What the service forwards is judged by the rules (invariant 1), and its
/// rewrite of the response reaches the client.
#[tokio::test(flavor = "multi_thread")]
async fn a_rewrite_is_applied_and_judged_by_the_rules() {
    let rules = r#"
  - id: no-rewritten
    when: path starts_with "/rewritten-secret"
    then: { deny: { status: 403 } }
  - id: upstream
    when: host == "upstream.test"
    then: { allow: { private_ok: true } }
"#;
    let (h, _) = start("/rewrite", "", rules).await;
    let res = h
        .client()
        .post(h.https_url("/fine-path"))
        .body("x")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body = res.text().await.unwrap();
    // The upstream saw the rewritten path; the service upper-cased the
    // response body on the way back.
    assert!(body.contains("\"PATH\":\"/REWRITTEN-PATH\""), "{body}");

    let res = h
        .client()
        .post(h.https_url("/fine-secret"))
        .body("x")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
    let ev = h.wait_events("request", 2).await;
    assert_eq!(ev[1]["terminal_rule"], "no-rewritten");
    assert_eq!(h.upstream.seen().len(), 1);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_deny_is_honoured() {
    let (h, _) = start("/deny", "", ALLOW_UPSTREAM).await;
    let res = h
        .client()
        .post(h.https_url("/x"))
        .body("x")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 451);
    assert_eq!(res.text().await.unwrap(), "the service said no\n");
    assert!(h.upstream.seen().is_empty());
    let ev = h.wait_events("request", 1).await;
    // The service answered; its status says it was a refusal.
    assert_eq!(ev[0]["decision"], "answered");
    assert_eq!(ev[0]["terminal_rule"], "layer:s");
    assert!(
        ev[0]["tags"].as_array().unwrap().contains(&"s:deny".into()),
        "{}",
        ev[0]
    );
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_service_can_deny_the_response_or_answer_itself() {
    let (h, _) = start("/deny-response", "", ALLOW_UPSTREAM).await;
    let res = h.client().get(h.https_url("/x")).send().await.unwrap();
    assert_eq!(res.status(), 403);
    assert_eq!(res.text().await.unwrap(), "not this answer\n");
    // The request did reach the upstream; its answer was replaced.
    assert_eq!(h.upstream.seen().len(), 1);
    h.stop().await;

    let (h, _) = start("/respond", "", ALLOW_UPSTREAM).await;
    let res = h.client().get(h.https_url("/x")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.headers()["x-from"], "service");
    assert_eq!(res.text().await.unwrap(), "made up");
    assert!(h.upstream.seen().is_empty());
    h.stop().await;
}

/// Fail closed: every way a service can fail before the response head
/// denies the exchange with `layer:<name>` and logs why.
#[tokio::test(flavor = "multi_thread")]
async fn failures_fail_closed() {
    for (path, kind) in [
        ("/no-protocol", "service:connect"),
        ("/garbage", "service:protocol"),
        ("/out-of-order", "service:protocol"),
        ("/bad-head", "service:protocol"),
        ("/smuggle", "invalid_request"),
        ("/slow", "service:timeout"),
    ] {
        let (h, _) = start(
            path,
            "    limits: { first_byte_timeout: 500ms }\n",
            ALLOW_UPSTREAM,
        )
        .await;
        let res = h
            .client()
            .post(h.https_url("/x"))
            .body("x")
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 503, "{path}");
        assert_eq!(res.headers()["x-roxy-rule"], "layer:s", "{path}");
        assert!(h.upstream.seen().is_empty(), "{path}");
        let ev = h.wait_events("layer_error", 1).await;
        assert_eq!(ev[0]["kind"], kind, "{path}: {}", ev[0]);
        assert_eq!(ev[0]["layer"], "s");
        assert_eq!(ev[0]["mode"], "enforce");
        h.stop().await;
    }
}

/// A connection lost mid-body never delivers that body as complete.
#[tokio::test(flavor = "multi_thread")]
async fn a_dropped_connection_fails_closed() {
    let (h, _) = start("/drop", "", ALLOW_UPSTREAM).await;
    let res = h
        .client()
        .post(h.https_url("/x"))
        .body("hello")
        .send()
        .await
        .unwrap();
    assert!(res.status().is_server_error(), "{}", res.status());
    // The upstream never saw the cut body end cleanly.
    assert!(
        h.upstream.seen().iter().all(|s| !s.body_ok),
        "{:?}",
        h.upstream.seen()
    );
    let ev = h.wait_events("layer_error", 1).await;
    assert_eq!(ev[0]["kind"], "service:closed", "{}", ev[0]);
    h.stop().await;

    // More bytes than the service declared: cut, as a protocol violation.
    let (h, _) = start("/too-long", "", ALLOW_UPSTREAM).await;
    let res = h
        .client()
        .post(h.https_url("/x"))
        .body("hello")
        .send()
        .await
        .unwrap();
    assert!(res.status().is_server_error(), "{}", res.status());
    assert!(h.upstream.seen().iter().all(|s| !s.body_ok));
    let ev = h.wait_events("layer_error", 1).await;
    assert_eq!(ev[0]["kind"], "service:protocol", "{}", ev[0]);
    h.stop().await;

    // After the response head: the client's body is cut.
    let (h, _) = start("/drop-response", "", ALLOW_UPSTREAM).await;
    let res = h.client().get(h.https_url("/x")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert!(res.bytes().await.is_err(), "the body must not end cleanly");
    let ev = h.wait_events("layer_error", 1).await;
    assert_eq!(ev[0]["kind"], "service:closed", "{}", ev[0]);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn observe_mode_cannot_block() {
    for path in ["/deny", "/garbage", "/no-protocol"] {
        let (h, st) = start(path, "    mode: observe\n", ALLOW_UPSTREAM).await;
        let res = h
            .client()
            .post(h.https_url("/x"))
            .body("x")
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200, "{path}");
        drop(res.bytes().await);
        assert_eq!(h.upstream.seen().len(), 1, "{path}");
        if path == "/no-protocol" {
            let ev = h.wait_events("layer_error", 1).await;
            assert_eq!(ev[0]["mode"], "observe", "{path}");
        } else {
            st.until("the open", |s| !s.opens().is_empty()).await;
            assert_eq!(st.opens()[0]["mode"], "observe", "{path}");
        }
        h.stop().await;
    }
}

/// Concurrent exchanges share one connection, as separate streams.
#[tokio::test(flavor = "multi_thread")]
async fn exchanges_share_a_connection() {
    let (h, st) = start("/echo", "", ALLOW_UPSTREAM).await;
    let c = h.client();
    let reqs = (0..8).map(|i| {
        let c = c.clone();
        let url = h.https_url(&format!("/n{i}"));
        async move { c.post(url).body(vec![b'a'; 100_000]).send().await.unwrap() }
    });
    for res in futures_util::future::join_all(reqs).await {
        assert_eq!(res.status(), 200);
        let v = json_of(&res.bytes().await.unwrap());
        assert_eq!(v["body_len"], 100_000);
    }
    assert_eq!(st.connections().len(), 1);
    let mut ids: Vec<u64> = st
        .opens()
        .iter()
        .map(|o| o["stream"].as_u64().unwrap())
        .collect();
    ids.sort_unstable();
    assert_eq!(ids, (1..=8).collect::<Vec<_>>());
    h.stop().await;
}

/// A full connection makes a new one; a full pool makes exchanges wait.
#[tokio::test(flavor = "multi_thread")]
async fn the_pool_grows_to_its_cap_then_waits() {
    let (h, st) = start(
        "/mixed",
        "    limits: { max_connections: 2, max_streams: 2 }\n",
        ALLOW_UPSTREAM,
    )
    .await;
    let c = h.client();
    let reqs: Vec<_> = (0..5)
        .map(|i| {
            let c = c.clone();
            let url = h.https_url(&format!("/hold{i}"));
            tokio::spawn(async move { c.get(url).send().await.unwrap().status() })
        })
        .collect();
    // Four streams on two connections; the fifth waits for a place.
    st.until("four opens", |s| s.opens().len() == 4).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(st.opens().len(), 4);
    assert_eq!(st.connections().len(), 2);
    for _ in 0..20 {
        st.release.notify_waiters();
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    for r in reqs {
        assert_eq!(r.await.unwrap(), 200);
    }
    assert_eq!(st.opens().len(), 5);
    assert_eq!(st.connections().len(), 2);
    h.stop().await;
}

/// Two layers using the same endpoint in one flow: one connection, two
/// streams, told apart by (flow, layer).
#[tokio::test(flavor = "multi_thread")]
async fn two_layers_on_one_endpoint_get_separate_streams() {
    let (addr, st) = start_service().await;
    let url = format!("http://{addr}/echo");
    let addons = format!("addons:\n{}{}", addon("s", &url, ""), addon("t", &url, ""));
    let h = Harness::start_with(Opts {
        rules: ALLOW_UPSTREAM,
        extra: &addons,
        ..Opts::default()
    })
    .await;
    let res = h
        .client()
        .post(h.https_url("/x"))
        .body("both")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "{:#?}", h.events("layer_error"));
    assert_eq!(json_of(&res.bytes().await.unwrap())["body_len"], 4);
    assert_eq!(st.connections().len(), 1);
    let opens = st.opens();
    assert_eq!(opens.len(), 2, "{opens:?}");
    assert_ne!(opens[0]["stream"], opens[1]["stream"]);
    assert_eq!(opens[0]["flow"], opens[1]["flow"]);
    let mut layers = vec![
        opens[0]["layer"].as_str().unwrap(),
        opens[1]["layer"].as_str().unwrap(),
    ];
    layers.sort_unstable();
    assert_eq!(layers, ["s", "t"]);
    let ev = h.wait_events("request", 1).await;
    assert_eq!(ev[0]["addons"], json!(["s", "t"]));
    h.stop().await;
}

/// A protocol violation on one stream fails that exchange only: the
/// others on the connection carry on, and the connection stays.
#[tokio::test(flavor = "multi_thread")]
async fn one_streams_failure_leaves_the_others() {
    let (h, st) = start("/mixed", "", ALLOW_UPSTREAM).await;
    let c = h.client();
    let held = tokio::spawn({
        let c = c.clone();
        let url = h.https_url("/hold-good");
        async move { c.get(url).send().await.unwrap() }
    });
    st.until("the held stream", |s| s.opens().len() == 1).await;
    let res = c.get(h.https_url("/bad")).send().await.unwrap();
    assert_eq!(res.status(), 503);
    let ev = h.wait_events("layer_error", 1).await;
    assert_eq!(ev[0]["kind"], "service:protocol", "{}", ev[0]);
    // roxy reset the broken stream.
    st.until("a reset", |s| !s.resets.lock().unwrap().is_empty())
        .await;
    assert_eq!(st.resets.lock().unwrap()[0].1, 2);

    st.release.notify_waiters();
    let res = held.await.unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(json_of(&res.bytes().await.unwrap())["path"], "/hold-good");
    let res = c.get(h.https_url("/after")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(st.connections().len(), 1);
    assert!(st.closed.lock().unwrap().is_empty());
    h.stop().await;
}

/// Losing the connection fails every exchange on it closed; the next
/// exchange gets a new connection.
#[tokio::test(flavor = "multi_thread")]
async fn losing_the_connection_fails_its_exchanges() {
    let (h, st) = start("/mixed", "", ALLOW_UPSTREAM).await;
    let c = h.client();
    let held = tokio::spawn({
        let c = c.clone();
        let url = h.https_url("/hold");
        async move { c.get(url).send().await.unwrap() }
    });
    st.until("the held stream", |s| s.opens().len() == 1).await;
    let res = c.get(h.https_url("/kill")).send().await.unwrap();
    assert_eq!(res.status(), 503);
    let res = held.await.unwrap();
    assert_eq!(res.status(), 503);
    let ev = h.wait_events("layer_error", 2).await;
    assert!(ev.iter().all(|e| e["kind"] == "service:closed"), "{ev:#?}");
    assert!(h.upstream.seen().is_empty());

    let res = c.get(h.https_url("/after")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(st.connections().len(), 2);
    h.stop().await;
}

/// A client that gives up resets its stream, not the connection.
#[tokio::test(flavor = "multi_thread")]
async fn a_client_that_gives_up_resets_its_stream() {
    let (h, st) = start("/mixed", "", ALLOW_UPSTREAM).await;
    let impatient = h
        .client_builder()
        .timeout(Duration::from_millis(300))
        .build()
        .unwrap();
    assert!(impatient.get(h.https_url("/hang")).send().await.is_err());
    st.until("a reset", |s| !s.resets.lock().unwrap().is_empty())
        .await;
    let res = h.client().get(h.https_url("/after")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(st.connections().len(), 1);
    h.stop().await;
}

/// Flow control: a stream whose client is not reading holds only its own
/// credit; another stream on the connection is not held up behind it.
#[tokio::test(flavor = "multi_thread")]
async fn a_slow_body_does_not_hold_up_others() {
    let (h, st) = start("/mixed", "", ALLOW_UPSTREAM).await;
    let c = h.client();
    let big = c.get(h.https_url("/big")).send().await.unwrap();
    assert_eq!(big.status(), 200);
    // Not read yet: the service is stuck on credit for it.
    let res = tokio::time::timeout(
        Duration::from_secs(5),
        c.post(h.https_url("/other"))
            .body(vec![b'b'; 600_000])
            .send(),
    )
    .await
    .expect("held up behind the unread body")
    .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(json_of(&res.bytes().await.unwrap())["body_len"], 600_000);
    assert_eq!(big.bytes().await.unwrap().len(), 1 << 20);
    assert_eq!(st.connections().len(), 1);
    h.stop().await;
}

/// Bytes past the stream's credit break the protocol on that stream.
#[tokio::test(flavor = "multi_thread")]
async fn bytes_past_the_credit_fail_the_stream() {
    let (h, st) = start("/mixed", "", ALLOW_UPSTREAM).await;
    // Cut either before the head reaches the client or after it: never
    // delivered as complete.
    if let Ok(res) = h.client().get(h.https_url("/overrun")).send().await {
        assert_eq!(res.status(), 200);
        assert!(res.bytes().await.is_err(), "the body must not end cleanly");
    }
    let ev = h.wait_events("layer_error", 1).await;
    assert_eq!(ev[0]["kind"], "service:protocol", "{}", ev[0]);
    let res = h.client().get(h.https_url("/after")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(st.connections().len(), 1);
    h.stop().await;
}

/// A `wss://` endpoint: dialled with TLS and verified against the
/// upstream trust roots.
#[tokio::test(flavor = "multi_thread")]
async fn a_wss_endpoint_works_with_a_trusted_certificate() {
    let (h, st) = start_tls(true, true).await;
    let res = h
        .client()
        .post(h.https_url("/over-tls"))
        .body(vec![b'z'; 400_000])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "{:#?}", h.events("layer_error"));
    let v = json_of(&res.bytes().await.unwrap());
    assert_eq!(v["body_len"], 400_000);
    assert_eq!(st.connections().len(), 1);
    assert_eq!(header(&st.connections()[0], "x-svc-key"), support::SECRET);
    let calls = h.wait_events("endpoint_call", 1).await;
    assert_eq!(calls[0]["status"], 101);
    h.stop().await;
}

/// A certificate that fails verification fails the exchange closed, and
/// the service never sees a handshake.
#[tokio::test(flavor = "multi_thread")]
async fn a_wss_endpoint_with_a_bad_certificate_fails_closed() {
    let (h, st) = start_tls(true, false).await;
    let res = h.client().get(h.https_url("/x")).send().await.unwrap();
    assert_eq!(res.status(), 503);
    assert_eq!(res.headers()["x-roxy-rule"], "layer:s");
    let ev = h.wait_events("layer_error", 1).await;
    assert_eq!(ev[0]["kind"], "service:connect", "{}", ev[0]);
    assert_eq!(st.connections().len(), 0);
    assert!(h.upstream.seen().is_empty());
    let calls = h.wait_events("endpoint_call", 1).await;
    assert!(calls[0]["status"].is_null(), "{}", calls[0]);
    h.stop().await;
}

/// The address floor applies to a `wss://` endpoint as to any other:
/// without `private_ok`, a private address is refused before TLS.
#[tokio::test(flavor = "multi_thread")]
async fn a_wss_endpoint_needs_private_ok_for_a_private_address() {
    let (h, st) = start_tls(false, true).await;
    let res = h.client().get(h.https_url("/x")).send().await.unwrap();
    assert_eq!(res.status(), 503);
    let ev = h.wait_events("layer_error", 1).await;
    assert_eq!(ev[0]["kind"], "service:connect", "{}", ev[0]);
    assert_eq!(st.connections().len(), 0);
    h.stop().await;
}

/// A reload that rotates the endpoint's secret: new exchanges go on a new
/// connection that carries the new value; the old connection finishes the
/// exchange it has, then closes.
#[tokio::test(flavor = "multi_thread")]
async fn a_rotated_secret_reaches_new_streams_and_old_connections_drain() {
    let (h, st) = start("/mixed", "", ALLOW_UPSTREAM).await;
    let c = h.client();
    let held = tokio::spawn({
        let c = c.clone();
        let url = h.https_url("/hold-old");
        async move { c.get(url).send().await.unwrap() }
    });
    st.until("the held stream", |s| s.opens().len() == 1).await;

    std::fs::write(h.dir.path().join("token"), "rotated-token-value").unwrap();
    assert!(h.running.as_ref().unwrap().reloader.reload_async().await);

    let res = c.get(h.https_url("/after")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let conns = st.connections();
    assert_eq!(conns.len(), 2, "{conns:?}");
    assert_eq!(header(&conns[0], "x-svc-key"), support::SECRET);
    assert_eq!(header(&conns[1], "x-svc-key"), "rotated-token-value");
    assert_eq!(st.opens()[1]["conn_index"], 1);
    // The old connection is still carrying the held exchange.
    assert!(st.closed.lock().unwrap().is_empty());

    st.release.notify_waiters();
    let res = held.await.unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(json_of(&res.bytes().await.unwrap())["path"], "/hold-old");
    st.until("the old connection to close", |s| {
        s.closed.lock().unwrap().contains(&0)
    })
    .await;
    assert!(!st.closed.lock().unwrap().contains(&1));
    let res = c.get(h.https_url("/again")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(st.connections().len(), 2);

    // An idle connection closes as soon as a reload retires it.
    assert!(h.running.as_ref().unwrap().reloader.reload_async().await);
    st.until("the idle connection to close", |s| {
        s.closed.lock().unwrap().contains(&1)
    })
    .await;
    h.stop().await;
}

/// An observe stream sees an exchange with no body through to the end
/// (an empty copy is not a cut one), and roxy credits back what it
/// ignores, so a service that sends more than a window is never stalled.
#[tokio::test(flavor = "multi_thread")]
async fn an_observer_sees_exchanges_through() {
    let (h, st) = start("/echo", "    mode: observe\n", ALLOW_UPSTREAM).await;
    let res = h.client().get(h.https_url("/x")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    drop(res.bytes().await);
    st.until("the observer to see it through", |s| {
        s.echoed.lock().unwrap().len() == 1
    })
    .await;
    assert_eq!(st.resets.lock().unwrap().len(), 0);
    h.stop().await;

    let (h, st) = start("/mixed", "    mode: observe\n", ALLOW_UPSTREAM).await;
    let res = h.client().get(h.https_url("/flood")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    drop(res.bytes().await);
    st.until("the service to send it all", |s| {
        s.echoed.lock().unwrap().len() == 1
    })
    .await;
    assert_eq!(h.events("layer_error").len(), 0);
    h.stop().await;
}
