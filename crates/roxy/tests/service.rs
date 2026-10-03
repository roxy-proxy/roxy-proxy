//! End-to-end tests of service layers (DESIGN.md §11.6): `roxy run` with a
//! `kind: service` addon whose exchanges stream through an in-test service
//! over a WebSocket (`roxy.layer.v1`). The service's behaviour is picked by
//! its URL path.

mod support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use serde_json::{Value, json};
use support::{Harness, Opts, fnv};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

const ALLOW_UPSTREAM: &str = r#"
  - id: upstream
    when: host == "upstream.test"
    then: { allow: { private_ok: true } }
"#;

#[derive(Default)]
struct SvcState {
    /// The handshake headers of every session.
    sessions: Mutex<Vec<Vec<(String, String)>>>,
}

type Ws = WebSocketStream<TcpStream>;

fn ctl(v: &Value) -> Message {
    Message::text(v.to_string())
}

/// The next message, as JSON for text and bytes for binary.
enum Got {
    Ctl(Value),
    Bytes(Vec<u8>),
    End,
}

async fn recv(ws: &mut Ws) -> Got {
    loop {
        match ws.next().await {
            None | Some(Err(_) | Ok(Message::Close(_))) => return Got::End,
            Some(Ok(Message::Text(t))) => return Got::Ctl(serde_json::from_str(&t).unwrap()),
            Some(Ok(Message::Binary(b))) => return Got::Bytes(b.to_vec()),
            Some(Ok(_)) => {}
        }
    }
}

/// Reads one whole message (head, body, end).
async fn whole(ws: &mut Ws) -> (Value, Vec<u8>) {
    let Got::Ctl(head) = recv(ws).await else {
        panic!("expected a head");
    };
    let mut body = Vec::new();
    loop {
        match recv(ws).await {
            Got::Bytes(b) => body.extend(b),
            Got::Ctl(_) => return (head, body),
            Got::End => panic!("closed mid-message"),
        }
    }
}

/// Sends a whole message back: head, body (if any), end.
async fn send_whole(ws: &mut Ws, head: Value, body: Vec<u8>, end: &str) {
    ws.send(ctl(&head)).await.unwrap();
    if !body.is_empty() {
        ws.send(Message::binary(body)).await.unwrap();
    }
    ws.send(ctl(&json!({ "type": end }))).await.unwrap();
}

/// Forwards every message as it arrives, applying `f` to heads and `g` to
/// response bytes.
async fn relay(ws: &mut Ws, f: impl Fn(Value) -> Value, g: impl Fn(Vec<u8>) -> Vec<u8>) {
    let mut in_response = false;
    loop {
        match recv(ws).await {
            Got::Ctl(v) => {
                if v["type"] == "response" {
                    in_response = true;
                }
                if ws.send(ctl(&f(v))).await.is_err() {
                    return;
                }
            }
            Got::Bytes(b) => {
                let b = if in_response { g(b) } else { b };
                if ws.send(Message::binary(b)).await.is_err() {
                    return;
                }
            }
            Got::End => return,
        }
    }
}

async fn session(path: &str, mut ws: Ws) {
    match path {
        "/echo" => relay(&mut ws, |v| v, |b| b).await,
        "/rewrite" => {
            relay(
                &mut ws,
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
            let _ = recv(&mut ws).await;
            ws.send(ctl(
                &json!({"type": "deny", "status": 451, "message": "the service said no"}),
            ))
            .await
            .unwrap();
        }
        "/deny-response" => {
            let (head, body) = whole(&mut ws).await;
            send_whole(&mut ws, head, body, "request_end").await;
            let _ = whole(&mut ws).await;
            ws.send(ctl(&json!({"type": "deny", "message": "not this answer"})))
                .await
                .unwrap();
        }
        "/respond" => {
            let _ = recv(&mut ws).await;
            let head =
                json!({"type": "response", "status": 200, "headers": [["x-from", "service"]]});
            send_whole(&mut ws, head, b"made up".to_vec(), "response_end").await;
        }
        "/garbage" => {
            let _ = recv(&mut ws).await;
            ws.send(Message::text("not json")).await.unwrap();
        }
        "/out-of-order" => {
            let _ = recv(&mut ws).await;
            ws.send(Message::binary(b"bytes first".to_vec()))
                .await
                .unwrap();
        }
        "/bad-head" => {
            let _ = recv(&mut ws).await;
            ws.send(ctl(&json!({"type": "request", "method": "GET",
                "url": "http://upstream.test/", "headers": [["bad header", "x"]]})))
                .await
                .unwrap();
        }
        // Forwards a request with framing fields a client could not send.
        "/smuggle" => {
            let _ = whole(&mut ws).await;
            let head = json!({"type": "request", "method": "POST", "url": "http://upstream.test/x",
                "headers": [["content-length", "3"], ["transfer-encoding", "chunked"]]});
            send_whole(&mut ws, head, b"abc".to_vec(), "request_end").await;
            let _ = recv(&mut ws).await;
        }
        "/slow" => tokio::time::sleep(Duration::from_secs(5)).await,
        // roxy refuses the handshake (no subprotocol); nothing to do.
        "/no-protocol" => {}
        // Forwards the request head and part of a body, then goes away.
        "/drop" => {
            let Got::Ctl(mut head) = recv(&mut ws).await else {
                return;
            };
            // Undeclared length, so only the lost connection is wrong.
            head["headers"] = json!([]);
            ws.send(ctl(&head)).await.unwrap();
            ws.send(Message::binary(b"partial".to_vec())).await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        // Declares a length, then sends more than that.
        "/too-long" => {
            let (mut head, _) = whole(&mut ws).await;
            head["headers"] = json!([["content-length", "3"]]);
            send_whole(&mut ws, head, b"too long".to_vec(), "request_end").await;
            let _ = recv(&mut ws).await;
        }
        // Passes the request on, then cuts the response short.
        "/drop-response" => {
            let (head, body) = whole(&mut ws).await;
            send_whole(&mut ws, head, body, "request_end").await;
            let Got::Ctl(head) = recv(&mut ws).await else {
                return;
            };
            ws.send(ctl(&head)).await.unwrap();
            ws.send(Message::binary(b"{\"partial\":".to_vec()))
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        p => panic!("unknown service path {p}"),
    }
}

// The handshake callback's error type is tungstenite's.
#[allow(clippy::result_large_err)]
async fn start_service() -> (std::net::SocketAddr, Arc<SvcState>) {
    let st = Arc::new(SvcState::default());
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let s = st.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = l.accept().await else {
                return;
            };
            let s = s.clone();
            tokio::spawn(async move {
                let path = Arc::new(Mutex::new(String::new()));
                let p = path.clone();
                let callback = move |req: &Request, mut res: Response| {
                    let path = req.uri().path().to_owned();
                    s.sessions.lock().unwrap().push(
                        req.headers()
                            .iter()
                            .map(|(n, v)| (n.to_string(), v.to_str().unwrap_or("").to_owned()))
                            .collect(),
                    );
                    if path != "/no-protocol" {
                        res.headers_mut()
                            .insert("sec-websocket-protocol", "roxy.layer.v1".parse().unwrap());
                    }
                    *p.lock().unwrap() = path;
                    Ok(res)
                };
                let Ok(ws) = tokio_tungstenite::accept_hdr_async(tcp, callback).await else {
                    return;
                };
                let path = path.lock().unwrap().clone();
                session(&path, ws).await;
            });
        }
    });
    (addr, st)
}

/// roxy with one service layer `s` at `path` on the in-test service.
async fn start(path: &str, extra: &str, rules: &str) -> (Harness, Arc<SvcState>) {
    let (addr, st) = start_service().await;
    let addons = format!(
        "addons:\n  - name: s\n    kind: service\n    endpoint: svc\n    endpoints:\n      \
         svc:\n        url: http://{addr}{path}\n        private_ok: true\n        \
         headers: {{ x-svc-key: \"${{secret:token}}\" }}\n{extra}"
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
    // Large enough to need many frames each way, streamed.
    let body: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
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
    assert_eq!(v["body_len"], 300_000);
    assert_eq!(v["body_hash"], fnv(&body));
    assert_eq!(v["headers"]["x-thing"], "kept");

    // One session for the exchange, with the flow metadata and the
    // endpoint's credential on the handshake.
    let sessions = st.sessions.lock().unwrap().clone();
    assert_eq!(sessions.len(), 1, "{sessions:?}");
    let s = &sessions[0];
    assert_eq!(header(s, "roxy-flow-layer"), "s");
    assert_eq!(header(s, "roxy-flow-mode"), "enforce");
    assert_eq!(header(s, "roxy-flow-client-ip"), "127.0.0.1");
    assert_eq!(header(s, "x-svc-key"), support::SECRET);
    let ev = h.wait_events("request", 1).await;
    assert_eq!(header(s, "roxy-flow-id"), ev[0]["flow"].as_str().unwrap());
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
    assert_eq!(ev[0]["decision"], "deny");
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
        }
        let sessions = st.sessions.lock().unwrap().clone();
        assert_eq!(header(&sessions[0], "roxy-flow-mode"), "observe", "{path}");
        h.stop().await;
    }
}
