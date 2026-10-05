//! An in-test `roxy.layer.v3` service behind the scripted upstream: a
//! WebSocket handshake carrying the subprotocol is served here, on any
//! port. The connection's behaviour is picked by the handshake's path:
//!
//! * `/svc/pass`: a conforming pass-through: every head, body byte and
//!   end roxy sends comes straight back on the same stream, in its own
//!   direction, within the credit roxy grants;
//! * `/svc/talk`: sends [`TALK_BYTES`] of request body on each stream as
//!   it opens, with no head, within the credit roxy grants, and logs the
//!   stream once all of it has gone;
//! * `/svc/flood`: sends one request body frame of [`FLOOD_BYTES`] on
//!   each stream as it opens, with no head and without waiting for
//!   credit;
//! * `/svc/stall`: completes the handshake and never reads.
//!
//! Every connection credits roxy back for the bytes it receives.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, PoisonError};

use bytes::Bytes;
use futures_util::{SinkExt as _, StreamExt as _};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::Role;

use crate::addons::service::SUBPROTOCOL;

/// Each body's starting credit, each way.
const WINDOW: u64 = 256 * 1024;

/// The direction bytes of binary frames, and their `credit` names.
const REQUEST: u8 = 0;
const RESPONSE: u8 = 1;

fn dir_name(dir: u8) -> &'static str {
    if dir == REQUEST {
        "request"
    } else {
        "response"
    }
}

fn dir_of(name: &str) -> Option<u8> {
    match name {
        "request" => Some(REQUEST),
        "response" => Some(RESPONSE),
        _ => None,
    }
}

/// What `/svc/flood` sends on each stream in one frame: more than the
/// window.
pub(crate) const FLOOD_BYTES: usize = 300 * 1024;

/// What `/svc/talk` sends on each stream, on credit: several windows.
pub(crate) const TALK_BYTES: usize = 4 * 256 * 1024;

/// What the service saw, across connections.
#[derive(Default)]
pub(crate) struct ServiceLog {
    opens: Mutex<Vec<Value>>,
    resets: Mutex<Vec<(u32, String)>>,
    talked: Mutex<Vec<u32>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl ServiceLog {
    /// Every `open` message, in arrival order.
    pub(crate) fn opens(&self) -> Vec<Value> {
        lock(&self.opens).clone()
    }

    /// Every reset roxy sent: (stream id, message).
    pub(crate) fn resets(&self) -> Vec<(u32, String)> {
        lock(&self.resets).clone()
    }

    /// Waits until `n` `/svc/talk` streams got all their bytes out.
    pub(crate) async fn until_talked(&self, n: usize) {
        let wait = async {
            while lock(&self.talked).len() < n {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), wait)
            .await
            .expect("the service gets its bytes out");
    }
}

/// Whether `req` is a service handshake.
pub(crate) fn is_handshake(req: &http::Request<Incoming>) -> bool {
    req.headers()
        .get("sec-websocket-protocol")
        .is_some_and(|v| v == SUBPROTOCOL)
}

/// Accepts the handshake and serves the connection by `path`.
pub(crate) fn accept(
    req: &mut http::Request<Incoming>,
    path: String,
    log: Arc<ServiceLog>,
) -> http::Response<Full<Bytes>> {
    let key = req
        .headers()
        .get("sec-websocket-key")
        .map(|k| String::from_utf8_lossy(k.as_bytes()).into_owned())
        .unwrap_or_default();
    let on = hyper::upgrade::on(req);
    tokio::spawn(async move {
        let Ok(up) = on.await else {
            return;
        };
        let ws = WebSocketStream::from_raw_socket(TokioIo::new(up), Role::Server, None).await;
        connection(ws, &path, log).await;
    });
    http::Response::builder()
        .status(101)
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-accept", roxy_http::ws::compute_accept(&key))
        .header("sec-websocket-protocol", SUBPROTOCOL)
        .body(Full::default())
        .unwrap()
}

/// What a pass-through stream still has to send in one direction, in
/// order, once roxy grants the credit for it.
enum Queued {
    Ctl(Value),
    Bytes(Bytes),
}

struct Lane {
    credit: u64,
    queue: VecDeque<Queued>,
}

impl Lane {
    fn new() -> Self {
        Self {
            credit: WINDOW,
            queue: VecDeque::new(),
        }
    }
}

/// One stream: a lane per body direction, indexed by direction byte.
struct Sess {
    lanes: [Lane; 2],
}

impl Sess {
    fn new() -> Self {
        Self {
            lanes: [Lane::new(), Lane::new()],
        }
    }
}

/// The direction a control message belongs to, for a pass-through.
fn lane_of(kind: &str) -> Option<u8> {
    match kind {
        "request" | "request_end" => Some(REQUEST),
        "response" | "response_end" => Some(RESPONSE),
        _ => None,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Pass,
    Talk,
    Flood,
}

impl Mode {
    fn of(path: &str) -> Self {
        if path.ends_with("/pass") {
            Self::Pass
        } else if path.ends_with("/talk") {
            Self::Talk
        } else {
            Self::Flood
        }
    }
}

struct Conn {
    mode: Mode,
    tx: mpsc::UnboundedSender<Message>,
    streams: HashMap<u32, Sess>,
    log: Arc<ServiceLog>,
}

fn text(stream: u32, mut v: Value) -> Message {
    v["stream"] = stream.into();
    Message::text(v.to_string())
}

fn binary(stream: u32, dir: u8, data: &[u8]) -> Message {
    let mut b = Vec::with_capacity(5 + data.len());
    b.extend_from_slice(&stream.to_be_bytes());
    b.push(dir);
    b.extend_from_slice(data);
    Message::binary(b)
}

impl Conn {
    fn send(&self, m: Message) {
        let _ = self.tx.send(m);
    }

    fn control(&mut self, mut v: Value) {
        let Some(id) = v["stream"].as_u64().and_then(|n| u32::try_from(n).ok()) else {
            return;
        };
        let kind = v["type"].as_str().unwrap_or_default().to_owned();
        match kind.as_str() {
            "open" => {
                lock(&self.log.opens).push(v);
                self.streams.insert(id, Sess::new());
                match self.mode {
                    Mode::Pass => {}
                    Mode::Talk => {
                        let s = self.streams.get_mut(&id).expect("just opened");
                        s.lanes[usize::from(REQUEST)]
                            .queue
                            .push_back(Queued::Bytes(Bytes::from(vec![0x5au8; TALK_BYTES])));
                        self.flush(id, REQUEST);
                    }
                    Mode::Flood => self.send(binary(id, REQUEST, &vec![0x5au8; FLOOD_BYTES])),
                }
            }
            "credit" => {
                let n = v["bytes"].as_u64().unwrap_or(0);
                let Some(dir) = v["dir"].as_str().and_then(dir_of) else {
                    return;
                };
                if let Some(s) = self.streams.get_mut(&id) {
                    s.lanes[usize::from(dir)].credit += n;
                }
                self.flush(id, dir);
            }
            "reset" => {
                let msg = v["message"].as_str().unwrap_or_default().to_owned();
                lock(&self.log.resets).push((id, msg));
                self.streams.remove(&id);
            }
            _ if self.mode == Mode::Pass => {
                let Some(dir) = lane_of(&kind) else {
                    return;
                };
                v.as_object_mut().map(|o| o.remove("stream"));
                if let Some(s) = self.streams.get_mut(&id) {
                    s.lanes[usize::from(dir)].queue.push_back(Queued::Ctl(v));
                }
                self.flush(id, dir);
            }
            _ => {}
        }
    }

    fn bytes(&mut self, id: u32, dir: u8, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        self.send(text(
            id,
            json!({"type": "credit", "dir": dir_name(dir), "bytes": data.len()}),
        ));
        if self.mode == Mode::Pass
            && let Some(s) = self.streams.get_mut(&id)
        {
            s.lanes[usize::from(dir)]
                .queue
                .push_back(Queued::Bytes(Bytes::copy_from_slice(data)));
            self.flush(id, dir);
        }
    }

    /// Sends what stream `id` has queued in direction `dir`, as far as
    /// its credit goes.
    fn flush(&mut self, id: u32, dir: u8) {
        let Some(s) = self.streams.get_mut(&id) else {
            return;
        };
        let lane = &mut s.lanes[usize::from(dir)];
        let mut out = Vec::new();
        while let Some(q) = lane.queue.pop_front() {
            match q {
                Queued::Ctl(v) => out.push(text(id, v)),
                Queued::Bytes(mut b) => {
                    // Frames of at most 32 KiB, so credit comes back in
                    // steps smaller than roxy's.
                    let n = usize::try_from(lane.credit).map_or(b.len(), |c| c.min(b.len()));
                    let n = n.min(32 * 1024);
                    if n == 0 {
                        lane.queue.push_front(Queued::Bytes(b));
                        break;
                    }
                    let part = b.split_to(n);
                    lane.credit -= n as u64;
                    out.push(binary(id, dir, &part));
                    if !b.is_empty() {
                        lane.queue.push_front(Queued::Bytes(b));
                    }
                }
            }
        }
        if lane.queue.is_empty() && self.mode == Mode::Talk {
            lock(&self.log.talked).push(id);
        }
        for m in out {
            self.send(m);
        }
    }
}

async fn connection<S>(ws: WebSocketStream<S>, path: &str, log: Arc<ServiceLog>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    if path.ends_with("/stall") {
        // Holds the socket open without reading it.
        let _ws = ws;
        return std::future::pending::<()>().await;
    }
    let (mut sink, mut stream) = ws.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
    tokio::spawn(async move {
        while let Some(m) = rx.recv().await {
            if sink.send(m).await.is_err() {
                return;
            }
        }
    });
    let mut conn = Conn {
        mode: Mode::of(path),
        tx,
        streams: HashMap::new(),
        log,
    };
    while let Some(Ok(m)) = stream.next().await {
        match m {
            Message::Text(t) => {
                if let Ok(v) = serde_json::from_str::<Value>(t.as_str()) {
                    conn.control(v);
                }
            }
            Message::Binary(b) if b.len() >= 5 => {
                let id = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
                conn.bytes(id, b[4], &b[5..]);
            }
            Message::Close(_) => return,
            Message::Binary(_) | Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
        }
    }
}
