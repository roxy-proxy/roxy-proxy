//! One connection to a service: the handshake, the framing, and the
//! reader and writer tasks every stream on it shares.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use bytes::BytesMut;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt as _, StreamExt as _};
use http::HeaderValue;
use roxy_http::Scheme;
use serde::Serialize;
use tokio::sync::mpsc;
use tokio_tungstenite::WebSocketStream;
pub(super) use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use super::super::super::{EndpointSpec, StackFlow, endpoint};
use super::super::{In, Out, ServiceError};
use super::lock;
use super::stream::{Reset, Stream};
use crate::flowlog::FlowEvent;
use crate::upstream::MaybeTls;
use crate::watch::Dir;

/// The WebSocket subprotocol a service must accept.
pub const SUBPROTOCOL: &str = "roxy.layer.v3";

/// Largest control message or body frame accepted from a service.
pub(super) const MAX_FRAME: usize = 16 * 1024 * 1024;

/// Body frames waiting for the socket, across all streams. Each stream
/// only queues what it has credit for.
pub(super) const WRITE_QUEUE: usize = 64;

pub(super) type Ws = WebSocketStream<MaybeTls>;

/// One connection: what streams send through, and the state its reader
/// shares.
pub(super) struct Link {
    pub(super) shared: Arc<LinkShared>,
    /// Ordered per stream: open, heads, body frames, ends. The socket
    /// closes once every sender is gone (the pool's, and each stream's).
    pub(super) data: mpsc::Sender<Queued>,
}

/// A message on a connection's data queue.
pub(super) struct Queued {
    pub(super) msg: Message,
    pub(super) wire: Arc<Wire>,
    /// It is the stream's `open`.
    pub(super) open: bool,
}

/// How far a stream has got on the wire. Once it is reset, nothing more
/// of it is written. A reset before its `open` was written does not tell
/// the service (the reset would overtake the queued `open`): the service
/// never hears of the stream.
#[derive(Default)]
pub(super) struct Wire(AtomicU8);

impl Wire {
    const UNSENT: u8 = 0;
    const WRITTEN: u8 = 1;
    const DROPPED: u8 = 2;

    /// Whether the writer writes a message of the stream (`open`: its
    /// `open` message).
    pub(super) fn write(&self, open: bool) -> bool {
        if open {
            self.0
                .compare_exchange(
                    Self::UNSENT,
                    Self::WRITTEN,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                )
                .is_ok()
        } else {
            self.0.load(Ordering::SeqCst) != Self::DROPPED
        }
    }

    /// The stream is reset: whether the service is told, which it is
    /// once the `open` has been written.
    pub(super) fn reset(&self) -> bool {
        self.0.swap(Self::DROPPED, Ordering::SeqCst) == Self::WRITTEN
    }
}

pub(super) struct LinkShared {
    pub(super) streams: Mutex<LinkState>,
    /// Credit and resets: never held up behind body frames, so the reader
    /// and feeders can always send them. Unbounded in count, bounded in
    /// fact: credit goes back in batches of a quarter window, so a stream
    /// queues a few credit messages per body and one reset, however small
    /// the service's frames, and the service cannot send more to earn
    /// more until the socket takes them.
    pub(super) ctl: mpsc::UnboundedSender<Message>,
}

pub(super) struct LinkState {
    pub(super) open: HashMap<u32, Arc<Stream>>,
    /// The next id to hand out; ids below it were opened.
    pub(super) next_id: u32,
    /// The connection failed: no new streams.
    pub(super) failed: bool,
}

impl LinkShared {
    pub(super) fn closed(&self) -> bool {
        let s = lock(&self.streams);
        s.failed || s.next_id == u32::MAX
    }

    pub(super) fn send_ctl(&self, stream: u32, m: &Out) {
        let _ = self.ctl.send(text(stream, m));
    }

    /// The connection failed: every stream on it fails, and it closes.
    pub(super) fn fail(&self, e: &ServiceError) {
        let streams: Vec<_> = {
            let mut s = lock(&self.streams);
            s.failed = true;
            s.open.drain().map(|(_, st)| st).collect()
        };
        for s in streams {
            s.fail(e.clone(), Reset::Skip);
        }
        let _ = self.ctl.send(Message::Close(None));
    }
}

#[derive(Serialize)]
pub(super) struct Envelope<'a> {
    pub(super) stream: u32,
    #[serde(flatten)]
    pub(super) msg: &'a Out,
}

pub(super) fn text(stream: u32, m: &Out) -> Message {
    // `Out` always serializes.
    Message::text(serde_json::to_string(&Envelope { stream, msg: m }).unwrap_or_default())
}

/// The direction byte of a binary frame.
pub(super) fn dir_byte(dir: Dir) -> u8 {
    match dir {
        Dir::Request => 0,
        Dir::Response => 1,
    }
}

pub(super) fn dir_of(byte: u8) -> Option<Dir> {
    match byte {
        0 => Some(Dir::Request),
        1 => Some(Dir::Response),
        _ => None,
    }
}

pub(super) fn binary(stream: u32, dir: Dir, data: &[u8]) -> Message {
    let mut b = BytesMut::with_capacity(5 + data.len());
    b.extend_from_slice(&stream.to_be_bytes());
    b.extend_from_slice(&[dir_byte(dir)]);
    b.extend_from_slice(data);
    Message::binary(b.freeze())
}

/// The handshake request for `spec`: the endpoint's URL as a WebSocket
/// one, its headers with secrets expanded, and the subprotocol.
pub(super) fn handshake_request(
    st: &StackFlow,
    spec: &EndpointSpec,
) -> Result<(Scheme, roxy_http::Authority, http::Request<()>), ServiceError> {
    let uri = &spec.url;
    let (scheme, authority) = endpoint::authority_of(uri).map_err(ServiceError::Connect)?;
    let ws_scheme = if scheme == Scheme::Http { "ws" } else { "wss" };
    let path = uri.path_and_query().map_or("/", |p| p.as_str());
    let url = format!(
        "{ws_scheme}://{}{path}",
        uri.authority().map_or("", |a| a.as_str())
    );
    let mut request = url
        .into_client_request()
        .map_err(|e| ServiceError::Connect(e.to_string()))?;
    let h = request.headers_mut();
    for (n, v) in endpoint::credentials(spec, st.secrets()).map_err(ServiceError::Connect)? {
        h.insert(n, v);
    }
    h.insert(
        http::header::SEC_WEBSOCKET_PROTOCOL,
        HeaderValue::from_static(SUBPROTOCOL),
    );
    Ok((scheme, authority, request))
}

/// Connects and completes the handshake through the connector (which runs
/// the address floor on the address it dials), then starts the
/// connection's reader and writer.
pub(super) async fn dial(
    st: &StackFlow,
    layer: &str,
    endpoint: &str,
    spec: &EndpointSpec,
) -> Result<Arc<Link>, ServiceError> {
    let started = Instant::now();
    let result = async {
        let (scheme, authority, request) = handshake_request(st, spec)?;
        let io = st
            .snap
            .upstream
            .connect_h1(scheme, &authority, spec.private)
            .await
            .map_err(|e| ServiceError::Connect(e.to_string()))?;
        let config = WebSocketConfig::default()
            .max_message_size(Some(MAX_FRAME))
            .max_frame_size(Some(MAX_FRAME));
        let (ws, res) = tokio_tungstenite::client_async_with_config(request, io, Some(config))
            .await
            .map_err(|e| ServiceError::Connect(e.to_string()))?;
        let proto = res
            .headers()
            .get(http::header::SEC_WEBSOCKET_PROTOCOL)
            .and_then(|v| v.to_str().ok());
        if proto != Some(SUBPROTOCOL) {
            return Err(ServiceError::Connect(format!(
                "the service did not accept subprotocol {SUBPROTOCOL}"
            )));
        }
        Ok(ws)
    }
    .await;
    st.shared.sink.emit(&FlowEvent::EndpointCall {
        ts: chrono::Utc::now(),
        flow: st.flow.to_string(),
        conn: st.client.id.to_string(),
        layer: layer.to_owned(),
        endpoint: endpoint.to_owned(),
        method: "GET".to_owned(),
        path: spec.url.path().to_owned(),
        status: result.is_ok().then_some(101),
        attempts: 1,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        error: result.as_ref().err().map(ToString::to_string),
    });
    let (sink, stream) = result?.split();
    let (data_tx, data_rx) = mpsc::channel(WRITE_QUEUE);
    let (ctl_tx, ctl_rx) = mpsc::unbounded_channel();
    let shared = Arc::new(LinkShared {
        streams: Mutex::new(LinkState {
            open: HashMap::new(),
            next_id: 1,
            failed: false,
        }),
        ctl: ctl_tx,
    });
    tokio::spawn(write(sink, data_rx, ctl_rx));
    tokio::spawn(read(shared.clone(), stream));
    Ok(Arc::new(Link {
        shared,
        data: data_tx,
    }))
}

/// Owns the socket's write half. Control messages go first, but a reset
/// never overtakes its stream's `open` ([`Wire`]). The socket closes once
/// every data sender is gone, or on a close.
pub(super) async fn write(
    mut sink: SplitSink<Ws, Message>,
    mut data: mpsc::Receiver<Queued>,
    mut ctl: mpsc::UnboundedReceiver<Message>,
) {
    loop {
        let m = tokio::select! {
            biased;
            Some(m) = ctl.recv() => m,
            m = data.recv() => match m {
                Some(q) if q.wire.write(q.open) => q.msg,
                Some(_) => continue,
                None => break,
            },
        };
        let close = matches!(m, Message::Close(_));
        if sink.send(m).await.is_err() || close {
            return;
        }
    }
    let _ = sink.close().await;
}

/// Reads the connection and hands each message to its stream. Only broken
/// framing (or the socket going) ends it, failing every stream on it.
pub(super) async fn read(shared: Arc<LinkShared>, mut ws: SplitStream<Ws>) {
    let framing = |what: &str| ServiceError::Protocol(what.to_owned());
    let err = loop {
        let routed = match ws.next().await {
            None | Some(Ok(Message::Close(_))) => {
                break ServiceError::Closed("the service closed the connection".into());
            }
            Some(Err(e)) => break ServiceError::Closed(e.to_string()),
            Some(Ok(Message::Binary(b))) => {
                if b.len() < 5 {
                    break framing("a binary frame shorter than its stream id and direction");
                }
                let id = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
                let Some(dir) = dir_of(b[4]) else {
                    break framing("a binary frame with an unknown direction");
                };
                route(&shared, id).map(|s| match s {
                    Some(s) => s.bytes(dir, &b[5..]),
                    // Ignored, and credited back, so a service still
                    // sending when the stream ended is never stalled.
                    None if b.len() > 5 => shared.send_ctl(
                        id,
                        &Out::Credit {
                            dir,
                            bytes: (b.len() - 5) as u64,
                        },
                    ),
                    None => {}
                })
            }
            Some(Ok(Message::Text(t))) => {
                let Ok(serde_json::Value::Object(v)) = serde_json::from_str(t.as_str()) else {
                    break framing("a text frame that is not a JSON object");
                };
                let Some(id) = v
                    .get("stream")
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|n| u32::try_from(n).ok())
                else {
                    break framing("a message without a valid `stream`");
                };
                route(&shared, id).map(|s| {
                    if let Some(s) = s {
                        match serde_json::from_value::<In>(serde_json::Value::Object(v)) {
                            Ok(m) => s.control(m),
                            Err(e) => {
                                s.fail(
                                    ServiceError::Protocol(format!("bad message: {e}")),
                                    Reset::Send,
                                );
                            }
                        }
                    }
                })
            }
            // Ping and pong are answered by the library.
            Some(Ok(_)) => Ok(()),
        };
        if let Err(e) = routed {
            break e;
        }
    };
    shared.fail(&err);
}

/// The open stream `id`; `None` for one that has ended (a message that
/// crossed its end); an error for one roxy never opened.
pub(super) fn route(shared: &LinkShared, id: u32) -> Result<Option<Arc<Stream>>, ServiceError> {
    let s = lock(&shared.streams);
    if let Some(stream) = s.open.get(&id) {
        return Ok(Some(stream.clone()));
    }
    if id == 0 || id >= s.next_id {
        return Err(ServiceError::Protocol(format!(
            "a message for stream {id}, which roxy never opened"
        )));
    }
    Ok(None)
}
