//! Client-facing HTTP/1.1 server codec (`DESIGN.md` §5.3, §5.5, §5.6).
//!
//! # Body streaming design
//!
//! A request body is never buffered. [`ServerConn::next_request`] returns the
//! request with a channel-backed [`Body`] (see [`Body::channel`]); the
//! producing end stays inside the `ServerConn`, together with the body
//! decoder (content-length or [`ChunkedDecoder`]). Bytes only move from the
//! socket into the channel while one of the `ServerConn` futures is being
//! polled — there are no spawned tasks:
//!
//! - [`ServerConn::drive`] runs a caller future (typically "send the request
//!   upstream and await the response head") concurrently with the body read
//!   loop, via `select!`. When the body completes first, it keeps awaiting the
//!   caller future; when the caller future completes first, the read loop is
//!   simply paused (it is cancel-safe: a decoded chunk waiting for channel
//!   capacity is held in the connection, not in the dropped future).
//! - [`ServerConn::respond`] writes the response while continuing to pump the
//!   rest of the request body (upstreams may answer before reading the whole
//!   body, and clients may not read the response until they finish sending).
//!   If the consumer dropped the request body (deny, early upstream answer),
//!   the remainder is drained and discarded up to [`DRAIN_LIMIT`] bytes, after
//!   which the connection is closed instead of being kept alive.
//!
//! Invariants:
//! - Backpressure: at most [`crate::model::CHANNEL_DEPTH`] chunks of at most
//!   one read buffer each are queued; the socket is not read while the queue
//!   is full.
//! - Any timeout, cap overflow, framing violation or EOF mid-body ends the
//!   body stream with an error (never a clean end), and the connection is
//!   unusable afterwards.
//! - Bytes after the current message (pipelining) stay in the connection
//!   buffer and are parsed by the next `next_request`; bytes after a CONNECT
//!   head are returned by [`ServerConn::accept_connect`].
//! - The caller must either forward/poll `req.body` or drop it; holding it
//!   un-polled stalls the connection until `limits.body_idle_timeout`.

mod chunked;
mod head;

use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use http::{HeaderMap, StatusCode};
use http_body::Body as _;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufWriter, ReadHalf, WriteHalf,
};
use tokio::time::{Instant, timeout, timeout_at};

pub use chunked::{ChunkedDecoder, Decoded};
pub use head::{Framing, Head, HeadScan, RequestHead, Role, parse_head, scan_head};

use crate::model::{
    Authority, Body, BodyError, BodySender, CanonicalRequest, CanonicalResponse, Headers,
    HttpFlags, Limits, ParseError, Reason, RequestMeta, TargetForm, Version, WriteError,
    status_forbids_body,
};

/// Read size per socket read.
const READ_CHUNK: usize = 16 * 1024;
/// Maximum request-body bytes discarded to keep a connection alive after the
/// consumer dropped the body; beyond this the connection is closed.
pub const DRAIN_LIMIT: u64 = 1024 * 1024;
/// Lingering-close budget (RFC 9112 §9.6): after a response that left
/// request bytes unread, roxy half-closes and discards input for at most
/// this long so the client sees the response rather than a reset.
const LINGER: Duration = Duration::from_secs(1);
const LINGER_BYTES: usize = 1024 * 1024;

/// What the client sent.
#[derive(Debug)]
pub enum Incoming {
    /// A request in the form legal for the role (absolute-form on the proxy
    /// port, origin-form in a tunnel).
    Request(CanonicalRequest),
    /// Origin-form on the proxy port. §4.1: the proxy must reject this unless
    /// the host is `roxy.internal`. Kept as a separate variant so it cannot be
    /// treated as an ordinary request by accident. `authority` comes from
    /// `Host` (port 80 default), `scheme` is `http`.
    OriginFormOnProxyPort(CanonicalRequest),
    /// `CONNECT host:port` on the proxy port. Answer with
    /// [`ServerConn::accept_connect`], [`ServerConn::respond`] (non-2xx),
    /// [`ServerConn::respond_proxy_auth_required`] (407 with a challenge) or
    /// [`ServerConn::respond_error_and_close`].
    Connect {
        /// Target authority.
        authority: Authority,
        /// Canonical headers.
        headers: Headers,
        /// Metadata (`proxy_authorization`).
        meta: RequestMeta,
    },
}

enum BodyDecoder {
    Length(u64),
    Chunked(ChunkedDecoder),
}

enum Pending {
    Data(Bytes),
    Trailers(HeaderMap),
    Finish,
}

struct BodyFeed {
    decoder: BodyDecoder,
    /// `None` once the consumer dropped the body: draining.
    sender: Option<BodySender>,
    pending: Option<Pending>,
    drained: u64,
}

struct ReadSide<IO> {
    rd: ReadHalf<IO>,
    buf: BytesMut,
    feed: Option<BodyFeed>,
    /// Request bytes were left unread (drain limit, abandoned body).
    abandoned: bool,
    limits: Arc<Limits>,
}

fn body_error_for(e: &ParseError, limits: &Limits) -> BodyError {
    match e.reason {
        Reason::BodyTooLarge => BodyError::TooLarge {
            limit: limits.max_request_body_bytes,
        },
        Reason::BodyTimeout => BodyError::Timeout,
        Reason::UnexpectedEof | Reason::Io => BodyError::Incomplete,
        _ => BodyError::Invalid(e.clone()),
    }
}

fn io_err(e: &std::io::Error) -> ParseError {
    ParseError::new(Reason::Io, e.to_string())
}

impl<IO: AsyncRead + AsyncWrite + Unpin> ReadSide<IO> {
    fn fail(&mut self, e: ParseError) -> ParseError {
        if let Some(mut feed) = self.feed.take()
            && let Some(tx) = feed.sender.take()
        {
            tx.abort(body_error_for(&e, &self.limits));
        }
        e
    }

    /// Reads more bytes, bounded by `body_idle_timeout`.
    async fn read_body_bytes(&mut self) -> Result<(), ParseError> {
        self.buf.reserve(READ_CHUNK);
        match timeout(
            self.limits.body_idle_timeout,
            self.rd.read_buf(&mut self.buf),
        )
        .await
        {
            Err(_) => Err(ParseError::new(
                Reason::BodyTimeout,
                "no request body progress",
            )),
            Ok(Err(e)) => Err(io_err(&e)),
            Ok(Ok(0)) => Err(ParseError::new(
                Reason::UnexpectedEof,
                "EOF in request body",
            )),
            Ok(Ok(_)) => Ok(()),
        }
    }

    /// Drives the request body to completion (or until the drain limit).
    /// Cancel-safe.
    async fn pump(&mut self) -> Result<(), ParseError> {
        let r = self.pump_inner().await;
        r.map_err(|e| self.fail(e))
    }

    async fn pump_inner(&mut self) -> Result<(), ParseError> {
        let idle = self.limits.body_idle_timeout;
        loop {
            let Some(feed) = self.feed.as_mut() else {
                return Ok(());
            };
            if feed.pending.is_some() {
                if let Some(tx) = feed.sender.as_mut() {
                    match timeout(idle, tx.ready()).await {
                        Err(_) => {
                            return Err(ParseError::new(
                                Reason::BodyTimeout,
                                "request body consumer stalled",
                            ));
                        }
                        Ok(Err(_)) => {
                            tracing::debug!("request body dropped by consumer; draining");
                            feed.sender = None;
                        }
                        Ok(Ok(())) => {}
                    }
                }
                let Some(pending) = feed.pending.take() else {
                    continue;
                };
                match (feed.sender.as_mut(), pending) {
                    (Some(tx), Pending::Data(b)) => match tx.try_push(b) {
                        Ok(()) => {}
                        Err(BodyError::Closed) => feed.sender = None,
                        Err(e) => {
                            return Err(ParseError::new(Reason::BodyTooLarge, e.to_string()));
                        }
                    },
                    (Some(tx), Pending::Trailers(t)) => {
                        if tx.try_push_trailers(t).is_err() {
                            feed.sender = None;
                        }
                    }
                    (Some(_), Pending::Finish) => {
                        if let Some(tx) = feed.sender.take() {
                            let _ = tx.try_finish();
                        }
                        self.feed = None;
                        return Ok(());
                    }
                    (None, Pending::Data(b)) => {
                        feed.drained += b.len() as u64;
                        if feed.drained > DRAIN_LIMIT {
                            tracing::debug!("drain limit reached; connection will close");
                            self.feed = None;
                            self.abandoned = true;
                            return Ok(());
                        }
                    }
                    (None, Pending::Trailers(_)) => {}
                    (None, Pending::Finish) => {
                        self.feed = None;
                        return Ok(());
                    }
                }
                continue;
            }
            let step = match &mut feed.decoder {
                BodyDecoder::Length(0) => Decoded::Done,
                BodyDecoder::Length(_) if self.buf.is_empty() => Decoded::NeedMore,
                BodyDecoder::Length(rem) => {
                    let n = usize::try_from(*rem)
                        .unwrap_or(usize::MAX)
                        .min(self.buf.len())
                        .min(READ_CHUNK);
                    *rem -= n as u64;
                    Decoded::Data(self.buf.split_to(n).freeze())
                }
                BodyDecoder::Chunked(d) => d.decode(&mut self.buf)?,
            };
            match step {
                Decoded::Data(b) => feed.pending = Some(Pending::Data(b)),
                Decoded::Trailers(t) => feed.pending = Some(Pending::Trailers(t)),
                Decoded::Done => feed.pending = Some(Pending::Finish),
                Decoded::NeedMore => self.read_body_bytes().await?,
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Idle,
    AwaitingResponse,
    AwaitingConnect,
    Closed,
    Broken,
}

#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)]
struct Exchange {
    is_head: bool,
    close: bool,
    expect_continue: bool,
    sent_100: bool,
    version: Version,
    upgrade: Option<String>,
}

/// Response framing on the client wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutFraming {
    /// No framing headers, no body (1xx/204/304).
    Empty,
    /// HEAD response: `content-length` if known, no body bytes.
    Head(Option<u64>),
    Length(u64),
    Chunked,
    /// HTTP/1.0 client, unknown length: body delimited by close.
    CloseDelimited,
}

/// Serialises a response head. `extra` carries fields that [`Headers`]
/// refuses (reserved names) and that roxy itself generates from validated
/// values; it is never fed from a message.
fn response_head(
    status: StatusCode,
    headers: &Headers,
    extra: &[(&str, &str)],
    framing: OutFraming,
    close: bool,
    upgrade: Option<&str>,
) -> BytesMut {
    let mut out = BytesMut::with_capacity(256 + headers.wire_len());
    out.extend_from_slice(b"HTTP/1.1 ");
    out.extend_from_slice(status.as_str().as_bytes());
    out.extend_from_slice(b" ");
    out.extend_from_slice(status.canonical_reason().unwrap_or("").as_bytes());
    out.extend_from_slice(b"\r\n");
    if !headers.contains("date") {
        out.extend_from_slice(b"date: ");
        out.extend_from_slice(httpdate::fmt_http_date(std::time::SystemTime::now()).as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    for (n, v) in headers {
        out.extend_from_slice(n.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    for (n, v) in extra {
        out.extend_from_slice(n.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    match framing {
        OutFraming::Length(n) | OutFraming::Head(Some(n)) => {
            out.extend_from_slice(format!("content-length: {n}\r\n").as_bytes());
        }
        OutFraming::Chunked => out.extend_from_slice(b"transfer-encoding: chunked\r\n"),
        OutFraming::Empty | OutFraming::Head(None) | OutFraming::CloseDelimited => {}
    }
    if let Some(u) = upgrade {
        out.extend_from_slice(b"connection: upgrade\r\nupgrade: ");
        out.extend_from_slice(u.as_bytes());
        out.extend_from_slice(b"\r\n");
    } else if close {
        out.extend_from_slice(b"connection: close\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

fn timed_out() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::TimedOut, "client write stalled")
}

async fn write_timed<W: AsyncWrite + Unpin>(
    w: &mut W,
    bufs: &[&[u8]],
    idle: Duration,
) -> Result<(), WriteError> {
    for b in bufs {
        timeout(idle, w.write_all(b))
            .await
            .map_err(|_| timed_out())??;
    }
    Ok(())
}

async fn flush_timed<W: AsyncWrite + Unpin>(w: &mut W, idle: Duration) -> Result<(), WriteError> {
    timeout(idle, w.flush()).await.map_err(|_| timed_out())??;
    Ok(())
}

/// Writes a response head and body. Bodies are streamed frame by frame.
async fn write_message<W: AsyncWrite + Unpin>(
    w: &mut W,
    head: BytesMut,
    mut body: Body,
    framing: OutFraming,
    idle: Duration,
) -> Result<(), WriteError> {
    write_timed(w, &[&head], idle).await?;
    let mut sent: u64 = 0;
    let expected = match framing {
        OutFraming::Empty | OutFraming::Head(_) => {
            flush_timed(w, idle).await?;
            return Ok(());
        }
        OutFraming::Length(n) => Some(n),
        OutFraming::Chunked | OutFraming::CloseDelimited => None,
    };
    loop {
        // Flush whatever is buffered before possibly waiting on the producer.
        flush_timed(w, idle).await?;
        let frame = timeout(idle, poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)))
            .await
            .map_err(|_| WriteError::Body(BodyError::Timeout))?;
        let Some(frame) = frame else { break };
        let frame = frame.map_err(WriteError::Body)?;
        let Ok(data) = frame.into_data() else {
            // Trailers are never sent to h1 clients.
            continue;
        };
        if data.is_empty() {
            continue;
        }
        sent += data.len() as u64;
        match framing {
            OutFraming::Length(n) => {
                if sent > n {
                    return Err(WriteError::Body(BodyError::LengthMismatch));
                }
                write_timed(w, &[&data], idle).await?;
            }
            OutFraming::Chunked => {
                let size = format!("{:X}\r\n", data.len());
                write_timed(w, &[size.as_bytes(), &data, b"\r\n"], idle).await?;
            }
            _ => write_timed(w, &[&data], idle).await?,
        }
    }
    if let Some(n) = expected
        && sent != n
    {
        return Err(WriteError::Body(BodyError::LengthMismatch));
    }
    if framing == OutFraming::Chunked {
        write_timed(w, &[b"0\r\n\r\n"], idle).await?;
    }
    flush_timed(w, idle).await
}

/// A strict HTTP/1.1 server connection over any byte stream.
pub struct ServerConn<IO> {
    r: ReadSide<IO>,
    w: BufWriter<WriteHalf<IO>>,
    role: Role,
    limits: Arc<Limits>,
    flags: Arc<HttpFlags>,
    state: State,
    exchange: Option<Exchange>,
    served: u64,
}

impl<IO> std::fmt::Debug for ServerConn<IO> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConn")
            .field("role", &self.role)
            .field("state", &self.state)
            .field("served", &self.served)
            .field("buffered", &self.r.buf.len())
            .finish_non_exhaustive()
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin + Send + 'static> ServerConn<IO> {
    /// Wraps a client stream.
    pub fn new(io: IO, role: Role, limits: Arc<Limits>, flags: Arc<HttpFlags>) -> Self {
        Self::with_buffered(io, BytesMut::new(), role, limits, flags)
    }

    /// Wraps a client stream whose first bytes were already read (e.g. by a
    /// protocol sniffer, or the leftover from [`ServerConn::accept_connect`]).
    pub fn with_buffered(
        io: IO,
        buffered: BytesMut,
        role: Role,
        limits: Arc<Limits>,
        flags: Arc<HttpFlags>,
    ) -> Self {
        let (rd, wr) = tokio::io::split(io);
        Self {
            r: ReadSide {
                rd,
                buf: buffered,
                feed: None,
                abandoned: false,
                limits: limits.clone(),
            },
            w: BufWriter::with_capacity(READ_CHUNK, wr),
            role,
            limits,
            flags,
            state: State::Idle,
            exchange: None,
            served: 0,
        }
    }

    /// Requests read so far.
    pub fn requests_served(&self) -> u64 {
        self.served
    }

    /// The connection role.
    pub fn role(&self) -> &Role {
        &self.role
    }

    /// Whether the connection has ended (no further requests will be read).
    pub fn is_closed(&self) -> bool {
        matches!(self.state, State::Closed | State::Broken)
    }

    /// Reads the head bytes of the next request. `Ok(None)` on clean EOF or
    /// keep-alive idle timeout.
    async fn read_head(&mut self) -> Result<Option<BytesMut>, ParseError> {
        let limits = self.limits.clone();
        let mut deadline = (self.served == 0).then(|| Instant::now() + limits.header_timeout);
        let mut scan_from = 0;
        loop {
            // RFC 9112 §2.2: ignore empty lines before the request line.
            let mut skipped = false;
            while self.r.buf.starts_with(b"\r\n") {
                self.r.buf.advance(2);
                skipped = true;
            }
            if skipped {
                scan_from = 0;
            }
            if !self.r.buf.is_empty() {
                match scan_head(&self.r.buf, scan_from, &limits)? {
                    HeadScan::Complete(n) => return Ok(Some(self.r.buf.split_to(n))),
                    HeadScan::Partial(p) => scan_from = p,
                }
            }
            self.r.buf.reserve(READ_CHUNK);
            let read = self.r.rd.read_buf(&mut self.r.buf);
            let n = if let Some(d) = deadline {
                timeout_at(d, read)
                    .await
                    .map_err(|_| ParseError::new(Reason::HeaderTimeout, "request head timeout"))?
            } else {
                match timeout(limits.idle_timeout, read).await {
                    Err(_) => {
                        tracing::debug!("keep-alive idle timeout");
                        return Ok(None);
                    }
                    Ok(r) => r,
                }
            }
            .map_err(|e| io_err(&e))?;
            if n == 0 {
                return if self.r.buf.is_empty() {
                    Ok(None)
                } else {
                    Err(ParseError::new(
                        Reason::UnexpectedEof,
                        "EOF in request head",
                    ))
                };
            }
            if deadline.is_none() {
                deadline = Some(Instant::now() + limits.header_timeout);
            }
        }
    }

    /// Reads the next request head. Returns `Ok(None)` on clean EOF between
    /// requests, on keep-alive idle timeout, or after a response that closed
    /// the connection. Any violation returns `Err`; the caller must then drop
    /// the connection (calling [`ServerConn::respond_error_and_close`] first
    /// if it wants to send an error status).
    #[allow(clippy::too_many_lines)]
    pub async fn next_request(&mut self) -> Result<Option<Incoming>, ParseError> {
        match self.state {
            State::Closed => return Ok(None),
            State::Idle => {}
            State::AwaitingResponse | State::AwaitingConnect | State::Broken => {
                return Err(ParseError::new(
                    Reason::InvalidState,
                    "next_request called before the previous exchange finished",
                ));
            }
        }
        let head = match self.read_head().await {
            Ok(Some(h)) => h,
            Ok(None) => {
                self.state = State::Closed;
                return Ok(None);
            }
            Err(e) => {
                self.state = State::Broken;
                return Err(e);
            }
        };
        let parsed = match parse_head(&head, &self.role, &self.limits, &self.flags) {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!(reason = e.reason.as_str(), detail = %e.detail, "rejected request head");
                self.state = State::Broken;
                return Err(e);
            }
        };
        self.served += 1;
        match parsed {
            Head::Connect {
                authority,
                headers,
                meta,
            } => {
                self.exchange = Some(Exchange {
                    is_head: false,
                    close: meta.close,
                    expect_continue: false,
                    sent_100: false,
                    version: meta.version,
                    upgrade: None,
                });
                self.state = State::AwaitingConnect;
                Ok(Some(Incoming::Connect {
                    authority,
                    headers,
                    meta,
                }))
            }
            Head::Request(h) => {
                let max = self.limits.max_request_body_bytes;
                let (body, feed) = match h.framing {
                    Framing::None => (Body::empty(), None),
                    Framing::Length(n) => {
                        let (tx, body) = Body::channel(max, Some(n));
                        (body, Some((BodyDecoder::Length(n), tx)))
                    }
                    Framing::Chunked => {
                        let (tx, body) = Body::channel(max, None);
                        let d = ChunkedDecoder::new(&self.limits, &self.flags);
                        (body, Some((BodyDecoder::Chunked(d), tx)))
                    }
                };
                self.r.feed = feed.map(|(decoder, tx)| BodyFeed {
                    decoder,
                    sender: Some(tx),
                    pending: None,
                    drained: 0,
                });
                self.exchange = Some(Exchange {
                    is_head: h.method == crate::model::Method::Head,
                    close: h.meta.close,
                    expect_continue: h.meta.expect_continue,
                    sent_100: false,
                    version: h.meta.version,
                    upgrade: h.meta.upgrade.clone(),
                });
                self.state = State::AwaitingResponse;
                let origin_on_proxy =
                    self.role == Role::ProxyPort && h.meta.target_form == TargetForm::Origin;
                let req = CanonicalRequest {
                    method: h.method,
                    scheme: h.scheme,
                    authority: h.authority,
                    path: h.path,
                    query: h.query,
                    headers: h.headers,
                    body,
                    meta: h.meta,
                };
                Ok(Some(if origin_on_proxy {
                    Incoming::OriginFormOnProxyPort(req)
                } else {
                    Incoming::Request(req)
                }))
            }
        }
    }

    /// Sends `100 Continue` if the current request expects it and it has not
    /// been sent yet. Call after the request phase allowed the request.
    pub async fn send_100_continue(&mut self) -> Result<(), WriteError> {
        if self.state != State::AwaitingResponse {
            return Err(WriteError::State("no request awaiting a response"));
        }
        let idle = self.limits.body_idle_timeout;
        if let Some(ex) = self.exchange.as_mut()
            && ex.expect_continue
            && !ex.sent_100
        {
            ex.sent_100 = true;
            write_timed(&mut self.w, &[b"HTTP/1.1 100 Continue\r\n\r\n"], idle).await?;
            flush_timed(&mut self.w, idle).await?;
        }
        Ok(())
    }

    /// Runs `fut` (e.g. forwarding the request upstream and awaiting the
    /// response head) while pumping the request body from the client into
    /// `req.body`. Sends `100 Continue` first if the client is waiting for
    /// it (driving the body means the request was allowed).
    ///
    /// Returns `Err` if the request body is invalid, too large, stalls or
    /// the client goes away; `fut` is dropped in that case and the connection
    /// must be closed.
    pub async fn drive<F: Future>(&mut self, fut: F) -> Result<F::Output, ParseError> {
        if self.r.feed.is_some() {
            self.send_100_continue()
                .await
                .map_err(|e| ParseError::new(Reason::Io, e.to_string()))?;
        }
        let mut fut = std::pin::pin!(fut);
        if self.r.feed.is_some() {
            tokio::select! {
                biased;
                out = &mut fut => return Ok(out),
                r = self.r.pump() => {
                    if let Err(e) = r {
                        self.state = State::Broken;
                        return Err(e);
                    }
                }
            }
        }
        Ok(fut.await)
    }

    fn out_framing(res: &CanonicalResponse, ex: &Exchange) -> OutFraming {
        if status_forbids_body(res.status) {
            OutFraming::Empty
        } else if ex.is_head {
            OutFraming::Head(res.meta.declared_length.or(res.body.known_length()))
        } else {
            match res.body.known_length() {
                Some(n) => OutFraming::Length(n),
                None if ex.version == Version::H1_0 => OutFraming::CloseDelimited,
                None => OutFraming::Chunked,
            }
        }
    }

    /// Writes the response to the current request (§5.5/§5.6 wire form),
    /// continuing to pump the request body concurrently. Afterwards the
    /// connection is either ready for [`ServerConn::next_request`] or closed
    /// (client `Connection: close`, HTTP/1.0, un-drained body, unanswered
    /// `Expect`, or `res.meta.close`).
    ///
    /// `res.meta.close == true` makes roxy end the connection after this
    /// response: the head carries `connection: close`, a request body the
    /// consumer already dropped is abandoned rather than drained, and after
    /// the body the write side is half-closed with the same lingering close
    /// as [`ServerConn::respond_error_and_close`]. Bytes the client sent after
    /// this request (pipelining) are discarded, never parsed as a request.
    ///
    /// 1xx responses are not accepted here (see
    /// [`ServerConn::send_100_continue`] and [`ServerConn::respond_upgrade`]),
    /// nor 2xx responses to CONNECT (see [`ServerConn::accept_connect`]).
    pub async fn respond(&mut self, res: CanonicalResponse) -> Result<(), WriteError> {
        if !matches!(self.state, State::AwaitingResponse | State::AwaitingConnect) {
            return Err(WriteError::State("no request awaiting a response"));
        }
        if res.status.is_informational() {
            return Err(WriteError::State(
                "1xx responses are sent by dedicated methods",
            ));
        }
        if self.state == State::AwaitingConnect && res.status.is_success() {
            return Err(WriteError::State(
                "use accept_connect to establish a tunnel",
            ));
        }
        let Some(ex) = self.exchange.take() else {
            return Err(WriteError::State("no exchange"));
        };
        if ex.expect_continue && !ex.sent_100 && self.r.feed.is_some() {
            // The client may or may not send the body now; we cannot know
            // where the next request starts, so close after the response.
            if let Some(mut feed) = self.r.feed.take()
                && let Some(tx) = feed.sender.take()
            {
                tx.abort(BodyError::Incomplete);
            }
            self.r.abandoned = true;
        }
        if res.meta.close
            && let Some(feed) = self.r.feed.as_mut()
            && feed.sender.as_ref().is_none_or(BodySender::is_closed)
        {
            // Closing anyway: do not spend up to DRAIN_LIMIT reading a body
            // nobody wants. A body the consumer still holds keeps flowing.
            if let Some(tx) = feed.sender.take() {
                tx.abort(BodyError::Incomplete);
            }
            self.r.feed = None;
            self.r.abandoned = true;
        }
        let framing = Self::out_framing(&res, &ex);
        let close = ex.close
            || res.meta.close
            || ex.version == Version::H1_0
            || self.r.abandoned
            || framing == OutFraming::CloseDelimited;
        let head = response_head(res.status, &res.headers, &[], framing, close, None);
        let idle = self.limits.body_idle_timeout;

        let result = {
            let write = write_message(&mut self.w, head, res.body, framing, idle);
            let pump = self.r.pump();
            let mut write = std::pin::pin!(write);
            let mut pump = std::pin::pin!(pump);
            let mut write_done = false;
            let mut pump_done = false;
            loop {
                if write_done && pump_done {
                    break Ok(());
                }
                tokio::select! {
                    r = &mut write, if !write_done => {
                        if let Err(e) = r { break Err(e); }
                        write_done = true;
                    }
                    r = &mut pump, if !pump_done => {
                        if let Err(e) = r { break Err(WriteError::Request(e)); }
                        pump_done = true;
                    }
                }
            }
        };
        if let Err(e) = result {
            self.state = State::Broken;
            return Err(e);
        }
        if close || self.r.abandoned {
            self.shutdown().await;
            self.state = State::Closed;
        } else {
            self.state = State::Idle;
        }
        Ok(())
    }

    /// Half-closes the write side and, if request bytes were left unread
    /// (an abandoned body, or pipelined bytes already buffered), lingers
    /// briefly discarding input so the client sees the response rather than
    /// a reset.
    async fn shutdown(&mut self) {
        let idle = self.limits.body_idle_timeout;
        let _ = flush_timed(&mut self.w, idle).await;
        let _ = timeout(idle, self.w.shutdown()).await;
        if self.r.abandoned || self.r.feed.is_some() || !self.r.buf.is_empty() {
            self.r.feed = None;
            self.r.buf.clear();
            let deadline = Instant::now() + LINGER;
            let mut discarded = 0;
            let mut scratch = vec![0u8; READ_CHUNK];
            while discarded < LINGER_BYTES {
                match timeout_at(deadline, self.r.rd.read(&mut scratch)).await {
                    Ok(Ok(n)) if n > 0 => discarded += n,
                    _ => break,
                }
            }
        }
    }

    /// Sends an error response with `connection: close` and closes. Use after
    /// a [`ParseError`] (with [`Reason::suggested_status`]) or to deny a
    /// CONNECT. The body is a small JSON object carrying only the reason code.
    pub async fn respond_error_and_close(
        mut self,
        status: StatusCode,
        reason: &Reason,
    ) -> Result<(), WriteError> {
        let body = format!(
            "{{\"error\":\"rejected by roxy\",\"reason\":\"{}\"}}",
            reason.as_str()
        );
        let mut headers = Headers::new();
        let _ = headers.insert("content-type", "application/json");
        self.close_with(status, &headers, &[], Bytes::from(body))
            .await
    }

    /// Answers the pending request or CONNECT with `407 Proxy Authentication
    /// Required`, a `proxy-authenticate: Basic realm="<realm>"` challenge,
    /// `connection: close` and `body` (sent with `content-length`; the caller
    /// supplies any `content-type` semantics by choosing the body), then
    /// closes like [`ServerConn::respond_error_and_close`] (an unread request
    /// body is abandoned; half-close, then lingering close).
    ///
    /// `realm` must be printable ASCII (`0x20..=0x7e`) without `"` or `\`,
    /// so it can be sent as a quoted-string without escaping. Otherwise this
    /// returns [`WriteError::State`] and the connection is dropped without a
    /// response.
    pub async fn respond_proxy_auth_required(
        mut self,
        realm: &str,
        body: Bytes,
    ) -> Result<(), WriteError> {
        if !matches!(self.state, State::AwaitingResponse | State::AwaitingConnect) {
            return Err(WriteError::State("no request awaiting a response"));
        }
        if !realm
            .bytes()
            .all(|b| (0x20..=0x7e).contains(&b) && b != b'"' && b != b'\\')
        {
            return Err(WriteError::State(
                "proxy auth realm must be printable ASCII without '\"' or '\\'",
            ));
        }
        let challenge = format!("Basic realm=\"{realm}\"");
        self.close_with(
            StatusCode::PROXY_AUTHENTICATION_REQUIRED,
            &Headers::new(),
            &[("proxy-authenticate", &challenge)],
            body,
        )
        .await
    }

    /// Writes a `connection: close` response with a fixed body, abandoning
    /// any unread request body, then shuts down and closes.
    async fn close_with(
        &mut self,
        status: StatusCode,
        headers: &Headers,
        extra: &[(&str, &str)],
        body: Bytes,
    ) -> Result<(), WriteError> {
        if self.state == State::Closed {
            return Ok(());
        }
        if let Some(mut feed) = self.r.feed.take() {
            if let Some(tx) = feed.sender.take() {
                tx.abort(BodyError::Incomplete);
            }
            self.r.abandoned = true;
        }
        let len = body.len() as u64;
        // A HEAD response describes the body but never carries it.
        let framing = if self.exchange.as_ref().is_some_and(|e| e.is_head) {
            OutFraming::Head(Some(len))
        } else {
            OutFraming::Length(len)
        };
        let head = response_head(status, headers, extra, framing, true, None);
        let idle = self.limits.body_idle_timeout;
        let r = write_message(&mut self.w, head, Body::from_bytes(body), framing, idle).await;
        self.shutdown().await;
        self.state = State::Closed;
        r
    }

    /// Accepts the pending CONNECT: writes `200 Connection Established` and
    /// returns the raw stream plus any bytes the client already sent beyond
    /// the CONNECT head (e.g. an eager TLS `ClientHello`).
    pub async fn accept_connect(mut self) -> Result<(IO, BytesMut), WriteError> {
        if self.state != State::AwaitingConnect {
            return Err(WriteError::State("no CONNECT awaiting a response"));
        }
        let idle = self.limits.body_idle_timeout;
        write_timed(
            &mut self.w,
            &[b"HTTP/1.1 200 Connection Established\r\n\r\n"],
            idle,
        )
        .await?;
        flush_timed(&mut self.w, idle).await?;
        let wr = self.w.into_inner();
        Ok((self.r.rd.unsplit(wr), self.r.buf))
    }

    /// Answers a WebSocket upgrade with the (already validated, see
    /// [`crate::ws::validate_upgrade_response`]) `101` from the upstream and
    /// returns the raw stream plus buffered bytes for the byte relay.
    pub async fn respond_upgrade(
        mut self,
        res: CanonicalResponse,
    ) -> Result<(IO, BytesMut), WriteError> {
        if self.state != State::AwaitingResponse {
            return Err(WriteError::State("no request awaiting a response"));
        }
        let Some(ex) = self.exchange.take() else {
            return Err(WriteError::State("no exchange"));
        };
        if res.status != StatusCode::SWITCHING_PROTOCOLS || self.r.feed.is_some() {
            return Err(WriteError::State(
                "upgrade needs a 101 and a complete request",
            ));
        }
        let Some(upgrade) = res.meta.upgrade.clone().or(ex.upgrade) else {
            return Err(WriteError::State("request did not ask for an upgrade"));
        };
        let head = response_head(
            res.status,
            &res.headers,
            &[],
            OutFraming::Empty,
            false,
            Some(&upgrade),
        );
        let idle = self.limits.body_idle_timeout;
        write_timed(&mut self.w, &[&head], idle).await?;
        flush_timed(&mut self.w, idle).await?;
        let wr = self.w.into_inner();
        Ok((self.r.rd.unsplit(wr), self.r.buf))
    }
}
