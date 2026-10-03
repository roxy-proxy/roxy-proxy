//! `message/http` (RFC 9112 §10.1): an HTTP/1.1 message carried as a body,
//! the wire format of service layers (`DESIGN.md` §11.6).
//!
//! roxy encodes the request or response in transit (head, then the body as
//! it streams, framed by `content-length` when its length is known and
//! chunked otherwise), and decodes what the service streams back with the
//! same strict checks as a client's request: a service cannot introduce
//! framing ambiguity, and what it returns is held to the workload's limits.

use std::fmt::Write as _;
use std::future::poll_fn;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use http_body::{Body as HttpBody, Frame, SizeHint};

use crate::h1::{ChunkedDecoder, Decoded, Framing, Head, HeadScan, Role, parse_head, scan_head};
use crate::layer::to_layer_request;
use crate::model::{
    Body, BodyError, CanonicalRequest, HttpFlags, Limits, ParseError, Reason, TargetForm, reject,
};

/// The media type of a `message/http` body.
pub const MEDIA_TYPE: &str = "message/http";

fn push_headers(out: &mut Vec<u8>, headers: &http::HeaderMap) {
    for (name, value) in headers {
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
}

fn push_framing(out: &mut Vec<u8>, known: Option<u64>, empty_ok: bool) -> bool {
    match known {
        Some(0) if empty_ok => false,
        Some(n) => {
            let _ = write!(Lossy(out), "content-length: {n}\r\n");
            false
        }
        None => {
            out.extend_from_slice(b"transfer-encoding: chunked\r\n");
            true
        }
    }
}

/// `fmt::Write` into a byte buffer.
struct Lossy<'a>(&'a mut Vec<u8>);

impl std::fmt::Write for Lossy<'_> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

/// Encodes a layer request (absolute URI, end-to-end headers) as
/// `message/http`: an absolute-form request line, `host`, the headers, the
/// framing, then the body as it streams.
pub fn encode_request(req: http::Request<Body>) -> Body {
    let (parts, body) = req.into_parts();
    let mut head = Vec::with_capacity(256);
    let _ = write!(
        Lossy(&mut head),
        "{} {} HTTP/1.1\r\n",
        parts.method,
        parts.uri
    );
    if let Some(a) = parts.uri.authority() {
        let _ = write!(Lossy(&mut head), "host: {a}\r\n");
    }
    push_headers(&mut head, &parts.headers);
    let chunked = push_framing(&mut head, body.known_length(), true);
    head.extend_from_slice(b"\r\n");
    encoder(head, body, chunked)
}

/// Encodes a layer response as `message/http`.
pub fn encode_response(res: http::Response<Body>) -> Body {
    let (parts, body) = res.into_parts();
    let mut head = Vec::with_capacity(256);
    let _ = write!(
        Lossy(&mut head),
        "HTTP/1.1 {} {}\r\n",
        parts.status.as_str(),
        parts.status.canonical_reason().unwrap_or("")
    );
    push_headers(&mut head, &parts.headers);
    let bodiless = matches!(parts.status.as_u16(), 204 | 304);
    let chunked = !bodiless && push_framing(&mut head, body.known_length(), false);
    head.extend_from_slice(b"\r\n");
    encoder(head, body, chunked)
}

fn encoder(head: Vec<u8>, body: Body, chunked: bool) -> Body {
    let known = (!chunked)
        .then(|| body.known_length().map(|n| n + head.len() as u64))
        .flatten();
    Body::wrap_native(
        Encode {
            head: Some(Bytes::from(head)),
            body,
            chunked,
            finished: false,
        },
        u64::MAX,
        known,
    )
}

struct Encode {
    head: Option<Bytes>,
    body: Body,
    chunked: bool,
    /// The last chunk (and any trailers) has been written.
    finished: bool,
}

impl HttpBody for Encode {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        if let Some(h) = self.head.take() {
            return Poll::Ready(Some(Ok(Frame::data(h))));
        }
        if self.finished {
            return Poll::Ready(None);
        }
        loop {
            let frame = match Pin::new(&mut self.body).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(Some(Ok(f))) => f,
                Poll::Ready(None) => {
                    self.finished = true;
                    return Poll::Ready(
                        self.chunked
                            .then(|| Ok(Frame::data(Bytes::from_static(b"0\r\n\r\n")))),
                    );
                }
            };
            match frame.into_data() {
                Ok(d) if d.is_empty() => {}
                Ok(d) if self.chunked => {
                    let mut out = Vec::with_capacity(d.len() + 20);
                    let _ = write!(Lossy(&mut out), "{:x}\r\n", d.len());
                    out.extend_from_slice(&d);
                    out.extend_from_slice(b"\r\n");
                    return Poll::Ready(Some(Ok(Frame::data(Bytes::from(out)))));
                }
                Ok(d) => return Poll::Ready(Some(Ok(Frame::data(d)))),
                Err(frame) => {
                    let Ok(trailers) = frame.into_trailers() else {
                        continue;
                    };
                    if !self.chunked {
                        return Poll::Ready(Some(Err(BodyError::Upstream(
                            "trailers on a length-delimited body".into(),
                        ))));
                    }
                    self.finished = true;
                    let mut out = b"0\r\n".to_vec();
                    push_headers(&mut out, &trailers);
                    out.extend_from_slice(b"\r\n");
                    return Poll::Ready(Some(Ok(Frame::data(Bytes::from(out)))));
                }
            }
        }
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

/// Reads `src` until a complete head is buffered; returns the head and any
/// bytes after it.
async fn read_head(src: &mut Body, limits: &Limits) -> Result<(BytesMut, BytesMut), ParseError> {
    let mut buf = BytesMut::new();
    let mut from = 0;
    loop {
        match scan_head(&buf, from, limits)? {
            HeadScan::Complete(n) => {
                let head = buf.split_to(n);
                return Ok((head, buf));
            }
            HeadScan::Partial(f) => from = f,
        }
        match poll_fn(|cx| Pin::new(&mut *src).poll_frame(cx)).await {
            Some(Ok(f)) => {
                if let Ok(d) = f.into_data() {
                    buf.extend_from_slice(&d);
                }
            }
            Some(Err(e)) => return reject(Reason::Io, format!("message: {e}")),
            None => {
                return reject(
                    Reason::UnexpectedEof,
                    "message ended before its head was complete",
                );
            }
        }
    }
}

/// Decodes a `message/http` request: an absolute-form request line, checked
/// exactly as a client's request on the proxy port (§5.3), with its body
/// decoded as it streams. Returns it as a layer request.
pub async fn decode_request(
    mut src: Body,
    limits: &Limits,
    flags: &HttpFlags,
) -> Result<http::Request<Body>, ParseError> {
    let (head, rest) = read_head(&mut src, limits).await?;
    let h = match parse_head(&head, &Role::ProxyPort, limits, flags)? {
        Head::Request(h) => h,
        Head::Connect { .. } => return reject(Reason::BadRequestTarget, "CONNECT in a message"),
    };
    if h.meta.target_form != TargetForm::Absolute {
        return reject(
            Reason::TargetFormMismatch,
            "a message/http request must use an absolute-form target",
        );
    }
    if h.meta.upgrade.is_some() {
        return reject(Reason::ReservedHeader, "upgrade in a message/http request");
    }
    let mode = match h.framing {
        Framing::None => Mode::Trailing,
        Framing::Length(n) => Mode::Length(n),
        Framing::Chunked => Mode::Chunked(ChunkedDecoder::new(limits, flags)),
    };
    let body = decoder(src, rest, mode, limits.max_request_body_bytes);
    Ok(to_layer_request(CanonicalRequest {
        method: h.method,
        scheme: h.scheme,
        authority: h.authority,
        path: h.path,
        query: h.query,
        headers: h.headers,
        body,
        meta: h.meta,
    }))
}

/// Decodes a `message/http` response (status 200–599) with its body
/// decoded as it streams.
pub async fn decode_response(
    mut src: Body,
    limits: &Limits,
    flags: &HttpFlags,
) -> Result<http::Response<Body>, ParseError> {
    let (head, rest) = read_head(&mut src, limits).await?;
    let h = crate::h1::parse_response_head(&head, limits, flags)?;
    let mode = match (h.framing, h.until_eof) {
        (Framing::None, true) => Mode::UntilEof,
        (Framing::None, false) => Mode::Trailing,
        (Framing::Length(n), _) => Mode::Length(n),
        (Framing::Chunked, _) => {
            let mut l = limits.clone();
            l.max_request_body_bytes = limits.max_response_body_bytes;
            Mode::Chunked(ChunkedDecoder::new(&l, flags))
        }
    };
    let body = decoder(src, rest, mode, limits.max_response_body_bytes);
    let mut out = http::Response::new(body);
    *out.status_mut() = h.status;
    *out.headers_mut() = h.headers.to_header_map();
    Ok(out)
}

fn decoder(src: Body, buf: BytesMut, mode: Mode, max: u64) -> Body {
    let known = match &mode {
        Mode::Trailing => Some(0),
        Mode::Length(n) => Some(*n),
        Mode::Chunked(_) | Mode::UntilEof => None,
    };
    Body::wrap_native(
        Decode {
            src,
            buf,
            mode,
            done: false,
        },
        max,
        known,
    )
}

enum Mode {
    /// `content-length`: this many bytes still to come.
    Length(u64),
    Chunked(ChunkedDecoder),
    /// No framing on a response: the rest of the message.
    UntilEof,
    /// The body is complete; only the end of the message may follow.
    Trailing,
}

struct Decode {
    src: Body,
    buf: BytesMut,
    mode: Mode,
    done: bool,
}

fn invalid(detail: &str) -> BodyError {
    BodyError::Invalid(ParseError::new(Reason::BadChunkFraming, detail))
}

impl HttpBody for Decode {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let this = &mut *self;
        loop {
            if this.done {
                return Poll::Ready(None);
            }
            // Serve what is buffered first.
            match &mut this.mode {
                Mode::Length(rem) if !this.buf.is_empty() => {
                    let n = usize::try_from(*rem)
                        .unwrap_or(usize::MAX)
                        .min(this.buf.len());
                    let chunk = this.buf.split_to(n).freeze();
                    *rem -= n as u64;
                    if *rem == 0 {
                        this.mode = Mode::Trailing;
                    }
                    return Poll::Ready(Some(Ok(Frame::data(chunk))));
                }
                Mode::Length(0) => {
                    this.mode = Mode::Trailing;
                    continue;
                }
                Mode::Chunked(d) => match d.decode(&mut this.buf) {
                    Err(e) => return Poll::Ready(Some(Err(BodyError::Invalid(e)))),
                    Ok(Decoded::Data(b)) => return Poll::Ready(Some(Ok(Frame::data(b)))),
                    Ok(Decoded::Trailers(t)) => {
                        return Poll::Ready(Some(Ok(Frame::trailers(t))));
                    }
                    Ok(Decoded::Done) => {
                        this.mode = Mode::Trailing;
                        continue;
                    }
                    Ok(Decoded::NeedMore) => {}
                },
                Mode::UntilEof if !this.buf.is_empty() => {
                    let chunk = this.buf.split().freeze();
                    return Poll::Ready(Some(Ok(Frame::data(chunk))));
                }
                Mode::Trailing if !this.buf.is_empty() => {
                    return Poll::Ready(Some(Err(invalid("bytes after the end of the message"))));
                }
                _ => {}
            }
            // Then read more of the message.
            match Pin::new(&mut this.src).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(Some(Ok(f))) => {
                    if let Ok(d) = f.into_data() {
                        this.buf.extend_from_slice(&d);
                    }
                }
                Poll::Ready(None) => match this.mode {
                    Mode::UntilEof | Mode::Trailing => this.done = true,
                    _ => return Poll::Ready(Some(Err(BodyError::Incomplete))),
                },
            }
        }
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn bytes(b: Body) -> Result<Bytes, BodyError> {
        b.collect_up_to(1 << 20).await
    }

    fn limits() -> Limits {
        Limits::default()
    }

    fn req(method: &str, uri: &str, body: Body) -> http::Request<Body> {
        let mut r = http::Request::new(body);
        *r.method_mut() = method.parse().unwrap();
        *r.uri_mut() = uri.parse().unwrap();
        r.headers_mut()
            .insert("x-a", http::HeaderValue::from_static("1"));
        r
    }

    /// A body that yields `parts` one frame at a time, of unknown length.
    fn streamed(parts: &[&'static [u8]]) -> Body {
        let (mut tx, body) = Body::channel(u64::MAX, None);
        let parts: Vec<Bytes> = parts.iter().map(|p| Bytes::from_static(p)).collect();
        tokio::spawn(async move {
            for p in parts {
                tx.send_data(p).await.unwrap();
            }
            tx.finish().await.unwrap();
        });
        body
    }

    #[tokio::test]
    async fn request_round_trips() {
        let enc = encode_request(req(
            "POST",
            "https://api.example.com/v1/x?q=1",
            Body::from_bytes("hello"),
        ));
        let wire = bytes(enc).await.unwrap();
        assert_eq!(
            &wire[..],
            b"POST https://api.example.com/v1/x?q=1 HTTP/1.1\r\nhost: api.example.com\r\n\
              x-a: 1\r\ncontent-length: 5\r\n\r\nhello"
        );
        let dec = decode_request(Body::from_bytes(wire), &limits(), &HttpFlags::default())
            .await
            .unwrap();
        assert_eq!(dec.uri(), "https://api.example.com/v1/x?q=1");
        assert_eq!(dec.headers()["x-a"], "1");
        assert_eq!(&bytes(dec.into_body()).await.unwrap()[..], b"hello");
    }

    #[tokio::test]
    async fn streams_chunked_both_ways() {
        let enc = encode_request(req(
            "POST",
            "http://h.test/",
            streamed(&[b"ab", b"", b"cde"]),
        ));
        let wire = bytes(enc).await.unwrap();
        assert!(
            wire.ends_with(b"transfer-encoding: chunked\r\n\r\n2\r\nab\r\n3\r\ncde\r\n0\r\n\r\n")
        );
        // Split anywhere, the decoder reassembles it.
        let (a, b) = wire.split_at(wire.len() / 2);
        let a = Bytes::copy_from_slice(a);
        let b = Bytes::copy_from_slice(b);
        let (mut tx, src) = Body::channel(u64::MAX, None);
        tokio::spawn(async move {
            tx.send_data(a).await.unwrap();
            tx.send_data(b).await.unwrap();
            tx.finish().await.unwrap();
        });
        let dec = decode_request(src, &limits(), &HttpFlags::default())
            .await
            .unwrap();
        assert_eq!(&bytes(dec.into_body()).await.unwrap()[..], b"abcde");
    }

    #[tokio::test]
    async fn response_round_trips() {
        let mut res = http::Response::new(Body::from_bytes("ok"));
        *res.status_mut() = http::StatusCode::CREATED;
        let wire = bytes(encode_response(res)).await.unwrap();
        assert_eq!(
            &wire[..],
            b"HTTP/1.1 201 Created\r\ncontent-length: 2\r\n\r\nok"
        );
        let dec = decode_response(Body::from_bytes(wire), &limits(), &HttpFlags::default())
            .await
            .unwrap();
        assert_eq!(dec.status(), 201);
        assert_eq!(&bytes(dec.into_body()).await.unwrap()[..], b"ok");

        // No framing: the body runs to the end of the message.
        let dec = decode_response(
            Body::from_bytes("HTTP/1.1 200 OK\r\nx: y\r\n\r\nrest of it"),
            &limits(),
            &HttpFlags::default(),
        )
        .await
        .unwrap();
        assert_eq!(&bytes(dec.into_body()).await.unwrap()[..], b"rest of it");
    }

    async fn req_err(wire: &'static str) -> String {
        match decode_request(Body::from_bytes(wire), &limits(), &HttpFlags::default()).await {
            Err(e) => format!("head: {e}"),
            Ok(r) => match bytes(r.into_body()).await {
                Err(e) => format!("body: {e}"),
                Ok(b) => panic!("accepted {wire:?} with body {b:?}"),
            },
        }
    }

    #[tokio::test]
    async fn refuses_ambiguity_and_garbage() {
        for wire in [
            "",
            "not http at all",
            "GET /relative HTTP/1.1\r\nhost: a.test\r\n\r\n",
            "CONNECT a.test:443 HTTP/1.1\r\nhost: a.test:443\r\n\r\n",
            "POST http://a.test/ HTTP/1.1\r\nhost: a.test\r\ncontent-length: 1\r\n\
             transfer-encoding: chunked\r\n\r\n",
            "POST http://a.test/ HTTP/1.1\r\nhost: a.test\r\ncontent-length: 1\r\n\
             content-length: 2\r\n\r\nab",
            "GET http://a.test/ HTTP/1.1\nhost: a.test\n\n",
            "GET http://a.test/ HTTP/1.1\r\nhost: b.test\r\n\r\n",
            "GET http://a.test/ HTTP/1.1\r\nhost: a.test\r\nconnection: upgrade\r\n\
             upgrade: websocket\r\n\r\n",
            // Truncated body, bytes after the message, a bad chunk.
            "POST http://a.test/ HTTP/1.1\r\nhost: a.test\r\ncontent-length: 5\r\n\r\nab",
            "GET http://a.test/ HTTP/1.1\r\nhost: a.test\r\n\r\nGET http://a.test/ HTTP/1.1\r\n\r\n",
            "POST http://a.test/ HTTP/1.1\r\nhost: a.test\r\ntransfer-encoding: chunked\r\n\r\nzz\r\n",
        ] {
            let e = req_err(wire).await;
            assert!(!e.is_empty(), "{wire:?}");
        }
    }

    #[tokio::test]
    async fn refuses_bad_responses() {
        for wire in [
            "HTTP/1.1 101 Switching Protocols\r\n\r\n",
            "HTTP/1.0 200 OK\r\n\r\n",
            "HTTP/1.1 200 OK\r\ncontent-length: 1\r\ntransfer-encoding: chunked\r\n\r\nx",
            "HTTP/1.1 204 No Content\r\ncontent-length: 1\r\n\r\nx",
            "HTTP/1.1 2000 OK\r\n\r\n",
            "HTTP/1.1 200 OK\r\nbad header\r\n\r\n",
        ] {
            let r = decode_response(Body::from_bytes(wire), &limits(), &HttpFlags::default()).await;
            assert!(r.is_err(), "{wire:?}");
        }
    }
}
