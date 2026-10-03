//! Streaming bodies.
//!
//! A [`Body`] is a pull-based sequence of byte chunks. Bodies that come
//! from the host stream: a chunk is read from the host only when the body
//! is pulled, so a layer that transforms chunk by chunk holds at most one
//! chunk at a time. Nothing is buffered unless the layer asks for it with
//! [`Body::read_to_end`].

use std::fmt;

use crate::bindings::wasi::http::types::{IncomingBody, IncomingRequest, IncomingResponse};
use crate::bindings::wasi::io::streams::{InputStream, StreamError};

/// Largest chunk read from the host at once.
pub(crate) const READ_CHUNK: u64 = 64 * 1024;

/// Why a body could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyError {
    /// [`Body::read_to_end`] reached its cap.
    TooLarge {
        /// The cap.
        limit: usize,
    },
    /// The stream failed (the host cut it, or the peer went away).
    Stream(String),
}

impl fmt::Display for BodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BodyError::TooLarge { limit } => write!(f, "body exceeds {limit} bytes"),
            BodyError::Stream(e) => write!(f, "body stream failed: {e}"),
        }
    }
}

impl std::error::Error for BodyError {}

/// A stateful chunk-by-chunk transform (see [`Body::pipe`]).
pub trait ChunkTransform {
    /// Transforms one chunk. May return fewer bytes (holding some back) or
    /// more.
    fn chunk(&mut self, chunk: Vec<u8>) -> Vec<u8>;

    /// Called once at the end of the body: emits whatever was held back.
    fn finish(&mut self) -> Vec<u8> {
        Vec::new()
    }
}

struct FnTransform<F>(F);

impl<F: FnMut(Vec<u8>) -> Vec<u8>> ChunkTransform for FnTransform<F> {
    fn chunk(&mut self, chunk: Vec<u8>) -> Vec<u8> {
        (self.0)(chunk)
    }
}

/// The host resource a streamed body belongs to. Kept alive until the body
/// is done with: a body must be dropped before the request or response it
/// came from.
// Never read: held only so the parent is dropped after the body.
#[allow(dead_code)]
pub(crate) enum Parent {
    Request(IncomingRequest),
    Response(IncomingResponse),
}

/// A body streamed from the host. Field order is drop order: the stream,
/// then the body, then its parent.
pub(crate) struct Incoming {
    stream: Option<InputStream>,
    body: Option<IncomingBody>,
    parent: Option<Parent>,
}

impl Incoming {
    pub(crate) fn new(body: IncomingBody, parent: Parent) -> Self {
        let stream = body.stream().ok();
        Self {
            stream,
            body: Some(body),
            parent: Some(parent),
        }
    }

    fn next_chunk(&mut self) -> Option<Result<Vec<u8>, BodyError>> {
        let stream = self.stream.as_ref()?;
        loop {
            match stream.blocking_read(READ_CHUNK) {
                Ok(chunk) if chunk.is_empty() => {}
                Ok(chunk) => return Some(Ok(chunk)),
                Err(StreamError::Closed) => {
                    self.close();
                    return None;
                }
                Err(StreamError::LastOperationFailed(e)) => {
                    let msg = e.to_debug_string();
                    self.close();
                    return Some(Err(BodyError::Stream(msg)));
                }
            }
        }
    }

    fn close(&mut self) {
        self.stream = None;
        self.body = None;
        self.parent = None;
    }
}

enum Inner {
    Empty,
    Bytes(Option<Vec<u8>>),
    Incoming(Incoming),
    Chunks(Box<dyn Iterator<Item = Result<Vec<u8>, BodyError>>>),
    Piped {
        source: Box<Body>,
        transform: Box<dyn ChunkTransform>,
        finished: bool,
    },
}

/// A request or response body.
pub struct Body {
    inner: Inner,
}

impl fmt::Debug for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match &self.inner {
            Inner::Empty => "empty",
            Inner::Bytes(_) => "bytes",
            Inner::Incoming(_) => "streamed",
            Inner::Chunks(_) => "chunks",
            Inner::Piped { .. } => "piped",
        };
        f.debug_struct("Body").field("kind", &kind).finish()
    }
}

impl Default for Body {
    fn default() -> Self {
        Self::empty()
    }
}

impl From<Vec<u8>> for Body {
    fn from(b: Vec<u8>) -> Self {
        Self::from_bytes(b)
    }
}

impl From<&[u8]> for Body {
    fn from(b: &[u8]) -> Self {
        Self::from_bytes(b.to_vec())
    }
}

impl From<String> for Body {
    fn from(s: String) -> Self {
        Self::from_bytes(s.into_bytes())
    }
}

impl From<&str> for Body {
    fn from(s: &str) -> Self {
        Self::from_bytes(s.as_bytes().to_vec())
    }
}

impl Body {
    /// An empty body.
    pub fn empty() -> Self {
        Self {
            inner: Inner::Empty,
        }
    }

    /// A body of one buffer.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            inner: Inner::Bytes(Some(bytes.into())),
        }
    }

    /// A body produced by an iterator of chunks.
    pub fn from_chunks<I>(chunks: I) -> Self
    where
        I: IntoIterator<Item = Result<Vec<u8>, BodyError>>,
        I::IntoIter: 'static,
    {
        Self {
            inner: Inner::Chunks(Box::new(chunks.into_iter())),
        }
    }

    pub(crate) fn incoming(body: IncomingBody, parent: Parent) -> Self {
        Self {
            inner: Inner::Incoming(Incoming::new(body, parent)),
        }
    }

    /// Transforms the body chunk by chunk, as it streams.
    #[must_use]
    pub fn transform<F>(self, f: F) -> Body
    where
        F: FnMut(Vec<u8>) -> Vec<u8> + 'static,
    {
        self.pipe(FnTransform(f))
    }

    /// Runs the body through a stateful [`ChunkTransform`], which may hold
    /// bytes back across chunks (to withhold part of a stream until it has
    /// been judged, say) and emit them at the end.
    #[must_use]
    pub fn pipe(self, transform: impl ChunkTransform + 'static) -> Body {
        Body {
            inner: Inner::Piped {
                source: Box::new(self),
                transform: Box::new(transform),
                finished: false,
            },
        }
    }

    /// Reads the whole body, failing once it exceeds `cap` bytes. The host
    /// also holds the layer to `max_buffered_body_bytes`.
    pub fn read_to_end(self, cap: usize) -> Result<Vec<u8>, BodyError> {
        let mut all = Vec::new();
        for chunk in self {
            let chunk = chunk?;
            if all.len() + chunk.len() > cap {
                return Err(BodyError::TooLarge { limit: cap });
            }
            all.extend_from_slice(&chunk);
        }
        Ok(all)
    }
}

impl Iterator for Body {
    type Item = Result<Vec<u8>, BodyError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match &mut self.inner {
                Inner::Empty => return None,
                Inner::Bytes(b) => return b.take().filter(|b| !b.is_empty()).map(Ok),
                Inner::Incoming(i) => return i.next_chunk(),
                Inner::Chunks(c) => return c.next(),
                Inner::Piped {
                    source,
                    transform,
                    finished,
                } => {
                    if *finished {
                        return None;
                    }
                    match source.next() {
                        Some(Ok(chunk)) => {
                            let out = transform.chunk(chunk);
                            if !out.is_empty() {
                                return Some(Ok(out));
                            }
                            // Held back entirely; pull the next chunk.
                        }
                        Some(Err(e)) => {
                            *finished = true;
                            return Some(Err(e));
                        }
                        None => {
                            *finished = true;
                            let out = transform.finish();
                            return (!out.is_empty()).then_some(Ok(out));
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transform_and_read() {
        let body =
            Body::from_chunks(vec![Ok(b"ab".to_vec()), Ok(b"cd".to_vec())]).transform(|mut c| {
                c.make_ascii_uppercase();
                c
            });
        assert_eq!(body.read_to_end(10).unwrap(), b"ABCD");
    }

    #[test]
    fn read_to_end_caps() {
        let body = Body::from_chunks(vec![Ok(b"abc".to_vec()), Ok(b"def".to_vec())]);
        assert_eq!(
            body.read_to_end(4).unwrap_err(),
            BodyError::TooLarge { limit: 4 }
        );
        assert_eq!(Body::empty().read_to_end(0).unwrap(), b"");
        assert_eq!(Body::from("").count(), 0);
    }

    struct HoldUntilEnd(Vec<u8>);
    impl ChunkTransform for HoldUntilEnd {
        fn chunk(&mut self, chunk: Vec<u8>) -> Vec<u8> {
            self.0.extend(chunk);
            Vec::new()
        }
        fn finish(&mut self) -> Vec<u8> {
            std::mem::take(&mut self.0)
        }
    }

    #[test]
    fn pipe_can_hold_back_and_flush() {
        let body = Body::from_chunks(vec![Ok(b"a".to_vec()), Ok(b"b".to_vec())])
            .pipe(HoldUntilEnd(Vec::new()));
        let chunks: Vec<_> = body.map(Result::unwrap).collect();
        assert_eq!(chunks, vec![b"ab".to_vec()]);
    }

    #[test]
    fn errors_pass_through_pipes() {
        let body = Body::from_chunks(vec![
            Ok(b"a".to_vec()),
            Err(BodyError::Stream("cut".into())),
        ])
        .transform(|c| c);
        let items: Vec<_> = body.collect();
        assert_eq!(items.len(), 2);
        assert!(items[1].is_err());
    }
}
