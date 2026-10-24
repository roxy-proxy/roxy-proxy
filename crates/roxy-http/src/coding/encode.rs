//! Streaming encoders, for a body roxy decoded and must pass on in the
//! coding it arrived in. Every data frame is flushed through each coding
//! before it is yielded, so an event stream is not held back for a fuller
//! compression block; the cost is some ratio.

use std::io::Write as _;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use flate2::Compression;
use flate2::write::{GzEncoder, ZlibEncoder};
use http::HeaderMap;
use http_body::Frame;
use ruzstd::encoding::{CompressionLevel, compress_to_vec};

use super::{Coding, Meter};
use crate::{Body, BodyError};

/// Brotli's quality and window (log2): a fast setting with a 256 KiB
/// window, so the encoder's state stays small.
const BR_QUALITY: u32 = 4;
const BR_LGWIN: u32 = 18;

/// What one encoder stage may hold, charged to the [`Meter`] before it is
/// created. Upper estimates: a deflate stage's window and hash tables, a
/// brotli stage's ring buffer and hasher at [`BR_LGWIN`], a zstd frame's
/// input and match tables.
fn memory(coding: Coding) -> u64 {
    match coding {
        Coding::Gzip | Coding::Deflate => 512 << 10,
        Coding::Br => 2 << 20,
        Coding::Zstd => 4 << 20,
    }
}

/// `body`, plain, encoded with `codings` (in the order they are applied) as
/// it streams. Each data frame comes out as soon as it went in, flushed
/// through every coding; trailers follow. The encoders' memory is charged
/// to `meter` first, and a charge it refuses fails the body with
/// [`BodyError::BudgetExhausted`].
pub fn encode_body(body: Body, codings: &[Coding], meter: Meter<'static>) -> Body {
    Body::wrap_native(
        EncodedBody {
            inner: body,
            codings: codings.to_vec(),
            meter: Some(meter),
            stages: Vec::new(),
            trailers: None,
            done: false,
        },
        u64::MAX,
        None,
    )
}

struct EncodedBody {
    inner: Body,
    codings: Vec<Coding>,
    /// Taken when the stages are built, on the first poll.
    meter: Option<Meter<'static>>,
    /// `stages[0]` is the coding applied first.
    stages: Vec<Stage>,
    trailers: Option<HeaderMap>,
    done: bool,
}

impl EncodedBody {
    /// Builds the stages once, charging their memory first.
    fn stages(&mut self) -> Result<(), BodyError> {
        let Some(mut meter) = self.meter.take() else {
            return Ok(());
        };
        let mut held: u64 = 0;
        for &c in &self.codings {
            held = held.saturating_add(memory(c));
            if !meter(held) {
                return Err(BodyError::BudgetExhausted);
            }
            self.stages.push(Stage::new(c));
        }
        Ok(())
    }

    /// `data` through every stage, flushed.
    fn encode(&mut self, data: &[u8]) -> Vec<u8> {
        let mut buf = data.to_vec();
        for s in &mut self.stages {
            buf = s.flush(&buf);
        }
        buf
    }

    /// The end of every stage: each finishes its stream, which the stages
    /// after it encode in turn.
    fn finish(&mut self) -> Vec<u8> {
        let mut buf = Vec::new();
        for s in &mut self.stages {
            let mut out = s.flush(&buf);
            out.extend(s.finish());
            buf = out;
        }
        buf
    }
}

impl http_body::Body for EncodedBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let this = &mut *self;
        loop {
            if this.done {
                return Poll::Ready(this.trailers.take().map(|t| Ok(Frame::trailers(t))));
            }
            if let Err(e) = this.stages() {
                this.done = true;
                return Poll::Ready(Some(Err(e)));
            }
            match ready!(Pin::new(&mut this.inner).poll_frame(cx)) {
                Some(Ok(f)) => match f.into_data() {
                    Ok(d) if d.is_empty() => {}
                    Ok(d) => return Poll::Ready(Some(Ok(Frame::data(this.encode(&d).into())))),
                    Err(f) => this.trailers = f.into_trailers().ok(),
                },
                Some(Err(e)) => {
                    this.done = true;
                    this.trailers = None;
                    return Poll::Ready(Some(Err(e)));
                }
                None => {
                    this.done = true;
                    let tail = this.finish();
                    if !tail.is_empty() {
                        return Poll::Ready(Some(Ok(Frame::data(tail.into()))));
                    }
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done && self.trailers.is_none()
    }
}

/// One coding's encoder. Writes go to a `Vec`, which cannot fail.
enum Stage {
    Gzip(GzEncoder<Vec<u8>>),
    Deflate(ZlibEncoder<Vec<u8>>),
    Br(Option<Box<brotli::CompressorWriter<Vec<u8>>>>),
    /// zstd has no flush in the encoder roxy uses, so each flush is a
    /// frame of its own; a stream of frames decodes as their concatenation
    /// (RFC 8878). Whether any frame was written: an empty body is still
    /// one frame.
    Zstd(bool),
}

const VEC_WRITE: &str = "writing to a Vec cannot fail";

impl Stage {
    fn new(coding: Coding) -> Self {
        match coding {
            Coding::Gzip => Self::Gzip(GzEncoder::new(Vec::new(), Compression::fast())),
            Coding::Deflate => Self::Deflate(ZlibEncoder::new(Vec::new(), Compression::fast())),
            Coding::Br => Self::Br(Some(Box::new(brotli::CompressorWriter::new(
                Vec::new(),
                32 << 10,
                BR_QUALITY,
                BR_LGWIN,
            )))),
            Coding::Zstd => Self::Zstd(false),
        }
    }

    /// `data` encoded and flushed, so a decoder can read all of it from
    /// what has been returned so far.
    fn flush(&mut self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Gzip(e) => {
                e.write_all(data).expect(VEC_WRITE);
                e.flush().expect(VEC_WRITE);
                std::mem::take(e.get_mut())
            }
            Self::Deflate(e) => {
                e.write_all(data).expect(VEC_WRITE);
                e.flush().expect(VEC_WRITE);
                std::mem::take(e.get_mut())
            }
            Self::Br(e) => {
                let e = e.as_mut().expect("flushed after finish");
                e.write_all(data).expect(VEC_WRITE);
                e.flush().expect(VEC_WRITE);
                std::mem::take(e.get_mut())
            }
            Self::Zstd(_) if data.is_empty() => Vec::new(),
            Self::Zstd(wrote) => {
                *wrote = true;
                compress_to_vec(data, CompressionLevel::Fastest)
            }
        }
    }

    /// The end of the stream.
    fn finish(&mut self) -> Vec<u8> {
        match self {
            Self::Gzip(e) => {
                e.try_finish().expect(VEC_WRITE);
                std::mem::take(e.get_mut())
            }
            Self::Deflate(e) => {
                e.try_finish().expect(VEC_WRITE);
                std::mem::take(e.get_mut())
            }
            Self::Br(e) => e.take().map(|e| (*e).into_inner()).unwrap_or_default(),
            Self::Zstd(true) => Vec::new(),
            Self::Zstd(wrote) => {
                *wrote = true;
                compress_to_vec(&b""[..], CompressionLevel::Fastest)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use http_body_util::BodyExt;

    use super::super::{Decoder, decode, unmetered};
    use super::*;

    const ALL: [Coding; 4] = [Coding::Gzip, Coding::Deflate, Coding::Br, Coding::Zstd];

    fn chunks(parts: &[&[u8]]) -> Body {
        let (mut tx, body) = Body::channel_with_depth(8, u64::MAX, None);
        for p in parts {
            tx.try_push(Bytes::copy_from_slice(p)).unwrap();
        }
        tx.try_finish().unwrap();
        body
    }

    async fn frames(body: Body) -> Vec<Bytes> {
        let mut body = body;
        let mut out = Vec::new();
        while let Some(f) = body.frame().await {
            if let Ok(d) = f.unwrap().into_data() {
                out.push(d);
            }
        }
        out
    }

    #[tokio::test]
    async fn every_coding_round_trips() {
        let parts: [&[u8]; 3] = [b"data: one\n\n", b"", b"data: two\n\n"];
        let mut stacks: Vec<Vec<Coding>> = ALL.iter().map(|c| vec![*c]).collect();
        stacks.push(vec![Coding::Gzip, Coding::Br]);
        stacks.push(vec![Coding::Zstd, Coding::Deflate, Coding::Gzip]);
        for codings in stacks {
            let out = frames(encode_body(chunks(&parts), &codings, unmetered())).await;
            let all: Vec<u8> = out.concat();
            let plain = decode(&codings, &all, 1 << 20, unmetered()).unwrap();
            assert_eq!(plain, parts.concat(), "{codings:?}");
        }
    }

    #[tokio::test]
    async fn an_empty_body_is_a_valid_stream() {
        for c in ALL {
            let all = frames(encode_body(Body::empty(), &[c], unmetered()))
                .await
                .concat();
            assert_eq!(
                decode(&[c], &all, 1 << 20, unmetered()).unwrap(),
                b"",
                "{c:?}"
            );
        }
    }

    /// Each frame decodes as it arrives: nothing waits for the next one.
    #[tokio::test]
    async fn each_frame_is_flushed() {
        for c in ALL {
            let mut body = encode_body(chunks(&[b"first", b"second"]), &[c], unmetered());
            let mut dec = Decoder::new(&[c], 1 << 20, unmetered());
            let first = body.frame().await.unwrap().unwrap().into_data().unwrap();
            dec.feed(&first);
            let mut buf = [0u8; 64];
            let mut got = Vec::new();
            loop {
                let n = dec.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            assert_eq!(got, b"first", "{c:?}");
        }
    }

    #[tokio::test]
    async fn a_refused_charge_fails_the_body() {
        let body = encode_body(chunks(&[b"x"]), &[Coding::Br], Box::new(|_| false));
        let e = body.collect().await.unwrap_err();
        assert!(matches!(e, BodyError::BudgetExhausted), "{e:?}");
    }
}
