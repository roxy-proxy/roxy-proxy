//! Content codings (RFC 9110 §8.4.1): strict, bounded decoders for `gzip`,
//! `deflate`, `br` and `zstd`.
//!
//! A [`Decoder`] is push in, pull out: [`Decoder::feed`] queues encoded
//! bytes and [`Decoder::read`] produces at most as many decoded bytes as the
//! caller asks for. Memory is bounded by the read size and the coding's
//! window, never by the compression ratio, so a decompression bomb costs
//! CPU, not memory. The windows are the client's to size (a brotli stream
//! declares up to 16 MiB), so each stage charges its window to the
//! caller's [`Meter`] before it is created, and a charge the meter refuses
//! fails the body.
//!
//! Decoding is strict. A truncated stream, a bad checksum, or any bytes
//! after the end of the stream are errors, so nothing can hide behind the
//! bytes roxy inspected.

use std::io::Read as _;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use brotli_decompressor::{BrotliDecompressStream, BrotliResult, BrotliState, StandardAlloc};
use bytes::Bytes;
use flate2::{Crc, Decompress, FlushDecompress, Status};
use http::HeaderMap;
use http_body::Frame;
use ruzstd::decoding::{BlockDecodingStrategy, FrameDecoder};

use crate::len_u64;
use crate::{Body, BodyError, Headers};

/// More codings than this in one `content-encoding` is refused rather than
/// decoded: each one is another decoder (and window) to allocate.
pub const MAX_CODINGS: usize = 4;

/// The largest zstd window accepted (RFC 9659: HTTP encoders must not use
/// more, and decoders may refuse it).
const ZSTD_MAX_WINDOW: u64 = 8 << 20;

/// The deflate window (RFC 1951): what a gzip or deflate stage holds.
const FLATE_WINDOW: u64 = 32 << 10;

/// Asked, before a decoder allocates, whether it may hold `bytes` in all:
/// the sum of its stages' windows so far. `false` fails the body with
/// [`DecodeError::BudgetExhausted`] before anything is allocated.
pub type Meter<'a> = Box<dyn FnMut(u64) -> bool + Send + 'a>;

/// A [`Meter`] that allows everything, for callers with no budget.
pub fn unmetered<'a>() -> Meter<'a> {
    Box::new(|_| true)
}

/// A gzip header this long without being complete is refused. A header is
/// 10 bytes plus an optional extra field (at most 64 KiB) and name and
/// comment fields, which no real encoder makes long.
const GZIP_MAX_HEADER: usize = 128 << 10;

/// Size of the buffer between stacked codings.
const STAGE_CHUNK: usize = 32 << 10;

/// Largest data frame a decoded body yields.
const FRAME_CHUNK: usize = 64 << 10;

/// A content coding roxy can decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coding {
    /// `gzip` (and its alias `x-gzip`), RFC 1952. Multi-member streams are
    /// accepted.
    Gzip,
    /// `deflate`: the zlib format of RFC 1950, as RFC 9110 defines it. Raw
    /// deflate without the zlib wrapper is refused.
    Deflate,
    /// `br`, RFC 7932.
    Br,
    /// `zstd`, RFC 8878, with a window of at most 8 MiB (RFC 9659).
    Zstd,
}

impl Coding {
    /// The coding named by a `content-encoding` token (case-insensitive).
    pub fn from_token(token: &str) -> Option<Self> {
        let t = token.to_ascii_lowercase();
        match t.as_str() {
            "gzip" | "x-gzip" => Some(Self::Gzip),
            "deflate" => Some(Self::Deflate),
            "br" => Some(Self::Br),
            "zstd" => Some(Self::Zstd),
            _ => None,
        }
    }

    /// The coding's canonical token.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Deflate => "deflate",
            Self::Br => "br",
            Self::Zstd => "zstd",
        }
    }
}

/// Why a body could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// A coding roxy does not decode, or more than [`MAX_CODINGS`].
    #[error("unsupported content coding `{0}`")]
    Unsupported(String),
    /// The bytes are not a valid stream in the declared coding.
    #[error("invalid {coding} data: {detail}")]
    Invalid {
        /// The coding that failed.
        coding: &'static str,
        /// What was wrong.
        detail: String,
    },
    /// The decoded body is larger than the decoder's limit.
    #[error("decoded body exceeds the {limit} byte cap")]
    TooLarge {
        /// The limit that was exceeded.
        limit: u64,
    },
    /// The [`Meter`] refused a stage's window.
    #[error("buffer budget cannot cover the decoder's window")]
    BudgetExhausted,
}

/// The codings in `headers`' `content-encoding` fields, in the order they
/// were applied. `identity` and empty list elements are skipped, so a body
/// with no coding gives an empty list. A value that is not a readable
/// string names no coding roxy knows, so it is [`DecodeError::Unsupported`]
/// rather than identity: the body must not be read as plain text.
pub fn content_codings(headers: &Headers) -> Result<Vec<Coding>, DecodeError> {
    let mut out = Vec::new();
    for raw in headers.get_all_raw("content-encoding") {
        let value = raw.to_str().map_err(|_| {
            DecodeError::Unsupported(String::from_utf8_lossy(raw.as_bytes()).into_owned())
        })?;
        for token in value.split(',').map(str::trim) {
            if token.is_empty() || token.eq_ignore_ascii_case("identity") {
                continue;
            }
            let c = Coding::from_token(token)
                .ok_or_else(|| DecodeError::Unsupported(token.to_owned()))?;
            if out.len() == MAX_CODINGS {
                return Err(DecodeError::Unsupported(format!(
                    "more than {MAX_CODINGS} codings"
                )));
            }
            out.push(c);
        }
    }
    Ok(out)
}

/// Decodes all of `input`, which was encoded with `codings` in that order.
/// The decoded body may be at most `limit` bytes; the stages' windows are
/// charged to `meter`.
pub fn decode(
    codings: &[Coding],
    input: &[u8],
    limit: u64,
    meter: Meter<'_>,
) -> Result<Vec<u8>, DecodeError> {
    let mut d = Decoder::new(codings, limit, meter);
    d.feed(input);
    d.finish();
    let mut out = Vec::new();
    let mut buf = vec![0u8; 64 << 10];
    loop {
        let n = d.read(&mut buf)?;
        if n == 0 {
            return Ok(out);
        }
        out.extend_from_slice(&buf[..n]);
    }
}

/// `body`, encoded with `codings`, as a decoded stream of unknown length.
///
/// Output is produced as the consumer reads it, at most 64 KiB per frame,
/// so a decompression bomb is paced by the reader like any other body.
/// More than `limit` decoded bytes fails the body with
/// [`BodyError::TooLarge`]; data that does not decode fails it with
/// [`BodyError::Undecodable`]; a window `meter` refuses fails it with
/// [`BodyError::BudgetExhausted`]. Trailers follow the decoded data.
pub fn decode_body(body: Body, codings: &[Coding], limit: u64, meter: Meter<'static>) -> Body {
    Body::wrap_native(
        DecodedBody {
            inner: body,
            dec: Decoder::new(codings, limit, meter),
            buf: vec![0u8; FRAME_CHUNK].into_boxed_slice(),
            inner_done: false,
            trailers: None,
            done: false,
        },
        u64::MAX,
        None,
    )
}

struct DecodedBody {
    inner: Body,
    dec: Decoder<'static>,
    buf: Box<[u8]>,
    inner_done: bool,
    trailers: Option<HeaderMap>,
    done: bool,
}

impl http_body::Body for DecodedBody {
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
            match this.dec.read(&mut this.buf) {
                Ok(0) => {}
                Ok(n) => {
                    return Poll::Ready(Some(Ok(Frame::data(Bytes::copy_from_slice(
                        &this.buf[..n],
                    )))));
                }
                Err(e) => {
                    this.done = true;
                    let e = match e {
                        DecodeError::TooLarge { limit } => BodyError::TooLarge { limit },
                        DecodeError::BudgetExhausted => BodyError::BudgetExhausted,
                        e @ (DecodeError::Unsupported(_) | DecodeError::Invalid { .. }) => {
                            BodyError::Undecodable(e.to_string())
                        }
                    };
                    return Poll::Ready(Some(Err(e)));
                }
            }
            if this.inner_done {
                this.done = true;
                return Poll::Ready(this.trailers.take().map(|t| Ok(Frame::trailers(t))));
            }
            match ready!(Pin::new(&mut this.inner).poll_frame(cx)) {
                Some(Ok(f)) => match f.into_data() {
                    Ok(d) => this.dec.feed(&d),
                    Err(f) => this.trailers = f.into_trailers().ok(),
                },
                Some(Err(e)) => {
                    this.done = true;
                    return Poll::Ready(Some(Err(e)));
                }
                None => {
                    this.inner_done = true;
                    this.dec.finish();
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done
    }
}

/// A streaming decoder for a stack of codings.
pub struct Decoder<'m> {
    /// `stages[0]` decodes the input as received: the coding applied last.
    stages: Vec<Slot>,
    /// Encoded bytes queued for each stage.
    pending: Vec<Pending>,
    limit: u64,
    produced: u64,
    /// No more input will be fed.
    ended: bool,
    /// Any input was fed at all. An empty body is empty whatever its
    /// declared coding, as clients decode it.
    fed: bool,
    /// The windows charged so far, and who they are charged to.
    held: u64,
    meter: Meter<'m>,
}

impl std::fmt::Debug for Decoder<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Decoder")
            .field(
                "codings",
                &self.stages.iter().map(Slot::coding).collect::<Vec<_>>(),
            )
            .field("produced", &self.produced)
            .field("held", &self.held)
            .finish_non_exhaustive()
    }
}

impl<'m> Decoder<'m> {
    /// A decoder for a body encoded with `codings` (in the order applied)
    /// whose decoded size may be at most `limit` bytes and whose windows
    /// are charged to `meter`.
    pub fn new(codings: &[Coding], limit: u64, meter: Meter<'m>) -> Self {
        let stages: Vec<Slot> = codings.iter().rev().map(|c| Slot::Waiting(*c)).collect();
        // With no codings, `pending[0]` holds the bytes passing through.
        let pending = (0..stages.len().max(1))
            .map(|_| Pending::default())
            .collect();
        Self {
            stages,
            pending,
            limit,
            produced: 0,
            ended: false,
            fed: false,
            held: 0,
            meter,
        }
    }

    /// Queues encoded bytes. With no codings they pass straight through.
    pub fn feed(&mut self, input: &[u8]) {
        debug_assert!(!self.ended, "feed after finish");
        if input.is_empty() {
            return;
        }
        self.fed = true;
        self.pending[0].push(input);
    }

    /// Marks the end of the input.
    pub fn finish(&mut self) {
        self.ended = true;
    }

    /// Decodes into `buf`, returning how many bytes were written. `0`
    /// means more input is needed or, after [`finish`](Self::finish), that
    /// the body ended cleanly; an incomplete stream is an error then.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, DecodeError> {
        if buf.is_empty() {
            return Ok(0);
        }
        let n = match self.stages.len().checked_sub(1) {
            None => self.passthrough_read(buf),
            Some(last) => self.pull(last, buf)?,
        };
        self.produced = self.produced.saturating_add(len_u64(n));
        if self.produced > self.limit {
            return Err(DecodeError::TooLarge { limit: self.limit });
        }
        if n == 0 && self.ended && self.fed {
            self.check_complete()?;
        }
        Ok(n)
    }

    /// Fills `buf` from stage `i`, pulling input from the stages before it.
    fn pull(&mut self, i: usize, buf: &mut [u8]) -> Result<usize, DecodeError> {
        loop {
            self.start(i)?;
            let Slot::Running(stage) = &mut self.stages[i] else {
                // Not enough of the stream yet to size the window.
                let Some(upstream) = i.checked_sub(1) else {
                    return Ok(0);
                };
                if self.pull_into(upstream, i)? == 0 {
                    return Ok(0);
                }
                continue;
            };
            let (used, made) = stage
                .step(self.pending[i].as_slice(), buf)
                .map_err(|detail| DecodeError::Invalid {
                    coding: stage.coding().as_str(),
                    detail,
                })?;
            self.pending[i].consume(used);
            if made > 0 {
                return Ok(made);
            }
            if used > 0 {
                continue;
            }
            // Stage `i` needs more input.
            let Some(upstream) = i.checked_sub(1) else {
                return Ok(0);
            };
            if self.pull_into(upstream, i)? == 0 {
                return Ok(0);
            }
        }
    }

    /// Pulls one chunk from stage `from` into stage `to`'s queue.
    fn pull_into(&mut self, from: usize, to: usize) -> Result<usize, DecodeError> {
        let mut tmp = vec![0u8; STAGE_CHUNK];
        let n = self.pull(from, &mut tmp)?;
        self.pending[to].push(&tmp[..n]);
        Ok(n)
    }

    /// Starts stage `i` once its queue shows enough of its stream to size
    /// its window and the meter covers that window; it stays waiting while
    /// more of the stream is needed first (a stream that ends before that
    /// is truncated, as [`Self::check_complete`] reports).
    fn start(&mut self, i: usize) -> Result<(), DecodeError> {
        let Slot::Waiting(coding) = self.stages[i] else {
            return Ok(());
        };
        let Some(window) = window(coding, self.pending[i].as_slice()) else {
            return Ok(());
        };
        let held = self.held.saturating_add(window);
        if !(self.meter)(held) {
            return Err(DecodeError::BudgetExhausted);
        }
        self.held = held;
        self.stages[i] = Slot::Running(stage_for(coding));
        Ok(())
    }

    /// After the input has ended and nothing more decodes: every stage must
    /// be at the end of a stream with nothing left over.
    fn check_complete(&self) -> Result<(), DecodeError> {
        for (stage, pending) in self.stages.iter().zip(&self.pending) {
            // A stage still waiting for its window never saw a whole stream.
            let detail = if !stage.is_done() {
                "truncated stream"
            } else if !pending.as_slice().is_empty() {
                "data after the end of the stream"
            } else {
                continue;
            };
            return Err(DecodeError::Invalid {
                coding: stage.coding().as_str(),
                detail: detail.to_owned(),
            });
        }
        Ok(())
    }

    fn passthrough_read(&mut self, buf: &mut [u8]) -> usize {
        let p = &mut self.pending[0];
        let src = p.as_slice();
        let n = src.len().min(buf.len());
        buf[..n].copy_from_slice(&src[..n]);
        p.consume(n);
        n
    }
}

/// A queue of encoded bytes for one stage.
#[derive(Default)]
struct Pending {
    buf: Vec<u8>,
    start: usize,
}

impl Pending {
    fn as_slice(&self) -> &[u8] {
        &self.buf[self.start..]
    }

    fn consume(&mut self, n: usize) {
        debug_assert!(n <= self.as_slice().len());
        self.start = self.start.saturating_add(n).min(self.buf.len());
        if self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
        }
    }

    fn push(&mut self, b: &[u8]) {
        if self.start > 0 && self.start >= self.buf.len() / 2 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        self.buf.extend_from_slice(b);
    }
}

/// A stage: waiting for enough of its stream to size and charge its
/// window, or decoding.
enum Slot {
    Waiting(Coding),
    Running(Box<dyn Stage>),
}

impl Slot {
    fn coding(&self) -> Coding {
        match self {
            Self::Waiting(c) => *c,
            Self::Running(s) => s.coding(),
        }
    }

    fn is_done(&self) -> bool {
        match self {
            Self::Waiting(_) => false,
            Self::Running(s) => s.is_done(),
        }
    }
}

fn stage_for(coding: Coding) -> Box<dyn Stage> {
    match coding {
        Coding::Gzip => Box::new(Gzip::new()),
        Coding::Deflate => Box::new(Zlib::new()),
        Coding::Br => Box::new(Brotli::new()),
        Coding::Zstd => Box::new(Zstd::new()),
    }
}

/// The memory a `coding` stage holds for a stream that starts with
/// `head`, known before the stage exists: the flate window; the ring
/// buffer brotli sizes from the window bits in its first byte; or the
/// largest zstd window accepted, which every frame of the stream may
/// declare. `None` until `head` has the byte that says.
fn window(coding: Coding, head: &[u8]) -> Option<u64> {
    match coding {
        Coding::Gzip | Coding::Deflate => Some(FLATE_WINDOW),
        Coding::Br => head.first().map(|&b| 1u64 << brotli_window_bits(b)),
        Coding::Zstd => Some(ZSTD_MAX_WINDOW),
    }
}

/// WBITS from the first byte of a brotli stream (RFC 7932 §9.1), least
/// significant bit first: 10 to 24. The large-window prefix, which the
/// decoder refuses, reads as the largest standard window.
#[expect(clippy::arithmetic_side_effects, reason = "n is at most 7")]
fn brotli_window_bits(b: u8) -> u32 {
    if b & 1 == 0 {
        return 16;
    }
    match u32::from(b >> 1) & 7 {
        0 => match u32::from(b >> 4) & 7 {
            0 => 17,
            1 => 24,
            n => 8 + n,
        },
        n => 17 + n,
    }
}

/// One coding's decoder.
trait Stage: Send {
    fn coding(&self) -> Coding;
    /// Decodes from the front of `input` into `out` (never empty).
    /// Returns `(consumed, produced)`; `(0, 0)` means it needs more input.
    fn step(&mut self, input: &[u8], out: &mut [u8]) -> Result<(usize, usize), String>;
    /// At the end of a complete stream.
    fn is_done(&self) -> bool;
}

/// Bytes consumed and produced by a flate2 call.
fn flate_step(
    z: &mut Decompress,
    input: &[u8],
    out: &mut [u8],
) -> Result<(usize, usize, Status), String> {
    let (in0, out0) = (z.total_in(), z.total_out());
    let status = z
        .decompress(input, out, FlushDecompress::None)
        .map_err(|e| e.to_string())?;
    // Both deltas are bounded by the slice lengths.
    let delta = |after: u64, before: u64| {
        after
            .checked_sub(before)
            .and_then(|d| usize::try_from(d).ok())
            .ok_or_else(|| "inflater counters went backwards".to_owned())
    };
    let used = delta(z.total_in(), in0)?;
    let made = delta(z.total_out(), out0)?;
    Ok((used, made, status))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GzState {
    Header,
    Body,
    Trailer,
    /// Between members: done, unless another member follows.
    End,
}

struct Gzip {
    state: GzState,
    inflate: Decompress,
    crc: Crc,
}

impl Gzip {
    fn new() -> Self {
        Self {
            state: GzState::Header,
            inflate: Decompress::new(false),
            crc: Crc::new(),
        }
    }
}

/// The length of the gzip member header at the front of `b`, `None` if it
/// is not all there yet.
fn gzip_header_len(b: &[u8]) -> Result<Option<usize>, String> {
    for (i, want) in [0x1f, 0x8b].into_iter().enumerate() {
        if b.get(i).is_some_and(|&x| x != want) {
            return Err("not a gzip member".to_owned());
        }
    }
    if b.get(2).is_some_and(|&m| m != 8) {
        return Err("unknown compression method".to_owned());
    }
    if b.len() < 10 {
        return Ok(None);
    }
    let flags = b[3];
    if flags & 0xe0 != 0 {
        return Err("reserved header flags set".to_owned());
    }
    // Optional fields only ever push the end further out, so an offset the
    // buffer cannot reach is "not all there yet", never an error.
    let mut i: usize = 10;
    if flags & 0x04 != 0 {
        let Some(x) = i.checked_add(2).and_then(|e| b.get(i..e)) else {
            return Ok(None);
        };
        let extra = usize::from(u16::from_le_bytes([x[0], x[1]]));
        i = i.saturating_add(2).saturating_add(extra);
    }
    for flag in [0x08, 0x10] {
        if flags & flag != 0 {
            let Some(rest) = b.get(i..) else {
                return Ok(None);
            };
            let Some(nul) = rest.iter().position(|&c| c == 0) else {
                return Ok(None);
            };
            i = i.saturating_add(nul).saturating_add(1);
        }
    }
    if flags & 0x02 != 0 {
        let Some(x) = i.checked_add(2).and_then(|e| b.get(i..e)) else {
            return Ok(None);
        };
        let mut crc = Crc::new();
        crc.update(&b[..i]);
        if crc.sum() & 0xffff != u32::from(u16::from_le_bytes([x[0], x[1]])) {
            return Err("header checksum mismatch".to_owned());
        }
        i = i.saturating_add(2);
    }
    Ok((b.len() >= i).then_some(i))
}

impl Stage for Gzip {
    fn coding(&self) -> Coding {
        Coding::Gzip
    }

    fn step(&mut self, input: &[u8], out: &mut [u8]) -> Result<(usize, usize), String> {
        match self.state {
            GzState::End if input.is_empty() => Ok((0, 0)),
            GzState::End | GzState::Header => {
                let Some(n) = gzip_header_len(input)? else {
                    if input.len() > GZIP_MAX_HEADER {
                        return Err("header too long".to_owned());
                    }
                    if self.state == GzState::End {
                        // Part of a next member: no longer done.
                        self.state = GzState::Header;
                    }
                    return Ok((0, 0));
                };
                self.state = GzState::Body;
                self.inflate.reset(false);
                self.crc.reset();
                Ok((n, 0))
            }
            GzState::Body => {
                let (used, made, status) = flate_step(&mut self.inflate, input, out)?;
                self.crc.update(&out[..made]);
                if status == Status::StreamEnd {
                    self.state = GzState::Trailer;
                }
                Ok((used, made))
            }
            GzState::Trailer => {
                let Some(t) = input.get(..8) else {
                    return Ok((0, 0));
                };
                let crc = u32::from_le_bytes([t[0], t[1], t[2], t[3]]);
                let size = u32::from_le_bytes([t[4], t[5], t[6], t[7]]);
                if crc != self.crc.sum() {
                    return Err("checksum mismatch".to_owned());
                }
                if size != self.crc.amount() {
                    return Err("length mismatch".to_owned());
                }
                self.state = GzState::End;
                Ok((8, 0))
            }
        }
    }

    fn is_done(&self) -> bool {
        self.state == GzState::End
    }
}

struct Zlib {
    inflate: Decompress,
    done: bool,
}

impl Zlib {
    fn new() -> Self {
        Self {
            inflate: Decompress::new(true),
            done: false,
        }
    }
}

impl Stage for Zlib {
    fn coding(&self) -> Coding {
        Coding::Deflate
    }

    fn step(&mut self, input: &[u8], out: &mut [u8]) -> Result<(usize, usize), String> {
        if self.done {
            return if input.is_empty() {
                Ok((0, 0))
            } else {
                Err("data after the end of the stream".to_owned())
            };
        }
        let (used, made, status) = flate_step(&mut self.inflate, input, out)?;
        self.done = status == Status::StreamEnd;
        Ok((used, made))
    }

    fn is_done(&self) -> bool {
        self.done
    }
}

struct Brotli {
    state: Box<BrotliState<StandardAlloc, StandardAlloc, StandardAlloc>>,
    done: bool,
}

impl Brotli {
    fn new() -> Self {
        Self {
            state: Box::new(BrotliState::new(
                StandardAlloc::default(),
                StandardAlloc::default(),
                StandardAlloc::default(),
            )),
            done: false,
        }
    }
}

impl Stage for Brotli {
    fn coding(&self) -> Coding {
        Coding::Br
    }

    fn step(&mut self, input: &[u8], out: &mut [u8]) -> Result<(usize, usize), String> {
        if self.done {
            return if input.is_empty() {
                Ok((0, 0))
            } else {
                Err("data after the end of the stream".to_owned())
            };
        }
        let (mut avail_in, mut in_off) = (input.len(), 0);
        let (mut avail_out, mut out_off, mut total) = (out.len(), 0, 0);
        let r = BrotliDecompressStream(
            &mut avail_in,
            &mut in_off,
            input,
            &mut avail_out,
            &mut out_off,
            out,
            &mut total,
            &mut self.state,
        );
        match r {
            BrotliResult::ResultSuccess => self.done = true,
            BrotliResult::NeedsMoreInput | BrotliResult::NeedsMoreOutput => {}
            BrotliResult::ResultFailure => {
                return Err(format!("{:?}", self.state.error_code));
            }
        }
        Ok((in_off, out_off))
    }

    fn is_done(&self) -> bool {
        self.done
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ZState {
    /// Between frames: done, unless another frame follows.
    FrameStart,
    /// Inside a skippable frame, with this many bytes left.
    Skip(u64),
    /// Decoding a frame's blocks.
    Blocks { checksum: bool },
    /// The frame's last block is decoded; draining its output.
    Drain { checksum: bool },
}

struct Zstd {
    dec: FrameDecoder,
    state: ZState,
}

impl Zstd {
    fn new() -> Self {
        let mut dec = FrameDecoder::new();
        dec.set_max_window_size(ZSTD_MAX_WINDOW);
        Self {
            dec,
            state: ZState::FrameStart,
        }
    }
}

/// The length of the zstd frame header at the front of `b` (RFC 8878
/// §3.1.1.1), `None` if fewer than 5 bytes are there.
#[expect(clippy::arithmetic_side_effects, reason = "every term is at most 8")]
fn zstd_header_len(b: &[u8]) -> Option<usize> {
    let fhd = *b.get(4)?;
    let single_segment = fhd & 0x20 != 0;
    let dict_id = [0, 1, 2, 4][usize::from(fhd & 0x03)];
    let content_size = match fhd >> 6 {
        0 => usize::from(single_segment),
        1 => 2,
        2 => 4,
        _ => 8,
    };
    Some(5 + usize::from(!single_segment) + dict_id + content_size)
}

/// The block at the front of `b`: its total length (header and content),
/// whether it is the frame's last, `None` if fewer than 3 bytes are there.
fn zstd_block(b: &[u8]) -> Result<Option<(usize, bool)>, String> {
    let Some(h) = b.get(..3) else {
        return Ok(None);
    };
    let h = u32::from_le_bytes([h[0], h[1], h[2], 0]);
    let last = h & 1 != 0;
    let size = usize::try_from(h >> 3).map_err(|_| "block too large".to_owned())?;
    let content = match (h >> 1) & 3 {
        0 | 2 => size,
        1 => 1,
        _ => return Err("reserved block type".to_owned()),
    };
    let len = content
        .checked_add(3)
        .ok_or_else(|| "block too large".to_owned())?;
    Ok(Some((len, last)))
}

impl Stage for Zstd {
    fn coding(&self) -> Coding {
        Coding::Zstd
    }

    fn step(&mut self, input: &[u8], out: &mut [u8]) -> Result<(usize, usize), String> {
        match self.state {
            ZState::FrameStart => {
                let Some(m) = input.get(..4) else {
                    return Ok((0, 0));
                };
                let magic = u32::from_le_bytes([m[0], m[1], m[2], m[3]]);
                if magic & 0xffff_fff0 == 0x184d_2a50 {
                    let Some(l) = input.get(4..8) else {
                        return Ok((0, 0));
                    };
                    self.state =
                        ZState::Skip(u64::from(u32::from_le_bytes([l[0], l[1], l[2], l[3]])));
                    return Ok((8, 0));
                }
                let Some(n) = zstd_header_len(input) else {
                    return Ok((0, 0));
                };
                let Some(header) = input.get(..n) else {
                    return Ok((0, 0));
                };
                self.dec.reset(header).map_err(|e| e.to_string())?;
                self.state = ZState::Blocks {
                    checksum: input[4] & 0x04 != 0,
                };
                Ok((n, 0))
            }
            ZState::Skip(0) => {
                // Not a pause for input: a frame may follow at once.
                self.state = ZState::FrameStart;
                self.step(input, out)
            }
            ZState::Skip(left) => {
                let n = usize::try_from(left).unwrap_or(usize::MAX).min(input.len());
                self.state = ZState::Skip(left.saturating_sub(len_u64(n)));
                Ok((n, 0))
            }
            ZState::Blocks { checksum } => {
                // Drain what the window no longer needs before decoding
                // more, so at most one block is ever buffered.
                if self.dec.can_collect() > 0 {
                    let n = self.dec.read(out).map_err(|e| e.to_string())?;
                    return Ok((0, n));
                }
                let Some((mut len, last)) = zstd_block(input)? else {
                    return Ok((0, 0));
                };
                if last && checksum {
                    len = len
                        .checked_add(4)
                        .ok_or_else(|| "block too large".to_owned())?;
                }
                let Some(mut block) = input.get(..len) else {
                    return Ok((0, 0));
                };
                self.dec
                    .decode_blocks(&mut block, BlockDecodingStrategy::UptoBlocks(1))
                    .map_err(|e| e.to_string())?;
                if last {
                    self.state = ZState::Drain { checksum };
                }
                // `block` is what the decoder left of `input[..len]`.
                Ok((len.saturating_sub(block.len()), 0))
            }
            ZState::Drain { checksum } => {
                let n = self.dec.read(out).map_err(|e| e.to_string())?;
                if n > 0 {
                    return Ok((0, n));
                }
                if checksum
                    && self.dec.get_checksum_from_data() != self.dec.get_calculated_checksum()
                {
                    return Err("checksum mismatch".to_owned());
                }
                self.state = ZState::FrameStart;
                self.step(input, out)
            }
        }
    }

    fn is_done(&self) -> bool {
        matches!(self.state, ZState::FrameStart | ZState::Skip(0))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    fn gzip(b: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(b).unwrap();
        e.finish().unwrap()
    }

    fn zlib(b: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(b).unwrap();
        e.finish().unwrap()
    }

    fn br(b: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        brotli::BrotliCompress(
            &mut &b[..],
            &mut out,
            &brotli::enc::BrotliEncoderParams::default(),
        )
        .unwrap();
        out
    }

    fn zstd(b: &[u8]) -> Vec<u8> {
        ruzstd::encoding::compress_to_vec(b, ruzstd::encoding::CompressionLevel::Fastest)
    }

    fn encode(c: Coding, b: &[u8]) -> Vec<u8> {
        match c {
            Coding::Gzip => gzip(b),
            Coding::Deflate => zlib(b),
            Coding::Br => br(b),
            Coding::Zstd => zstd(b),
        }
    }

    const ALL: [Coding; 4] = [Coding::Gzip, Coding::Deflate, Coding::Br, Coding::Zstd];

    /// [`super::decode`] with no budget.
    fn decode(codings: &[Coding], input: &[u8], limit: u64) -> Result<Vec<u8>, DecodeError> {
        super::decode(codings, input, limit, unmetered())
    }

    /// [`super::decode`] with a meter that records what it was asked for
    /// and refuses once the total passes `cap`.
    fn decode_metered(
        codings: &[Coding],
        input: &[u8],
        cap: u64,
    ) -> (Result<Vec<u8>, DecodeError>, Vec<u64>) {
        let mut asked = Vec::new();
        let r = super::decode(
            codings,
            input,
            u64::MAX,
            Box::new(|held| {
                asked.push(held);
                held <= cap
            }),
        );
        (r, asked)
    }

    #[expect(
        clippy::arithmetic_side_effects,
        reason = "20_000 * 7919 fits in a u32"
    )]
    fn sample() -> Vec<u8> {
        let mut v = Vec::new();
        for i in 0..20_000u32 {
            v.extend_from_slice(
                format!("line {i}: BEGIN PRIVATE KEY {}\n", i * 7919 % 1000).as_bytes(),
            );
        }
        v
    }

    /// Decodes `input` fed in `chunk`-sized pieces, reading `read`-sized.
    fn decode_chunked(
        codings: &[Coding],
        input: &[u8],
        chunk: usize,
        read: usize,
    ) -> Result<Vec<u8>, DecodeError> {
        let mut d = Decoder::new(codings, u64::MAX, unmetered());
        let mut out = Vec::new();
        let mut buf = vec![0u8; read];
        for piece in input.chunks(chunk) {
            d.feed(piece);
            loop {
                let n = d.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..n]);
            }
        }
        d.finish();
        loop {
            let n = d.read(&mut buf)?;
            if n == 0 {
                return Ok(out);
            }
            out.extend_from_slice(&buf[..n]);
        }
    }

    fn invalid(r: Result<Vec<u8>, DecodeError>) -> String {
        match r {
            Err(DecodeError::Invalid { detail, .. }) => detail,
            other => panic!("expected invalid, got {other:?}"),
        }
    }

    #[test]
    fn each_coding_round_trips() {
        let body = sample();
        for c in ALL {
            let enc = encode(c, &body);
            assert_eq!(decode(&[c], &enc, u64::MAX).unwrap(), body, "{c:?}");
        }
    }

    #[test]
    fn result_does_not_depend_on_how_input_or_output_is_split() {
        let body = sample();
        for c in ALL {
            let enc = encode(c, &body);
            for (chunk, read) in [(1, 7), (13, 1), (4096, 100_000), (usize::MAX, 1 << 16)] {
                let got = decode_chunked(&[c], &enc, chunk.min(enc.len()), read).unwrap();
                assert_eq!(got, body, "{c:?} chunk {chunk} read {read}");
            }
        }
    }

    #[test]
    fn stacked_codings_are_undone_in_reverse() {
        let body = sample();
        let enc = br(&gzip(&body));
        assert_eq!(
            decode(&[Coding::Gzip, Coding::Br], &enc, u64::MAX).unwrap(),
            body
        );
        assert_eq!(
            decode_chunked(&[Coding::Gzip, Coding::Br], &enc, 100, 333).unwrap(),
            body
        );
        // The wrong order is an error, not garbage.
        assert!(decode(&[Coding::Br, Coding::Gzip], &enc, u64::MAX).is_err());
    }

    #[test]
    fn identity_passes_through() {
        assert_eq!(decode(&[], b"plain", 10).unwrap(), b"plain");
        assert_eq!(
            decode(&[], b"plain", 3).unwrap_err(),
            DecodeError::TooLarge { limit: 3 }
        );
    }

    #[test]
    fn an_empty_body_is_empty_in_any_coding() {
        for c in ALL {
            assert_eq!(decode(&[c], b"", 0).unwrap(), b"");
        }
    }

    #[test]
    fn the_limit_applies_to_the_decoded_size() {
        let bomb = vec![0u8; 8 << 20];
        for c in ALL {
            let enc = encode(c, &bomb);
            assert!(enc.len() < 1 << 20, "{c:?} compresses well");
            assert_eq!(
                decode(&[c], &enc, 1 << 20).unwrap_err(),
                DecodeError::TooLarge { limit: 1 << 20 },
                "{c:?}"
            );
            assert_eq!(decode(&[c], &enc, 8 << 20).unwrap().len(), 8 << 20);
        }
    }

    #[test]
    fn a_read_never_returns_more_than_asked() {
        let bomb = vec![b'a'; 4 << 20];
        for c in ALL {
            let mut d = Decoder::new(&[c], u64::MAX, unmetered());
            d.feed(&encode(c, &bomb));
            d.finish();
            let mut buf = [0u8; 100];
            assert_eq!(d.read(&mut buf).unwrap(), 100, "{c:?}");
        }
    }

    #[test]
    fn truncation_is_an_error() {
        let body = sample();
        for c in ALL {
            let enc = encode(c, &body);
            for cut in [1, enc.len() / 2, enc.len() - 1] {
                assert!(
                    decode(&[c], &enc[..cut], u64::MAX).is_err(),
                    "{c:?} cut at {cut}"
                );
            }
        }
    }

    #[test]
    fn trailing_bytes_are_an_error() {
        let body = sample();
        for c in ALL {
            let mut enc = encode(c, &body);
            enc.extend_from_slice(b"hidden");
            invalid(decode(&[c], &enc, u64::MAX));
            enc.truncate(enc.len() - 6);
            enc.push(0);
            invalid(decode(&[c], &enc, u64::MAX));
        }
    }

    #[test]
    fn corrupt_checksums_are_errors() {
        let body = sample();
        let mut g = gzip(&body);
        let n = g.len();
        g[n - 8] ^= 1;
        assert_eq!(
            invalid(decode(&[Coding::Gzip], &g, u64::MAX)),
            "checksum mismatch"
        );
        let mut g = gzip(&body);
        g[n - 4] ^= 1;
        assert_eq!(
            invalid(decode(&[Coding::Gzip], &g, u64::MAX)),
            "length mismatch"
        );
        let mut z = zlib(&body);
        let n = z.len();
        z[n - 1] ^= 1;
        invalid(decode(&[Coding::Deflate], &z, u64::MAX));
    }

    #[test]
    fn gzip_members_concatenate() {
        let mut enc = gzip(b"first ");
        enc.extend(gzip(b"second"));
        assert_eq!(
            decode(&[Coding::Gzip], &enc, u64::MAX).unwrap(),
            b"first second"
        );
        assert_eq!(
            decode_chunked(&[Coding::Gzip], &enc, 1, 3).unwrap(),
            b"first second"
        );
    }

    #[test]
    fn gzip_optional_header_fields() {
        let mut e = flate2::GzBuilder::new()
            .filename("a.txt")
            .comment("note")
            .extra(vec![1, 2, 3])
            .write(Vec::new(), flate2::Compression::default());
        e.write_all(b"payload").unwrap();
        let enc = e.finish().unwrap();
        assert_eq!(
            decode_chunked(&[Coding::Gzip], &enc, 1, 64).unwrap(),
            b"payload"
        );
    }

    #[test]
    fn gzip_header_checksum_is_checked() {
        // A minimal member with FHCRC, then the same with a wrong CRC16.
        let body = gzip(b"x");
        let mut good = body[..10].to_vec();
        good[3] |= 0x02;
        let mut crc = Crc::new();
        crc.update(&good);
        good.extend_from_slice(&u16::try_from(crc.sum() & 0xffff).unwrap().to_le_bytes());
        good.extend_from_slice(&body[10..]);
        assert_eq!(decode(&[Coding::Gzip], &good, 10).unwrap(), b"x");
        good[10] ^= 1;
        assert_eq!(
            invalid(decode(&[Coding::Gzip], &good, 10)),
            "header checksum mismatch"
        );
    }

    #[test]
    fn raw_deflate_is_refused() {
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(b"raw").unwrap();
        invalid(decode(&[Coding::Deflate], &e.finish().unwrap(), 100));
    }

    #[test]
    fn zstd_frames_concatenate_and_skippable_frames_are_skipped() {
        let mut enc = zstd(b"one ");
        enc.extend_from_slice(&0x184d_2a53u32.to_le_bytes());
        enc.extend_from_slice(&3u32.to_le_bytes());
        enc.extend_from_slice(b"xyz");
        enc.extend(zstd(b"two"));
        assert_eq!(decode(&[Coding::Zstd], &enc, 100).unwrap(), b"one two");
        assert_eq!(
            decode_chunked(&[Coding::Zstd], &enc, 1, 2).unwrap(),
            b"one two"
        );
    }

    #[test]
    fn an_empty_skippable_frame_does_not_end_the_body() {
        let mut enc = 0x184d_2a50u32.to_le_bytes().to_vec();
        enc.extend_from_slice(&0u32.to_le_bytes());
        enc.extend(zstd(b"after"));
        assert_eq!(decode(&[Coding::Zstd], &enc, 100).unwrap(), b"after");
        assert_eq!(
            decode_chunked(&[Coding::Zstd], &enc, 1, 1).unwrap(),
            b"after"
        );
    }

    #[test]
    fn zstd_checksums_are_checked() {
        let mut enc = zstd(&sample());
        assert_ne!(enc[4] & 0x04, 0, "the encoder writes a checksum");
        let n = enc.len();
        enc[n - 1] ^= 1;
        assert_eq!(
            invalid(decode(&[Coding::Zstd], &enc, u64::MAX)),
            "checksum mismatch"
        );
    }

    /// Each stage charges its window to the meter before it exists:
    /// brotli the window its first byte declares, zstd the largest window
    /// accepted, gzip and deflate the flate window; stacked codings add
    /// up. A charge the meter refuses fails the decode before a byte is
    /// decoded, and the meter is never asked for more once it has refused.
    #[test]
    fn stages_charge_their_windows_before_decoding() {
        let body = sample();
        let (r, asked) = decode_metered(&[Coding::Gzip], &gzip(&body), u64::MAX);
        assert_eq!(r.unwrap(), body);
        assert_eq!(asked, vec![FLATE_WINDOW]);
        let (r, asked) = decode_metered(&[Coding::Zstd], &zstd(&body), u64::MAX);
        assert_eq!(r.unwrap(), body);
        assert_eq!(asked, vec![ZSTD_MAX_WINDOW]);
        let enc = br(&body);
        let declared = 1u64 << brotli_window_bits(enc[0]);
        let (r, asked) = decode_metered(&[Coding::Br], &enc, u64::MAX);
        assert_eq!(r.unwrap(), body);
        assert_eq!(asked, vec![declared]);
        // The stage applied last is charged first; the inner one once the
        // outer has produced its first byte.
        let (r, asked) = decode_metered(&[Coding::Br, Coding::Gzip], &gzip(&enc), u64::MAX);
        assert_eq!(r.unwrap(), body);
        assert_eq!(asked, vec![FLATE_WINDOW, FLATE_WINDOW + declared]);

        // A 1 KiB body whose first byte declares WBITS 24 costs 16 MiB.
        let mut bomb = vec![0x0f];
        bomb.extend(std::iter::repeat_n(0u8, 1023));
        let (r, asked) = decode_metered(&[Coding::Br], &bomb, 8 << 20);
        assert_eq!(r.unwrap_err(), DecodeError::BudgetExhausted);
        assert_eq!(asked, vec![1 << 24]);
        let (r, asked) = decode_metered(&[Coding::Br, Coding::Br], &bomb, 1 << 24);
        assert!(r.is_err(), "{r:?}");
        assert_eq!(asked, vec![1 << 24], "no charge after a refusal");
    }

    /// RFC 7932 §9.1: the window bits are the first 1 to 7 bits of the
    /// stream.
    #[test]
    fn brotli_window_bits_follow_the_spec() {
        assert_eq!(brotli_window_bits(0b0000_0000), 16);
        assert_eq!(brotli_window_bits(0b1111_1110), 16, "only bit 0 counts");
        for n in 1..=7u8 {
            assert_eq!(brotli_window_bits(1 | n << 1), 17 + u32::from(n));
        }
        assert_eq!(brotli_window_bits(0b0000_0001), 17);
        for n in 2..=7u8 {
            assert_eq!(brotli_window_bits(1 | n << 4), 8 + u32::from(n));
        }
        assert_eq!(
            brotli_window_bits(0b0001_0001),
            24,
            "large window reads as the maximum"
        );
        for wbits in [16u32, 18, 22, 24] {
            let p = brotli::enc::BrotliEncoderParams {
                lgwin: i32::try_from(wbits).unwrap(),
                ..Default::default()
            };
            let mut out = Vec::new();
            brotli::BrotliCompress(&mut &sample()[..], &mut out, &p).unwrap();
            assert!(
                brotli_window_bits(out[0]) <= wbits,
                "lgwin {wbits}: {}",
                out[0]
            );
        }
    }

    /// A streaming body charges the same way, and ends with its own error
    /// when the meter refuses.
    #[tokio::test]
    async fn a_decoded_body_fails_when_the_meter_refuses() {
        let enc = br(&sample());
        let body = decode_body(
            Body::from_bytes(enc.clone()),
            &[Coding::Br],
            u64::MAX,
            Box::new(|_| false),
        );
        let (frames, end) = drain(body).await;
        assert!(frames.is_empty(), "{frames:?}");
        assert_eq!(end.unwrap_err(), BodyError::BudgetExhausted);
        let body = decode_body(
            Body::from_bytes(enc),
            &[Coding::Br],
            u64::MAX,
            Box::new(|held| held <= 1 << 24),
        );
        let (frames, end) = drain(body).await;
        end.unwrap();
        assert_eq!(frames.concat(), sample());
    }

    #[test]
    fn zstd_windows_over_8_mib_are_refused() {
        // Frame header: magic, FHD 0 (window descriptor present, no
        // checksum), window descriptor for 16 MiB (exponent 14, mantissa 0).
        let mut f = 0xfd2f_b528u32.to_le_bytes().to_vec();
        f.extend_from_slice(&[0x00, 14 << 3]);
        // A last, empty raw block.
        f.extend_from_slice(&[0x01, 0x00, 0x00]);
        invalid(decode(&[Coding::Zstd], &f, 100));
        // The same frame with an 8 MiB window decodes to nothing.
        f[5] = 13 << 3;
        assert_eq!(decode(&[Coding::Zstd], &f, 100).unwrap(), b"");
    }

    /// Drains `body`: its data frames, then `Err` if it failed.
    async fn drain(mut body: Body) -> (Vec<Vec<u8>>, Result<(), BodyError>) {
        use http_body_util::BodyExt as _;
        let mut frames = Vec::new();
        while let Some(f) = body.frame().await {
            match f {
                Ok(f) => {
                    if let Ok(d) = f.into_data() {
                        frames.push(d.to_vec());
                    }
                }
                Err(e) => return (frames, Err(e)),
            }
        }
        (frames, Ok(()))
    }

    #[tokio::test]
    async fn a_decoded_body_streams_in_bounded_frames() {
        let body = vec![b'x'; 1 << 20];
        let enc = gzip(&body);
        let (mut tx, inner) = Body::channel(u64::MAX, None);
        tokio::spawn(async move {
            for piece in enc.chunks(100) {
                tx.ready().await.unwrap();
                tx.try_push(Bytes::copy_from_slice(piece)).unwrap();
            }
            tx.ready().await.unwrap();
            tx.try_finish().unwrap();
        });
        let (frames, end) = drain(decode_body(inner, &[Coding::Gzip], u64::MAX, unmetered())).await;
        end.unwrap();
        assert!(frames.iter().all(|f| f.len() <= FRAME_CHUNK));
        assert_eq!(frames.concat(), body);
    }

    #[tokio::test]
    async fn a_decoded_body_fails_rather_than_ending_short() {
        let mut enc = gzip(b"payload");
        enc.truncate(enc.len() - 1);
        let (_, end) = drain(decode_body(
            Body::from_bytes(enc),
            &[Coding::Gzip],
            100,
            unmetered(),
        ))
        .await;
        assert!(matches!(end, Err(BodyError::Undecodable(_))), "{end:?}");

        let enc = gzip(&vec![0u8; 1 << 20]);
        let (_, end) = drain(decode_body(
            Body::from_bytes(enc),
            &[Coding::Gzip],
            1000,
            unmetered(),
        ))
        .await;
        assert_eq!(end, Err(BodyError::TooLarge { limit: 1000 }));
    }

    #[test]
    fn content_codings_parse() {
        let h = |vals: &[&str]| {
            let mut h = Headers::new();
            for v in vals {
                h.append("content-encoding", v).unwrap();
            }
            content_codings(&h)
        };
        assert_eq!(h(&[]).unwrap(), vec![]);
        assert_eq!(h(&["identity"]).unwrap(), vec![]);
        assert_eq!(h(&["GZIP"]).unwrap(), vec![Coding::Gzip]);
        assert_eq!(h(&["x-gzip, br"]).unwrap(), vec![Coding::Gzip, Coding::Br]);
        assert_eq!(
            h(&["deflate", " , zstd"]).unwrap(),
            vec![Coding::Deflate, Coding::Zstd]
        );
        assert_eq!(
            h(&["compress"]).unwrap_err(),
            DecodeError::Unsupported("compress".into())
        );
        assert!(h(&["gzip, gzip, gzip, gzip, gzip"]).is_err());
    }

    /// The cap counts codings across every `content-encoding` field, not
    /// per field; `identity` and empty elements never count.
    #[test]
    fn content_codings_cap_spans_fields() {
        let h = |vals: &[&str]| {
            let mut h = Headers::new();
            for v in vals {
                h.append("content-encoding", v).unwrap();
            }
            content_codings(&h)
        };
        let four = vec![Coding::Gzip, Coding::Br, Coding::Deflate, Coding::Zstd];
        assert_eq!(h(&["gzip, br", "deflate, zstd"]).unwrap(), four);
        assert_eq!(
            h(&["gzip", "br", "deflate", "identity, , zstd", "identity"]).unwrap(),
            four
        );
        assert_eq!(
            h(&["gzip, br", "deflate, zstd", "gzip"]).unwrap_err(),
            DecodeError::Unsupported(format!("more than {MAX_CODINGS} codings"))
        );
        assert_eq!(
            h(&["gzip", "br", "deflate", "zstd", "br"]).unwrap_err(),
            DecodeError::Unsupported(format!("more than {MAX_CODINGS} codings"))
        );
    }

    #[test]
    fn content_codings_unreadable_value_is_not_identity() {
        let obs = crate::HttpFlags {
            allow_obs_text: true,
            ..crate::HttpFlags::default()
        };
        let h = Headers::try_from_raw(
            [(&b"content-encoding"[..], &b"gz\xffip"[..])],
            &crate::Limits::default(),
            &obs,
        )
        .unwrap();
        assert!(matches!(
            content_codings(&h).unwrap_err(),
            DecodeError::Unsupported(_)
        ));
    }
}
