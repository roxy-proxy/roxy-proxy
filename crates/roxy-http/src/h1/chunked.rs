//! Strict chunked transfer-coding decoder (RFC 9112 §7.1 with roxy's
//! restrictions). Pure state machine over a `BytesMut` (fuzz target).

use bytes::{Buf, Bytes, BytesMut};
use http::HeaderMap;

use super::head::{Bare, scan_section};
use crate::chars::{hex_val, is_field_value_byte};
use crate::len_u64;
use crate::model::{
    Headers, HttpFlags, Limits, ParseError, Reason, is_forbidden_trailer, parse_field_line, reject,
};

/// Longest chunk-size line accepted without extensions (16 hex digits).
const MAX_SIZE_LINE: usize = 16;
/// Longest chunk-size line accepted when extensions are allowed.
const MAX_EXT_LINE: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Size,
    Data(u64),
    DataCrlf,
    Trailers,
    Done,
}

/// One decoding step.
#[derive(Debug, PartialEq, Eq)]
pub enum Decoded {
    /// Chunk data (zero-copy split of the input buffer).
    Data(Bytes),
    /// The trailer section (only when trailers are allowed).
    Trailers(HeaderMap),
    /// The body is complete; bytes after it remain in the buffer.
    Done,
    /// Need more input.
    NeedMore,
}

/// Strict chunked decoder.
#[derive(Debug)]
pub struct ChunkedDecoder {
    state: State,
    total: u64,
    limits: Limits,
    flags: HttpFlags,
}

impl ChunkedDecoder {
    /// A decoder enforcing `limits.max_request_body_bytes` and the `http.*`
    /// flags.
    pub fn new(limits: &Limits, flags: &HttpFlags) -> Self {
        Self {
            state: State::Size,
            total: 0,
            limits: limits.clone(),
            flags: flags.clone(),
        }
    }

    /// Decoded body bytes so far.
    pub fn total(&self) -> u64 {
        self.total
    }

    /// Whether the terminating chunk (and trailers) have been consumed.
    pub fn is_done(&self) -> bool {
        self.state == State::Done
    }

    /// Advances the decoder, consuming bytes from `buf`.
    pub fn decode(&mut self, buf: &mut BytesMut) -> Result<Decoded, ParseError> {
        loop {
            match self.state {
                State::Done => return Ok(Decoded::Done),
                State::Size => {
                    let Some(size) = self.size_line(buf)? else {
                        return Ok(Decoded::NeedMore);
                    };
                    let max_body = self.limits.max_request_body_bytes;
                    self.total = match self.total.checked_add(size) {
                        Some(t) if t <= max_body => t,
                        _ => {
                            return reject(
                                Reason::BodyTooLarge,
                                format!("chunked body exceeds {max_body} bytes"),
                            );
                        }
                    };
                    self.state = if size == 0 {
                        State::Trailers
                    } else {
                        State::Data(size)
                    };
                }
                State::Data(rem) => {
                    if buf.is_empty() {
                        return Ok(Decoded::NeedMore);
                    }
                    let n = usize::try_from(rem).unwrap_or(usize::MAX).min(buf.len());
                    let chunk = buf.split_to(n).freeze();
                    let rem = rem.saturating_sub(len_u64(n));
                    self.state = if rem == 0 {
                        State::DataCrlf
                    } else {
                        State::Data(rem)
                    };
                    return Ok(Decoded::Data(chunk));
                }
                State::DataCrlf => match buf.as_ref() {
                    [] | [b'\r'] => return Ok(Decoded::NeedMore),
                    [b'\r', b'\n', ..] => {
                        buf.advance(2);
                        self.state = State::Size;
                    }
                    _ => return reject(Reason::BadChunkFraming, "missing CRLF after chunk data"),
                },
                State::Trailers => match buf.as_ref() {
                    [] | [b'\r'] => return Ok(Decoded::NeedMore),
                    [b'\r', b'\n', ..] => {
                        buf.advance(2);
                        self.state = State::Done;
                        return Ok(Decoded::Done);
                    }
                    [b'\n', ..] => return reject(Reason::BareLf, "bare LF ending chunked body"),
                    [b'\r', _, ..] => return reject(Reason::BareCr, "bare CR ending chunked body"),
                    _ => {
                        if !self.flags.allow_trailers {
                            return reject(Reason::Trailers, "trailer section present");
                        }
                        let Some(map) = self.trailers(buf)? else {
                            return Ok(Decoded::NeedMore);
                        };
                        self.state = State::Done;
                        return Ok(Decoded::Trailers(map));
                    }
                },
            }
        }
    }

    /// Parses a chunk-size line; `None` if incomplete.
    fn size_line(&self, buf: &mut BytesMut) -> Result<Option<u64>, ParseError> {
        let allow_ext = self.flags.allow_chunk_extensions;
        let max = if allow_ext {
            MAX_EXT_LINE
        } else {
            MAX_SIZE_LINE
        };
        let lf = buf.iter().position(|&b| b == b'\n');
        let line_end = lf.unwrap_or(buf.len());
        let line = &buf[..line_end];
        // Bare CR anywhere before the (possible) final CR.
        if line.strip_suffix(b"\r").unwrap_or(line).contains(&b'\r') {
            return reject(Reason::BareCr, "bare CR in chunk-size line");
        }
        let digits = line.iter().take_while(|&&b| hex_val(b).is_some()).count();
        let after = &line[digits..];
        // Early rejection of malformed prefixes, before the line is complete.
        match after.first() {
            Some(b';') if !allow_ext => {
                return reject(Reason::ChunkExtension, "chunk extension");
            }
            None | Some(b'\r' | b';') => {}
            Some(_) => return reject(Reason::BadChunkSize, "invalid chunk size"),
        }
        if digits > MAX_SIZE_LINE {
            return reject(Reason::BadChunkSize, "chunk size longer than 16 hex digits");
        }
        let Some(lf) = lf else {
            if buf.len() > max.saturating_add(1) {
                return reject(Reason::BadChunkSize, "chunk-size line too long");
            }
            return Ok(None);
        };
        let Some(cr) = lf.checked_sub(1).filter(|&cr| buf[cr] == b'\r') else {
            return reject(Reason::BareLf, "bare LF in chunk-size line");
        };
        // Same bound as the partial-line check above: line without CRLF <= max.
        if lf > max.saturating_add(1) {
            return reject(Reason::BadChunkSize, "chunk-size line too long");
        }
        if digits == 0 {
            return reject(Reason::BadChunkSize, "empty chunk size");
        }
        let ext = &line[digits..cr];
        if !ext.is_empty() {
            // allow_ext is true here; extensions are validated and discarded.
            if !ext.iter().all(|&b| is_field_value_byte(b, false)) {
                return reject(Reason::ChunkExtension, "malformed chunk extension");
            }
        }
        // At most 16 hex digits, so the value always fits.
        let Some(size) = str::from_utf8(&line[..digits])
            .ok()
            .and_then(|s| u64::from_str_radix(s, 16).ok())
        else {
            return reject(Reason::BadChunkSize, "invalid chunk size");
        };
        buf.advance(lf.saturating_add(1));
        Ok(Some(size))
    }

    /// Parses the trailer section (allowed); `None` if incomplete. Fields
    /// go through the same line, name, value and count rules as the head,
    /// and forbidden trailer names are refused before that.
    fn trailers(&self, buf: &mut BytesMut) -> Result<Option<HeaderMap>, ParseError> {
        let max_bytes = self.limits.max_header_bytes;
        let end = match scan_section(buf, 0) {
            Err(Bare::Lf(_)) => return reject(Reason::BareLf, "bare LF in trailers"),
            Err(Bare::Cr(_)) => return reject(Reason::BareCr, "bare CR in trailers"),
            Ok(end) => end,
        };
        let Some(end) = end else {
            if buf.len() > max_bytes {
                return reject(Reason::HeadTooLarge, "trailer section too large");
            }
            return Ok(None);
        };
        if end > max_bytes {
            return reject(Reason::HeadTooLarge, "trailer section too large");
        }
        let section = buf.split_to(end);
        let mut raw = Vec::new();
        for line in section
            .strip_suffix(b"\r\n\r\n")
            .unwrap_or(&section)
            .split(|&b| b == b'\n')
        {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let (name, value) = parse_field_line(line, self.flags.allow_obs_text)?;
            let lower = String::from_utf8_lossy(name).to_ascii_lowercase();
            if is_forbidden_trailer(&lower) {
                return reject(Reason::Trailers, format!("{lower} not allowed in trailers"));
            }
            raw.push((name, value));
        }
        let checked = Headers::try_from_raw(raw, &self.limits, &self.flags)?;
        Ok(Some(checked.to_header_map()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(
        input: &[u8],
        flags: &HttpFlags,
    ) -> Result<(Vec<u8>, Option<HeaderMap>, BytesMut), Reason> {
        let mut d = ChunkedDecoder::new(&Limits::default(), flags);
        let mut buf = BytesMut::from(input);
        let mut out = Vec::new();
        let mut trailers = None;
        loop {
            match d.decode(&mut buf).map_err(|e| e.reason)? {
                Decoded::Data(b) => out.extend_from_slice(&b),
                Decoded::Trailers(t) => trailers = Some(t),
                Decoded::Done => return Ok((out, trailers, buf)),
                Decoded::NeedMore => return Err(Reason::UnexpectedEof),
            }
        }
    }

    #[test]
    fn basic() {
        let f = HttpFlags::default();
        let (body, t, rest) = run(b"5\r\nhello\r\nA\r\n0123456789\r\n0\r\n\r\nNEXT", &f).unwrap();
        assert_eq!(body, b"hello0123456789");
        assert!(t.is_none());
        assert_eq!(&rest[..], b"NEXT");
        let (body, _, _) = run(b"000\r\n\r\n", &f).unwrap();
        assert_eq!(body, b"");
    }

    #[test]
    fn byte_at_a_time() {
        let input = b"3\r\nabc\r\n1\r\nd\r\n0\r\n\r\n";
        let mut d = ChunkedDecoder::new(&Limits::default(), &HttpFlags::default());
        let mut buf = BytesMut::new();
        let mut out = Vec::new();
        for &b in input {
            buf.extend_from_slice(&[b]);
            loop {
                match d.decode(&mut buf).unwrap() {
                    Decoded::Data(x) => out.extend_from_slice(&x),
                    Decoded::NeedMore | Decoded::Done => break,
                    Decoded::Trailers(_) => unreachable!(),
                }
            }
        }
        assert!(d.is_done());
        assert_eq!(out, b"abcd");
    }

    #[test]
    fn rejections() {
        let f = HttpFlags::default();
        for (input, r) in [
            (&b"0x5\r\nhello\r\n0\r\n\r\n"[..], Reason::BadChunkSize),
            (b"+5\r\nhello\r\n0\r\n\r\n", Reason::BadChunkSize),
            (b"-5\r\n", Reason::BadChunkSize),
            (b" 5\r\n", Reason::BadChunkSize),
            (b"5 \r\n", Reason::BadChunkSize),
            (b"\r\n", Reason::BadChunkSize),
            (
                b"00000000000000005\r\nhello\r\n0\r\n\r\n",
                Reason::BadChunkSize,
            ),
            (b"5;ext=1\r\nhello\r\n0\r\n\r\n", Reason::ChunkExtension),
            (b"5\nhello\r\n0\r\n\r\n", Reason::BareLf),
            (b"5\r\r\nhello", Reason::BareCr),
            (b"5\r\nhelloXX\r\n", Reason::BadChunkFraming),
            (b"5\r\nhello\n0\r\n\r\n", Reason::BadChunkFraming),
            (b"0\r\nX-T: 1\r\n\r\n", Reason::Trailers),
            (b"0\r\n\n", Reason::BareLf),
            (b"FFFFFFFFFFFFFFFF\r\n", Reason::BodyTooLarge),
        ] {
            assert_eq!(
                run(input, &f).unwrap_err(),
                r,
                "{:?}",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn allowed_extensions_and_trailers() {
        let f = HttpFlags {
            allow_chunk_extensions: true,
            allow_trailers: true,
            ..HttpFlags::default()
        };
        let (body, t, _) = run(b"5;a=b\r\nhello\r\n0\r\nX-Checksum: abc\r\n\r\n", &f).unwrap();
        assert_eq!(body, b"hello");
        assert_eq!(t.unwrap().get("x-checksum").unwrap(), "abc");
        for (input, r) in [
            (&b"0\r\nContent-Length: 5\r\n\r\n"[..], Reason::Trailers),
            (b"0\r\nTransfer-Encoding: chunked\r\n\r\n", Reason::Trailers),
            (b"0\r\nHost: x\r\n\r\n", Reason::Trailers),
            (b"0\r\n x: 1\r\n\r\n", Reason::ObsFold),
            (b"0\r\nx : 1\r\n\r\n", Reason::WhitespaceBeforeColon),
            (b"5;a\x01\r\nhello\r\n0\r\n\r\n", Reason::ChunkExtension),
        ] {
            assert_eq!(
                run(input, &f).unwrap_err(),
                r,
                "{:?}",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn trailer_section_limits() {
        let f = HttpFlags {
            allow_trailers: true,
            ..HttpFlags::default()
        };
        let small = Limits {
            max_header_bytes: 32,
            ..Limits::default()
        };
        let mut d = ChunkedDecoder::new(&small, &f);
        let mut buf =
            BytesMut::from(&b"0\r\nX-Long: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n\r\n"[..]);
        assert_eq!(d.decode(&mut buf).unwrap_err().reason, Reason::HeadTooLarge);
        // The cap applies before the section is complete, so an endless
        // trailer cannot be buffered.
        let mut d = ChunkedDecoder::new(&small, &f);
        let mut buf = BytesMut::from(&b"0\r\nX-Long: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"[..]);
        assert_eq!(d.decode(&mut buf).unwrap_err().reason, Reason::HeadTooLarge);

        let few = Limits {
            max_headers: 1,
            ..Limits::default()
        };
        let mut d = ChunkedDecoder::new(&few, &f);
        let mut buf = BytesMut::from(&b"0\r\nX-A: 1\r\nX-B: 2\r\n\r\n"[..]);
        assert_eq!(
            d.decode(&mut buf).unwrap_err().reason,
            Reason::TooManyHeaders
        );
        let mut d = ChunkedDecoder::new(&few, &f);
        let mut buf = BytesMut::from(&b"0\r\nX-A: 1\r\n\r\n"[..]);
        assert!(matches!(d.decode(&mut buf).unwrap(), Decoded::Trailers(_)));
    }

    #[test]
    fn body_cap() {
        let l = Limits {
            max_request_body_bytes: 8,
            ..Limits::default()
        };
        let mut d = ChunkedDecoder::new(&l, &HttpFlags::default());
        let mut buf = BytesMut::from(&b"5\r\nhello\r\n5\r\nworld\r\n"[..]);
        assert!(matches!(d.decode(&mut buf).unwrap(), Decoded::Data(_)));
        assert_eq!(d.decode(&mut buf).unwrap_err().reason, Reason::BodyTooLarge);
    }
}
