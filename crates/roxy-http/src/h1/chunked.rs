//! Strict chunked transfer-coding decoder (RFC 9112 §7.1 with the
//! restrictions in docs/http.md#body). Pure state machine over a `BytesMut` (fuzz target).

use bytes::{Buf, Bytes, BytesMut};
use http::{HeaderMap, HeaderName};

use crate::chars::{hex_val, is_field_value_byte, is_token};
use crate::model::{HttpFlags, Limits, ParseError, Reason, is_reserved, reject, validate_value};

/// Longest chunk-size line accepted without extensions (16 hex digits).
const MAX_SIZE_LINE: usize = 16;
/// Longest chunk-size line accepted when extensions are allowed.
const MAX_EXT_LINE: usize = 4096;

/// Trailer fields that are never accepted even with `http.allow_trailers`
/// (framing, routing, authentication and content metadata; RFC 9110 §6.5.1).
const FORBIDDEN_TRAILERS: &[&str] = &[
    "authorization",
    "cookie",
    "set-cookie",
    "content-type",
    "content-encoding",
    "content-range",
    "expect",
    "range",
    "max-forwards",
    "cache-control",
];

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
    max_body: u64,
    max_trailer_bytes: usize,
    max_headers: usize,
    allow_ext: bool,
    allow_trailers: bool,
    allow_obs_text: bool,
}

impl ChunkedDecoder {
    /// A decoder enforcing `limits.max_request_body_bytes` and the `http.*`
    /// flags.
    pub fn new(limits: &Limits, flags: &HttpFlags) -> Self {
        Self {
            state: State::Size,
            total: 0,
            max_body: limits.max_request_body_bytes,
            max_trailer_bytes: limits.max_header_bytes,
            max_headers: limits.max_headers,
            allow_ext: flags.allow_chunk_extensions,
            allow_trailers: flags.allow_trailers,
            allow_obs_text: flags.allow_obs_text,
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
                    self.total = match self.total.checked_add(size) {
                        Some(t) if t <= self.max_body => t,
                        _ => {
                            return reject(
                                Reason::BodyTooLarge,
                                format!("chunked body exceeds {} bytes", self.max_body),
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
                    let rem = rem - n as u64;
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
                        if !self.allow_trailers {
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
        let max = if self.allow_ext {
            MAX_EXT_LINE
        } else {
            MAX_SIZE_LINE
        };
        let lf = buf.iter().position(|&b| b == b'\n');
        let line_end = lf.unwrap_or(buf.len());
        let line = &buf[..line_end];
        // Bare CR anywhere before the (possible) final CR.
        for (i, &b) in line.iter().enumerate() {
            if b == b'\r' && i + 1 < line.len() {
                return reject(Reason::BareCr, "bare CR in chunk-size line");
            }
        }
        let digits = line.iter().take_while(|&&b| hex_val(b).is_some()).count();
        let after = &line[digits..];
        // Early rejection of malformed prefixes, before the line is complete.
        match after.first() {
            Some(b';') if !self.allow_ext => {
                return reject(Reason::ChunkExtension, "chunk extension");
            }
            None | Some(b'\r' | b';') => {}
            Some(_) => return reject(Reason::BadChunkSize, "invalid chunk size"),
        }
        if digits > MAX_SIZE_LINE {
            return reject(Reason::BadChunkSize, "chunk size longer than 16 hex digits");
        }
        let Some(lf) = lf else {
            if buf.len() > max + 1 {
                return reject(Reason::BadChunkSize, "chunk-size line too long");
            }
            return Ok(None);
        };
        if lf == 0 || buf[lf - 1] != b'\r' {
            return reject(Reason::BareLf, "bare LF in chunk-size line");
        }
        // Same bound as the partial-line check above: line without CRLF <= max.
        if lf > max + 1 {
            return reject(Reason::BadChunkSize, "chunk-size line too long");
        }
        if digits == 0 {
            return reject(Reason::BadChunkSize, "empty chunk size");
        }
        let ext = &line[digits..lf - 1];
        if !ext.is_empty() {
            // allow_ext is true here; extensions are validated and discarded.
            if !ext.iter().all(|&b| is_field_value_byte(b, false)) {
                return reject(Reason::ChunkExtension, "malformed chunk extension");
            }
        }
        let size = line[..digits].iter().fold(0u64, |acc, &b| {
            acc << 4 | u64::from(hex_val(b).unwrap_or(0))
        });
        buf.advance(lf + 1);
        Ok(Some(size))
    }

    /// Parses the trailer section (allowed); `None` if incomplete.
    fn trailers(&self, buf: &mut BytesMut) -> Result<Option<HeaderMap>, ParseError> {
        let mut end = None;
        for i in 0..buf.len() {
            match buf[i] {
                b'\n' if i == 0 || buf[i - 1] != b'\r' => {
                    return reject(Reason::BareLf, "bare LF in trailers");
                }
                b'\n' if i >= 3 && &buf[i - 3..=i] == b"\r\n\r\n" => {
                    end = Some(i + 1);
                    break;
                }
                b'\r' if buf.get(i + 1).is_some_and(|&n| n != b'\n') => {
                    return reject(Reason::BareCr, "bare CR in trailers");
                }
                _ => {}
            }
        }
        let Some(end) = end else {
            if buf.len() > self.max_trailer_bytes {
                return reject(Reason::HeadTooLarge, "trailer section too large");
            }
            return Ok(None);
        };
        if end > self.max_trailer_bytes {
            return reject(Reason::HeadTooLarge, "trailer section too large");
        }
        let section = buf.split_to(end);
        let body = &section[..end - 4];
        let mut map = HeaderMap::new();
        for (count, line) in body.split(|&b| b == b'\n').enumerate() {
            if count >= self.max_headers {
                return reject(Reason::TooManyHeaders, "too many trailer fields");
            }
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if matches!(line.first(), Some(b' ' | b'\t')) {
                return reject(Reason::ObsFold, "obs-fold in trailers");
            }
            let Some(colon) = line.iter().position(|&b| b == b':') else {
                return reject(Reason::BadChunkFraming, "malformed trailer line");
            };
            let name = &line[..colon];
            if matches!(name.last(), Some(b' ' | b'\t')) {
                return reject(Reason::WhitespaceBeforeColon, "whitespace before colon");
            }
            if !is_token(name) {
                return reject(Reason::InvalidHeaderName, "invalid trailer name");
            }
            let lname = name.to_ascii_lowercase();
            let lname_str = String::from_utf8_lossy(&lname);
            if is_reserved(&lname_str)
                || FORBIDDEN_TRAILERS.contains(&lname_str.as_ref())
                || lname_str.starts_with("content-")
            {
                return reject(
                    Reason::Trailers,
                    format!("{lname_str} not allowed in trailers"),
                );
            }
            let value = validate_value(&line[colon + 1..], self.allow_obs_text)?;
            let name = HeaderName::from_bytes(&lname)
                .map_err(|_| ParseError::new(Reason::InvalidHeaderName, "invalid trailer name"))?;
            map.append(name, value);
        }
        Ok(Some(map))
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
