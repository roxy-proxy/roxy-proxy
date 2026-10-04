//! WebSocket frame codec (RFC 6455 §5) for message rules
//! (docs/websockets.md#message-rules).
//!
//! [`Decoder`] is sans-IO and resumable: feed it bytes as they arrive and it
//! yields whole messages. A data message is reassembled from its fragments;
//! a control frame is a message of its own, even in the middle of a
//! fragmented one. [`encode`] writes a message back as one unfragmented
//! frame, so what leaves roxy is the canonical form of what was checked.
//!
//! Strictness: no extension is ever negotiated on a parsed WebSocket, so
//! the RSV bits must be zero. Lengths must use the minimal encoding. Client
//! frames must be masked and server frames must not be. Anything else is a
//! protocol error, and errors are sticky: a decoder that failed never
//! yields again.

use thiserror::Error;

/// Close codes roxy sends (RFC 6455 §7.4.1).
pub mod close {
    /// The peer broke the protocol.
    pub const PROTOCOL_ERROR: u16 = 1002;
    /// A text message (or close reason) that is not UTF-8.
    pub const INVALID_DATA: u16 = 1007;
    /// A rule denied the WebSocket.
    pub const POLICY: u16 = 1008;
    /// A message over `limits.max_ws_message_bytes`.
    pub const TOO_BIG: u16 = 1009;
}

/// Largest control frame payload (RFC 6455 §5.5).
const MAX_CONTROL: u64 = 125;

/// Who sent the frames a [`Decoder`] reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Peer {
    /// Client frames: always masked.
    Client,
    /// Server frames: never masked.
    Server,
}

/// A message opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

impl Opcode {
    /// The wire value (`ws.opcode`).
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Text => 1,
            Self::Binary => 2,
            Self::Close => 8,
            Self::Ping => 9,
            Self::Pong => 10,
        }
    }

    fn is_control(self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }
}

/// A whole message: a reassembled data message or one control frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub opcode: Opcode,
    pub data: Data,
}

/// A message payload, unmasked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Data {
    /// A text message, validated as UTF-8.
    Text(String),
    /// Anything else, a close frame's code and reason included.
    Bytes(Vec<u8>),
}

impl Message {
    pub fn payload(&self) -> &[u8] {
        match &self.data {
            Data::Text(s) => s.as_bytes(),
            Data::Bytes(b) => b,
        }
    }

    pub fn len(&self) -> usize {
        self.payload().len()
    }

    pub fn is_empty(&self) -> bool {
        self.payload().is_empty()
    }

    /// The text of a text message.
    pub fn text(&self) -> Option<&str> {
        match &self.data {
            Data::Text(s) => Some(s),
            Data::Bytes(_) => None,
        }
    }
}

/// Why a stream of frames was refused, with the close code to send.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("websocket {code}: {detail}")]
pub struct FrameError {
    pub code: u16,
    pub detail: &'static str,
}

fn fail<T>(code: u16, detail: &'static str) -> Result<T, FrameError> {
    Err(FrameError { code, detail })
}

/// The frame whose payload is being read.
#[derive(Debug)]
struct Frame {
    fin: bool,
    /// `None` for a continuation frame.
    opcode: Option<Opcode>,
    mask: Option<[u8; 4]>,
    remaining: u64,
    /// Payload bytes read so far (the mask offset).
    read: u64,
}

/// Resumable decoder for one direction of a WebSocket.
#[derive(Debug)]
pub struct Decoder {
    from: Peer,
    max_message: u64,
    head: [u8; 14],
    head_len: usize,
    frame: Option<Frame>,
    /// The data message being reassembled.
    partial: Option<(Opcode, Vec<u8>)>,
    /// The control frame being read.
    control: Vec<u8>,
    /// A close frame was decoded: nothing may follow it.
    closed: bool,
    failed: Option<FrameError>,
}

impl Decoder {
    /// A decoder for frames sent by `from`, refusing data messages larger
    /// than `max_message` bytes.
    pub fn new(from: Peer, max_message: u64) -> Self {
        Self {
            from,
            max_message,
            head: [0; 14],
            head_len: 0,
            frame: None,
            partial: None,
            control: Vec::new(),
            closed: false,
            failed: None,
        }
    }

    /// Consumes bytes from `input` until a whole message is decoded or
    /// `input` is empty (`Ok(None)`: feed more). Call again with the rest
    /// of `input` after a message.
    pub fn decode(&mut self, input: &mut &[u8]) -> Result<Option<Message>, FrameError> {
        if let Some(e) = &self.failed {
            return Err(e.clone());
        }
        let r = self.step(input);
        if let Err(e) = &r {
            self.failed = Some(e.clone());
        }
        r
    }

    fn step(&mut self, input: &mut &[u8]) -> Result<Option<Message>, FrameError> {
        loop {
            if self.frame.is_none() {
                if input.is_empty() {
                    return Ok(None);
                }
                if self.closed {
                    return fail(close::PROTOCOL_ERROR, "frame after close");
                }
                let need = self.head_needed();
                let k = (need - self.head_len).min(input.len());
                self.head[self.head_len..self.head_len + k].copy_from_slice(&input[..k]);
                self.head_len += k;
                *input = &input[k..];
                // The first two bytes decide the header length.
                if self.head_len < self.head_needed() {
                    continue;
                }
                self.start_frame()?;
            }
            let Some(f) = self.frame.as_mut() else {
                continue;
            };
            let k = usize::try_from(f.remaining)
                .unwrap_or(usize::MAX)
                .min(input.len());
            let buf = if f.opcode.is_some_and(Opcode::is_control) {
                &mut self.control
            } else {
                match self.partial.as_mut() {
                    Some((_, b)) => b,
                    None => return fail(close::PROTOCOL_ERROR, "continuation without a message"),
                }
            };
            let start = buf.len();
            buf.extend_from_slice(&input[..k]);
            if let Some(m) = f.mask {
                let off = usize::try_from(f.read % 4).unwrap_or(0);
                for (i, b) in buf[start..].iter_mut().enumerate() {
                    *b ^= m[(off + i) % 4];
                }
            }
            *input = &input[k..];
            f.read += k as u64;
            f.remaining -= k as u64;
            if f.remaining > 0 {
                return Ok(None);
            }
            if let Some(msg) = self.end_frame()? {
                return Ok(Some(msg));
            }
        }
    }

    /// Header bytes needed, as far as the bytes so far tell.
    fn head_needed(&self) -> usize {
        if self.head_len < 2 {
            return 2;
        }
        let ext = match self.head[1] & 0x7f {
            126 => 2,
            127 => 8,
            _ => 0,
        };
        let mask = if self.head[1] & 0x80 == 0 { 0 } else { 4 };
        2 + ext + mask
    }

    fn start_frame(&mut self) -> Result<(), FrameError> {
        let h = &self.head[..self.head_len];
        self.head_len = 0;
        let fin = h[0] & 0x80 != 0;
        if h[0] & 0x70 != 0 {
            return fail(close::PROTOCOL_ERROR, "reserved bits set");
        }
        let opcode = match h[0] & 0x0f {
            0 => None,
            1 => Some(Opcode::Text),
            2 => Some(Opcode::Binary),
            8 => Some(Opcode::Close),
            9 => Some(Opcode::Ping),
            10 => Some(Opcode::Pong),
            _ => return fail(close::PROTOCOL_ERROR, "unknown opcode"),
        };
        let masked = h[1] & 0x80 != 0;
        if masked != (self.from == Peer::Client) {
            return fail(
                close::PROTOCOL_ERROR,
                if masked {
                    "masked server frame"
                } else {
                    "unmasked client frame"
                },
            );
        }
        let (len, rest) = match h[1] & 0x7f {
            126 => {
                let n = u64::from(u16::from_be_bytes([h[2], h[3]]));
                if n < 126 {
                    return fail(close::PROTOCOL_ERROR, "non-minimal length");
                }
                (n, &h[4..])
            }
            127 => {
                let mut b = [0u8; 8];
                b.copy_from_slice(&h[2..10]);
                let n = u64::from_be_bytes(b);
                if n >> 63 != 0 {
                    return fail(close::PROTOCOL_ERROR, "length with the top bit set");
                }
                if n <= 0xffff {
                    return fail(close::PROTOCOL_ERROR, "non-minimal length");
                }
                (n, &h[10..])
            }
            n => (u64::from(n), &h[2..]),
        };
        let mask = masked.then(|| [rest[0], rest[1], rest[2], rest[3]]);
        match opcode {
            Some(op) if op.is_control() => {
                if !fin {
                    return fail(close::PROTOCOL_ERROR, "fragmented control frame");
                }
                if len > MAX_CONTROL {
                    return fail(close::PROTOCOL_ERROR, "control frame over 125 bytes");
                }
            }
            Some(op) => {
                if self.partial.is_some() {
                    return fail(
                        close::PROTOCOL_ERROR,
                        "new message before the previous one ended",
                    );
                }
                if len > self.max_message {
                    return fail(close::TOO_BIG, "message too big");
                }
                self.partial = Some((op, Vec::new()));
            }
            None => {
                let Some((_, b)) = &self.partial else {
                    return fail(close::PROTOCOL_ERROR, "continuation without a message");
                };
                if (b.len() as u64).saturating_add(len) > self.max_message {
                    return fail(close::TOO_BIG, "message too big");
                }
            }
        }
        self.frame = Some(Frame {
            fin,
            opcode,
            mask,
            remaining: len,
            read: 0,
        });
        Ok(())
    }

    /// The current frame's payload is complete.
    fn end_frame(&mut self) -> Result<Option<Message>, FrameError> {
        let Some(f) = self.frame.take() else {
            return Ok(None);
        };
        if let Some(op) = f.opcode.filter(|op| op.is_control()) {
            let payload = std::mem::take(&mut self.control);
            if op == Opcode::Close {
                check_close(&payload)?;
                self.closed = true;
            }
            return Ok(Some(Message {
                opcode: op,
                data: Data::Bytes(payload),
            }));
        }
        if !f.fin {
            return Ok(None);
        }
        let Some((op, payload)) = self.partial.take() else {
            return fail(close::PROTOCOL_ERROR, "continuation without a message");
        };
        let data = if op == Opcode::Text {
            match String::from_utf8(payload) {
                Ok(s) => Data::Text(s),
                Err(_) => return fail(close::INVALID_DATA, "text message is not UTF-8"),
            }
        } else {
            Data::Bytes(payload)
        };
        Ok(Some(Message { opcode: op, data }))
    }
}

/// A close frame's payload: empty, or a valid code and a UTF-8 reason
/// (RFC 6455 §5.5.1, §7.4).
fn check_close(p: &[u8]) -> Result<(), FrameError> {
    match p {
        [] => Ok(()),
        [_] => fail(close::PROTOCOL_ERROR, "close payload of one byte"),
        [a, b, reason @ ..] => {
            let code = u16::from_be_bytes([*a, *b]);
            let valid = matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999);
            if !valid {
                return fail(close::PROTOCOL_ERROR, "invalid close code");
            }
            if std::str::from_utf8(reason).is_err() {
                return fail(close::INVALID_DATA, "close reason is not UTF-8");
            }
            Ok(())
        }
    }
}

/// Appends `payload` to `out` as one unfragmented frame, masked with `mask`
/// when given (frames toward a server must be).
pub fn encode(opcode: Opcode, payload: &[u8], mask: Option<[u8; 4]>, out: &mut Vec<u8>) {
    out.push(0x80 | opcode.as_u8());
    let m = if mask.is_some() { 0x80 } else { 0 };
    match payload.len() {
        n @ 0..=125 => out.push(m | u8::try_from(n).unwrap_or(125)),
        n @ 126..=0xffff => {
            out.push(m | 0x7e);
            out.extend_from_slice(&u16::try_from(n).unwrap_or(u16::MAX).to_be_bytes());
        }
        n => {
            out.push(m | 0x7f);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    match mask {
        Some(k) => {
            out.extend_from_slice(&k);
            out.extend(payload.iter().zip(k.iter().cycle()).map(|(b, k)| b ^ k));
        }
        None => out.extend_from_slice(payload),
    }
}

/// A close frame carrying `code` and no reason.
pub fn encode_close(code: u16, mask: Option<[u8; 4]>, out: &mut Vec<u8>) {
    encode(Opcode::Close, &code.to_be_bytes(), mask, out);
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX: u64 = 1024;
    const KEY: [u8; 4] = [0x37, 0xfa, 0x21, 0x3d];

    fn frame(fin: bool, op: u8, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
        let mut out = Vec::new();
        let opcode = match op {
            1 => Opcode::Text,
            8 => Opcode::Close,
            9 => Opcode::Ping,
            10 => Opcode::Pong,
            _ => Opcode::Binary,
        };
        encode(opcode, payload, mask, &mut out);
        out[0] = u8::from(fin) << 7 | op;
        out
    }

    fn all(from: Peer, mut input: &[u8]) -> Result<Vec<Message>, FrameError> {
        let mut d = Decoder::new(from, MAX);
        let mut out = Vec::new();
        while let Some(m) = d.decode(&mut input)? {
            out.push(m);
        }
        assert_eq!(input, &[] as &[u8]);
        Ok(out)
    }

    fn bytewise(from: Peer, input: &[u8]) -> Result<Vec<Message>, FrameError> {
        let mut d = Decoder::new(from, MAX);
        let mut out = Vec::new();
        for b in input {
            let mut one = std::slice::from_ref(b);
            while let Some(m) = d.decode(&mut one)? {
                out.push(m);
            }
        }
        Ok(out)
    }

    fn err(from: Peer, input: &[u8]) -> FrameError {
        all(from, input).unwrap_err()
    }

    #[test]
    fn rfc6455_examples() {
        // §5.7: a single-frame unmasked text message, then a masked one.
        let hello = b"\x81\x05\x48\x65\x6c\x6c\x6f";
        let m = all(Peer::Server, hello).unwrap();
        assert_eq!(m[0].text(), Some("Hello"));
        let masked = b"\x81\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58";
        let m = all(Peer::Client, masked).unwrap();
        assert_eq!(m[0].text(), Some("Hello"));
        // A fragmented unmasked text message.
        let m = all(Peer::Server, b"\x01\x03\x48\x65\x6c\x80\x02\x6c\x6f").unwrap();
        assert_eq!(
            m,
            vec![Message {
                opcode: Opcode::Text,
                data: Data::Text("Hello".into())
            }]
        );
        // Ping, and a 256-byte binary message with a 16-bit length.
        let m = all(Peer::Server, b"\x89\x05\x48\x65\x6c\x6c\x6f").unwrap();
        assert_eq!((m[0].opcode, m[0].payload()), (Opcode::Ping, &b"Hello"[..]));
        let mut big = vec![0x82, 0x7e, 0x01, 0x00];
        big.extend(std::iter::repeat_n(7u8, 256));
        assert_eq!(all(Peer::Server, &big).unwrap()[0].len(), 256);
    }

    #[test]
    fn control_frame_inside_a_fragmented_message() {
        let mut input = frame(false, 1, b"He", Some(KEY));
        input.extend(frame(true, 9, b"p", Some(KEY)));
        input.extend(frame(false, 0, b"ll", Some(KEY)));
        input.extend(frame(true, 0, b"o", Some(KEY)));
        let m = all(Peer::Client, &input).unwrap();
        assert_eq!(m.len(), 2);
        assert_eq!((m[0].opcode, m[0].payload()), (Opcode::Ping, &b"p"[..]));
        assert_eq!(m[1].text(), Some("Hello"));
        assert_eq!(bytewise(Peer::Client, &input).unwrap(), m);
    }

    #[test]
    fn protocol_errors() {
        let p = close::PROTOCOL_ERROR;
        let cases: Vec<(Peer, Vec<u8>, u16)> = vec![
            (Peer::Server, b"\xc1\x00".to_vec(), p),           // RSV1
            (Peer::Server, b"\xa1\x00".to_vec(), p),           // RSV2
            (Peer::Server, b"\x83\x00".to_vec(), p),           // opcode 3
            (Peer::Server, b"\x8b\x00".to_vec(), p),           // opcode 11
            (Peer::Client, b"\x81\x00".to_vec(), p),           // unmasked client frame
            (Peer::Server, frame(true, 1, b"", Some(KEY)), p), // masked server frame
            (Peer::Server, b"\x80\x00".to_vec(), p),           // continuation first
            (Peer::Server, b"\x09\x00".to_vec(), p),           // fragmented ping
            (Peer::Server, b"\x01\x00\x81\x00".to_vec(), p),   // new message mid-message
            (Peer::Server, b"\x82\x7e\x00\x05".to_vec(), p),   // non-minimal 16-bit
            (
                Peer::Server,
                b"\x82\x7f\x00\x00\x00\x00\x00\x00\x01\x00".to_vec(),
                p,
            ),
            (
                Peer::Server,
                b"\x82\x7f\x80\x00\x00\x00\x00\x00\x00\x00".to_vec(),
                p,
            ),
            (Peer::Server, b"\x88\x01\x03".to_vec(), p), // one-byte close
            (Peer::Server, b"\x88\x02\x03\xed".to_vec(), p), // close 1005
            (Peer::Server, b"\x88\x02\x0b\xb7".to_vec(), p), // close 2999
            (Peer::Server, b"\x88\x00\x81\x00".to_vec(), p), // frame after close
            (
                Peer::Server,
                b"\x81\x02\xc3\x28".to_vec(),
                close::INVALID_DATA,
            ),
            (
                Peer::Server,
                b"\x88\x04\x03\xe8\xc3\x28".to_vec(),
                close::INVALID_DATA,
            ),
        ];
        for (from, input, code) in cases {
            assert_eq!(err(from, &input).code, code, "{input:02x?}");
            assert_eq!(
                bytewise(from, &input).unwrap_err().code,
                code,
                "{input:02x?}"
            );
        }
        // A 126-byte ping.
        let mut ping = vec![0x89, 0x7e, 0x00, 0x7e];
        ping.extend([0; 126]);
        assert_eq!(err(Peer::Server, &ping).code, p);
    }

    #[test]
    fn text_split_inside_a_code_point_is_fine() {
        let mut input = b"\x01\x01\xc3".to_vec();
        input.extend(b"\x80\x01\xa9");
        assert_eq!(all(Peer::Server, &input).unwrap()[0].text(), Some("é"));
    }

    #[test]
    fn size_limit_counts_the_reassembled_message() {
        let mut input = frame(false, 2, &[0; 1000], None);
        input.extend(frame(true, 0, &[0; 24], None));
        assert_eq!(all(Peer::Server, &input).unwrap()[0].len(), 1024);
        let mut input = frame(false, 2, &[0; 1000], None);
        input.extend(frame(true, 0, &[0; 25], None));
        assert_eq!(err(Peer::Server, &input).code, close::TOO_BIG);
        // Refused at the header, before any payload arrives.
        assert_eq!(
            err(Peer::Server, b"\x82\x7f\x00\x00\x00\x01\x00\x00\x00\x00").code,
            close::TOO_BIG
        );
    }

    #[test]
    fn errors_are_sticky() {
        let mut d = Decoder::new(Peer::Server, MAX);
        let mut bad: &[u8] = b"\x83\x00";
        assert!(d.decode(&mut bad).is_err());
        let mut good: &[u8] = b"\x81\x00";
        assert!(d.decode(&mut good).is_err());
    }

    #[test]
    fn encode_round_trips_at_every_length_boundary() {
        for n in [0usize, 1, 125, 126, 127, 0xffff, 0x1_0000] {
            let payload: Vec<u8> = (0..n).map(|i| u8::try_from(i % 251).unwrap()).collect();
            for (from, mask) in [(Peer::Client, Some(KEY)), (Peer::Server, None)] {
                let mut out = Vec::new();
                encode(Opcode::Binary, &payload, mask, &mut out);
                let mut d = Decoder::new(from, 1 << 20);
                let mut input = &out[..];
                let m = d.decode(&mut input).unwrap().unwrap();
                assert_eq!(m.payload(), &payload[..], "n={n}");
                assert_eq!(input, &[] as &[u8]);
            }
        }
    }

    #[test]
    fn close_frames() {
        let mut out = Vec::new();
        encode_close(close::POLICY, Some(KEY), &mut out);
        let m = all(Peer::Client, &out).unwrap();
        assert_eq!(
            (m[0].opcode, m[0].payload()),
            (Opcode::Close, &[0x03, 0xf0][..])
        );
        let m = all(Peer::Server, b"\x88\x00").unwrap();
        assert!(m[0].is_empty());
        let m = all(Peer::Server, b"\x88\x05\x03\xe8\x62\x79\x65").unwrap();
        assert_eq!(&m[0].payload()[2..], b"bye");
    }
}
