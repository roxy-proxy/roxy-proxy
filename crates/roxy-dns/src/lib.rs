//! The DNS wire codec behind roxy's DNS listener.
//!
//! Pure functions over bytes, no I/O, so it can be fuzzed directly. The
//! listener needs very little of DNS: it reads one question and answers it
//! from its own configuration, never by asking anyone else. So the parser
//! accepts only that shape, strictly:
//!
//! * a query (`QR` clear) with opcode QUERY;
//! * exactly one question, of class IN, whose name is uncompressed, made of
//!   letters, digits, `-` and `_`, and not the root;
//! * no answer or authority records, and at most one additional record,
//!   which must be an EDNS OPT record (accepted and ignored);
//! * nothing after the last record.
//!
//! Anything else is either dropped ([`Parsed::Drop`]) or answered with an
//! error code and no question ([`Parsed::Error`]). Answers are built by
//! [`answer`] and always fit in [`MAX_UDP_PAYLOAD`] bytes, so nothing is
//! ever truncated.

// Casts go through `From` / `TryFrom`, so a narrowing one cannot slip in.
#![warn(clippy::as_conversions)]
// Length and offset arithmetic on untrusted input is checked, so a broken
// invariant fails the message instead of wrapping.
#![warn(clippy::arithmetic_side_effects)]

use std::net::IpAddr;

/// The classic UDP payload limit (RFC 1035 §2.3.4). Every message
/// [`answer`] and [`error`] build fits in it.
pub const MAX_UDP_PAYLOAD: usize = 512;

/// Longest name on the wire, length octets and root label included
/// (RFC 1035 §2.3.4).
const MAX_WIRE_NAME: usize = 255;
const MAX_LABEL: usize = 63;
const HEADER: usize = 12;

/// `A`.
pub const TYPE_A: u16 = 1;
/// `AAAA`.
pub const TYPE_AAAA: u16 = 28;
const TYPE_OPT: u16 = 41;
const CLASS_IN: u16 = 1;

const FLAG_QR: u16 = 0x8000;
const FLAG_AA: u16 = 0x0400;
const FLAG_RD: u16 = 0x0100;
const FLAG_RA: u16 = 0x0080;
const OPCODE_SHIFT: u16 = 11;
const OPCODE_QUERY: u8 = 0;

/// Response codes roxy sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rcode {
    /// The name exists; the answer may be empty (NODATA).
    NoError,
    /// The query is malformed.
    FormErr,
    /// The opcode is not QUERY.
    NotImp,
    /// A well-formed query roxy will not answer (class, name).
    Refused,
}

impl Rcode {
    /// The wire value.
    pub fn code(self) -> u8 {
        match self {
            Self::NoError => 0,
            Self::FormErr => 1,
            Self::NotImp => 4,
            Self::Refused => 5,
        }
    }

    /// The name used in the flow log.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoError => "noerror",
            Self::FormErr => "formerr",
            Self::NotImp => "notimp",
            Self::Refused => "refused",
        }
    }
}

/// One accepted question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    /// Message id, echoed in the answer.
    pub id: u16,
    /// `RD`, echoed in the answer.
    pub rd: bool,
    /// The name: lower-case, labels joined with `.`, no trailing dot.
    pub name: String,
    /// The question type (`A`, `AAAA`, ...).
    pub qtype: u16,
    /// The question exactly as sent (name, type and class), echoed in the
    /// answer so a resolver that randomises case (DNS 0x20) sees its own
    /// spelling back.
    question: Vec<u8>,
}

impl Query {
    /// The question as sent: name, type and class.
    pub fn question(&self) -> &[u8] {
        &self.question
    }
}

/// The result of [`parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    /// A question to answer with [`answer`].
    Query(Query),
    /// A message to answer with [`error`]: the header could be read, the
    /// rest could not be accepted.
    Error {
        /// Message id.
        id: u16,
        /// The query's opcode, echoed.
        opcode: u8,
        /// `RD`, echoed.
        rd: bool,
        /// Why.
        rcode: Rcode,
    },
    /// Not answered: too short to have a header, or not a query at all.
    /// Answering responses could start a loop between two servers.
    Drop,
}

/// Parses one DNS message. Never panics, for any input.
#[must_use]
pub fn parse(msg: &[u8]) -> Parsed {
    let Some(head) = msg.get(..HEADER) else {
        return Parsed::Drop;
    };
    let id = u16::from_be_bytes([head[0], head[1]]);
    let flags = u16::from_be_bytes([head[2], head[3]]);
    if flags & FLAG_QR != 0 {
        return Parsed::Drop;
    }
    // Four bits wide, so it always fits.
    let opcode = u8::try_from((flags >> OPCODE_SHIFT) & 0xf).unwrap_or(u8::MAX);
    let rd = flags & FLAG_RD != 0;
    let err = |rcode| Parsed::Error {
        id,
        opcode,
        rd,
        rcode,
    };
    if opcode != OPCODE_QUERY {
        return err(Rcode::NotImp);
    }
    let mut counts = head[4..].as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes(*c));
    let mut count = || counts.next().unwrap_or(u16::MAX);
    let (qd, an, ns, ar) = (count(), count(), count(), count());
    if qd != 1 || an != 0 || ns != 0 || ar > 1 {
        return err(Rcode::FormErr);
    }
    let Some((name, name_end)) = read_name(msg, HEADER) else {
        return err(Rcode::FormErr);
    };
    let Some(qend) = name_end.checked_add(4) else {
        return err(Rcode::FormErr);
    };
    let Some(fixed) = msg.get(name_end..qend) else {
        return err(Rcode::FormErr);
    };
    let qtype = u16::from_be_bytes([fixed[0], fixed[1]]);
    let qclass = u16::from_be_bytes([fixed[2], fixed[3]]);
    let mut end = qend;
    if ar == 1 {
        match read_opt(msg, end) {
            Some(e) => end = e,
            None => return err(Rcode::FormErr),
        }
    }
    if end != msg.len() {
        return err(Rcode::FormErr);
    }
    let Some(name) = name else {
        return err(Rcode::Refused);
    };
    if qclass != CLASS_IN {
        return err(Rcode::Refused);
    }
    Parsed::Query(Query {
        id,
        rd,
        name,
        qtype,
        question: msg[HEADER..qend].to_vec(),
    })
}

/// Reads an uncompressed name at `at`. `None` if it is malformed;
/// `Some((None, end))` if it is well-formed but not a name roxy answers
/// (the root, or a byte outside letters, digits, `-` and `_`).
fn read_name(msg: &[u8], mut at: usize) -> Option<(Option<String>, usize)> {
    let start = at;
    let mut name = String::new();
    let mut acceptable = true;
    loop {
        let len = usize::from(*msg.get(at)?);
        // 0xc0 is a compression pointer, 0x40 and 0x80 are the obsolete
        // extended label types: none belongs in a question.
        if len > MAX_LABEL {
            return None;
        }
        at = at.checked_add(1)?;
        if len == 0 {
            break;
        }
        let end = at.checked_add(len)?;
        let label = msg.get(at..end)?;
        at = end;
        if at.checked_sub(start)? >= MAX_WIRE_NAME {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        for &b in label {
            if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' {
                name.push(char::from(b.to_ascii_lowercase()));
            } else {
                acceptable = false;
            }
        }
    }
    let name = (acceptable && !name.is_empty()).then_some(name);
    Some((name, at))
}

/// Reads an EDNS OPT record at `at` (RFC 6891 §6.1.2); returns its end.
fn read_opt(msg: &[u8], at: usize) -> Option<usize> {
    let fixed = msg.get(at..at.checked_add(11)?)?;
    // Owner name is the root; type OPT. Class (UDP size), TTL (extended
    // rcode, version, flags) and the options are not used.
    if fixed[0] != 0 || u16::from_be_bytes([fixed[1], fixed[2]]) != TYPE_OPT {
        return None;
    }
    let rdlen = usize::from(u16::from_be_bytes([fixed[9], fixed[10]]));
    let end = at.checked_add(11)?.checked_add(rdlen)?;
    (end <= msg.len()).then_some(end)
}

fn header(id: u16, opcode: u8, rd: bool, aa: bool, rcode: Rcode, qd: u16, an: u16) -> Vec<u8> {
    let mut flags = FLAG_QR | FLAG_RA | (u16::from(opcode & 0xf) << OPCODE_SHIFT);
    if rd {
        flags |= FLAG_RD;
    }
    if aa {
        flags |= FLAG_AA;
    }
    flags |= u16::from(rcode.code());
    let mut out = Vec::with_capacity(MAX_UDP_PAYLOAD);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&qd.to_be_bytes());
    out.extend_from_slice(&an.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out
}

/// The answer to `q`: the addresses in `addrs` of the family `q` asks
/// for (IPv4 for `A`, IPv6 for `AAAA`, none for any other type), each with
/// `ttl` seconds. No matching address is an empty NOERROR answer (NODATA).
/// Addresses that would take the message past [`MAX_UDP_PAYLOAD`] are left
/// out.
#[must_use]
pub fn answer(q: &Query, addrs: &[IpAddr], ttl: u32) -> Vec<u8> {
    let rdata: Vec<Vec<u8>> = addrs
        .iter()
        .filter_map(|ip| match (q.qtype, ip) {
            (TYPE_A, IpAddr::V4(v4)) => Some(v4.octets().to_vec()),
            (TYPE_AAAA, IpAddr::V6(v6)) => Some(v6.octets().to_vec()),
            _ => None,
        })
        .collect();
    // Owner (a pointer to the question name), type, class, TTL, length.
    let fixed = 2 + 2 + 2 + 4 + 2;
    let room = MAX_UDP_PAYLOAD
        .saturating_sub(HEADER)
        .saturating_sub(q.question.len());
    let fits = rdata
        .iter()
        .scan(0usize, |used, r| {
            *used = used.saturating_add(fixed).saturating_add(r.len());
            Some(*used)
        })
        .take_while(|used| *used <= room)
        .count();
    let rdata = &rdata[..fits];
    let an = u16::try_from(rdata.len()).unwrap_or(0);
    let mut out = header(q.id, OPCODE_QUERY, q.rd, true, Rcode::NoError, 1, an);
    out.extend_from_slice(&q.question);
    for r in rdata {
        // The question name always starts right after the header.
        out.extend_from_slice(&[0xc0, 0x0c]);
        out.extend_from_slice(&q.qtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&u16::try_from(r.len()).unwrap_or(0).to_be_bytes());
        out.extend_from_slice(r);
    }
    out
}

/// The answer to a [`Parsed::Error`]: the header alone, no question.
#[must_use]
pub fn error(id: u16, opcode: u8, rd: bool, rcode: Rcode) -> Vec<u8> {
    header(id, opcode, rd, false, rcode, 0, 0)
}

#[cfg(test)]
mod tests;
