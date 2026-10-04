use std::net::{Ipv4Addr, Ipv6Addr};

use proptest::prelude::*;

use super::*;

/// A query for `name` (dotted, no trailing dot) of type `qtype`.
fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&FLAG_RD.to_be_bytes());
    m.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        m.push(u8::try_from(label.len()).unwrap());
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&CLASS_IN.to_be_bytes());
    m
}

fn with_opt(mut m: Vec<u8>, rdata: &[u8]) -> Vec<u8> {
    m[11] = 1;
    m.push(0);
    m.extend_from_slice(&TYPE_OPT.to_be_bytes());
    m.extend_from_slice(&1232u16.to_be_bytes());
    m.extend_from_slice(&[0, 0, 0, 0]);
    m.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
    m.extend_from_slice(rdata);
    m
}

fn parsed_query(m: &[u8]) -> Query {
    match parse(m) {
        Parsed::Query(q) => q,
        other => panic!("expected a query, got {other:?}"),
    }
}

fn rcode_of(m: &[u8]) -> Option<Rcode> {
    match parse(m) {
        Parsed::Error { rcode, .. } => Some(rcode),
        Parsed::Query(_) => Some(Rcode::NoError),
        Parsed::Drop => None,
    }
}

/// The parts of an answer the tests look at.
#[derive(Debug, PartialEq, Eq)]
struct Reply {
    id: u16,
    rcode: u8,
    question: Vec<u8>,
    records: Vec<(u16, u32, Vec<u8>)>,
}

fn read_reply(m: &[u8]) -> Reply {
    assert!(m.len() <= MAX_UDP_PAYLOAD);
    let flags = u16::from_be_bytes([m[2], m[3]]);
    assert_ne!(flags & FLAG_QR, 0, "QR set");
    let qd = u16::from_be_bytes([m[4], m[5]]);
    let an = u16::from_be_bytes([m[6], m[7]]);
    let mut at = HEADER;
    let mut question = Vec::new();
    if qd == 1 {
        let (_, end) = read_name(m, at).unwrap();
        question = m[at..end + 4].to_vec();
        at = end + 4;
    }
    let mut records = Vec::new();
    for _ in 0..an {
        assert_eq!(&m[at..at + 2], &[0xc0, 0x0c]);
        let ty = u16::from_be_bytes([m[at + 2], m[at + 3]]);
        let ttl = u32::from_be_bytes([m[at + 6], m[at + 7], m[at + 8], m[at + 9]]);
        let len = usize::from(u16::from_be_bytes([m[at + 10], m[at + 11]]));
        records.push((ty, ttl, m[at + 12..at + 12 + len].to_vec()));
        at += 12 + len;
    }
    assert_eq!(at, m.len(), "no trailing bytes");
    Reply {
        id: u16::from_be_bytes([m[0], m[1]]),
        rcode: u8::try_from(flags & 0xf).unwrap(),
        question,
        records,
    }
}

const V4: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 16, 0, 2));
const V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0xfd00, 0x16, 0, 0, 0, 0, 0, 2));

#[test]
fn a_query_gets_the_ipv4_address() {
    let q = parsed_query(&query(0x1234, "Example.COM", TYPE_A));
    assert_eq!(q.name, "example.com");
    assert_eq!(q.qtype, TYPE_A);
    assert!(q.rd);
    let r = read_reply(&answer(&q, &[V4, V6], 60));
    assert_eq!(r.id, 0x1234);
    assert_eq!(r.rcode, 0);
    assert_eq!(r.records, vec![(TYPE_A, 60, vec![10, 16, 0, 2])]);
}

#[test]
fn the_question_is_echoed_with_its_case() {
    let m = query(7, "ExAmPlE.com", TYPE_A);
    let q = parsed_query(&m);
    let r = read_reply(&answer(&q, &[V4], 60));
    assert_eq!(r.question, m[HEADER..].to_vec());
}

#[test]
fn aaaa_gets_the_ipv6_address_or_nodata() {
    let q = parsed_query(&query(1, "example.com", TYPE_AAAA));
    let r = read_reply(&answer(&q, &[V4, V6], 30));
    assert_eq!(r.records.len(), 1);
    assert_eq!(r.records[0].0, TYPE_AAAA);
    assert_eq!(r.records[0].2.len(), 16);
    let r = read_reply(&answer(&q, &[V4], 30));
    assert_eq!(r.rcode, 0);
    assert_eq!(r.records, Vec::new());
}

#[test]
fn other_types_get_nodata() {
    // HTTPS (65) would carry ECH configs and alternative endpoints.
    for ty in [65, 64, 15, 16, 255] {
        let q = parsed_query(&query(1, "example.com", ty));
        let r = read_reply(&answer(&q, &[V4, V6], 30));
        assert_eq!(r.rcode, 0);
        assert!(r.records.is_empty(), "type {ty}");
    }
}

#[test]
fn answers_never_exceed_512_bytes() {
    let long = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61),
    ]
    .join(".");
    let q = parsed_query(&query(1, &long, TYPE_AAAA));
    let many: Vec<IpAddr> = (0..64u16)
        .map(|i| IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, i)))
        .collect();
    let m = answer(&q, &many, 1);
    let r = read_reply(&m);
    assert_ne!(r.records, Vec::new());
    assert!(m.len() <= MAX_UDP_PAYLOAD);
}

#[test]
fn edns_opt_is_accepted_and_ignored() {
    let q = parsed_query(&with_opt(
        query(9, "example.com", TYPE_A),
        &[0, 10, 0, 2, 1, 2],
    ));
    assert_eq!(q.name, "example.com");
    // The OPT record is not echoed.
    assert_eq!(
        q.question,
        query(9, "example.com", TYPE_A)[HEADER..].to_vec()
    );
}

#[test]
fn malformed_queries_get_formerr() {
    let good = query(1, "example.com", TYPE_A);
    let mut two_questions = good.clone();
    two_questions[5] = 2;
    let mut an = good.clone();
    an[7] = 1;
    let mut ns = good.clone();
    ns[9] = 1;
    let mut ar_two = good.clone();
    ar_two[11] = 2;
    let mut ar_not_opt = good.clone();
    ar_not_opt[11] = 1;
    ar_not_opt.extend_from_slice(&[0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
    let mut trailing = good.clone();
    trailing.push(0);
    let mut opt_short = with_opt(good.clone(), &[1, 2, 3]);
    opt_short.pop();
    let mut pointer = good[..HEADER].to_vec();
    pointer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
    let mut extended = good[..HEADER].to_vec();
    extended.extend_from_slice(&[0x41, b'a', 0, 0, 1, 0, 1]);
    let mut no_fixed = good.clone();
    no_fixed.truncate(good.len() - 2);
    let mut cut_label = good[..HEADER].to_vec();
    cut_label.extend_from_slice(&[5, b'a', b'b']);
    let mut zero_questions = good[..HEADER].to_vec();
    zero_questions[5] = 0;
    for (what, m) in [
        ("two questions", two_questions),
        ("an answer record", an),
        ("an authority record", ns),
        ("two additional records", ar_two),
        ("a non-OPT additional record", ar_not_opt),
        ("a trailing byte", trailing),
        ("a cut OPT record", opt_short),
        ("a compression pointer", pointer),
        ("an extended label", extended),
        ("no type and class", no_fixed),
        ("a cut label", cut_label),
        ("no question", zero_questions),
    ] {
        assert_eq!(rcode_of(&m), Some(Rcode::FormErr), "{what}");
    }
}

#[test]
fn a_name_over_255_bytes_is_formerr() {
    let ok = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61),
    ]
    .join(".");
    assert_eq!(rcode_of(&query(1, &ok, TYPE_A)), Some(Rcode::NoError));
    let long = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(62),
    ]
    .join(".");
    assert_eq!(rcode_of(&query(1, &long, TYPE_A)), Some(Rcode::FormErr));
}

#[test]
fn unanswerable_names_and_classes_are_refused() {
    let mut chaos = query(1, "version.bind", 16);
    let n = chaos.len();
    chaos[n - 1] = 3;
    assert_eq!(rcode_of(&chaos), Some(Rcode::Refused));
    let mut root = query(1, "x", TYPE_A)[..HEADER].to_vec();
    root.extend_from_slice(&[0, 0, 1, 0, 1]);
    assert_eq!(rcode_of(&root), Some(Rcode::Refused));
    for bad in [
        "exa mple.com",
        "exa\u{0}mple.com",
        "a*.example.com",
        "exämple.com",
    ] {
        assert_eq!(
            rcode_of(&query(1, bad, TYPE_A)),
            Some(Rcode::Refused),
            "{bad:?}"
        );
    }
    assert_eq!(
        rcode_of(&query(1, "_dmarc.ex-ample.com", TYPE_A)),
        Some(Rcode::NoError)
    );
}

#[test]
fn other_opcodes_get_notimp() {
    let mut m = query(5, "example.com", TYPE_A);
    m[2] |= 2 << 3; // STATUS
    let Parsed::Error {
        id,
        opcode,
        rd,
        rcode,
    } = parse(&m)
    else {
        panic!("expected an error");
    };
    assert_eq!((id, opcode, rd, rcode), (5, 2, true, Rcode::NotImp));
    let r = read_reply(&error(id, opcode, rd, rcode));
    assert_eq!(r.id, 5);
    assert_eq!(r.rcode, 4);
    assert_eq!(r.question, Vec::<u8>::new());
}

#[test]
fn responses_and_runts_are_dropped() {
    let mut response = query(1, "example.com", TYPE_A);
    response[2] |= 0x80;
    assert_eq!(parse(&response), Parsed::Drop);
    assert_eq!(parse(&[0; 11]), Parsed::Drop);
    assert_eq!(parse(&[]), Parsed::Drop);
    // Our own answers are responses, so two roxies cannot loop.
    let q = parsed_query(&query(1, "example.com", TYPE_A));
    assert_eq!(parse(&answer(&q, &[V4], 1)), Parsed::Drop);
}

proptest! {
    #[test]
    fn parse_never_panics_and_answers_are_well_formed(
        bytes in proptest::collection::vec(any::<u8>(), 0..600),
    ) {
        match parse(&bytes) {
            Parsed::Query(q) => {
                let r = read_reply(&answer(&q, &[V4, V6], 5));
                prop_assert_eq!(r.id, q.id);
                prop_assert!(!q.name.is_empty());
                prop_assert_eq!(q.name.to_ascii_lowercase(), q.name.clone());
            }
            Parsed::Error { id, opcode, rd, rcode } => {
                let r = read_reply(&error(id, opcode, rd, rcode));
                prop_assert_eq!(r.id, id);
            }
            Parsed::Drop => {}
        }
    }

    #[test]
    fn valid_names_round_trip(
        labels in proptest::collection::vec("[a-zA-Z0-9_-]{1,20}", 1..8),
        qtype in any::<u16>(),
    ) {
        let name = labels.join(".");
        let q = parsed_query(&query(3, &name, qtype));
        prop_assert_eq!(&q.name, &name.to_ascii_lowercase());
        prop_assert_eq!(q.qtype, qtype);
    }
}
