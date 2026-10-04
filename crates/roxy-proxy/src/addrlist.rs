//! Address lists: large, named sets of CIDR ranges used
//! as an unconditional upstream denylist (`upstream.deny_lists`) and as
//! `ip in @name` literals in rules.
//!
//! # Representation
//!
//! Each list is two sorted tables of disjoint CIDR blocks, one for IPv4
//! (`u32` bounds) and one for IPv6 (`u128` bounds). A lookup is one binary
//! search per address form (at most ~20 probes for a million entries) and
//! never allocates.
//!
//! This is used instead of a binary prefix trie because
//! it gives the same guarantees with a fraction of the memory: 8 bytes per
//! IPv4 block and 32 per IPv6 block in two flat `Vec`s, against tens of bytes
//! per *node* (and up to 32/128 nodes per entry) for a pointer trie. Building
//! is one sort plus a linear sweep, and the table is cache-friendly.
//!
//! CIDR blocks either nest or are disjoint, so "merging" duplicates and
//! overlaps means dropping every block contained in another one. Adjacent
//! blocks are *not* coalesced: a hit reports a CIDR that appears verbatim in
//! the list source, which keeps the `matched_cidr` of a flow event greppable.
//!
//! # Address forms
//!
//! A lookup checks every form under which an address could be reached
//! (see [`AddressList::lookup`]): an attacker must not be able to dodge an
//! IPv4 entry by writing the address as IPv4-mapped, IPv4-compatible, NAT64
//! (`64:ff9b::/96`) or 6to4 (`2002::/16`) IPv6. Entries written in the
//! IPv4-mapped form (`::ffff:10.0.0.0/104`) are stored as IPv4.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use crate::addr::reachable_forms;

/// Named lists by name, as held in a policy snapshot.
pub type AddressLists = HashMap<String, Arc<AddressList>>;

/// A malformed list entry.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("address list {list}: line {line}: {entry:?} {reason}")]
pub struct ListError {
    /// The list's name.
    pub list: String,
    /// 1-based line (or, for inline lists, 1-based entry index).
    pub line: usize,
    /// The offending entry, trimmed.
    pub entry: String,
    /// What is wrong with it.
    pub reason: String,
}

/// One block `[start, end]` of a CIDR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Block<T> {
    start: T,
    end: T,
}

/// A compiled address list. Immutable; share it behind an [`Arc`].
#[derive(Clone)]
pub struct AddressList {
    name: String,
    v4: Box<[Block<u32>]>,
    v6: Box<[Block<u128>]>,
}

impl std::fmt::Debug for AddressList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AddressList")
            .field("name", &self.name)
            .field("v4", &self.v4.len())
            .field("v6", &self.v6.len())
            .finish()
    }
}

/// Parses one entry: a CIDR (`10.0.0.0/8`, `2001:db8::/32`) or a bare
/// address (`192.0.2.1`, a /32 or /128). Host bits set in a CIDR
/// (`10.0.0.1/8`) are an error, as in the rule DSL. IPv4-mapped IPv6 CIDRs
/// of at least /96 are returned as the equivalent IPv4 CIDR.
pub fn parse_entry(s: &str) -> Result<IpNet, String> {
    let s = s.trim();
    let net = if s.contains('/') {
        let net: IpNet = s
            .parse()
            .map_err(|_| "is not a valid CIDR (address/prefix-length)".to_owned())?;
        if net.trunc() != net {
            return Err(format!("has host bits set (did you mean {}?)", net.trunc()));
        }
        net
    } else {
        IpNet::from(
            s.parse::<IpAddr>()
                .map_err(|_| "is not an IP address or CIDR".to_owned())?,
        )
    };
    Ok(normalise_net(net))
}

/// `::ffff:a.b.c.d/96+n` → `a.b.c.d/n`.
fn normalise_net(net: IpNet) -> IpNet {
    if let IpNet::V6(v6) = net
        && v6.prefix_len() >= 96
        && let Some(v4) = v6.network().to_ipv4_mapped()
        && let Ok(n) = Ipv4Net::new(v4, v6.prefix_len() - 96)
    {
        return IpNet::V4(n);
    }
    net
}

fn block_v4(n: Ipv4Net) -> Block<u32> {
    Block {
        start: u32::from(n.network()),
        end: u32::from(n.broadcast()),
    }
}

fn block_v6(n: Ipv6Net) -> Block<u128> {
    Block {
        start: u128::from(n.network()),
        end: u128::from(n.broadcast()),
    }
}

/// Sorts and drops blocks contained in an earlier one. CIDR blocks nest or
/// are disjoint, so the result is sorted and disjoint.
fn merge<T: Ord + Copy>(mut blocks: Vec<Block<T>>) -> Box<[Block<T>]> {
    // Widest block first among equal starts, so it absorbs the rest.
    blocks.sort_unstable_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
    let mut out: Vec<Block<T>> = Vec::with_capacity(blocks.len());
    for b in blocks {
        match out.last() {
            Some(last) if b.start <= last.end => {
                debug_assert!(b.end <= last.end, "CIDR blocks nest or are disjoint");
            }
            _ => out.push(b),
        }
    }
    out.into_boxed_slice()
}

fn find<T: Ord + Copy>(blocks: &[Block<T>], x: T) -> Option<Block<T>> {
    let i = blocks.partition_point(|b| b.start <= x);
    let b = *blocks.get(i.checked_sub(1)?)?;
    (x <= b.end).then_some(b)
}

fn net_v4(b: Block<u32>) -> IpNet {
    // For a CIDR block, `end - start` is 2^(32-p) - 1: its one bits count
    // the host bits.
    let host_bits = (b.end - b.start).count_ones();
    #[allow(clippy::cast_possible_truncation)] // host_bits <= 32
    let prefix = 32 - host_bits as u8;
    IpNet::V4(Ipv4Net::new(Ipv4Addr::from(b.start), prefix).expect("prefix <= 32"))
}

fn net_v6(b: Block<u128>) -> IpNet {
    let host_bits = (b.end - b.start).count_ones();
    #[allow(clippy::cast_possible_truncation)] // host_bits <= 128
    let prefix = 128 - host_bits as u8;
    IpNet::V6(Ipv6Net::new(Ipv6Addr::from(b.start), prefix).expect("prefix <= 128"))
}

impl AddressList {
    /// Parses list source text: one CIDR or address per line, `#` starts a
    /// comment (whole-line or trailing), blank lines are ignored and
    /// surrounding whitespace is trimmed. The first malformed line is an
    /// error naming its line number.
    pub fn parse(name: &str, text: &str) -> Result<AddressList, ListError> {
        let mut nets = Vec::new();
        for (i, raw) in text.lines().enumerate() {
            let entry = raw.split('#').next().unwrap_or("").trim();
            if entry.is_empty() {
                continue;
            }
            let net = parse_entry(entry).map_err(|reason| ListError {
                list: name.to_owned(),
                line: i + 1,
                entry: entry.to_owned(),
                reason,
            })?;
            nets.push(net);
        }
        Ok(Self::from_nets(name, nets))
    }

    /// Builds a list from already-parsed networks (inline lists). Host bits
    /// are ignored (each network is truncated).
    pub fn from_nets(name: &str, nets: impl IntoIterator<Item = IpNet>) -> AddressList {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for net in nets {
            match normalise_net(net.trunc()) {
                IpNet::V4(n) => v4.push(block_v4(n)),
                IpNet::V6(n) => v6.push(block_v6(n)),
            }
        }
        AddressList {
            name: name.to_owned(),
            v4: merge(v4),
            v6: merge(v6),
        }
    }

    /// The list's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Entries after merging duplicates and contained ranges.
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    /// Whether the list has no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Approximate heap footprint of the tables, in bytes.
    pub fn heap_bytes(&self) -> usize {
        std::mem::size_of_val(&*self.v4) + std::mem::size_of_val(&*self.v6)
    }

    fn lookup_v4(&self, ip: Ipv4Addr) -> Option<IpNet> {
        find(&self.v4, u32::from(ip)).map(net_v4)
    }

    fn lookup_v6(&self, ip: Ipv6Addr) -> Option<IpNet> {
        find(&self.v6, u128::from(ip)).map(net_v6)
    }

    /// The list entry containing `ip`, if any, in any of its
    /// [`reachable_forms`]: as given, its IPv4 form (IPv4-mapped /
    /// IPv4-compatible), and the IPv4 address a NAT64 or 6to4 gateway would
    /// reach. Any hit counts. O(log n), no allocation.
    pub fn lookup(&self, ip: IpAddr) -> Option<IpNet> {
        reachable_forms(ip).find_map(|form| match form {
            IpAddr::V4(v4) => self.lookup_v4(v4),
            IpAddr::V6(v6) => self.lookup_v6(v6),
        })
    }

    /// Whether `ip` is listed ([`AddressList::lookup`]). Broad: also matches
    /// the IPv4 address a NAT64 or 6to4 address translates to. Use this for
    /// **deny** decisions (the upstream address floor), where matching more
    /// forms is the safe direction.
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.lookup(ip).is_some()
    }

    /// Exact membership for the rule DSL (`ip in @list`). The only
    /// equivalence applied is IPv4-mapped IPv6 (`::ffff:a.b.c.d`), which is
    /// the same address. NAT64, 6to4 and IPv4-compatible forms are distinct
    /// addresses and are matched only if listed as such: a rule like
    /// `client.ip in @internal` → `allow` must not treat an attacker's 6to4
    /// address that embeds an internal IPv4 address as internal.
    pub fn contains_exact(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.lookup_v4(v4).is_some(),
            IpAddr::V6(v6) => {
                self.lookup_v6(v6).is_some()
                    || v6
                        .to_ipv4_mapped()
                        .is_some_and(|v4| self.lookup_v4(v4).is_some())
            }
        }
    }

    /// Every entry, IPv4 first, in address order.
    pub fn iter(&self) -> impl Iterator<Item = IpNet> + '_ {
        self.v4
            .iter()
            .map(|b| net_v4(*b))
            .chain(self.v6.iter().map(|b| net_v6(*b)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn exact_membership_ignores_translated_forms() {
        let l = AddressList::parse("internal", "10.0.0.0/8\n").unwrap();
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(l.contains_exact(ip("10.1.2.3")));
        assert!(
            l.contains_exact(ip("::ffff:10.1.2.3")),
            "mapped is the same address"
        );
        // 6to4 and NAT64 embedding 10.1.2.3 are different addresses.
        assert!(!l.contains_exact(ip("2002:a01:203::1")));
        assert!(!l.contains_exact(ip("64:ff9b::a01:203")));
        // ...but the deny-floor lookup still catches them.
        assert!(l.contains(ip("2002:a01:203::1")));
        assert!(l.contains(ip("64:ff9b::a01:203")));
    }

    #[test]
    fn parses_comments_blanks_and_whitespace() {
        let l = AddressList::parse(
            "t",
            "# header\n\n  10.0.0.0/8  \n192.0.2.1 # one host\n\t2001:db8::/32\r\n   \n#x\n",
        )
        .unwrap();
        assert_eq!(l.len(), 3);
        assert_eq!(
            l.iter().collect::<Vec<_>>(),
            [net("10.0.0.0/8"), net("192.0.2.1/32"), net("2001:db8::/32")]
        );
        assert_eq!(l.name(), "t");
        assert!(AddressList::parse("e", "# nothing\n\n").unwrap().is_empty());
    }

    #[test]
    fn bad_lines_name_their_line() {
        let e = AddressList::parse("blocked", "10.0.0.0/8\n# ok\n\nnot-an-ip\n").unwrap_err();
        assert_eq!(e.line, 4);
        assert_eq!(e.entry, "not-an-ip");
        assert_eq!(e.list, "blocked");
        assert!(e.to_string().contains("line 4"), "{e}");
        for (text, needle) in [
            ("10.0.0.1/8", "host bits set (did you mean 10.0.0.0/8?)"),
            ("10.0.0.0/33", "not a valid CIDR"),
            ("2001:db8::1/32", "host bits"),
            ("1.2.3", "not an IP address"),
            ("1.2.3.4 5.6.7.8", "not an IP address"),
            ("010.0.0.1", "not an IP address"),
            ("1.2.3.4/", "not a valid CIDR"),
        ] {
            let e = AddressList::parse("x", text).unwrap_err();
            assert_eq!(e.line, 1);
            assert!(e.reason.contains(needle), "{text}: {e}");
        }
    }

    #[test]
    fn merges_duplicates_and_contained_ranges() {
        let l = AddressList::parse(
            "m",
            "10.1.0.0/16\n10.0.0.0/8\n10.0.0.0/8\n10.2.3.4\n11.0.0.0/8\n2001:db8::/32\n2001:db8:1::/48\n",
        )
        .unwrap();
        assert_eq!(
            l.iter().collect::<Vec<_>>(),
            [net("10.0.0.0/8"), net("11.0.0.0/8"), net("2001:db8::/32")]
        );
        assert_eq!(l.len(), 3);
        // Adjacent blocks stay separate, each reported as written.
        let l = AddressList::parse("a", "10.0.0.0/25\n10.0.0.128/25\n").unwrap();
        assert_eq!(l.len(), 2);
        assert_eq!(l.lookup(ip("10.0.0.127")), Some(net("10.0.0.0/25")));
        assert_eq!(l.lookup(ip("10.0.0.128")), Some(net("10.0.0.128/25")));
    }

    #[test]
    fn lookup_boundaries() {
        let l = AddressList::parse(
            "b",
            "10.0.0.0/24\n10.0.2.0/24\n0.0.0.0/32\n255.255.255.255\n2001:db8::/126\n::/128\nffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff\n",
        )
        .unwrap();
        for (a, hit) in [
            ("10.0.0.0", Some("10.0.0.0/24")),
            ("10.0.0.255", Some("10.0.0.0/24")),
            ("9.255.255.255", None),
            ("10.0.1.0", None),
            ("10.0.1.255", None),
            ("10.0.2.0", Some("10.0.2.0/24")),
            ("10.0.2.255", Some("10.0.2.0/24")),
            ("10.0.3.0", None),
            ("0.0.0.0", Some("0.0.0.0/32")),
            ("0.0.0.1", None),
            ("255.255.255.255", Some("255.255.255.255/32")),
            ("255.255.255.254", None),
            ("2001:db8::", Some("2001:db8::/126")),
            ("2001:db8::3", Some("2001:db8::/126")),
            ("2001:db8::4", None),
            ("2001:db7:ffff:ffff:ffff:ffff:ffff:ffff", None),
            ("::", Some("::/128")),
            (
                "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                Some("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"),
            ),
        ] {
            assert_eq!(l.lookup(ip(a)), hit.map(net), "{a}");
        }
        let all = AddressList::parse("all", "0.0.0.0/0\n::/0\n").unwrap();
        assert_eq!(all.lookup(ip("1.2.3.4")), Some(net("0.0.0.0/0")));
        assert_eq!(all.lookup(ip("2606:4700::1")), Some(net("::/0")));
        let empty = AddressList::from_nets("e", []);
        assert_eq!(empty.lookup(ip("1.2.3.4")), None);
        assert_eq!(empty.lookup(ip("::1")), None);
    }

    #[test]
    fn v6_forms_of_listed_v4_addresses_are_caught() {
        let l = AddressList::parse("v4", "127.0.0.0/8\n192.168.1.0/24\n").unwrap();
        for a in [
            "::ffff:127.0.0.1",   // IPv4-mapped
            "::127.0.0.1",        // IPv4-compatible
            "64:ff9b::7f00:1",    // NAT64
            "2002:7f00:1::1",     // 6to4
            "::ffff:192.168.1.9", // mapped
            "64:ff9b::c0a8:105",  // NAT64 192.168.1.5
        ] {
            assert!(l.lookup(ip(a)).is_some(), "{a}");
        }
        assert_eq!(l.lookup(ip("::ffff:8.8.8.8")), None);
        assert_eq!(l.lookup(ip("64:ff9b::808:808")), None);
        assert_eq!(l.lookup(ip("::1")), None);

        // An IPv4-mapped entry is stored as IPv4 and matches plain IPv4.
        let l = AddressList::parse("m", "::ffff:10.0.0.0/104\n").unwrap();
        assert_eq!(l.iter().collect::<Vec<_>>(), [net("10.0.0.0/8")]);
        assert!(l.contains(ip("10.9.9.9")));
        // A v6 entry covering the NAT64 prefix matches as v6.
        let l = AddressList::parse("n", "64:ff9b::/96\n").unwrap();
        assert!(l.contains(ip("64:ff9b::808:808")));
        assert!(!l.contains(ip("8.8.8.8")));
    }

    #[test]
    fn heap_bytes_is_flat() {
        let l = AddressList::parse("h", "1.0.0.0/8\n2.0.0.0/8\n::1\n").unwrap();
        assert_eq!(l.heap_bytes(), 2 * 8 + 32);
    }

    mod prop {
        use super::*;
        use proptest::prelude::*;

        fn any_net() -> impl Strategy<Value = IpNet> {
            prop_oneof![
                // Clustered so ranges overlap and nest.
                (0u32..=0xff, 0u8..=32).prop_map(|(hi, p)| {
                    let raw = Ipv4Addr::from((hi << 24) | 0x00ab_cd00);
                    IpNet::V4(Ipv4Net::new(raw, p.min(32)).unwrap().trunc())
                }),
                (any::<u32>(), 8u8..=32)
                    .prop_map(|(a, p)| IpNet::V4(Ipv4Net::new(a.into(), p).unwrap().trunc())),
                (any::<u128>(), 0u8..=128)
                    .prop_map(|(a, p)| IpNet::V6(Ipv6Net::new(a.into(), p).unwrap().trunc())),
                (0u16..4, 100u8..=128).prop_map(|(s, p)| {
                    let a = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, s, 0x1234);
                    IpNet::V6(Ipv6Net::new(a, p).unwrap().trunc())
                }),
            ]
        }

        fn any_ip() -> impl Strategy<Value = IpAddr> {
            prop_oneof![
                any::<u32>().prop_map(|a| IpAddr::V4(a.into())),
                (0u32..=0xff, any::<u8>()).prop_map(|(hi, lo)| IpAddr::V4(
                    ((hi << 24) | 0x00ab_cd00 | u32::from(lo)).into()
                )),
                any::<u128>().prop_map(|a| IpAddr::V6(a.into())),
                (0u16..4, any::<u16>()).prop_map(|(s, lo)| {
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, s, lo))
                }),
            ]
        }

        /// The naive reference: any entry contains the address in any of
        /// its forms.
        fn naive(nets: &[IpNet], ip: IpAddr) -> bool {
            let forms: Vec<IpAddr> = reachable_forms(ip).collect();
            nets.iter()
                .any(|n| forms.iter().any(|f| normalise_net(*n).contains(f)))
        }

        proptest! {
            #[test]
            fn matches_a_naive_scan(
                nets in proptest::collection::vec(any_net(), 0..64),
                ips in proptest::collection::vec(any_ip(), 1..64),
            ) {
                let l = AddressList::from_nets("p", nets.clone());
                // Merging never loses or invents coverage.
                for e in l.iter() {
                    prop_assert!(nets.iter().any(|n| normalise_net(*n) == e));
                }
                for ip in ips.into_iter().chain(nets.iter().map(IpNet::network)) {
                    let hit = l.lookup(ip);
                    prop_assert_eq!(hit.is_some(), naive(&nets, ip), "{}", ip);
                    if let Some(h) = hit {
                        prop_assert!(nets.iter().any(|n| normalise_net(*n) == h));
                    }
                }
            }

            #[test]
            fn parse_round_trips(nets in proptest::collection::vec(any_net(), 0..32)) {
                let text = nets.iter().map(ToString::to_string).collect::<Vec<_>>().join("\n");
                let parsed = AddressList::parse("r", &text).unwrap();
                let built = AddressList::from_nets("r", nets);
                prop_assert_eq!(parsed.iter().collect::<Vec<_>>(), built.iter().collect::<Vec<_>>());
            }
        }
    }
}
