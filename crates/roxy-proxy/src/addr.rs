//! The upstream address floor: every resolved candidate is
//! checked before roxy connects, so DNS rebinding and IP-literal tricks
//! cannot reach private destinations.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use ipnet::IpNet;

use crate::addrlist::AddressList;

/// Address-policy settings (`upstream.*`).
#[derive(Debug, Clone)]
pub struct AddressPolicy {
    /// Deny loopback, link-local, RFC 1918, CGNAT, ULA, multicast,
    /// unspecified and reserved ranges unless a rule says `private_ok`.
    pub deny_private_ranges: bool,
    /// Never valid destinations; nothing opts out.
    pub deny_cidrs: Vec<IpNet>,
    /// Exceptions to the private-range floor (not to `deny_cidrs` or
    /// `deny_lists`), for internal services every flow may reach.
    pub allow_cidrs: Vec<IpNet>,
    /// `upstream.deny_lists`, resolved. Never valid destinations;
    /// neither `private_ok` nor `allow_cidrs` opts out.
    pub deny_lists: Vec<Arc<AddressList>>,
}

impl Default for AddressPolicy {
    fn default() -> Self {
        Self {
            deny_private_ranges: true,
            deny_cidrs: Vec::new(),
            allow_cidrs: Vec::new(),
            deny_lists: Vec::new(),
        }
    }
}

/// Whether a flow may reach the private ranges: a rule's
/// `allow: { private_ok: true }`, or an addon endpoint's `private_ok`. An
/// enum, not a `bool`, so it can't be swapped with another flag at a call
/// site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrivateAddrs {
    Deny,
    Allow,
}

impl PrivateAddrs {
    /// From a configured `private_ok`.
    pub fn from_private_ok(private_ok: bool) -> Self {
        if private_ok { Self::Allow } else { Self::Deny }
    }
}

/// Why an address was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressDenied {
    /// The (canonical) address.
    pub ip: IpAddr,
    /// `private_range:<class>`, `deny_cidrs` or `list:<name>`.
    pub reason: String,
    /// The configured CIDR that matched, for `deny_cidrs` and lists.
    pub matched_cidr: Option<IpNet>,
    /// The address list that matched.
    pub list: Option<String>,
}

/// IPv4-mapped (`::ffff:a.b.c.d`) and IPv4-compatible addresses become
/// IPv4, so a v4 rule cannot be bypassed by writing the address as v6.
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return IpAddr::V4(v4);
            }
            let seg = v6.segments();
            // Deprecated IPv4-compatible form ::a.b.c.d (not :: and ::1).
            if seg[..6] == [0; 6] && !(seg[6] == 0 && seg[7] <= 1) {
                return IpAddr::V4(embedded_v4(seg[6], seg[7]));
            }
            IpAddr::V6(v6)
        }
        v4 @ IpAddr::V4(_) => v4,
    }
}

fn embedded_v4(hi: u16, lo: u16) -> Ipv4Addr {
    let [o1, o2] = hi.to_be_bytes();
    let [o3, o4] = lo.to_be_bytes();
    Ipv4Addr::new(o1, o2, o3, o4)
}

/// The IPv4 address a translating gateway would reach for `v6`: NAT64
/// with the well-known prefix (`64:ff9b::/96`) or the local-use prefix
/// (`64:ff9b:1::/48`, taking the last 32 bits as a `/96` deployment does),
/// or 6to4 (`2002::/16`).
fn translated_v4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    let seg = v6.segments();
    if seg[..6] == [0x64, 0xff9b, 0, 0, 0, 0] || seg[..3] == [0x64, 0xff9b, 1] {
        return Some(embedded_v4(seg[6], seg[7]));
    }
    if seg[0] == 0x2002 {
        return Some(embedded_v4(seg[1], seg[2]));
    }
    None
}

/// Every form of `ip` a connection to it may reach: the address as given,
/// its [`canonical`] IPv4 form, and the IPv4 address a NAT64 or 6to4
/// gateway translates it to. Deny decisions match any of them, since
/// matching more is the safe direction for a deny. Allow decisions must
/// not: an attacker's 6to4 address embedding an allowed IPv4 address is
/// not that address.
pub fn reachable_forms(ip: IpAddr) -> impl Iterator<Item = IpAddr> {
    let canon = Some(canonical(ip)).filter(|c| *c != ip);
    let translated = match ip {
        IpAddr::V6(v6) => translated_v4(v6).map(IpAddr::V4),
        IpAddr::V4(_) => None,
    };
    std::iter::once(ip).chain(canon).chain(translated)
}

fn v4_class(ip: Ipv4Addr) -> Option<&'static str> {
    let o = ip.octets();
    Some(match o {
        [0, ..] => "unspecified",
        [10, ..] | [192, 168, ..] => "private",
        [172, b, ..] if (16..32).contains(&b) => "private",
        [100, b, ..] if (64..128).contains(&b) => "shared",
        [127, ..] => "loopback",
        [169, 254, ..] => "link_local",
        [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _] => "documentation",
        [198, 18 | 19, ..] => "benchmarking",
        [224..=239, ..] => "multicast",
        [192, 0, 0, _] | [240..=255, ..] => "reserved",
        _ => return None,
    })
}

fn v6_class(ip: Ipv6Addr) -> Option<&'static str> {
    let seg = ip.segments();
    if ip.is_unspecified() {
        return Some("unspecified");
    }
    if ip.is_loopback() {
        return Some("loopback");
    }
    Some(match seg[0] {
        x if x & 0xfe00 == 0xfc00 => "unique_local",
        x if x & 0xffc0 == 0xfe80 => "link_local",
        x if x & 0xffc0 == 0xfec0 => "site_local",
        x if x & 0xff00 == 0xff00 => "multicast",
        0x2001 if seg[1] == 0x0db8 => "documentation",
        0x0100 if seg[1..4] == [0, 0, 0] => "discard",
        _ => return None,
    })
}

/// The built-in private/special class of `ip`, if any: of the first of
/// its [`reachable_forms`] that has one, so a NAT64 or 6to4 address is
/// classed by the IPv4 address a gateway would reach.
pub fn private_class(ip: IpAddr) -> Option<&'static str> {
    reachable_forms(ip).find_map(|form| match form {
        IpAddr::V4(v4) => v4_class(v4),
        IpAddr::V6(v6) => v6_class(v6),
    })
}

impl AddressPolicy {
    /// Checks one candidate address: `deny_cidrs`, then the private-range
    /// floor, then every deny list. [`PrivateAddrs::Allow`] lifts the
    /// private-range floor only; it never overrides `deny_cidrs` or a deny
    /// list.
    pub fn check(&self, ip: IpAddr, private: PrivateAddrs) -> Result<(), AddressDenied> {
        let denied = |reason: String, matched_cidr, list| AddressDenied {
            ip: canonical(ip),
            reason,
            matched_cidr,
            list,
        };
        // Denies match every form the address may reach.
        if let Some(net) =
            reachable_forms(ip).find_map(|form| self.deny_cidrs.iter().find(|n| n.contains(&form)))
        {
            return Err(denied("deny_cidrs".into(), Some(*net), None));
        }
        // The exemption matches the address itself only (and its IPv4 form,
        // the same address): a translated form of it is a different address.
        if self.deny_private_ranges
            && private == PrivateAddrs::Deny
            && let Some(class) = private_class(ip)
            && !self.allow_cidrs.iter().any(|n| n.contains(&canonical(ip)))
        {
            return Err(denied(format!("private_range:{class}"), None, None));
        }
        for list in &self.deny_lists {
            if let Some(net) = list.lookup(ip) {
                let name = list.name().to_owned();
                return Err(denied(format!("list:{name}"), Some(net), Some(name)));
            }
        }
        Ok(())
    }

    /// Checks every candidate; any denied candidate denies the whole set
    /// (an attacker-controlled name gets no second roll of the dice).
    pub fn check_all(&self, ips: &[IpAddr], private: PrivateAddrs) -> Result<(), AddressDenied> {
        for ip in ips {
            self.check(*ip, private)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::PrivateAddrs::{Allow, Deny};
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn classes() {
        for (a, c) in [
            ("127.0.0.1", "loopback"),
            ("10.1.2.3", "private"),
            ("172.31.0.1", "private"),
            ("192.168.1.1", "private"),
            ("169.254.169.254", "link_local"),
            ("100.64.0.1", "shared"),
            ("0.0.0.0", "unspecified"),
            ("224.0.0.1", "multicast"),
            ("255.255.255.255", "reserved"),
            ("::1", "loopback"),
            ("::", "unspecified"),
            ("fd00::1", "unique_local"),
            ("fe80::1", "link_local"),
            ("ff02::1", "multicast"),
            ("::ffff:127.0.0.1", "loopback"),
            ("::ffff:10.0.0.1", "private"),
            ("::127.0.0.1", "loopback"),
            ("64:ff9b::7f00:1", "loopback"),
            ("2002:c0a8:0101::1", "private"),
            ("64:ff9b:1::a00:1", "private"),
            ("64:ff9b:1:ab:cd:ef:7f00:1", "loopback"),
        ] {
            assert_eq!(private_class(ip(a)), Some(c), "{a}");
        }
        for a in [
            "1.1.1.1",
            "8.8.8.8",
            "2606:4700::1111",
            "172.32.0.1",
            "64:ff9b::808:808",
            "64:ff9b:1::808:808",
            "2002:808:808::1",
        ] {
            assert_eq!(private_class(ip(a)), None, "{a}");
        }
    }

    #[test]
    fn policy() {
        let p = AddressPolicy {
            deny_private_ranges: true,
            deny_cidrs: vec!["1.2.3.0/24".parse().unwrap()],
            allow_cidrs: vec!["10.9.9.9/32".parse().unwrap()],
            deny_lists: Vec::new(),
        };
        assert!(p.check(ip("127.0.0.1"), Deny).is_err());
        assert!(p.check(ip("127.0.0.1"), Allow).is_ok());
        assert!(p.check(ip("10.9.9.9"), Deny).is_ok());
        assert!(p.check(ip("10.9.9.8"), Deny).is_err());
        let d = p.check(ip("::ffff:1.2.3.4"), Allow).unwrap_err();
        assert_eq!(d.reason, "deny_cidrs");
        assert_eq!(d.ip, ip("1.2.3.4"));
        assert!(p.check(ip("8.8.8.8"), Deny).is_ok());
        assert!(
            p.check_all(&[ip("8.8.8.8"), ip("192.168.0.1")], Deny)
                .is_err()
        );
    }

    /// `deny_cidrs` match every form an address may reach, like deny lists;
    /// `allow_cidrs` exempt the address itself only.
    #[test]
    fn deny_cidrs_match_translated_forms_and_allow_cidrs_do_not() {
        let p = AddressPolicy {
            deny_private_ranges: true,
            deny_cidrs: vec!["203.0.113.0/24".parse().unwrap()],
            allow_cidrs: vec!["10.9.9.9/32".parse().unwrap()],
            deny_lists: Vec::new(),
        };
        for a in [
            "203.0.113.7",
            "::ffff:203.0.113.7",
            "::203.0.113.7",
            "64:ff9b::cb00:7107",
            "64:ff9b:1::cb00:7107",
            "2002:cb00:7107::1",
        ] {
            let d = p.check(ip(a), Allow).unwrap_err();
            assert_eq!(d.reason, "deny_cidrs", "{a}");
            assert_eq!(
                d.matched_cidr,
                Some("203.0.113.0/24".parse().unwrap()),
                "{a}"
            );
        }
        assert!(p.check(ip("10.9.9.9"), Deny).is_ok());
        assert!(p.check(ip("::ffff:10.9.9.9"), Deny).is_ok());
        for a in ["64:ff9b::a09:909", "2002:a09:909::1"] {
            assert_eq!(
                p.check(ip(a), Deny).unwrap_err().reason,
                "private_range:private",
                "{a}"
            );
        }
    }

    #[test]
    fn deny_lists_are_a_hard_floor() {
        let list =
            AddressList::parse("blocked", "127.0.0.0/8\n203.0.113.0/24\n10.9.9.9\n").unwrap();
        let p = AddressPolicy {
            deny_private_ranges: true,
            deny_cidrs: Vec::new(),
            allow_cidrs: vec!["10.9.9.9/32".parse().unwrap()],
            deny_lists: vec![Arc::new(list)],
        };
        // `private_ok` does not bypass a list.
        let d = p.check(ip("127.0.0.1"), Allow).unwrap_err();
        assert_eq!(d.reason, "list:blocked");
        assert_eq!(d.list.as_deref(), Some("blocked"));
        assert_eq!(d.matched_cidr, Some("127.0.0.0/8".parse().unwrap()));
        // Neither does `allow_cidrs`.
        assert_eq!(
            p.check(ip("10.9.9.9"), Allow).unwrap_err().reason,
            "list:blocked"
        );
        // Without private_ok the private floor answers first.
        assert_eq!(
            p.check(ip("127.0.0.1"), Deny).unwrap_err().reason,
            "private_range:loopback"
        );
        // Public address, v6 spellings of it.
        for a in [
            "203.0.113.7",
            "::ffff:203.0.113.7",
            "64:ff9b::cb00:7107",
            "2002:cb00:7107::1",
        ] {
            let d = p.check(ip(a), Allow).unwrap_err();
            assert_eq!(d.list.as_deref(), Some("blocked"), "{a}");
            assert_eq!(
                d.matched_cidr,
                Some("203.0.113.0/24".parse().unwrap()),
                "{a}"
            );
        }
        // Any listed candidate denies the whole set.
        let d = p
            .check_all(&[ip("8.8.8.8"), ip("203.0.113.1")], Allow)
            .unwrap_err();
        assert_eq!(d.ip, ip("203.0.113.1"));
        assert!(p.check_all(&[ip("8.8.8.8"), ip("1.1.1.1")], Allow).is_ok());
    }
}
