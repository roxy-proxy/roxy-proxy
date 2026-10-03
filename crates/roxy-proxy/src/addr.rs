//! The upstream address floor (`DESIGN.md` §7): every resolved candidate is
//! checked before roxy connects, so DNS rebinding and IP-literal tricks
//! cannot reach private destinations.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;

/// Address-policy settings (`upstream.*`).
#[derive(Debug, Clone)]
pub struct AddressPolicy {
    /// Deny loopback, link-local, RFC 1918, CGNAT, ULA, multicast,
    /// unspecified and reserved ranges unless a rule says `private_ok`.
    pub deny_private_ranges: bool,
    /// Never valid destinations; nothing opts out.
    pub deny_cidrs: Vec<IpNet>,
    /// Exceptions to the private-range floor (not to `deny_cidrs`), for
    /// internal services every flow may reach.
    pub allow_cidrs: Vec<IpNet>,
}

impl Default for AddressPolicy {
    fn default() -> Self {
        Self {
            deny_private_ranges: true,
            deny_cidrs: Vec::new(),
            allow_cidrs: Vec::new(),
        }
    }
}

/// Why an address was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressDenied {
    /// The (canonical) address.
    pub ip: IpAddr,
    /// `private_range:<class>` or `deny_cidrs`.
    pub reason: String,
    /// The configured CIDR that matched, for `deny_cidrs`.
    pub matched_cidr: Option<IpNet>,
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
    // NAT64 (64:ff9b::/96) and 6to4 (2002::/16) embed an IPv4 address that a
    // gateway would reach: classify that.
    if seg[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return v4_class(embedded_v4(seg[6], seg[7]));
    }
    if seg[0] == 0x2002 {
        return v4_class(embedded_v4(seg[1], seg[2]));
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

/// The built-in private/special class of `ip`, if any.
pub fn private_class(ip: IpAddr) -> Option<&'static str> {
    match canonical(ip) {
        IpAddr::V4(v4) => v4_class(v4),
        IpAddr::V6(v6) => v6_class(v6),
    }
}

impl AddressPolicy {
    /// Checks one candidate address. `private_ok` comes from the flow's
    /// `allow: { private_ok: true }`; it never overrides `deny_cidrs`.
    pub fn check(&self, ip: IpAddr, private_ok: bool) -> Result<(), AddressDenied> {
        let ip = canonical(ip);
        if let Some(net) = self.deny_cidrs.iter().find(|n| n.contains(&ip)) {
            return Err(AddressDenied {
                ip,
                reason: "deny_cidrs".into(),
                matched_cidr: Some(*net),
            });
        }
        if self.deny_private_ranges
            && !private_ok
            && let Some(class) = private_class(ip)
            && !self.allow_cidrs.iter().any(|n| n.contains(&ip))
        {
            return Err(AddressDenied {
                ip,
                reason: format!("private_range:{class}"),
                matched_cidr: None,
            });
        }
        Ok(())
    }

    /// Checks every candidate; any denied candidate denies the whole set
    /// (an attacker-controlled name gets no second roll of the dice).
    pub fn check_all(&self, ips: &[IpAddr], private_ok: bool) -> Result<(), AddressDenied> {
        for ip in ips {
            self.check(*ip, private_ok)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
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
        ] {
            assert_eq!(private_class(ip(a)), Some(c), "{a}");
        }
        for a in ["1.1.1.1", "8.8.8.8", "2606:4700::1111", "172.32.0.1"] {
            assert_eq!(private_class(ip(a)), None, "{a}");
        }
    }

    #[test]
    fn policy() {
        let p = AddressPolicy {
            deny_private_ranges: true,
            deny_cidrs: vec!["1.2.3.0/24".parse().unwrap()],
            allow_cidrs: vec!["10.9.9.9/32".parse().unwrap()],
        };
        assert!(p.check(ip("127.0.0.1"), false).is_err());
        assert!(p.check(ip("127.0.0.1"), true).is_ok());
        assert!(p.check(ip("10.9.9.9"), false).is_ok());
        assert!(p.check(ip("10.9.9.8"), false).is_err());
        let d = p.check(ip("::ffff:1.2.3.4"), true).unwrap_err();
        assert_eq!(d.reason, "deny_cidrs");
        assert_eq!(d.ip, ip("1.2.3.4"));
        assert!(p.check(ip("8.8.8.8"), false).is_ok());
        assert!(
            p.check_all(&[ip("8.8.8.8"), ip("192.168.0.1")], false)
                .is_err()
        );
    }
}
