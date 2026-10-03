//! Scheme, host and authority. Parsing lives in [`crate::url`].

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// URI scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scheme {
    /// `http`
    Http,
    /// `https`
    Https,
}

impl Scheme {
    /// Lower-case scheme name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }

    /// Default port for the scheme.
    pub const fn default_port(self) -> u16 {
        match self {
            Scheme::Http => 80,
            Scheme::Https => 443,
        }
    }
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A validated host.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Host {
    /// Lower-cased DNS name of A-labels, no trailing dot. Only produced by
    /// [`crate::url::parse_host`].
    Dns(String),
    /// IPv4 literal (strict dotted-quad).
    Ipv4(Ipv4Addr),
    /// IPv6 literal (written in brackets in an authority).
    Ipv6(Ipv6Addr),
}

impl Host {
    /// DNS name, if this is one.
    pub fn dns_name(&self) -> Option<&str> {
        match self {
            Host::Dns(s) => Some(s),
            _ => None,
        }
    }
}

impl fmt::Display for Host {
    /// The host as it appears in an authority (IPv6 in brackets).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Host::Dns(s) => f.write_str(s),
            Host::Ipv4(ip) => write!(f, "{ip}"),
            Host::Ipv6(ip) => write!(f, "[{ip}]"),
        }
    }
}

/// Host plus an always-explicit port.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Authority {
    /// Host.
    pub host: Host,
    /// Port; always explicit internally.
    pub port: u16,
}

impl Authority {
    /// Creates an authority.
    pub fn new(host: Host, port: u16) -> Self {
        Self { host, port }
    }

    /// The `Host` header / `:authority` form: the port is included only when
    /// it is not the default for `scheme`.
    pub fn to_host_header(&self, scheme: Scheme) -> String {
        if self.port == scheme.default_port() {
            self.host.to_string()
        } else {
            self.to_string()
        }
    }
}

impl fmt::Display for Authority {
    /// Internal form: always `host:port`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_header_omits_default_port() {
        let a = Authority::new(Host::Dns("example.com".into()), 443);
        assert_eq!(a.to_string(), "example.com:443");
        assert_eq!(a.to_host_header(Scheme::Https), "example.com");
        assert_eq!(a.to_host_header(Scheme::Http), "example.com:443");
        let v6 = Authority::new(Host::Ipv6(Ipv6Addr::LOCALHOST), 8080);
        assert_eq!(v6.to_host_header(Scheme::Http), "[::1]:8080");
    }
}
