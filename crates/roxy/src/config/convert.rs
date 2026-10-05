//! The one place config values become runtime types (`roxy_http::Limits`,
//! `roxy_http::HttpFlags`, the proxy's HTTP behaviour, upstream settings,
//! upstream TLS options).

use roxy_http::{HttpFlags, Limits};
use roxy_proxy::HttpBehaviour;
use roxy_proxy::addr::AddressPolicy;
use roxy_proxy::{DnsSettings, UpstreamSettings};
use roxy_tls::{MinTlsVersion, UpstreamTlsOptions};

use super::{Config, Resolver, TlsVersion, UpstreamVerify};

fn usize_of(b: bytesize::ByteSize) -> usize {
    usize::try_from(b.as_u64()).unwrap_or(usize::MAX)
}

impl From<&Config> for Limits {
    fn from(c: &Config) -> Self {
        let l = &c.limits;
        Limits {
            max_header_bytes: usize_of(l.max_header_bytes),
            max_url_bytes: usize_of(l.max_url_bytes),
            max_headers: l.max_headers,
            max_request_body_bytes: l.max_request_body_bytes.as_u64(),
            max_response_body_bytes: l.max_response_body_bytes.as_u64(),
            max_inspect_body_bytes: l.max_inspect_body_bytes.as_u64(),
            max_ws_message_bytes: l.max_ws_message_bytes.as_u64(),
            max_observer_lag_bytes: l.max_observer_lag_bytes.as_u64(),
            max_buffered_bytes: l.max_buffered_bytes.as_u64(),
            header_timeout: l.header_timeout,
            body_idle_timeout: l.body_idle_timeout,
            response_header_timeout: l.response_header_timeout,
            idle_timeout: l.idle_timeout,
            h2_max_concurrent_streams: l.h2_max_concurrent_streams,
            h2_max_header_list_bytes: usize_of(l.h2_max_header_list_bytes),
        }
    }
}

impl From<&Config> for HttpFlags {
    fn from(c: &Config) -> Self {
        let h = &c.http;
        HttpFlags {
            allow_http10: h.allow_http10,
            allow_trailers: h.allow_trailers,
            allow_chunk_extensions: h.allow_chunk_extensions,
            allow_obs_text: h.allow_obs_text,
            allow_body_on_get: h.allow_body_on_get,
        }
    }
}

impl From<&Config> for HttpBehaviour {
    fn from(c: &Config) -> Self {
        let h = &c.http;
        HttpBehaviour {
            allow_plain_in_connect: h.allow_plain_in_connect,
            strip_accept_encoding: h.strip_accept_encoding,
            decode_for_addons: h.decode_for_addons,
        }
    }
}

impl From<&Config> for UpstreamSettings {
    fn from(c: &Config) -> Self {
        let u = &c.upstream;
        UpstreamSettings {
            dns: DnsSettings {
                servers: match &u.dns.resolver {
                    Resolver::System => None,
                    Resolver::Servers(s) => Some(s.clone()),
                },
                cache_ttl_cap: u.dns.cache_ttl_cap,
                static_hosts: u
                    .dns
                    .static_hosts
                    .iter()
                    .map(|(name, ip)| (name.trim_end_matches('.').to_ascii_lowercase(), vec![*ip]))
                    .collect(),
            },
            address_policy: AddressPolicy {
                deny_private_ranges: u.deny_private_ranges,
                deny_cidrs: u.deny_cidrs.clone(),
                allow_cidrs: u.allow_cidrs.clone(),
                // Resolved from `upstream.deny_lists` when the snapshot is
                // built (`PolicyUpdate::deny_lists`).
                deny_lists: Vec::new(),
            },
            connect_timeout: u.connect_timeout,
            ..UpstreamSettings::default()
        }
    }
}

impl From<&Config> for UpstreamTlsOptions {
    fn from(c: &Config) -> Self {
        let t = &c.tls.upstream;
        UpstreamTlsOptions {
            extra_roots_pem: match t.verify {
                UpstreamVerify::Strict => Vec::new(),
                UpstreamVerify::StrictExtraRoots => t.extra_roots.clone(),
            },
            min_version: match t.min_version {
                TlsVersion::Tls12 => MinTlsVersion::Tls12,
                TlsVersion::Tls13 => MinTlsVersion::Tls13,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_codec() {
        let c = Config::from_yaml("version: 1\n").unwrap();
        assert_eq!(Limits::from(&c), Limits::default());
        assert_eq!(HttpFlags::from(&c), HttpFlags::default());
        assert_eq!(HttpBehaviour::from(&c), HttpBehaviour::default());
    }

    #[test]
    fn static_hosts_are_normalised() {
        let c = Config::from_yaml(
            "version: 1\nupstream:\n  dns:\n    static_hosts: { \"Upstream.Test.\": 127.0.0.1 }\n",
        )
        .unwrap();
        let u = UpstreamSettings::from(&c);
        assert_eq!(
            u.dns.static_hosts.get("upstream.test"),
            Some(&vec!["127.0.0.1".parse().unwrap()])
        );
    }
}
