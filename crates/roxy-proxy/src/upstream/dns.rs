//! roxy's own name resolution. The agent's DNS is
//! irrelevant in proxy mode.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use hickory_resolver::TokioResolver;
use hickory_resolver::config::{
    ConnectionConfig, NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts,
};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use roxy_http::Host;

use super::ConnectError;

/// `upstream.dns.*`.
#[derive(Debug, Clone)]
pub struct DnsSettings {
    /// Explicit nameservers; `None` = system configuration.
    pub servers: Option<Vec<SocketAddr>>,
    /// Upper bound on how long a positive or negative answer is cached.
    pub cache_ttl_cap: Duration,
    /// Fixed answers for names (lower-case, no trailing dot), consulted
    /// before DNS. Intended for tests and air-gapped deployments; answers
    /// are still subject to the address floor.
    pub static_hosts: HashMap<String, Vec<IpAddr>>,
}

impl Default for DnsSettings {
    fn default() -> Self {
        Self {
            servers: None,
            cache_ttl_cap: Duration::from_secs(60),
            static_hosts: HashMap::new(),
        }
    }
}

/// Resolver with static overrides.
pub(crate) struct Dns {
    resolver: TokioResolver,
    static_hosts: HashMap<String, Vec<IpAddr>>,
}

impl std::fmt::Debug for Dns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dns").finish_non_exhaustive()
    }
}

impl Dns {
    pub(crate) fn new(s: &DnsSettings) -> Result<Self, String> {
        let mut builder = match &s.servers {
            None => TokioResolver::builder_tokio()
                .map_err(|e| format!("reading the system DNS configuration: {e}"))?,
            Some(servers) => {
                let ns = servers
                    .iter()
                    .map(|addr| {
                        let mut udp = ConnectionConfig::udp();
                        udp.port = addr.port();
                        let mut tcp = ConnectionConfig::tcp();
                        tcp.port = addr.port();
                        NameServerConfig::new(addr.ip(), true, vec![udp, tcp])
                    })
                    .collect();
                TokioResolver::builder_with_config(
                    ResolverConfig::from_name_servers(ns),
                    TokioRuntimeProvider::default(),
                )
            }
        };
        let opts: &mut ResolverOpts = builder.options_mut();
        opts.positive_max_ttl = Some(s.cache_ttl_cap);
        opts.negative_max_ttl = Some(s.cache_ttl_cap);
        // The hosts file is part of "system" only; explicit servers mean
        // exactly those servers.
        if s.servers.is_some() {
            opts.use_hosts_file = ResolveHosts::Never;
        }
        let resolver = builder
            .build()
            .map_err(|e| format!("building the DNS resolver: {e}"))?;
        Ok(Self {
            resolver,
            static_hosts: s.static_hosts.clone(),
        })
    }

    /// Every address for `host` (IP literals resolve to themselves).
    pub(crate) async fn resolve(&self, host: &Host) -> Result<Vec<IpAddr>, ConnectError> {
        let name = match host {
            Host::Ipv4(ip) => return Ok(vec![IpAddr::V4(*ip)]),
            Host::Ipv6(ip) => return Ok(vec![IpAddr::V6(*ip)]),
            Host::Dns(name) => name,
        };
        if let Some(ips) = self.static_hosts.get(name.as_str()) {
            return Ok(ips.clone());
        }
        // Fully qualify so search domains are never appended.
        let fqdn = format!("{name}.");
        let lookup = self
            .resolver
            .lookup_ip(fqdn.as_str())
            .await
            .map_err(|e| ConnectError::Dns(e.to_string()))?;
        let ips: Vec<IpAddr> = lookup.iter().collect();
        if ips.is_empty() {
            return Err(ConnectError::Dns(format!("no addresses for {name}")));
        }
        Ok(ips)
    }
}
