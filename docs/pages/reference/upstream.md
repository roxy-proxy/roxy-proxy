# Upstream

How roxy reaches the origin: its own DNS, the
[address floor](/policies/address-lists) that every connection passes, and
upstream TLS. The connector lives in
`roxy-proxy::upstream`.

```yaml
upstream:
  dns:
    resolver: system           # system | [ "1.1.1.1:53", ... ]
    cache_ttl_cap: 60s
    static_hosts: {}           # name: ip, consulted before DNS
  deny_private_ranges: true
  deny_cidrs: []               # never valid destinations
  allow_cidrs: []              # exceptions to the private-range floor only
  deny_lists: [blocked]        # names from address_lists
  connect_timeout: 10s         # TCP connect, over all of a name's addresses together
```

`deny_cidrs` and `allow_cidrs` entries are stored as address-list entries
are: an IPv4-mapped entry (`::ffff:203.0.113.0/120`) becomes the IPv4 CIDR
(`203.0.113.0/24`) and matches the address however a client spells it.

## DNS

roxy resolves names itself with `hickory-resolver`, from the system config
or explicit servers. Results are cached for their TTL, capped by
`dns.cache_ttl_cap`. The workload's own DNS is irrelevant; block its DNS at
the network layer. `static_hosts` answers fixed names before DNS (for tests
and air-gapped deployments), and its answers still pass the address floor.

A name with several addresses is dialled one address at a time, IPv4 and
IPv6 alternating from the resolver's first, within one `connect_timeout`
for all of them: each attempt gets an equal share of the time left, so an
address that drops packets does not take the whole budget from the ones
after it. The TLS handshake has its own `connect_timeout`.

## Upstream TLS

rustls, with the bundled Mozilla roots (`webpki-roots`), plus
`tls.upstream.extra_roots` when `tls.upstream.verify` is
`strict+extra_roots`. Verification is always on. The SNI is the canonical
host. ALPN offers `h2` and `http/1.1` (only `http/1.1` for WebSocket
upgrades). The minimum version is `tls.upstream.min_version` (1.2).

```yaml
tls:
  upstream:
    verify: strict             # strict | strict+extra_roots
    extra_roots: []            # PEM files
    min_version: "1.2"         # "1.2" | "1.3"
```

## Errors

| failure | response | flow log |
|---|---|---|
| address floor | `403`, `_address_policy` | `upstream_denied`, reason `private_range:<class>`, `deny_cidrs` or `list:<name>` |
| DNS, connect, TLS | `502` | `upstream_error`, reason `dns_failed`, `connect_failed` or `tls_failed` |
| a target roxy cannot dial (no host, an unknown scheme) | `502` | `upstream_error`, reason `invalid_target` |
| timeout | `504` | `upstream_error`, reason `timeout` |
| a response roxy cannot canonicalise | `502` | `upstream_error`, reason `protocol_error` |

Every row answers with the same body
([Deny responses](/reference/http#deny-responses)); the reason is in the
flow log only, so a client cannot tell a name that does not resolve from a
port that is closed.
