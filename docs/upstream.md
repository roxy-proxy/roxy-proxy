# Upstream

How roxy reaches the origin: its own DNS, the address floor that every
connection passes, and upstream TLS. The connector lives in
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
  connect_timeout: 10s
```

## DNS

roxy resolves names itself with `hickory-resolver`, from the system config
or explicit servers. Results are cached for their TTL, capped by
`dns.cache_ttl_cap`. The workload's own DNS is irrelevant; block its DNS at
the network layer. `static_hosts` answers fixed names before DNS (for tests
and air-gapped deployments), and its answers still pass the address floor.

## Address floor

After resolution and before every connect, each candidate IP is checked, in
this order:

1. `deny_cidrs` and every list in `deny_lists`: never valid, and nothing
   opts out.
2. With `deny_private_ranges` (default true): loopback, link-local,
   RFC 1918, CGNAT, ULA, multicast, unspecified and reserved ranges are
   denied, except addresses in `allow_cidrs` and flows whose allow rule says
   `private_ok: true`.

The check is on the resolved IP, not the name, so DNS rebinding does not
help, and IP-literal hosts go through the same check. If any resolved
address is denied, the whole flow is denied: an attacker-controlled name
does not get a second roll of the dice. A hit denies with `403`,
`terminal_rule: _address_policy`, and an `upstream_denied` event naming the
host, the resolved IP, the reason (`private_range:<class>`, `deny_cidrs` or
`list:<name>`) and the CIDR that matched.

`redirect` targets and addon endpoint calls pass the same floor.

## Address lists

Named sets of CIDR ranges (threat-intel feeds, cloud metadata ranges, whole
countries), used as an unconditional deny floor and as `@name` in rules.

```yaml
address_lists:
  - name: blocked
    file: /etc/roxy/lists/blocked.txt    # one IPv4/IPv6 CIDR or address per line; `#` comments
  - name: cloud-metadata
    inline: [169.254.169.254/32, "fd00:ec2::254/128", 100.100.100.200/32]
```

- **Representation.** Each list compiles into two sorted tables of disjoint
  CIDR blocks, one per family, looked up by binary search: 8 bytes per IPv4
  block, 32 per IPv6, no allocation per lookup. A million IPv4 plus 100k
  IPv6 entries take about 11 MiB and look up in tens of nanoseconds.
  Nested and duplicate entries are merged; a malformed line is an error
  naming the file and line. A file larger than
  `limits.max_address_list_bytes` (256 MiB) is a load error.
- **Two matching modes.** The deny floor matches broadly: the address as
  given, its IPv4-mapped and IPv4-compatible forms, and the IPv4 address a
  NAT64 (`64:ff9b::/96`) or 6to4 (`2002::/16`) address would reach, because
  matching more is the safe direction for a deny. Rule membership
  (`ip in @list`) is exact, with only the IPv4-mapped equivalence, because a
  rule might *allow* on membership: `client.ip in @internal` must not treat
  a 6to4 address embedding an internal IPv4 address as internal.
- **In rules.** `@name` works wherever a CIDR does, on the right of `in` /
  `not in` with an ip field: `client.ip in @internal`. An undefined list is
  a compile error.
- **Reload.** List files are watched with the config. A changed file is
  recompiled and swapped with the policy, and the upstream connection pools
  are flushed, so a pooled connection to a newly denied IP is never reused.
- `roxy check` reports the entry count of each list.

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
| address floor | `403`, `_address_policy` | `upstream_denied` |
| DNS, connect, TLS | `502` | `upstream_error`, reason `dns_failed`, `connect_failed` or `tls_failed` |
| timeout | `504` | `upstream_error`, reason `timeout` |
| a response roxy cannot canonicalise | `502` | `upstream_error`, reason `protocol_error` |
