# Upstream

How roxy reaches the origin: its own DNS, the
[address floor](/reference/address-lists#address-floor) that every
connection passes, and upstream TLS.

```yaml
upstream:
  dns:
    resolver: system           # system | [ "1.1.1.1:53", ... ]
    cache_ttl_cap: 60s         # caps each record's TTL in the cache
    static_hosts: {}           # name: ip, answered before DNS; still passes the address floor
  deny_private_ranges: true
  deny_cidrs: []               # never valid destinations
  allow_cidrs: []              # exceptions to the private-range floor only
  deny_lists: [blocked]        # names from address_lists
  connect_timeout: 10s         # TCP connect, over all of a name's addresses together; then the TLS handshake, within another
  max_h2_connections_per_origin: 4   # at least 1

tls:
  upstream:
    verify: strict             # strict | strict+extra_roots
    extra_roots: []            # PEM files
    min_version: "1.2"         # "1.2" | "1.3"
```

`deny_cidrs` and `allow_cidrs` entries are stored as address-list entries
are: an IPv4-mapped entry (`::ffff:203.0.113.0/120`) becomes the IPv4 CIDR
(`203.0.113.0/24`) and matches the address however a client spells it.

## DNS

roxy resolves names itself with `hickory-resolver` (the workload's own DNS
is irrelevant; block it at the network layer). A and AAAA are both looked
up. Several addresses are dialled one at a time, IPv4 and IPv6 alternating
from the resolver's first, within one `connect_timeout` for all; each
attempt gets an equal share of the time left.

## Upstream TLS

rustls with the bundled Mozilla roots (`webpki-roots`), plus `extra_roots`
under `strict+extra_roots`. Verification is always on. The SNI is the
canonical host. ALPN offers `h2` and `http/1.1` (only `http/1.1` for
WebSocket upgrades). The handshake has its own `connect_timeout` after the
TCP connect's: an upstream that accepts the connection but never completes
TLS fails with `504`, reason `timeout`, message `upstream TLS handshake`.

## Connections

Connections to an origin are pooled by scheme and authority and closed
after 90 s idle. HTTP/1.1 opens one connection per concurrent request.
HTTP/2 multiplexes: an origin that negotiates `h2` gets up to
`max_h2_connections_per_origin` connections, each driven by its own task.
A request goes to the connection with the fewest exchanges in flight (a
response body still streaming counts), so a lightly used origin stays on
one connection and concurrent load spreads evenly across the limit. Each
connection offers a 2 MiB stream window, an 8 MiB connection window and
1 MiB frames.

An origin that closes an HTTP/2 connection with `GOAWAY` (nginx does at
`keepalive_requests`) fails every stream above the last one it names, which
it never processed. roxy sends such a request again on another connection,
up to twice, if it has no body; a request with a body is answered `502`
(`upstream_error`, reason `protocol_error`), as its body has already
streamed to the connection.

## Errors

| failure | response | flow log |
|---|---|---|
| address floor | `403`, `_address_policy` | `upstream_denied`, reason `private_range:<class>`, `deny_cidrs` or `list:<name>` |
| DNS, connect, TLS | `502` | `upstream_error`, reason `dns_failed`, `connect_failed` or `tls_failed` |
| a target roxy cannot dial (no host, an unknown scheme) | `502` | `upstream_error`, reason `invalid_target` |
| timeout (connect, TLS handshake or response headers) | `504` | `upstream_error`, reason `timeout`; `message` names the stage |
| a response roxy cannot canonicalise | `502` | `upstream_error`, reason `protocol_error` |

Every row answers with the same body
([deny responses](/reference/http#deny-responses)); the reason is in the
flow log only.
