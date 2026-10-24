# Upstream

How roxy reaches the origin: it resolves names itself, checks every
address against the [address floor](/reference/address-lists#address-floor),
and verifies the origin's TLS certificate.

```yaml
upstream:
  dns:
    resolver: system           # system | [ "1.1.1.1:53", ... ]
    cache_ttl_cap: 60s         # the longest roxy caches an answer
    static_hosts: {}           # name: ip, used before DNS; still checked by the address floor
  deny_private_ranges: true
  deny_cidrs: []               # never connect to these
  allow_cidrs: []              # exceptions to the private ranges only
  deny_lists: [blocked]        # names from address_lists
  connect_timeout: 10s         # for the TCP connection, then again for the TLS handshake
  max_h2_connections_per_origin: 4

tls:
  upstream:
    verify: strict             # strict | strict+extra_roots
    extra_roots: []            # PEM files
    min_version: "1.2"         # "1.2" | "1.3"
```

`deny_cidrs` and `allow_cidrs` entries must be networks: `roxy check`
refuses `10.1.2.3/8` and suggests `10.0.0.0/8`.

## DNS

roxy resolves upstream names itself, so the workload's DNS plays no part.
If a name has several addresses, roxy tries them in turn, alternating
IPv4 and IPv6, within one `connect_timeout`. The resolver is set up at
startup, so changing `upstream.dns` needs a
[restart](/guides/operations#restart-only-settings).

## Upstream TLS

roxy verifies every upstream certificate against the Mozilla root
certificates, plus `extra_roots` with `verify: strict+extra_roots`.
Verification cannot be turned off. The TLS handshake has its own
`connect_timeout`.

## Connections

roxy keeps connections to each origin open for reuse, and closes them
after 90 seconds idle. Over HTTP/1.1 it opens one connection per request
in progress. Over HTTP/2 it uses up to `max_h2_connections_per_origin`
connections and spreads requests across them.

If an HTTP/2 origin closes a connection before handling some requests,
roxy retries those without a body on another connection. A request with
a body gets `502`, since its body has already been sent.

## Errors

| failure | response | flow log |
|---|---|---|
| the address floor refuses the address | `403`, `_address_policy` | `upstream_denied` |
| DNS, connection or TLS failure | `502` | `upstream_error`, reason `dns_failed`, `connect_failed` or `tls_failed` |
| a target roxy cannot connect to | `502` | `upstream_error`, reason `invalid_target` |
| a timeout connecting, during the TLS handshake or waiting for the response | `504` | `upstream_error`, reason `timeout` |
| a response roxy cannot parse | `502` | `upstream_error`, reason `protocol_error` |

The client gets the usual refusal body
([deny responses](/reference/http#deny-responses)). The reason is in the
flow log only.
