# HTTP

How clients talk to roxy, how requests are parsed, and what goes to the
upstream and back.

## Listener modes

| mode | the client speaks | request target |
|---|---|---|
| `http_proxy` (default) | HTTP/1.1 to a proxy (`HTTP_PROXY` / `HTTPS_PROXY`) | absolute-form, or CONNECT and then origin-form inside the tunnel |
| `http` | plain HTTP/1.1 to roxy as if it were the server | origin-form; `Host` names the target |

roxy does not authenticate clients. Rules see `listener.name` and
`client.ip`.

```yaml
listeners:
  - name: proxy
    mode: http_proxy           # the default
    bind: 0.0.0.0:3128
    quarantine_on:             # optional
      parse_errors: { count: 20, window: 1m }
  - name: gateway
    mode: http
    bind: 0.0.0.0:8080
    forwarded_for:             # optional; mode: http only
      trusted_hops: 1          # the proxies in front of roxy
```

`quarantine_on.parse_errors` [quarantines](/guides/operations#quarantine)
roxy once the listener has refused `count` malformed requests within
`window`. It needs `roxy run --state-dir`.

## HTTP proxy

* **Absolute-form** (`GET http://host/path HTTP/1.1`) is plain HTTP.
  `Host` must match the URL.
* **CONNECT** opens a tunnel that roxy inspects ([below](/reference/http#connect)).
* **Origin-form** is refused, except for the host `roxy.internal`, which
  serves the CA at `/roxy-ca.pem`
  ([CA distribution](/guides/ca-certificates#ca-distribution)).
* `Proxy-Authorization` is never forwarded.

## HTTP listener

For a gateway behind a load balancer that terminates TLS
([HTTP gateway](/guides/gateway)).

* Only origin-form requests are accepted.
* `Host` names the target: exactly one, port 80 unless given, scheme
  `http`. Without a `redirect` the request goes to that host over plain
  HTTP.
* A client that starts a TLS handshake is closed
  (`tls_on_http_listener`).

### Clients behind a load balancer

Without `forwarded_for`, `client.ip` is the TCP peer, which behind a load
balancer is the load balancer. With `forwarded_for.trusted_hops: N`, each
of the N proxies in front of roxy is taken to append the address it saw
to `X-Forwarded-For`, so the client is the Nth entry from the right.
Entries further left were written by the client and are ignored.

* That address is `client.ip` everywhere: rules, metric keys, addons and
  the flow log. The flow log also records the TCP peer as `client.peer`.
* A request with fewer entries than hops, or with a trusted entry that is
  not a plain IP address, is refused with `400`
  (`forwarded_for_invalid`). It is never attributed to the peer instead.
* The header is forwarded as received.

The hop count does not prove that a request came through those proxies.
A client that can reach the listener directly can write its own entries,
so the network must let only the trusted proxies reach the listener.

## CONNECT

A CONNECT gets `200 Connection Established`. Rules decide on the requests
inside the tunnel. The tunnel's first bytes must be:

* **A TLS ClientHello.** With `tls.require_sni_match` (default true) the
  SNI must name the CONNECT host (`sni_mismatch`). roxy terminates TLS
  with a certificate for that host, then reads HTTP/1.1 or HTTP/2.
* **Plain HTTP**, only with `http.allow_plain_in_connect` (default
  false).

Anything else is closed, so raw TCP never passes. Requests inside the
tunnel must name the CONNECT host.

## HTTP/2

roxy offers HTTP/2 inside TLS tunnels (`http.enable_h2`, default true).
Upstream, it uses HTTP/2 or HTTP/1.1, whichever the origin chooses.
WebSocket upgrades always use HTTP/1.1
([WebSockets](/reference/websockets)).

### Informational responses

roxy does not relay `1xx` responses from upstream, such as
`103 Early Hints`. It sends its own `100 Continue` once the rules allow an
upload.

### Trailers

`http.allow_response_trailers` (default true) forwards an origin's
response trailers, so gRPC works. `http.allow_request_trailers` (default
false) accepts trailers on requests; without it, a request with trailers
is refused (`trailers`). Request trailers arrive after the rules have
decided, which is why they are opt-in, and can only be forwarded to an
HTTP/2 origin.

A trailer may not carry framing, routing, authentication or `content-*`
fields. A request with one is refused. A response with one is ended
early, so the client never sees it as complete.

## Rejection rules

A malformed request closes the connection and logs a `parse_error` event
with a stable reason code. The settings under `http:` default to strict.
The same checks apply to HTTP/1.1, HTTP/2 and requests an addon passes on.

### Request line

* The method is a token of at most 32 bytes.
* The version is `HTTP/1.1`. `HTTP/1.0` needs `http.allow_http10`.
* Lines end in CRLF. A bare LF or CR anywhere in the head is refused.
* The head is at most `limits.max_header_bytes` (64 KiB) and the URL at
  most `limits.max_url_bytes` (8 KiB).

### Headers

* No whitespace before the colon, no folded lines.
* Values are visible ASCII, space and tab. Control characters are
  refused. Bytes above 127 need `http.allow_obs_text`, and rules read
  each as one ISO-8859-1 character.
* At most `limits.max_headers` (100) fields.
* Exactly one `Host`, matching the URL or the CONNECT host.
* A host is a DNS name in ASCII (internationalised names as `xn--`
  labels), an IPv4 address, or a bracketed IPv6 address.
* At most one `Content-Length`, digits only. A duplicate is refused even
  with the same value.
* `Transfer-Encoding`, if present, is exactly `chunked`, and never
  together with `Content-Length`.
* GET, HEAD, DELETE, OPTIONS and TRACE may carry a body only with
  `http.allow_body_on_get` (`body_on_bodiless_method`).
* `Expect` may only be `100-continue`; anything else gets `417`.
* Hop-by-hop fields (`Connection` and the fields it names, `Keep-Alive`,
  `Proxy-Connection`, `Proxy-Authorization`, `Proxy-Authenticate`, `TE`,
  `Trailer`, `Transfer-Encoding`, `Upgrade`) are never forwarded.
  `Upgrade` is honoured only for a WebSocket a rule allows.

### Body

* Chunk extensions need `http.allow_chunk_extensions`.
* A body is at most `limits.max_request_body_bytes` (1 GiB).
* Timeouts are in [limits](/reference/limits#limits).

### HTTP/2 requests

* The pseudo-headers appear exactly once each, before other headers.
* Connection-specific headers reset the stream. `te` is accepted only as
  `trailers`.
* `:path` is normalised like an HTTP/1.1 target. `:authority` must match
  the CONNECT host, and so must `host` if present.
* `limits.h2_max_concurrent_streams` and `limits.h2_max_header_list_bytes`
  cap streams per connection and header bytes per stream.

## URL normalisation

Applied to the request target, for matching and forwarding alike.

1. The path starts with `/`. Percent-encodings must be well formed.
   `[ ] { } | ^` are percent-encoded. Space, control characters, `"`, `<`,
   `>`, `\`, a backtick and non-ASCII are refused.
2. Percent-encoded unreserved characters (`A–Z a–z 0–9 - . _ ~`) are
   decoded. Other encodings stay as they are: `%2F` stays `%2F`.
3. Hex digits in the remaining encodings are upper-cased.
4. Dot segments are removed, including encoded ones. A path that climbs
   above the root is refused.
5. An empty path becomes `/`.
6. The query is validated the same way, but nothing in it is decoded.
7. A fragment is refused.
8. The host is lower-cased, its trailing dot removed, and the port made
   explicit.

## Upstream requests

roxy writes the request out in one canonical form, over HTTP/2 or
HTTP/1.1. Changes made by rules and addons pass the same validation as
the client's request: a header value containing a line break denies the
exchange.

## Responses

Upstreams are trusted ([threat model](/design/threat-model)), but roxy
re-frames every response: hop-by-hop fields are removed and the framing
rebuilt. Redirects are forwarded, not followed. Compressed bodies pass
through unchanged. Size and time limits are in
[limits](/reference/limits#limits).

## Content codings

roxy decodes `content-encoding` only to inspect a body. `body.text` and
`response.body.text` see the decoded text, while the bytes forwarded are
the bytes received ([body rules](/reference/rule-language#body-rules)).
Addons are the exception: by default they get decoded bodies
([content codings for addons](/reference/addon-configuration#content-codings)).

roxy decodes `gzip`, `x-gzip`, `deflate`, `br` and `zstd`, stacked up to
four deep. Decoding is strict: a truncated or corrupt body cannot be
inspected, and a rule that reads it fails closed.

`http.strip_accept_encoding` (default false) removes `accept-encoding`
from every request, so origins answer uncompressed.

## Deny responses

Every refusal roxy makes has the same shape:

```
HTTP/1.1 403 Forbidden
content-type: application/json
cache-control: no-store
x-roxy-rule: <rule id>
connection: close

{"error":"blocked by roxy","rule":"<rule id>","flow":"<flow id>"}
```

| refusal | status | `rule` |
|---|---|---|
| a rule denies | `403`, or the rule's `deny.status` | the rule id |
| roxy is quarantined | `403` | `_quarantined` |
| address floor | `403` | `_address_policy` |
| unavailable policy input | `503` | `_fail_closed` |
| failed addon | `503` | `layer:<name>` |
| upstream failure | `502` (`504` for a timeout) | none |

The response never says why. The reason is in the flow log only.

A malformed request is refused before any rule sees it, with its reason:

```
HTTP/1.1 400 Bad Request
content-type: application/json
connection: close

{"error":"rejected by roxy","reason":"cl_and_te"}
```

The status is `400`, or a closer one for the reason (`413`, `414`,
`431`). On HTTP/2 the stream is reset instead.

A rule sets the status and message with
`deny: { status: 451, message: "..." }`. After a deny the connection is
closed, unless the rule says `deny: { close: false }`. After an upstream
failure the connection stays open.
