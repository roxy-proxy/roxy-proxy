# HTTP

How clients talk to roxy, how requests are parsed and canonicalised, and
what goes to the upstream and back. The parsing lives in `roxy-http`; the
connection handling in `roxy-proxy`.

## Explicit proxy

Clients set `HTTP_PROXY` / `HTTPS_PROXY` and speak HTTP/1.1 to an
explicit listener.

```yaml
listeners:
  - name: proxy                # rules can match listener.name
    mode: explicit             # the default, and the only mode
    bind: 0.0.0.0:3128
```

On the proxy port:

- **Absolute-form requests** (`GET http://host/path HTTP/1.1`) are plain
  HTTP. The `Host` header must equal the URI authority.
- **CONNECT** opens a tunnel that roxy inspects ([below](/reference/http#connect)).
- **Origin-form requests** (`GET /path`) are rejected, except to the host
  `roxy.internal`, which serves the CA certificate at `/roxy-ca.pem`
  ([TLS](/operate/ca-certificates#ca-distribution)). Anything else there is `404`.

roxy does not authenticate clients: a client is who its network position
says it is, which rules see as `listener.name` and `client.ip`. A `Proxy-Authorization` header is hop-by-hop and dropped, never
forwarded.

## CONNECT

A CONNECT gets `200 Connection Established`. There
are no connect-time rules: every allow or deny decision is made on the
requests inside the tunnel. roxy then peeks the tunnel's first bytes:

- **A TLS ClientHello:** roxy reads the SNI and ALPN
  ([ClientHello sniffing](/reference/tls#clienthello-sniffing)). The SNI must name
  the CONNECT host (`tls.require_sni_match`, default true), compared after
  both are canonicalised (`sni_mismatch` otherwise); an SNI that is not a usable
  host name is closed (`bad_sni`). A client that sends no SNI gets the CONNECT
  host. roxy terminates TLS with a leaf for that host, and the inner protocol
  must be HTTP/1.1 or HTTP/2 by ALPN.
- **Plaintext HTTP**, if `http.allow_plain_in_connect` is true (default
  false): parsed as HTTP.
- **Anything else:** the connection is closed. Raw TCP never passes
  through CONNECT.

Inside a tunnel, requests are origin-form, and their `Host` (or
`:authority`) must match the SNI / CONNECT host, port-normalised.

## HTTP/2

Clients may speak HTTP/2 inside a TLS tunnel, negotiated by ALPN
(`http.enable_h2`, default true; every mainstream client falls back to
HTTP/1.1 when it is off). HTTP/2 uses the `h2` crate, which is strict by
spec, followed by the same semantic validation as HTTP/1.1
([HTTP/2 requests](/reference/http#http2-requests)). Upstream, roxy offers `h2` and
`http/1.1` and serialises each request as whichever the origin negotiates;
the canonical model is version-agnostic. WebSocket upgrades always use
HTTP/1.1 ([WebSockets](/policies/websockets)).

gRPC and other HTTP/2-only protocols need trailers: set
`http.allow_trailers`. Request trailers are forwarded only when the origin
negotiates `h2`. HTTP/1.1 cannot carry them without naming them in a
`Trailer` header up front, and roxy does not know the names until the body
ends, so a request that carries trailers to an HTTP/1.1 origin fails with
the `trailers` reason (`400` and the connection closed on HTTP/1.1, a
stream reset on HTTP/2) before the origin sees it complete.

## Canonical request

The client-facing HTTP/1.1 codec is roxy's own, built on `httparse` for
tokenising. It does not use hyper's server because hyper resolves
ambiguities as RFC 9112 allows (for example, chunked wins when both
`Transfer-Encoding` and `Content-Length` are present), and roxy must reject
them instead.

```rust
pub struct CanonicalRequest {
    pub method: Method,        // validated token
    pub scheme: Scheme,        // Http | Https
    pub authority: Authority,  // host (DNS name | IPv4 | IPv6), port always explicit
    pub path: Path,            // normalised, see below
    pub query: Option<Query>,  // validated raw bytes, parsed pairs for matching
    pub headers: Headers,      // lowercase names, ordered, validated, hop-by-hop removed
    pub body: Body,            // Empty | Sized | Chunked stream, caps enforced
    pub meta: RequestMeta,     // client version, ids, timestamps
}
```

## Rejection rules

A violation closes the connection, not just the request, and emits a
`parse_error` flow event with a stable reason code that can be alerted on.
The strictness knobs live under `http:` and all default to strict.

### Request line

- The method must be a valid `token`.
- The request-target form must fit the context: absolute-form on the proxy
  port, origin-form inside a tunnel, authority-form only for CONNECT.
- The version must be exactly `HTTP/1.1`. `HTTP/1.0` needs
  `http.allow_http10`, and an HTTP/1.0 connection is closed after its
  response whatever `Connection` says; `HTTP/0.9` is never accepted.
- Lines end in CRLF. A bare LF or bare CR anywhere in the head is rejected.
- The head is at most `limits.max_header_bytes` (64 KiB) and the URL at
  most `limits.max_url_bytes` (8 KiB).

### Headers

- Names are `token`s, with no whitespace before the colon and no obs-fold.
- Values are visible ASCII, SP and HTAB, with surrounding whitespace
  stripped. CR, LF, NUL and other control characters are rejected;
  non-ASCII needs `http.allow_obs_text`.
- At most `limits.max_headers` (100) fields.
- Exactly one `Host`, matching the URI authority (absolute-form) or the
  SNI / CONNECT host (in a tunnel). An HTTP/1.0 absolute-form request
  (`http.allow_http10`) may omit it; the URI names the target.
- At most one `Proxy-Authorization`.
- At most one `Content-Length`, digits only, at most 19 digits. A
  duplicate is rejected even when the values are equal.
- `Transfer-Encoding`, if present, is exactly `chunked`: one field, one
  value, no parameters, no other codings.
- `Content-Length` and `Transfer-Encoding` together are rejected.
- GET, HEAD, DELETE, OPTIONS, CONNECT and TRACE with a non-empty body are
  rejected unless `http.allow_body_on_get`.
- `Expect` may only be `100-continue`; roxy sends `100 Continue` itself once
  the rules allow the request. When a rule reads the request body
  (`body.text`, `body.bytes`, ...) the body is part of the decision, so the
  `100 Continue` goes out before it; a deny then follows the body. Anything
  else gets `417`.
- Hop-by-hop fields (`Connection` and every field it names, `Keep-Alive`,
  `Proxy-Connection`, `Proxy-Authorization`, `TE`, `Trailer`,
  `Transfer-Encoding`, `Upgrade`) are consumed by roxy and never forwarded.
  `Upgrade` is honoured only for a WebSocket a rule allows.

### Body

- Chunk sizes are hex digits only, at most 16. Chunk extensions need
  `http.allow_chunk_extensions`; trailers need `http.allow_trailers` and
  an origin that negotiates `h2` (see above). The final CRLF is enforced.
- The body is at most `limits.max_request_body_bytes` (1 GiB), enforced
  while streaming: exceeding it closes the connection mid-stream. The
  default is generous so large uploads work.
- The head must arrive within `limits.header_timeout` (10 s) of its first
  byte, whether that byte opened the connection or was pipelined behind
  the previous request. The body may not stall for longer than
  `limits.body_idle_timeout` (30 s), which also bounds how long the client
  may go without taking the next part of the response (on HTTP/2 the
  stream is reset with `CANCEL`; `response_error`, reason `client_stalled`).
- A client that closes its connection while roxy is still waiting for the
  response ends the exchange, body or no body. Nothing is written back, and
  the flow is logged with reason `client_gone`.

### HTTP/2 requests

- Pseudo-headers (`:method`, `:scheme`, `:authority`, `:path`) appear
  exactly once each, before regular headers.
- Connection-specific headers (`connection`, `keep-alive`,
  `transfer-encoding`, `upgrade`, `proxy-connection`) reset the stream
  (RFC 9113 §8.2.2). `te` is accepted only as `trailers`.
- `:path` goes through the same normaliser and `limits.max_url_bytes` cap
  as HTTP/1.1. `:authority` must equal the SNI, and a `host` header, if
  present, must equal `:authority`.
- Streams per connection and header bytes per stream are capped by
  `limits.h2_max_concurrent_streams` and `limits.h2_max_header_list_bytes`.
  CONTINUATION-flood and rapid-reset defences come from the `h2` crate.
- The first stream must open within `limits.header_timeout` of the
  connection, as an HTTP/1.1 request head must; between requests the
  connection may idle for `limits.idle_timeout`.

## URL normalisation

Applied to the request target, both for rule matching and for what is
forwarded, so the upstream sees exactly what the rules matched.

1. The path starts with `/` and contains `pchar` and `/`, with well-formed
   percent-encodings. The visible ASCII that mainstream clients send raw
   but RFC 3986 excludes (`[ ] { } | ^` and `` ` ``) is percent-encoded
   rather than rejected, so `/a|b` is forwarded and matched as `/a%7Cb`.
   Space, control bytes, `"`, `<`, `>`, `\` and non-ASCII are rejected.
2. Percent-encoded unreserved characters (`A–Z a–z 0–9 - . _ ~`) are
   decoded. Other encodings stay as they are, so `%2F` stays `%2F`: roxy
   takes no position on whether it is a separator, and the client cannot
   exploit the difference because matching and forwarding agree.
3. Hex digits in the remaining encodings are upper-cased.
4. Dot segments (including ones that were `%2E`-encoded before step 2) are
   removed per RFC 3986 §5.2.4. A path that climbs above the root is
   rejected.
5. An empty path becomes `/`.
6. The query is validated the same way and its hex upper-cased. `/`, `?`,
   `[` and `]` are also allowed raw; `{ } | ^` and `` ` `` are
   percent-encoded; nothing is decoded. It is parsed into pairs for
   matching only.
7. A fragment in an HTTP/1.1 request target is rejected. The `h2` crate
   drops a fragment from an HTTP/2 `:path` before roxy sees it; matching and
   forwarding both use the path without it.
8. The host is lower-cased; IDNA labels must already be A-labels (`xn--`)
   and raw Unicode is rejected; the port is made explicit; a trailing dot is
   removed.

## Upstream serialisation

The canonical request is written to the origin as HTTP/2 or HTTP/1.1,
whichever ALPN negotiates. For HTTP/2 the mapping is the obvious one
(pseudo-headers from the canonical fields, `host` dropped for
`:authority`). The HTTP/1.1 form:

- `METHOD <origin-form path[?query]> HTTP/1.1`;
- `host` first, then the headers in canonical order, lowercase;
- `content-length` when the length is known, otherwise clean `chunked`
  with no extensions, never both. A body with trailers is not sent over
  HTTP/1.1: the request fails instead;
- connection management by roxy's pool; no client hop-by-hop field
  survives.

Changes from rules and addons are applied to the canonical model before
serialisation, so they pass the same validation: a header value with a CRLF
in it is rejected and the flow denied.

## Responses

Upstreams are trusted, so the response side is about clean re-framing and
resource limits. hyper parses the response and roxy builds a
`CanonicalResponse` from it:

- Status and headers are kept, names lower-cased. `Set-Cookie` and
  `WWW-Authenticate` stay separate fields, never combined.
- Hop-by-hop fields are stripped and the framing is regenerated for the
  client: `content-length` when known, otherwise clean chunked (HTTP/1.1)
  or DATA frames (HTTP/2). Responses to HEAD, and `1xx`, `204` and `304`
  responses, carry no body.
- Empty non-final DATA frames are never sent upstream: HTTP/2 servers treat
  them as a flood.
- `limits.max_response_body_bytes` (1 GiB) caps the body.
  `limits.response_header_timeout` (60 s) starts once the request body has
  been sent, so a long upload is not cut short by it. While the body is
  still being sent, the exchange fails (`504`) only if the upstream stops
  taking it for twice `limits.body_idle_timeout`.
- The upstream may pause for up to `limits.response_body_idle_timeout`
  (5 m) between parts of the response body. A longer pause ends the
  exchange (`response_error`, reason `response_body_timeout`): on HTTP/1.1
  the connection closes, on HTTP/2 the stream is reset with `CANCEL`.
- A client that closes its connection while roxy waits for the next part
  of the response body ends the exchange at once, on HTTP/1.1 as on
  HTTP/2: the body is dropped, which releases the upstream and any service
  streams. A body that is already there is still written. HTTP/1.1 cannot
  tell a client that only shut down its sending side from one that left,
  so it treats both as gone.
- Redirects are forwarded, not followed. The client's next request is a new
  exchange, judged on its own.
- Encoded bodies pass through untouched ([below](/reference/http#content-codings)).

## Content codings

roxy decodes `content-encoding` to inspect a body, never to forward it:
`body.text` and `response.body.text` see the decoded text
([rules](/policies/body-rules)), and the bytes forwarded are the bytes
received.

| coding | format |
|---|---|
| `gzip`, `x-gzip` | RFC 1952; several members in a row are one body |
| `deflate` | the zlib format (RFC 1950), as RFC 9110 defines it; raw deflate is refused |
| `br` | RFC 7932 |
| `zstd` | RFC 8878, with a window of at most 8 MiB (RFC 9659) |

- Codings listed together are undone in reverse order. `identity` is
  ignored. At most 4 codings are decoded; more is refused.
- An empty body is empty whatever its coding.
- Decoding is strict. Truncated data, a bad checksum, or any bytes after
  the end of the stream make the body undecodable, so nothing the rules did
  not see can follow what they did.
- The decoders work in bounded steps: a highly compressed body costs time,
  not memory. The decoded size counts against the same cap as the body as
  sent.

With addons, roxy also decodes bodies at the edge of the stack, so layers
see them decoded ([addons](/addons/overview#content-codings)). This is the one case
where roxy forwards a body decoded.

`http.strip_accept_encoding` (default false) removes `accept-encoding` from
every request as roxy reads it, so origins answer uncompressed. The addons,
the rules and the flow log all see the request without it. This trades
bandwidth from the origin for no decoding at all.

## Deny responses

When roxy denies a request it answers itself:

```
HTTP/1.1 403 Forbidden
content-type: application/json
cache-control: no-store
x-roxy-rule: <rule id>
connection: close

{"error":"blocked by roxy","rule":"<rule id>","flow":"<flow id>"}
```

Every refusal roxy originates has this body. The address floor answers
`403` with `rule: _address_policy`; an unavailable policy input answers
`503` with `rule: _fail_closed`; a failed addon layer answers `503` with
`rule: layer:<name>`; an upstream failure answers `502` (`504` for a
timeout) with no `rule`. The body never says why: the reason code
(`dns_failed`, `connect_failed`, `metric_table_full`, ...) is in the flow
log only, so a client cannot tell an unresolvable name from a closed port,
or learn that a table is full.

The status and message can be set per rule
(`deny: { status: 451, message: "..." }`). After a deny the connection is
closed (`connection: close` on HTTP/1.1, `GOAWAY` on HTTP/2) unless the
rule says `deny: { close: false }`, so a probing
client loses its warm connection on every attempt, and roxy does not read
the rest of a request body it has refused: the response goes out at once
and the connection closes behind it. An upstream failure (`502`, `504`)
says nothing about the client, so the connection stays open on both
versions.
