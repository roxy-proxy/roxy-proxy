# HTTP

How clients talk to roxy, how requests are parsed and canonicalised, and
what goes to the upstream and back.

## Listener modes

| mode | the client speaks | request target |
|---|---|---|
| `http_proxy` (default) | HTTP/1.1 to a proxy (`HTTP_PROXY` / `HTTPS_PROXY`) | absolute-form, or CONNECT and then origin-form inside the tunnel |
| `http` | plain HTTP/1.1 to roxy as if it were the server | origin-form; `Host` names the target |

Each mode accepts one protocol and closes anything else. roxy does not
authenticate clients; rules see `listener.name` and `client.ip`.

```yaml
listeners:
  - name: proxy
    mode: http_proxy           # the default
    bind: 0.0.0.0:3128
```

## HTTP proxy

- **Absolute-form** (`GET http://host/path HTTP/1.1`): plain HTTP; `Host`
  must equal the URI authority.
- **CONNECT**: a tunnel roxy inspects ([below](/reference/http#connect)).
- **Origin-form**: rejected, except to `roxy.internal`, which serves the CA
  certificate at `/roxy-ca.pem`
  ([CA distribution](/guides/ca-certificates#ca-distribution)) and `404`
  for anything else.
- `Proxy-Authorization` is hop-by-hop: dropped, never forwarded.

## HTTP listener

For a gateway behind a TLS-terminating load balancer
([HTTP gateway](/guides/gateway)).

- Only origin-form. Absolute-form, CONNECT and `*` are refused
  (`target_form_mismatch`; `bad_request_target` for `*`) and the connection
  closed.
- The target is `Host`: required, exactly one (`missing_host`,
  `multiple_host`, `bad_authority`), port 80 unless given, scheme `http`.
  Hosts may differ between requests on one connection.
- Without a `redirect` the upstream is the `Host` authority over plain
  HTTP; `redirect` with `scheme: https` sends it on over TLS.
- `roxy.internal` is a host like any other.
- A TLS handshake is closed at the record header (`tls_on_http_listener`).

## CONNECT

A CONNECT gets `200 Connection Established`; decisions are made on the
requests inside the tunnel. The tunnel's first bytes must be:

- **A TLS ClientHello**
  ([ClientHello sniffing](/reference/tls#clienthello-sniffing)). With
  `tls.require_sni_match` (default true) the SNI must name the CONNECT host,
  compared canonicalised (`sni_mismatch`); an unusable SNI is closed
  (`bad_sni`); no SNI means the CONNECT host. roxy terminates TLS with a
  leaf for that host; the inner protocol is HTTP/1.1 or HTTP/2 by ALPN.
- **Plaintext HTTP**, only with `http.allow_plain_in_connect` (default
  false).

Anything else is closed; raw TCP never passes. Inside a tunnel, requests
are origin-form and their `Host` (or `:authority`) must match the SNI /
CONNECT host, port-normalised.

## HTTP/2

Inside a TLS tunnel, by ALPN (`http.enable_h2`, default true). The `h2`
crate parses it; the same semantic validation as HTTP/1.1 follows
([HTTP/2 requests](/reference/http#http2-requests)). Upstream, roxy offers
`h2` and `http/1.1` and serialises as whichever the origin negotiates: the
canonical authority goes out as `host` over HTTP/1.1 and as `:authority`
alone over HTTP/2, never both. WebSocket upgrades always use HTTP/1.1
([WebSockets](/reference/websockets)).

### Trailers

Two settings, one per direction. `http.allow_response_trailers` (default
true) forwards an origin's response trailers to the client, as HTTP/2
trailers or as the trailer section of a chunked HTTP/1.1 response (a
response with a declared length cannot carry them). gRPC, which puts the
call's outcome in `grpc-status`, works by default.
`http.allow_request_trailers` (default false) accepts trailers on requests,
HTTP/2 trailers or a chunked trailer section; without it a request that
carries them is refused with reason `trailers`. Request trailers arrive
after the rules have decided, so they stay opt-in. In either direction a
trailer section may not carry framing, routing, authentication or
`content-*` fields (`authorization`, `cookie`, `set-cookie`, `range`,
`max-forwards`, `cache-control`, every hop-by-hop name): on a request that
is a rejection, on a response the body is cut before the client sees it
complete. A body a rule or addon buffers to read keeps its trailers.

Request trailers reach an origin only over `h2`: HTTP/1.1 needs the names
in a `Trailer` header before the body. Trailers to an HTTP/1.1 origin fail
with reason `trailers` (`400` and close on HTTP/1.1, a stream reset on
HTTP/2) before the origin sees the request complete, for as long as any
HTTP/1.1 connection to that origin is open or pooled (hyper keeps idle
connections about 90 s), including one opened for a request held to
HTTP/1.1.

## Canonical request

The client-facing HTTP/1.1 codec is roxy's own (on `httparse` for
tokenising): ambiguities RFC 9112 lets a server resolve are rejected.

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
`parse_error` flow event with a stable reason code. The knobs live under
`http:` and default to strict.

The header and body rules are one implementation, applied to every request
roxy judges: an HTTP/1.1 head, an HTTP/2 stream, and what a service layer
passes on. Each path adds only its own wire rules ahead of them (line
structure for HTTP/1.1, pseudo-headers and connection-specific fields for
HTTP/2, the fields a layer may not set), so a field list one path refuses
the others refuse for the same reason.

### Request line

- The method is a valid `token`.
- The target form fits the context: absolute-form on the proxy port,
  origin-form in a tunnel or on an `http` listener, authority-form only for
  CONNECT on the proxy port.
- The version is exactly `HTTP/1.1`. `HTTP/1.0` needs `http.allow_http10`
  and its connection closes after the response whatever `Connection` says;
  `HTTP/0.9` is never accepted.
- Lines end in CRLF; a bare LF or CR anywhere in the head is rejected.
- Head at most `limits.max_header_bytes` (64 KiB); URL at most
  `limits.max_url_bytes` (8 KiB).

### Headers

- Names are `token`s, no whitespace before the colon, no obs-fold.
- Values are visible ASCII, SP and HTAB, surrounding whitespace stripped.
  CR, LF, NUL and other controls are rejected; non-ASCII needs
  `http.allow_obs_text`.
- At most `limits.max_headers` (100) fields.
- Exactly one `Host`, matching the URI authority (absolute-form) or the
  SNI / CONNECT host (tunnel); on an `http` listener it names the target.
  An HTTP/1.0 absolute-form request may omit it.
- At most one `Proxy-Authorization`.
- At most one `Content-Length`, digits only, at most 19 digits; a duplicate
  is rejected even with equal values. A non-zero length declared for a body
  that has already ended (a layer passing `content-length` with an empty
  body) is `bad_content_length`, not an empty body.
- `Transfer-Encoding`, if present, is exactly `chunked`: one field, one
  value, no parameters, no other codings; rejected together with
  `Content-Length`.
- GET, HEAD, DELETE, OPTIONS, CONNECT and TRACE with a non-empty body need
  `http.allow_body_on_get`.
- `Expect` may only be `100-continue`; anything else gets `417`. roxy sends
  `100 Continue` once the rules allow the request; when a rule reads the
  request body it goes out before the body is judged, and a deny follows
  the body.
- Hop-by-hop fields (`Connection` and every field it names, `Keep-Alive`,
  `Proxy-Connection`, `Proxy-Authorization`, `TE`, `Trailer`,
  `Transfer-Encoding`, `Upgrade`) are consumed and never forwarded.
  `Upgrade` is honoured only for a WebSocket a rule allows.

### Body

- Chunk sizes are hex, at most 16 digits. Chunk extensions need
  `http.allow_chunk_extensions`; trailers need `http.allow_request_trailers`
  and an `h2` origin ([trailers](/reference/http#trailers)). The final CRLF
  is enforced.
- At most `limits.max_request_body_bytes` (1 GiB), enforced while
  streaming: exceeding it closes the connection mid-stream.
- The head must arrive within `limits.header_timeout` (10 s) of its first
  byte, whether that byte opened the connection or was pipelined. The body
  may not stall longer than `limits.body_idle_timeout` (10 m), which also
  bounds how long the client may go without taking the next part of the
  response (on HTTP/2: stream reset with `CANCEL`, `response_error`, reason
  `client_stalled`).
- A client that closes while roxy still waits for the response ends the
  exchange; nothing is written back; reason `client_gone`.

### HTTP/2 requests

- Pseudo-headers (`:method`, `:scheme`, `:authority`, `:path`) exactly once
  each, before regular headers.
- Connection-specific headers (`connection`, `keep-alive`,
  `transfer-encoding`, `upgrade`, `proxy-connection`) reset the stream
  (RFC 9113 §8.2.2). `te` is accepted only as `trailers`.
- `:path` goes through the same normaliser and `limits.max_url_bytes` cap.
  `:authority` must equal the SNI; a `host` header, if present, must equal
  `:authority`.
- `limits.h2_max_concurrent_streams` and `limits.h2_max_header_list_bytes`
  cap streams per connection and header bytes per stream.
  CONTINUATION-flood and rapid-reset defences come from the `h2` crate.
- The first stream must open within `limits.header_timeout`; between
  requests the connection may idle for `limits.idle_timeout`.

## URL normalisation

Applied to the request target, for matching and forwarding alike.

1. The path starts with `/` and contains `pchar` and `/`, with well-formed
   percent-encodings. `[ ] { } | ^` and `` ` `` are percent-encoded rather
   than rejected (`/a|b` becomes `/a%7Cb`). Space, control bytes, `"`,
   `<`, `>`, `\` and non-ASCII are rejected.
2. Percent-encoded unreserved characters (`A–Z a–z 0–9 - . _ ~`) are
   decoded; other encodings stay (`%2F` stays `%2F`).
3. Hex digits in the remaining encodings are upper-cased.
4. Dot segments (including ones `%2E`-encoded before step 2) are removed
   per RFC 3986 §5.2.4. A path that climbs above the root is rejected.
5. An empty path becomes `/`.
6. The query is validated the same way and its hex upper-cased. `/`, `?`,
   `[` and `]` are also allowed raw; `{ } | ^` and `` ` `` are
   percent-encoded; nothing is decoded. It is parsed into pairs for
   matching only.
7. A fragment in an HTTP/1.1 target is rejected. The `h2` crate drops a
   fragment from an HTTP/2 `:path` before roxy sees it.
8. The host is lower-cased; IDNA labels must already be A-labels (`xn--`),
   raw Unicode is rejected; the port is made explicit; a trailing dot is
   removed.

## Upstream serialisation

HTTP/2 or HTTP/1.1, whichever ALPN negotiates. HTTP/2 takes the
pseudo-headers from the canonical fields and drops `host` for
`:authority`. HTTP/1.1:

- `METHOD <origin-form path[?query]> HTTP/1.1`;
- `host` first, then the headers in canonical order, lowercase;
- `content-length` when known, otherwise clean `chunked` with no
  extensions, never both; a body with trailers fails instead;
- connection management by roxy's pool; no client hop-by-hop field
  survives.

Changes from rules and addons are applied to the canonical model before
serialisation and pass the same validation: a header value with a CRLF
denies the flow.

## Responses

Upstreams are trusted ([threat model](/design/threat-model)). hyper parses
the response and roxy builds a `CanonicalResponse`:

- Status and headers are kept, names lower-cased; `Set-Cookie` and
  `WWW-Authenticate` stay separate fields.
- Hop-by-hop fields are stripped and the framing regenerated:
  `content-length` when known, otherwise clean chunked (HTTP/1.1) or DATA
  frames (HTTP/2), with the origin's trailers after the body
  ([trailers](/reference/http#trailers)). Responses to HEAD, and `1xx`,
  `204` and `304`, carry no body. Empty non-final DATA frames are never
  sent upstream.
- `limits.max_response_body_bytes` (1 GiB) caps the body.
  `limits.response_header_timeout` (15 m) starts once the request body has
  been sent; while it is still being sent, the exchange fails (`504`) only
  if the upstream stops taking it for twice `limits.body_idle_timeout`.
- The upstream may pause up to `limits.response_body_idle_timeout` (30 m)
  between parts of the body; longer ends the exchange (`response_error`,
  reason `response_body_timeout`): close on HTTP/1.1, `CANCEL` on HTTP/2.
- A client that closes while roxy waits for the next part of the body ends
  the exchange at once on both versions: the body is dropped, releasing the
  upstream and any service streams; a part already there is still written.
  On HTTP/1.1 a client that shut down only its sending side counts as gone.
- Redirects are forwarded, not followed. Encoded bodies pass through
  untouched ([below](/reference/http#content-codings)).

## Content codings

roxy decodes `content-encoding` to inspect a body, never to forward it:
`body.text` and `response.body.text` see the decoded text
([body rules](/reference/rule-language#body-rules)); the bytes forwarded
are the bytes received. The one exception is addons: bodies are decoded at
the edge of the stack and forwarded decoded
([content codings for addons](/reference/addon-configuration#content-codings)).

| coding | format |
|---|---|
| `gzip`, `x-gzip` | RFC 1952; several members in a row are one body |
| `deflate` | zlib format (RFC 1950), as RFC 9110 defines it; raw deflate is refused |
| `br` | RFC 7932, the window the stream declares (up to 16 MiB) |
| `zstd` | RFC 8878, window at most 8 MiB (RFC 9659) |

- Stacked codings are undone in reverse order; `identity` is ignored; at
  most 4 codings, more is refused.
- An empty body is empty whatever its coding.
- Decoding is strict: truncated data, a bad checksum, or bytes after the
  end of the stream make the body undecodable.
- Decoders work in bounded steps (a highly compressed body costs time, not
  memory); each decoder's window is charged to the
  [buffer budget](/reference/limits#buffer-budget) before it is allocated.
  The decoded size counts against the same cap as the body as sent.

`http.strip_accept_encoding` (default false) removes `accept-encoding` from
every request as roxy reads it, so origins answer uncompressed. Addons,
rules and the flow log see the request without it.

## Deny responses

```
HTTP/1.1 403 Forbidden
content-type: application/json
cache-control: no-store
x-roxy-rule: <rule id>
connection: close

{"error":"blocked by roxy","rule":"<rule id>","flow":"<flow id>"}
```

Every refusal roxy originates has this body:

| refusal | status | `rule` |
|---|---|---|
| a rule denies | `403`, or the rule's `deny.status` | the rule id |
| address floor | `403` | `_address_policy` |
| unavailable policy input | `503` | `_fail_closed` |
| failed addon layer | `503` | `layer:<name>` |
| upstream failure | `502` (`504` for a timeout) | none |

The body names the rule and the flow, never why: the reason code
(`dns_failed`, `connect_failed`, `metric_table_full`, ...) is in the flow
log only.

A request roxy cannot parse is refused with a different body, before any
rule has seen it:

```
HTTP/1.1 400 Bad Request
content-type: application/json
connection: close

{"error":"rejected by roxy","reason":"cl_and_te"}
```

`reason` is the `parse_error` code ([rejection rules](/reference/http#rejection-rules)),
which describes the request's syntax and says nothing about policy. The
status is `400`, or the closer one the code has (`413`, `414`, `431`, ...);
on HTTP/2 the stream is reset instead.

A rule sets the status and message with `deny: { status: 451, message:
"..." }`. After a deny the connection is closed (`connection: close` on
HTTP/1.1, `GOAWAY` on HTTP/2) unless the rule says `deny: { close: false
}`; roxy does not read the rest of a refused request body. After an
upstream failure (`502`, `504`) the connection stays open on both versions.
