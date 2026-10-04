# HTTP

How clients talk to roxy, how requests are parsed and canonicalised, and
what goes to the upstream and back. The parsing lives in `roxy-http`; the
connection handling in `roxy-proxy`.

## Explicit proxy

Clients set `HTTP_PROXY` / `HTTPS_PROXY` and speak HTTP/1.1 to an
explicit listener. (Clients without proxy settings use [direct
listeners](#direct-listeners) instead.)

```yaml
listeners:
  - name: proxy                # rules can match listener.name
    mode: explicit             # the default; or direct
    bind: 0.0.0.0:3128
    auth:                      # optional
      basic: { users_file: /etc/roxy/users }
```

On the proxy port:

- **Absolute-form requests** (`GET http://host/path HTTP/1.1`) are plain
  HTTP. The `Host` header must equal the URI authority.
- **CONNECT** opens a tunnel that roxy inspects ([below](#connect)).
- **Origin-form requests** (`GET /path`) are rejected, except to the host
  `roxy.internal`, which serves the CA certificate at `/roxy-ca.pem`
  ([TLS](tls.md#ca-distribution)). Anything else there is `404`.

### Proxy authentication

With `auth.basic`, every request and CONNECT needs
`Proxy-Authorization: Basic`, checked against a file of `user:bcrypt-hash`
lines (blank lines and `#` comments ignored). A missing or wrong credential
gets `407`. Unknown users are checked against a dummy hash, so they take as
long as known ones. The user becomes `client.user` in rules and in the flow
log. `Proxy-Authorization` is never forwarded.

## CONNECT

A CONNECT that passes proxy auth gets `200 Connection Established`. There
are no connect-time rules: every allow or deny decision is made on the
requests inside the tunnel. roxy then peeks the tunnel's first bytes:

- **A TLS ClientHello:** roxy reads the SNI and ALPN
  ([ClientHello sniffing](tls.md#clienthello-sniffing)). The SNI must equal
  the CONNECT host (`tls.require_sni_match`, default true); a client that
  sends no SNI gets the CONNECT host. roxy terminates TLS with a leaf for
  that host, and the inner protocol must be HTTP/1.1 or HTTP/2 by ALPN.
- **Plaintext HTTP**, if `http.allow_plain_in_connect` is true (default
  false): parsed as HTTP.
- **Anything else:** the connection is closed. Raw TCP never passes
  through CONNECT.

Inside a tunnel, requests are origin-form, and their `Host` (or
`:authority`) must match the SNI / CONNECT host, port-normalised.

## Direct listeners

A direct listener takes connections that a client addressed to the origin
itself, usually because roxy's [DNS listener](dns.md) answered the
origin's name with roxy's address. The client has no proxy settings and
does not know roxy is there.

```yaml
listeners:
  - { name: https, mode: direct, bind: 0.0.0.0:443 }
  - { name: http,  mode: direct, bind: 0.0.0.0:80 }
  - { name: alt,   mode: direct, bind: 0.0.0.0:8443, target_port: 443 }
```

The target's port is `target_port`: the port clients connect to. It
defaults to the bind port; set it when something in between (such as
Docker port publishing) maps one port to another. roxy peeks at the first
bytes, as it does inside a CONNECT tunnel:

- **A TLS ClientHello with an SNI:** the target is the SNI and
  `target_port`. roxy terminates TLS with a leaf for the SNI, and from
  there the connection is a terminated tunnel: ALPN `h2` or `http/1.1`,
  origin-form requests whose `Host` must match the SNI. A ClientHello
  without an SNI is closed (`no_sni`): roxy cannot know the target. So
  is one whose SNI is not a usable host name (`bad_sni`).
- **Plaintext HTTP:** origin-form requests, and each request's `Host`
  names its target. `Host` is required, and its port (80 when absent)
  must equal `target_port` (`host_mismatch` otherwise). `roxy.internal`
  serves the CA certificate here, as on the proxy port.
- **Anything else:** the connection is closed (`non_http_on_direct`).

roxy resolves the target name itself ([upstream](upstream.md#dns)); the
address the client connected to is roxy's own and plays no part. There are
no connect-time rules: every decision is made on the requests, and
`listener.mode` is `direct` in rules. Direct listeners take no `auth`,
since their clients send no `Proxy-Authorization`.

## HTTP/2

Clients may speak HTTP/2 inside a TLS tunnel, negotiated by ALPN
(`http.enable_h2`, default true; every mainstream client falls back to
HTTP/1.1 when it is off). HTTP/2 uses the `h2` crate, which is strict by
spec, followed by the same semantic validation as HTTP/1.1
([HTTP/2 requests](#http2-requests)). Upstream, roxy offers `h2` and
`http/1.1` and serialises each request as whichever the origin negotiates;
the canonical model is version-agnostic. WebSocket upgrades always use
HTTP/1.1 ([WebSockets](websockets.md)).

gRPC and other HTTP/2-only protocols need trailers: set
`http.allow_trailers`.

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
  `http.allow_http10`; `HTTP/0.9` is never accepted.
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
  SNI / CONNECT host (in a tunnel).
- At most one `Content-Length`, digits only, at most 19 digits. A
  duplicate is rejected even when the values are equal.
- `Transfer-Encoding`, if present, is exactly `chunked`: one field, one
  value, no parameters, no other codings.
- `Content-Length` and `Transfer-Encoding` together are rejected.
- GET, HEAD, DELETE, OPTIONS, CONNECT and TRACE with a non-empty body are
  rejected unless `http.allow_body_on_get`.
- `Expect` may only be `100-continue`; roxy sends `100 Continue` itself once
  the rules allow the request. Anything else gets `417`.
- Hop-by-hop fields (`Connection` and every field it names, `Keep-Alive`,
  `Proxy-Connection`, `Proxy-Authorization`, `TE`, `Trailer`,
  `Transfer-Encoding`, `Upgrade`) are consumed by roxy and never forwarded.
  `Upgrade` is honoured only for a WebSocket a rule allows.

### Body

- Chunk sizes are hex digits only, at most 16. Chunk extensions need
  `http.allow_chunk_extensions`; trailers need `http.allow_trailers`. The
  final CRLF is enforced.
- The body is at most `limits.max_request_body_bytes` (1 GiB), enforced
  while streaming: exceeding it closes the connection mid-stream. The
  default is generous so large uploads work.
- The head must arrive within `limits.header_timeout` (10 s), and the body
  may not stall for longer than `limits.body_idle_timeout` (30 s).

### HTTP/2 requests

- Pseudo-headers (`:method`, `:scheme`, `:authority`, `:path`) appear
  exactly once each, before regular headers.
- Connection-specific headers (`connection`, `keep-alive`,
  `transfer-encoding`, `upgrade`, `proxy-connection`) reset the stream
  (RFC 9113 §8.2.2). `te` is accepted only as `trailers`.
- `:path` goes through the same normaliser as HTTP/1.1. `:authority` must
  equal the SNI, and a `host` header, if present, must equal `:authority`.
- Streams per connection and header bytes per stream are capped by
  `limits.h2_max_concurrent_streams` and `limits.h2_max_header_list_bytes`.
  CONTINUATION-flood and rapid-reset defences come from the `h2` crate.

## URL normalisation

Applied to the request target, both for rule matching and for what is
forwarded, so the upstream sees exactly what the rules matched.

1. The path starts with `/` and contains only `pchar` and `/`, with
   well-formed percent-encodings. Anything else is rejected.
2. Percent-encoded unreserved characters (`A–Z a–z 0–9 - . _ ~`) are
   decoded. Other encodings stay as they are, so `%2F` stays `%2F`: roxy
   takes no position on whether it is a separator, and the client cannot
   exploit the difference because matching and forwarding agree.
3. Hex digits in the remaining encodings are upper-cased.
4. Dot segments (including ones that were `%2E`-encoded before step 2) are
   removed per RFC 3986 §5.2.4. A path that climbs above the root is
   rejected.
5. An empty path becomes `/`.
6. The query is validated the same way and its hex upper-cased, but
   otherwise untouched. It is parsed into pairs for matching only.
7. A fragment in a request target is rejected.
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
  with no extensions or trailers, never both;
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
- Redirects are forwarded, not followed. The client's next request is a new
  exchange, judged on its own.
- Compressed bodies pass through untouched. roxy does not decompress for
  inspection: `body.text` and `response.body.text` are a lossy UTF-8 view of
  the bytes as sent.

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

A refusal that is not a rule's deny (an upstream error, a failed addon)
carries a `reason` instead of `rule`.

The status and message can be set per rule
(`deny: { status: 451, message: "..." }`). After a deny the connection is
closed (`connection: close` on HTTP/1.1, `GOAWAY` on HTTP/2), so a probing
client loses its warm connection on every attempt. A refused proxy
authentication gets `407`.
