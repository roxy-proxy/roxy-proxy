# roxy — design

A TLS-inspecting HTTP firewall for containing (potentially adversarial) AI agent
traffic. A Rust reimplementation of the useful subset of mitmproxy, without a UI,
with a declarative rule language, stateful metrics, and sandboxed WASM addons.

Status: design, pre-implementation. Sections marked **Open** need a decision
before or during the relevant milestone; each has a proposed default.

---

## 1. Goals and non-goals

### Goals

1. **Fail closed.** Anything roxy cannot parse, verify, or classify is dropped.
   An empty rule set denies everything. An addon that crashes denies the flow.
   A config that fails to compile is not loaded.
2. **Inspect all HTTP.** roxy generates its own CA on first start and mints leaf
   certificates per hostname. Clients are expected to trust that CA (pulled from
   roxy or injected into the sandbox). Uninspected passthrough is never implicit.
3. **Canonical re-serialisation.** Requests and responses are parsed into a
   strict internal model and re-emitted in one unambiguous wire form. Nothing
   the agent sends reaches the upstream byte-for-byte. This defeats request
   smuggling, header-injection, and path-confusion classes of attack.
4. **Explicit `HTTP_PROXY` mode first.** It is the most defensible mode and the
   one wanted first. Transparent TCP mode (Linux REDIRECT/TPROXY) is **deferred**
   (§4.2) but the connection model leaves room for it so it can be added as one
   more listener without touching the pipeline.
5. **Declarative rules.** YAML config, hot-reloaded, with a readable expression
   DSL for stateless matching and metric-based stateful rules
   (metric → operator → threshold → action).
6. **Extensible.** WASM component addons with a defined host API can inspect,
   mutate, deny, or redirect flows. Any language that targets the component
   model (Rust, Python via componentize-py, Go, JS).
7. **Gateway-ready.** Sidecar per sandbox is the default deployment, but client
   identity (source IP, proxy-auth user, listener) is a first-class rule field
   so one roxy can front many sandboxes later.
8. **Auditable.** Structured JSONL flow log with the matched rule and decision
   for every request. Optional body capture.

### Non-goals (for now)

- Web UI, interactive flow editing, replay.
- Non-Linux transparent mode.
- Being a general-purpose caching or load-balancing proxy.
- HTTP/3 / QUIC. UDP is blocked at the host firewall layer; roxy only speaks TCP.
- Persistent or distributed state (the state store is a trait so this can come later).

---

## 2. Threat model

**Attacker:** the agent process inside the sandbox. It controls every byte sent
to roxy, may be running arbitrary code, and may have root inside its own
container.

**Trusted:** the host, roxy's binary and config, the secrets roxy holds, the
public CA trust store for upstream verification, and the upstreams that the
rules permit. roxy does not treat upstream responses as adversarial; it only
applies the size and time limits needed to protect its own resources and
re-frames responses so the client sees one clean wire form.

**roxy must prevent:**

- Reaching any destination not permitted by rules, including via Host/SNI
  spoofing, DNS rebinding, redirects to private ranges, CONNECT to arbitrary
  ports, or non-HTTP protocols tunnelled through CONNECT.
- Desync/smuggling between roxy and the upstream (or between roxy and the
  client) via ambiguous framing.
- Exfiltrating real credentials: the agent should only ever hold placeholders.
- Exhausting roxy's memory, CPU, or file descriptors (slowloris, huge headers,
  unbounded bodies, cardinality attacks on stateful metric keys, WASM runaway).
- Learning anything useful from deny responses beyond the rule id.

**roxy does not attempt to prevent:** side channels via timing or DNS from the
sandbox (block DNS egress at the host firewall; in proxy mode roxy resolves),
compromise of an upstream the rules already permit, or compromise of the host
running roxy.

**Well-behaved clients must work unhindered.** Strictness is aimed at
malformed or ambiguous traffic. A conforming HTTP/1.1 or HTTP/2 client doing
ordinary things (large uploads, keep-alive, 100-continue, WebSockets,
redirects, compression) through an allowed rule should notice nothing except
the CA. Any default that would trip a conforming client is a bug.

---

## 3. Architecture overview

```
                       ┌────────────────────────────────────────────────────────┐
  agent ──TCP──▶       │ Listener (explicit | transparent)                      │
                       │   ▼                                                    │
                       │ ConnectPhase  ── connect rules (client.*, dst.*, sni)  │
                       │   ▼                                                    │
                       │ TLS terminate (rustls, leaf minted by roxy CA)         │
                       │   ▼  ALPN → h1 | h2                                    │
                       │ Strict parse → CanonicalRequest                        │
                       │   ▼                                                    │
                       │ RequestPhase ── rules + metrics + addons → Decision    │
                       │   ▼  allow(+mutations)                                 │
                       │ Upstream connector (own DNS, SSRF policy, rustls)      │
                       │   ▼  hyper client, HTTP/1.1                             │
                       │ Strict parse → CanonicalResponse                       │
                       │   ▼                                                    │
                       │ ResponsePhase ── rules + addons → Decision             │
                       │   ▼                                                    │
                       │ Re-serialise to client (h1 | h2)                       │
                       │                                                        │
                       │ FlowLog (JSONL) ◀── every phase emits events           │
                       └────────────────────────────────────────────────────────┘
```

### Crate layout (Cargo workspace)

| crate | responsibility |
|---|---|
| `roxy-http` | Canonical request/response model, strict HTTP/1.1 codec, h2 ↔ canonical mapping, URL normalisation, body framing with caps, WebSocket frame codec. No I/O policy. |
| `roxy-tls` | CA generation/persistence, leaf cert minting + cache, rustls server/client config builders, ClientHello sniffing (SNI, ALPN). |
| `roxy-rules` | Expression DSL (lexer, parser, type-checker, compiler), rule set, phases, actions, metrics/state store, hot-reload-safe `Policy` snapshot. |
| `roxy-wasm` | wasmtime component host, WIT world, addon lifecycle, fuel/memory limits, host-call implementations. |
| `roxy-proxy` | Listeners, connection state machine, flow pipeline, upstream connector (DNS, SSRF policy, pool), WebSocket relay, flow log emission. |
| `roxy` | Binary: CLI (`run`, `check`, `ca export`, `rule test`), config loading, reload watcher, wiring. |
| `roxy-addon` | SDK for Rust addon authors: generated WIT bindings + ergonomic wrappers. Published independently. |
| `wit/` | The `roxy:addon` WIT package. Language-agnostic contract for addons. |

Dependencies point downward: `roxy` → `roxy-proxy` → {`roxy-http`, `roxy-tls`,
`roxy-rules`, `roxy-wasm`}. `roxy-http` and `roxy-rules` have no network I/O and
are fully unit/fuzz-testable.

### Key runtime types

```rust
// roxy-proxy
struct ClientConn { id, listener: ListenerId, peer: SocketAddr, mode: Mode,
                    user: Option<String>, original_dst: Option<SocketAddr> }

struct Flow { id, conn: Arc<ClientConn>, tls: Option<TlsInfo>,
              request: CanonicalRequest, response: Option<CanonicalResponse>,
              tags: Vec<String>, matched: Vec<RuleId>, decision: Decision }

enum Decision { Allow { mutations: Vec<Mutation> }, Deny { status, body },
                Passthrough /* connect phase, transparent only */ }

// roxy-rules
struct Policy { connect: RuleChain, request: RuleChain, response: RuleChain,
                ws: RuleChain, metrics: MetricDefs, addons: AddonOrder }
// Swapped atomically on reload: Arc<ArcSwap<Policy>>.
```

---

## 4. Modes and listeners

A config may define several listeners, each with a name and mode. Rules can
match on `listener.name`.

### 4.1 Explicit proxy mode (default)

Client speaks HTTP/1.1 to roxy on the proxy port.

- **Absolute-form requests** (`GET http://host/path HTTP/1.1`): plain HTTP.
  Parsed, canonicalised, evaluated. `Host` header must equal the URI authority.
- **CONNECT host:port**: evaluated in the *connect phase*. If allowed, roxy
  replies `200 Connection Established` and then **peeks the first bytes**:
  - TLS ClientHello → extract SNI and ALPN. SNI must equal the CONNECT host
    (`tls.require_sni_match`, default true; no-SNI uses the CONNECT host).
    Terminate TLS with a leaf cert for that host. Inner protocol must be
    HTTP/1.1 or HTTP/2 (ALPN) → request phase.
  - Looks like plaintext HTTP and `http.allow_plain_in_connect` is true →
    parse as HTTP.
  - Anything else → **close**. No raw TCP through CONNECT, ever.
- **Proxy-Authorization** (Basic) optional. When configured, unauthenticated
  requests get `407`; the user becomes `client.user` for rules and logs. This
  is the identity mechanism for gateway deployments.
- Origin-form requests (`GET /path`) on the proxy port are rejected, except for
  the magic host `roxy.internal` (see §9 CA distribution).

### 4.2 Transparent mode (Linux) — deferred

Not in the initial build. Kept here so the hooks it needs are designed in now:

- `ClientConn.original_dst: Option<SocketAddr>` (always `None` in proxy mode).
- `Listener` is a trait with one implementation (`ExplicitListener`) in M1;
  `TransparentListener` is added later and hands the same
  `(stream, ClientConn)` to the shared pipeline.
- Connect-phase fields `dst.host`, `dst.port`, `dst.ip` exist from M1 (filled
  from the CONNECT authority in proxy mode).
- `listener.mode` is a rule field from M1 with the single value `explicit`.
- The `passthrough` action is reserved in the action enum and rejected by the
  compiler with "requires a transparent listener" until the listener exists.

When built, traffic is steered to roxy by nftables/iptables REDIRECT or
TPROXY. roxy recovers the original destination via `SO_ORIGINAL_DST`
(`IP6T_SO_ORIGINAL_DST` for v6).

On accept, roxy peeks the first bytes and classifies:

| first bytes | default | rule-gated alternative |
|---|---|---|
| TLS ClientHello | MITM, require HTTP inside | `passthrough` (connect phase, requires `transparent.allow_passthrough: true`) |
| Plaintext HTTP request line | parse as HTTP | — |
| anything else | close | `passthrough` to `dst.ip:dst.port` if a connect rule says so |

**Open — upstream target in transparent mode.** The agent chose a destination
IP and then presented a Host/SNI. Options: `resolve` (roxy resolves the
hostname itself and ignores the original IP; same behaviour as proxy mode, host
rules cannot be spoofed), `original_dst` (connect where the agent was going;
Host header is attacker-controlled so host-based rules are weak), or
`require_match` (deny if roxy's resolution does not contain the original IP;
breaks on CDNs). **Proposed default: `resolve`.** Config key
`transparent.upstream_target`. Passthrough flows always use `original_dst` by
definition and are matched on `tls.sni`/`dst.*` only.

Deployment notes that must ship with the docs: roxy's own uid must be exempt
from the REDIRECT rule; DNS (udp/53) and all other UDP should be blocked at the
firewall; IPv6 must be redirected too or blocked.

### 4.3 Connect-phase semantics

Connect rules see `client.*`, `listener.*`, `dst.host`, `dst.port`, `dst.ip`,
`tls.sni`, `tls.alpn`. Terminal actions: `allow` (proceed to decrypt and
inspect), `deny`, `passthrough`.

If no connect rule matches, the default is **allow-to-inspect**, not deny,
because the request phase is the real gate and "allow" here only means "we will
decrypt and look". `passthrough` is never a default.

---

## 5. Canonical HTTP model and strict parsing

This is the heart of the defensive posture. `roxy-http` owns it.

### 5.1 Why not just use hyper's server?

hyper is excellent but its HTTP/1.1 server *resolves* ambiguities per RFC 9112
(e.g. when both `Transfer-Encoding` and `Content-Length` are present it uses
chunked and drops CL). roxy must **reject** them. So the client-facing HTTP/1.1
codec is roxy's own (built on `httparse` for tokenisation, which is strict about
token characters), with roxy's semantic validator and body framer on top.
HTTP/2 client-side uses the `h2` crate (strict by spec) followed by the same
semantic validator.

Upstream is plain hyper client: pooling, HTTP/1.1 and HTTP/2 (via ALPN) to the
origin, lenient-but-safe response parsing. Upstreams are trusted (§2), so
hyper's RFC-conformant resolution of response ambiguities is fine; roxy only
re-frames the response for the client.

### 5.1a HTTP/2 status

HTTP/2 **is** supported in the design on both sides; it is sequenced, not
excluded.

- **Client side** (agent → roxy, inside the TLS tunnel): negotiated by ALPN.
  Until the h2 server path lands (M1 unit E, see §15), roxy offers only `http/1.1` in ALPN and
  every mainstream client (curl, Python httpx/requests/aiohttp, Node fetch,
  Go net/http, Rust reqwest) silently uses HTTP/1.1. No breakage, only loss
  of multiplexing. Once it lands, `http.enable_h2` defaults to true.
- **Upstream side** (roxy → origin): hyper client with ALPN `h2, http/1.1`
  from M1. The canonical model is version-agnostic, so the same request is
  serialised as h1 or h2 depending on what the origin negotiates.
- **gRPC and other h2-only protocols** need h2 end-to-end *and* trailers.
  They work once client-side h2 is in and `http.allow_trailers` is enabled
  for the flow. Client-side h2 was pulled into M1 (unit E) for this reason; it
  is additive and does not touch the h1 codec.

### 5.2 CanonicalRequest

```rust
pub struct CanonicalRequest {
    pub method: Method,              // validated token; known methods are enum variants
    pub scheme: Scheme,              // Http | Https
    pub authority: Authority,        // host: Host (DnsName | Ipv4 | Ipv6), port: u16 (always explicit)
    pub path: Path,                  // normalised, see 5.4
    pub query: Option<Query>,        // raw validated bytes + parsed pairs (for matching only)
    pub headers: Headers,            // lowercase names, ordered, validated, hop-by-hop removed
    pub body: Body,                  // Empty | Sized(u64, stream) | Chunked(stream); caps enforced
    pub meta: RequestMeta,           // client version (h1/h2), flow ids, timestamps
}
```

### 5.3 Rejection rules (HTTP/1.1 request parsing)

Any violation closes the connection (not just the request) and emits a
`parse_error` flow event with a reason code. Reason codes are stable strings so
they can be alerted on.

Request line:
- Method must be a valid `token`; non-ASCII or control chars reject.
- Request-target form must match the context (absolute-form on the proxy port,
  origin-form inside a tunnel, authority-form only for CONNECT).
- Version must be exactly `HTTP/1.1`. HTTP/1.0 rejected by default
  (`http.allow_http10`, default false). HTTP/0.9 never.
- Line terminator must be CRLF. Bare LF or bare CR anywhere in head → reject.
- Total head size ≤ `limits.max_header_bytes` (default 64 KiB);
  URL length ≤ `limits.max_url_bytes` (default 8 KiB).

Headers:
- Name must be a `token`; no whitespace before the colon; no obs-fold.
- Value: visible ASCII, SP and HTAB only; leading/trailing OWS stripped.
  Any CR, LF, NUL, or other control char → reject. Non-ASCII → reject
  (configurable `http.allow_obs_text`, default false).
- Header count ≤ `limits.max_headers` (default 100).
- `Host`: exactly one. In absolute-form requests it must match the URI
  authority. Inside a tunnel it must match the SNI/CONNECT host
  (port-normalised). Mismatch → reject.
- `Content-Length`: at most one occurrence. Must be digits only, no sign, no
  whitespace, ≤ 19 digits. Duplicate (even with equal values) → reject.
- `Transfer-Encoding`: if present, must be exactly `chunked` (single header,
  single value, case-insensitive, no parameters, no other codings). Any
  other value or combination → reject.
- `Content-Length` **and** `Transfer-Encoding` both present → reject.
- Methods without defined body semantics (GET, HEAD, DELETE, OPTIONS,
  CONNECT, TRACE) with a non-zero body → reject (`http.allow_body_on_get`,
  default false).
- `Expect`: only `100-continue` accepted; roxy itself sends `100 Continue`
  after the request phase allows the request. Anything else → `417`.
- Hop-by-hop headers (`Connection` and everything it names, `Keep-Alive`,
  `Proxy-Connection`, `Proxy-Authorization`, `TE`, `Trailer`,
  `Transfer-Encoding`, `Upgrade`) are consumed by roxy and never forwarded.
  `Upgrade` is only honoured for WebSocket when a rule allows it (§8).

Body:
- Chunked: chunk-size must be hex digits only (≤ 16 digits); chunk extensions
  rejected (`http.allow_chunk_extensions`, default false); trailers rejected by
  default (`http.allow_trailers`, default false); final CRLF enforced.
- Total body ≤ `limits.max_request_body_bytes` (default 1 GiB) even when
  streaming; exceeding closes the connection mid-stream. The default is
  generous on purpose: large uploads from a well-behaved client must work.
- Read timeouts: head ≤ `limits.header_timeout` (10 s), body inactivity ≤
  `limits.body_idle_timeout` (30 s).

HTTP/2 (client side):
- Pseudo-headers validated (`:method`, `:scheme`, `:authority`, `:path`
  present exactly once, in order, before regular headers — `h2` enforces most).
- Connection-specific headers (`connection`, `keep-alive`, `transfer-encoding`,
  `upgrade`, `proxy-connection`) → stream reset (RFC 9113 §8.2.2).
- `te` only with value `trailers`; otherwise reset.
- `:path` goes through the same normaliser as h1; `:authority` must equal
  SNI; `host` header, if present, must equal `:authority`.
- Stream and connection concurrency limits from `limits.h2_*`.
- CONTINUATION flood / rapid-reset defences come from `h2` crate defaults;
  roxy additionally caps total header bytes per stream.

### 5.4 URL normalisation

Applied to the request path, used both for rule matching and for what is
forwarded, so the upstream sees exactly what the rules matched.

1. Path must begin with `/`. Must contain only `pchar` / `/` with well-formed
   percent-encodings (`%` followed by two hex digits). Anything else → reject.
2. Percent-encoded **unreserved** characters (`A–Z a–z 0–9 - . _ ~`) are
   decoded. All other encodings are left as-is (so `%2F` stays `%2F`; roxy
   does not take a position on whether it is a separator, and neither can the
   agent exploit the difference, because matching and forwarding agree).
3. Hex digits in remaining encodings are upper-cased.
4. Dot segments (`.` and `..`, including ones that were `%2E`-encoded before
   step 2) are removed per RFC 3986 §5.2.4. A path that tries to climb above
   root → reject.
5. Empty path → `/`.
6. Query: validated the same way (allowed chars, well-formed encodings), hex
   upper-cased, otherwise untouched. Parsed into pairs for rule matching only.
7. Fragments are not valid in request targets → reject.
8. Authority: host lower-cased; IDNA labels must already be A-labels
   (`xn--`), raw Unicode → reject; port made explicit; trailing dot removed.

### 5.5 Serialisation to upstream

HTTP/1.1 or HTTP/2 to the origin, whichever hyper negotiates via ALPN
(`h2, http/1.1`). The canonical model is version-agnostic; the h2 mapping is
the obvious one (pseudo-headers from the canonical fields, `host` header
dropped in favour of `:authority`). The HTTP/1.1 wire form:

- Request line: `METHOD <origin-form path[?query]> HTTP/1.1\r\n`.
- `host: <authority>` first, then headers in canonical order (lowercase
  names; hyper writes lowercase by default, which is universally accepted).
- Body: if length is known → `content-length`. Otherwise → clean `chunked`
  with no extensions or trailers. Never both.
- `connection: keep-alive` managed by the pool. No client hop-by-hop headers
  survive.
- Mutations from rules/addons are applied to the canonical model *before*
  serialisation, so they are subject to the same validation (an addon cannot
  inject a header with a CRLF in it — the mutation is rejected and the flow
  denied).

### 5.6 CanonicalResponse

Upstreams are trusted, so the response path is about correct re-framing and
resource limits, not adversarial parsing. hyper parses the response; roxy
builds a `CanonicalResponse` from it with minimal processing:

- Status and headers taken from hyper as-is. Header names lower-cased; values
  must be valid `http::HeaderValue`s (hyper already guarantees this).
- `Set-Cookie` and `WWW-Authenticate` preserved as separate values, never
  combined.
- Hop-by-hop headers stripped; `connection`/`keep-alive`/`transfer-encoding`
  regenerated for the client connection.
- Body streamed through with `content-length` when known, else clean chunked
  (h1) or DATA frames (h2). Responses to HEAD, `1xx`, `204`, `304` carry no
  body, per framing rules.
- `limits.max_response_body_bytes` (default 1 GiB) and
  `limits.response_header_timeout` protect roxy's memory and connection slots.
  Bodies are never buffered unless a rule or addon asks for body content.
- Redirect responses (`3xx` with `location`) are forwarded; the agent's
  follow-up request is a new flow evaluated on its own. roxy does not follow
  redirects.
- Compressed bodies (`content-encoding`) pass through untouched unless a
  response rule or addon needs `response.body.text`, in which case roxy
  decompresses for inspection only and forwards the original bytes.

### 5.7 Decision responses

When roxy denies an HTTP request it answers itself:

```
HTTP/1.1 403 Forbidden
content-type: application/json
x-roxy-rule: <rule id>
content-length: ...

{"error":"blocked by roxy","rule":"<rule id>","flow":"<flow id>"}
```

Status and body are overridable per rule (`deny: { status: 451, message: "..." }`).
Connect-phase denies reply `403` to the CONNECT. Transparent-mode denies before
TLS is established can only close the socket.

---

## 6. Rule language

### 6.1 Config shape

```yaml
version: 1

listeners:
  - name: proxy
    mode: explicit
    bind: 0.0.0.0:3128
    auth:                      # optional; makes client.user available
      basic: { users_file: /etc/roxy/users }
  # Deferred (§4.2). Shape reserved so configs do not change when it lands:
  # - name: tproxy
  #   mode: transparent
  #   bind: 0.0.0.0:3129
  #   allow_passthrough: false
  #   upstream_target: resolve   # resolve | original_dst | require_match

ca_server:
  bind: 0.0.0.0:3130           # plain HTTP, serves /roxy-ca.pem and /healthz

tls:
  ca_dir: /var/lib/roxy/ca     # generated if absent
  require_sni_match: true
  upstream:
    verify: strict             # strict | strict+extra_roots
    extra_roots: []
    min_version: "1.2"

http:
  allow_http10: false
  allow_trailers: false
  allow_chunk_extensions: false
  allow_plain_in_connect: false
  enable_h2: false             # client-side h2; default false until M1 unit E lands, then true

limits:
  max_header_bytes: 64kb
  max_url_bytes: 8kb
  max_headers: 100
  max_request_body_bytes: 1gb
  max_response_body_bytes: 1gb
  max_inspect_body_bytes: 1mb   # only buffered when a rule/addon needs body content
  max_ws_message_bytes: 16mb    # inspect tier only
  max_capture_body_bytes: 16mb
  header_timeout: 10s
  body_idle_timeout: 30s
  response_header_timeout: 60s
  idle_timeout: 300s            # client keep-alive idle
  h2_max_concurrent_streams: 100
  h2_max_header_list_bytes: 64kb
  max_connections_per_client: 256
  max_metric_keys: 100000

upstream:
  dns:
    resolver: system           # system | [ "1.1.1.1:53", ... ]
    cache_ttl_cap: 60s
  deny_private_ranges: true    # loopback, link-local, RFC1918, ULA, multicast, unspecified
  connect_timeout: 10s

secrets:
  openai: { env: OPENAI_API_KEY }
  gh:     { file: /run/secrets/github_token }

metrics:
  - id: github_writes
    count: requests
    where: host under "api.github.com" and method in [POST, PUT, PATCH, DELETE]
    key: [client.ip]
    window: 1m
  - id: egress_bytes
    count: request_bytes
    where: true
    key: [client.ip]
    window: 1h

rules:
  - id: no-writes-burst
    when: metric.github_writes >= 30 and host under "api.github.com"
    then: deny

  - id: egress-budget
    when: metric.egress_bytes > 500mb
    then: { deny: { status: 429, message: "hourly egress budget exhausted" } }

  - id: openai
    when: host == "api.openai.com" and path starts_with "/v1/" and method == POST
    then:
      - set_header: { authorization: "Bearer ${secret:openai}" }
      - allow

  - id: github-reads
    when: host under "github.com" and method in [GET, HEAD]
    then: allow

  - id: pypi
    when: host in ["pypi.org", "files.pythonhosted.org"] and method == GET
    then: allow

  - id: ws-example
    when: host == "ws.example.com" and header["upgrade"] == "websocket"
    then: { allow: { upgrade: websocket } }

  - id: log-upstream-5xx
    phase: response
    when: response.status >= 500
    then: { log: { level: warn, message: "upstream 5xx" } }

addons:
  - name: pii-scan
    path: /etc/roxy/addons/pii_scan.wasm
    hooks: [request, response]
    stage: before_rules          # before_rules | in_chain | after_rules
    config: { threshold: 0.8 }
    capabilities: [state, log]
```

Relative paths in the config (`ca_dir`, secret files, addon paths, log and
capture paths) resolve against the process working directory.

Rules are evaluated **top to bottom, first terminal action wins**. A rule's
`then` is a list of actions (or a single action shorthand). Non-terminal
actions (`set_header`, `tag`, `log`, `call`, …) take effect and evaluation
continues to the next rule. When the chain is exhausted with no terminal
action, the request is **denied** (`default-deny`, rule id `_default`).

Each rule has a `phase` (`connect`, `request` (default), `response`, `ws`). The
compiler rejects a rule that references a field unavailable in its phase.

### 6.2 Expression DSL

Design goals: readable at a glance, small, statically typed, no user-defined
functions (that is what addons are for), guaranteed linear-time matching
(the `regex` crate; no backtracking).

```
expr        := or
or          := and ( "or" and )*
and         := not ( "and" not )*
not         := "not" not | primary
primary     := "(" expr ")" | comparison | predicate
comparison  := operand OP operand
predicate   := field                         ; boolean-typed field
operand     := field | field "[" string "]" | literal
OP          := "==" | "!=" | "<" | "<=" | ">" | ">="
             | "in" | "not in"
             | "starts_with" | "ends_with" | "contains"
             | "like"        ; glob, full-match ( * ? )
             | "matches"     ; regex, full-match (anchor explicitly with .* if needed)
             | "under"       ; host == X or host ends_with "." + X
literal     := string | number [unit] | bool | list | cidr | bare_ident
list        := "[" literal ("," literal)* "]"
unit        := kb | mb | gb | ms | s | m | h          ; 1024-based sizes
bare_ident  := [A-Z][A-Z_]*                          ; HTTP method names only
```

Strings are double-quoted with `\"` and `\\` escapes. Comments `# ...` are
allowed inside multi-line YAML block scalars.

Fields by phase (type in brackets):

| field | type | connect | request | response | ws |
|---|---|---|---|---|---|
| `client.ip`, `client.port`, `client.user` | ip, int, string | ✓ | ✓ | ✓ | ✓ |
| `listener.name`, `listener.mode` | string | ✓ | ✓ | ✓ | ✓ |
| `dst.host`, `dst.port`, `dst.ip` | string, int, ip | ✓ | | | |
| `tls.sni`, `tls.alpn`, `tls.version` | string | ✓ | ✓ | ✓ | ✓ |
| `method`, `scheme`, `host`, `port`, `path`, `url` | string/int | | ✓ | ✓ | ✓ |
| `query["k"]`, `query.raw` | string | | ✓ | ✓ | ✓ |
| `header["name"]` | string (first value; `header.all["name"]` → list) | | ✓ | ✓ | |
| `body.size`, `body.text` (rule-gated buffering, see below) | int, string | | ✓ | ✓ | |
| `response.status`, `response.header["name"]`, `response.body.*` | | | | ✓ | |
| `ws.direction` (`c2s`/`s2c`), `ws.opcode`, `ws.size`, `ws.text` | | | | | ✓ |
| `metric.<id>` | int | ✓ | ✓ | ✓ | ✓ |
| `@<list>` (literal, not a field) | address list, usable on the right of `in` / `not in` with any ip-typed field | ✓ | ✓ | ✓ | ✓ |
| `state["key"]` | string (set by `set_state`) | ✓ | ✓ | ✓ | ✓ |
| `tag["name"]` | bool (set by `tag` earlier in the chain) | ✓ | ✓ | ✓ | ✓ |

Type checking at compile time: `host under 443` is a config error, as is a
regex that fails to compile, a CIDR with a bad mask, or a `metric.foo` with no
such metric. `in` accepts a list of the operand's type, or a CIDR for ips.

**Body access.** `body.text` and `response.body.text` force roxy to buffer the
body (up to `limits.max_inspect_body_bytes`, default 1 MiB; larger bodies make
the predicate false *and* log `body_too_large_to_inspect`) for flows whose
other predicates match. The compiler determines per-rule whether the body is
needed; rules without body predicates never buffer and stream end-to-end.

### 6.3 Actions

Terminal:

| action | phases | effect |
|---|---|---|
| `allow` | all | proceed. `allow: { upgrade: websocket }` additionally permits the Upgrade as a byte relay (§8.1); `allow: { upgrade: websocket, inspect: true }` routes messages through the `ws` phase (§8.2). |
| `deny` | all | `deny: { status: 403, message: "…" }`. In `ws` phase drops the message; `deny: { close: true }` closes the socket. |
| `passthrough` | connect (transparent only, deferred) | relay bytes to `dst.ip:dst.port` uninspected. Logged. Compiler rejects it until a transparent listener exists. |

Non-terminal (evaluation continues):

| action | phases | effect |
|---|---|---|
| `set_header: { name: value }` | request, response | set/replace. Values may reference `${secret:name}` (request phase only). Validated as header values; invalid → flow denied. |
| `remove_header: [names]` | request, response | |
| `rewrite_path: { match: regex, to: replacement }` | request | `$1` groups; result re-normalised per §5.4 |
| `set_query: {k: v}` / `remove_query: [k]` | request | |
| `redirect: { host, port, scheme? }` | request | change the upstream target. Re-runs the connect-phase policy against the new target. `Host` header is unchanged unless `rewrite_host: true`. |
| `tag: name` | all | sets `tag["name"]` for later rules, addons and the log |
| `log: { level, message }` | all | emits an extra log event |
| `set_state: { key, value, ttl }` | all | writes to the state store (visible as `state["key"]`) |
| `capture: request | response | both` | request, response | writes bodies to the capture dir (§10) |
| `call: addon_name` | request, response, ws | runs that addon's hook now; its decision may deny or mutate |

Actions are a small closed enum, deliberately. Anything richer is an addon.

**`then` grammar.** `then` is one action or a list of actions. An action is
either a bare word (`allow`, `deny`, `passthrough`) or a single-key map whose
key is the action name and whose value is that action's argument:

```yaml
then: allow                                  # bare word
then: { deny: { status: 451, message: "no" } }   # single-key map
then:                                        # list, evaluated in order
  - set_header: { authorization: "Bearer ${secret:openai}" }
  - remove_header: [x-debug]
  - tag: billing
  - allow: { upgrade: websocket }
```

A map with more than one key, an unknown action name, an argument of the
wrong shape, or a terminal action followed by further actions in the same
list is a compile error. `then` is required on every rule.

### 6.4 Stateful metrics and state

A metric is `(what to count, filter, key, window)`. Rules compare it with an
operator and threshold and attach an action. This is the user's "metric,
operator, threshold, action" model with the metric defined once and reused.

```yaml
metrics:
  - id: <string>
    count: requests | request_bytes | response_bytes | errors | denied | unique(<field>)
    where: <expr>                 # evaluated in the phase where the counted thing is known
    key: [<field>, ...]           # optional; omitted = one global series
    window: <duration>            # optional; omitted = cumulative since start
```

Implementation: `DashMap<KeyTuple, SlidingWindow>` with fixed-bucket sliding
windows (window / 60 buckets, so a 1-minute window has 1-second resolution).
`unique` uses a HyperLogLog. Total keys across all metrics bounded by
`limits.max_metric_keys` with LRU eviction, so an attacker varying a key cannot
grow memory without bound. Metric values are incremented *after* a flow's
decision in that phase, and read *before*, so a rule `metric.x >= 30` denies
the 31st request.

`state` is a bounded TTL key/value map shared by rules and addons (`set_state`
action, `state.get/set` host calls). Both metrics and state live behind a
`StateStore` trait so a shared backend (Redis) can be added for multi-instance
gateways without touching the engine.

Metrics are exported for Prometheus later via the same registry (§10).

### 6.5 Compilation and hot reload

`roxy check <config>` and the reload path share one function:
`Config::parse → Policy::compile → Result<Policy, Vec<Diagnostic>>`.
Diagnostics include rule id, line/column within the expression, and a message.

Reload: `notify` watches the config file (and addon `.wasm` paths). On change,
compile; on success, `ArcSwap` the new `Policy`. In-flight flows finish under
the policy they started with; the next request on any connection uses the new
one. Metric series whose `id` and shape are unchanged are retained across
reloads. On failure: keep the old policy, log `config_reload_failed` with
diagnostics, never partially apply. `SIGHUP` also triggers reload.

### 6.6 Dry run

`roxy rule test --config roxy.yaml 'POST https://api.github.com/repos/x/y/issues' -H 'content-type: application/json'`
prints the matched rules, actions taken, and final decision without any
network I/O. Essential for operators and for golden tests.

---

## 7. Upstream connector

- **DNS:** roxy resolves with `hickory-resolver` (system config or explicit
  servers). Results cached with TTL capped by `upstream.dns.cache_ttl_cap`.
  The agent's own DNS is irrelevant in proxy mode.
- **Address policy (hard floor, §7.1):** after resolution, every candidate IP
  is checked against the built-in private-range set and every configured
  address denylist. This check is on the resolved IP, not the name, so
  rebinding does not help; IP-literal hosts go through the same check. A rule
  can opt a flow into private destinations with `allow: { private_ok: true }`;
  nothing can opt out of a denylist.
- **TLS to upstream:** rustls with bundled `webpki-roots` plus
  `tls.upstream.extra_roots`. Verification is always on. SNI is the canonical
  host. ALPN `h2, http/1.1`. Minimum TLS 1.2.
- **Pool:** hyper client pool keyed by `(scheme, host, port, resolved ip)`.
  `redirect` actions change the key. The pool is flushed when an address list
  or the address policy changes on reload, so a pooled connection to a newly
  denied IP is never reused.

### 7.1 Address denylists (M2)

An MVP requirement: operators must be able to feed roxy large lists of CIDR
ranges (threat-intel feeds, cloud metadata ranges, whole countries) that it
will refuse to connect to, with the same visibility as any other decision.

```yaml
address_lists:
  - name: blocked
    file: /etc/roxy/lists/blocked.txt    # one IPv4/IPv6 CIDR or address per line; `#` comments; blank lines ok
  - name: cloud-metadata
    inline: [169.254.169.254/32, "fd00:ec2::254/128", 100.100.100.200/32]

upstream:
  deny_private_ranges: true
  deny_lists: [blocked, cloud-metadata]  # hard floor, checked on every connect
```

- **Representation:** each list compiles into a binary prefix trie (one for
  v4, one for v6) so a lookup costs at most 32 or 128 node visits regardless
  of list size. A million entries is tens of MiB and loads in well under a
  second. IPv4-mapped IPv6 addresses are normalised to v4 before lookup.
  Overlapping and duplicate entries are merged; a malformed line is a config
  error naming the file and line.
- **Enforcement:** `upstream.deny_lists` is applied in the connector after DNS
  resolution and before every connect, independent of the rule chain. A hit
  denies the flow with `403`, rule id `_address_policy`, and emits an
  `upstream_denied` flow event with `list`, `matched_cidr`, `resolved_ip`,
  and `host`. If *some* resolved addresses are denied and others are not,
  the whole flow is denied (an attacker-controlled name must not get a second
  roll of the dice).
- **In the DSL:** `@name` is an address-list literal usable wherever a CIDR
  is: `client.ip in @internal`, `dst.ip not in @blocked`. Referencing an
  undefined list is a compile error. This lets the same lists gate client
  identity in gateway mode or be combined with other predicates in rules,
  while `upstream.deny_lists` stays the unconditional floor.
- **Reload:** list files are watched alongside the config; a changed file is
  recompiled and swapped atomically with the policy, and the upstream pool is
  flushed. Metrics `roxy_address_list_entries{list}` and
  `roxy_address_denied_total{list}` are exposed when the Prometheus endpoint
  lands.
- **`roxy check`** reports entry counts per list and
  `roxy rule test` shows an address-policy hit for an IP-literal URL.
- **Timeouts:** connect, TLS handshake, response header, body idle.
- Upstream failures map to `502` (connect/TLS), `504` (timeout), `502` with
  reason `upstream_protocol_error` for canonicalisation failures. Each is a
  distinct flow-log reason code.

---

## 8. WebSockets

An Upgrade is only honoured when a request-phase rule terminates with
`allow: { upgrade: websocket }`. Plain `allow` strips `Upgrade`/`Connection:
upgrade` and forwards an ordinary request (fail closed on the upgrade).

Two tiers, chosen per rule. The default is the one that is invisible to a
well-behaved client.

### 8.1 Relay tier (default, M1)

`allow: { upgrade: websocket }`. roxy forwards the upgrade request to the
upstream (after the usual header canonicalisation; `Sec-WebSocket-*` headers
and the client's extension offer pass through untouched), checks that the
upstream answered `101` with a correct `Sec-WebSocket-Accept`, relays the
`101` to the client, and then **splices bytes in both directions** until
either side closes. No frame parsing, no re-masking, no reassembly.
`permessage-deflate` and subprotocols work exactly as negotiated end to end.
The only limits are the connection idle timeout and the per-client connection
cap. The flow log gets one `ws_open` and one `ws_close` event with byte counts.

This is a plain TCP pipe inside an already-authorised, already-decrypted
flow, so it costs nothing in M1 and is what most operators should use.

### 8.2 Inspect tier (M3)

`allow: { upgrade: websocket, inspect: true }`. Needed only when there are
`ws`-phase rules or addons that must see message content. roxy removes
extensions from the offer (compressed frames cannot be inspected), validates
the `101` (no extensions, subprotocol ⊆ offered), and relays through a frame
codec:

- RSV bits must be zero; unknown opcodes → close `1002`.
- Client→server frames must be masked; server→client must not be.
- Control frames ≤ 125 bytes, not fragmented.
- Fragmented messages are reassembled up to `limits.max_ws_message_bytes`
  (default 16 MiB) for evaluation and forwarded as a single frame; over-size
  → close `1009`.
- Text frames must be valid UTF-8 → else close `1007`.
- Re-masking with roxy's own random mask on the way to the server.

The `ws` phase runs per message with `ws.direction`, `ws.opcode`, `ws.size`,
`ws.text`. Actions: `allow`, `deny` (drop the message or close), `tag`,
`log`, `call`. Addons get `on-ws-message`. The compiler emits a config error
if a `ws`-phase rule or a `ws` addon hook exists but no rule enables
`inspect: true`, since it could never fire.

HTTP/2 clients: `CONNECT :protocol=websocket` (RFC 8441) is not supported
initially; clients fall back to HTTP/1.1 for the WebSocket connection, which
every mainstream library does automatically.

---

## 9. TLS and the CA

- **CA generation:** on first `roxy run` (or `roxy ca init`), generate an
  ECDSA P-256 CA with `rcgen`, 10-year validity, `CA:TRUE, pathlen:0`, key
  usage `keyCertSign, cRLSign`. Written to `tls.ca_dir/roxy-ca.pem` and
  `roxy-ca.key` (mode 0600). Existing files are reused; a corrupt pair is a
  fatal startup error (no silent regeneration — that would invalidate the
  trust clients already have).
- **Leaf certs:** minted on demand per hostname (SAN = DNS name, or IP SAN for
  IP targets), ECDSA P-256, 7-day validity, signed by the CA. One shared leaf
  keypair (as mitmproxy does; the CA key is what matters). Cached in an LRU
  (`tls.leaf_cache_size`, default 10 000). Minting is sync and ~1 ms, done on
  the blocking pool.
- **Client-facing rustls:** `ResolvesServerCert` picks/mints by SNI. ALPN
  offers `h2` (if `http.enable_h2`) and `http/1.1`. TLS 1.2 + 1.3. A cheap
  per-connection `ServerConfig` carries the CONNECT host as the fallback name
  for SNI-less clients; an SNI that is present but invalid fails the handshake
  rather than silently using the fallback. Session resumption is off (no
  session storage, no TLS 1.3 tickets): agent clients are short-lived and
  resumption state is one more thing to bound.
- **Distribution:** the CA cert (never the key) is served at
  `http://<ca_server.bind>/roxy-ca.pem` and, in explicit mode, at
  `http://roxy.internal/roxy-ca.pem` through the proxy itself (the mitm.it
  trick: `curl -x $HTTP_PROXY http://roxy.internal/roxy-ca.pem`). `roxy ca
  export [--der|--pem]` prints it for injection at image build time.
- **ClientHello sniffing:** a small parser that reads just enough of the first
  TLS record to extract SNI and ALPN, with a hard cap on bytes read (16 KiB) and
  a timeout. A ClientHello split across several TLS records, or a malformed or
  hostile `server_name` (non-ASCII, NUL, duplicate extension), is classified as
  not-TLS and the connection is closed; no real client does either. Used after CONNECT in proxy mode to get SNI/ALPN and to confirm
  the tunnel carries TLS; reused by transparent mode later for MITM vs
  passthrough vs close.

---

## 10. Observability

### 10.1 Flow log

One JSON object per line, written to stdout or `log.flow.path`. Every flow
produces at least one `request` event; connection-level events are optional
(`log.flow.connection_events`).

```json
{"ts":"2026-10-03T10:12:00.123Z","event":"request","flow":"01J9…","conn":"01J9…",
 "listener":"proxy","client":{"ip":"10.0.0.7","port":51234,"user":null},
 "tls":{"sni":"api.github.com","alpn":"h2","version":"1.3"},
 "req":{"method":"POST","host":"api.github.com","port":443,"path":"/repos/x/y/issues",
        "query":null,"headers_bytes":812,"body_bytes":1032,"content_type":"application/json"},
 "res":{"status":201,"headers_bytes":1420,"body_bytes":5120},
 "decision":"allow","rules":["openai-key","github-writes"],"tags":["billing"],
 "mutations":["set_header:authorization"],"addons":["pii-scan"],
 "timing":{"total_ms":412,"upstream_connect_ms":38,"upstream_ttfb_ms":350}}
```

Event types: `connect`, `request`, `response_error`, `ws_message` (sampled or
denied only, configurable), `parse_error`, `upstream_error`, `addon_error`,
`config_reloaded`, `config_reload_failed`, `passthrough`.

**Redaction:** every injected secret value is registered with a `Redactor`
that scrubs it from any logged string. Header values for `authorization`,
`proxy-authorization`, `cookie`, `set-cookie`, `x-api-key` are never logged
in full (`log.redact_headers` to extend). Query strings are logged with
values redacted by default.

Sinks implement `trait FlowSink { fn emit(&self, event: &FlowEvent); }`:
`Stdout`, `File` (with size rotation), later `UnixSocket` (live stream),
`Otlp`.

### 10.2 Body capture

`capture` action writes `<capture_dir>/<flow id>.req.body` /
`.res.body` plus a `.meta.json` with the canonical head. Capped by
`limits.max_capture_body_bytes`. Off unless a rule asks for it. Secrets are
*not* redacted inside bodies (document loudly).

### 10.3 Operational logging and metrics

`tracing` for roxy's own logs (JSON or pretty, `RUST_LOG`). A Prometheus
`/metrics` endpoint on the `ca_server` listener is a later milestone; the
`metrics:` registry is designed so each user metric becomes a gauge there.

---

## 11. WASM addons

### 11.1 Model

Addons are WebAssembly **components** (not core modules) implementing the
`roxy:addon` world. roxy hosts them with `wasmtime`. Each addon is
instantiated once per worker thread (component instances are not `Send`), so
addon state is per-thread; shared state goes through the host `state` API.

Addons are **in the path** of every flow. Each addon declares a `stage` per
hook:

| stage | when it runs | typical use |
|---|---|---|
| `before_rules` (default) | on every canonical request, before the rule chain | reshape traffic: rewrite, redirect to another upstream, call a helper service and substitute its output, deny early |
| `in_chain` | when a rule's `call: <addon>` action is evaluated | precise ordering relative to specific rules |
| `after_rules` | only on requests the rules allowed | enrichment, logging, last-mile mutation |

Response hooks mirror this (`before_rules` sees every upstream response
before response-phase rules; `after_rules` sees only those the rules let
through).

**Invariant: the rule chain always evaluates the final outgoing request.**
Whatever an addon produces is re-validated by the canonical model (a header
with CRLF, a path that climbs above root, an invalid host → the flow is
denied with reason `addon_invalid_mutation`) and then evaluated by the rules
exactly as if the agent had sent it. An addon can reshape traffic; it cannot
bypass policy. The YAML rules remain the floor, auditable without reading
WASM.

**Sub-requests.** With the `http` capability an addon may call
`fetch(request) -> response` from inside a hook (e.g. send the body to a
redaction service and forward what comes back). Each sub-request is itself a
flow: canonicalised, run through the connect/request/response rule chains
with `client.user = "addon:<name>"` and tag `addon-subrequest`, subject to
the address denylists (§7.1) and all limits, and logged like any other flow.
A sub-request that the rules deny returns a `403` to the addon, which decides
what to do. Sub-request depth is capped at 1 (an addon cannot trigger an
addon). The hook's own deadline (§11.3) includes time spent in `fetch`, so
this capability comes with a larger default timeout (`addons.fetch_timeout`,
5 s).

### 11.2 WIT sketch

```wit
package roxy:addon@0.1.0;

interface types {
  record header { name: string, value: list<u8> }
  record request {
    flow-id: string, method: string, scheme: string, host: string, port: u16,
    path: string, query: option<string>, headers: list<header>,
    body: option<list<u8>>,          // present up to the configured cap
    body-truncated: bool,
    client-ip: string, client-user: option<string>, tags: list<string>,
  }
  record response { flow-id: string, status: u16, headers: list<header>,
                    body: option<list<u8>>, body-truncated: bool }
  record ws-message { flow-id: string, direction: direction, opcode: u8, payload: list<u8> }
  enum direction { client-to-server, server-to-client }

  variant request-decision {
    continue,                          // unchanged
    modify(request-patch),             // set/remove headers, path, query, redirect target
    deny(deny-info),
    respond(synthetic-response),       // synthetic response without upstream (later milestone)
  }
  record request-patch { set-headers: list<header>, remove-headers: list<string>,
                         method: option<string>, path: option<string>, query: option<string>,
                         body: option<list<u8>>,          // replaces the body (bounded)
                         redirect: option<tuple<string, u16>> }
  record deny-info { status: u16, message: string }
  record synthetic-response { status: u16, headers: list<header>, body: list<u8> }
  variant response-decision { continue, modify(response-patch), deny(deny-info) }
  variant ws-decision { continue, drop, close(u16) }
}

interface host {
  use types.{header};
  log: func(level: u8, msg: string);
  state-get: func(key: string) -> option<string>;
  state-set: func(key: string, value: string, ttl-ms: option<u64>);
  metric-get: func(id: string, key: list<string>) -> option<u64>;
  secret-get: func(name: string) -> option<string>;   // only if capability granted
  fetch: func(req: sub-request) -> result<sub-response, fetch-error>;  // `http` capability; see §11.1
  config: func() -> string;                            // addon's JSON config blob
}

world addon {
  import host;
  use types.{request, response, ws-message, request-decision, response-decision, ws-decision};
  export init: func() -> result<_, string>;
  export on-request: func(req: request) -> request-decision;
  export on-response: func(res: response) -> response-decision;
  export on-ws-message: func(msg: ws-message) -> ws-decision;
}
```

Bodies are passed as bounded byte buffers in MVP (`addons.max_body_bytes`,
default 1 MiB; larger bodies arrive truncated with `body-truncated: true`, and
an addon that needs the full body should deny). Streaming body resources are
a later extension of the world.

### 11.3 Safety

- **Capabilities** declared in config (`capabilities: [state, log, secrets, http]`);
  host functions not granted trap → the flow is denied and `addon_error` logged.
- **Fuel** per hook call (`addons.fuel_per_call`) and **epoch deadline**
  (`addons.timeout`, default 50 ms) — exceeding either denies the flow.
- **Memory** cap per instance (`addons.max_memory`, default 64 MiB).
- Any trap or malformed decision (e.g. header with CRLF) → deny.
- Addons never see raw bytes from the wire, only the canonical model.
- No WASI sockets or filesystem imports in MVP; addons are pure functions over
  the flow plus the host API.

### 11.4 Authoring

`roxy-addon` (Rust) wraps the generated bindings:

```rust
use roxy_addon::prelude::*;

struct PiiScan;
impl Addon for PiiScan {
    fn on_request(&mut self, req: Request) -> RequestDecision {
        if let Some(body) = req.body_utf8() {
            if looks_like_ssn(body) { return RequestDecision::deny(403, "PII in request"); }
        }
        RequestDecision::Continue
    }
}
roxy_addon::export!(PiiScan);
```

Python authors use `componentize-py` against the same WIT. An `examples/addons/`
directory ships one Rust and one Python addon plus a `Makefile` to build them.

---

## 12. Resource limits and self-protection

- Per-client-IP connection cap; global connection cap; accept backpressure.
- All reads bounded (head size, body size, ClientHello size, WS message size).
- Timeouts at every stage; idle keep-alive timeout for client connections.
- Metric/state key cardinality caps with LRU.
- Leaf cert cache bounded.
- No allocation proportional to attacker-controlled numbers before validation
  (e.g. `content-length: 10^18` does not pre-allocate).
- The proxy port serves *only* proxy semantics plus `roxy.internal`. Health,
  CA download and (later) metrics live on a separate `ca_server` bind so they
  can be firewalled differently.
- roxy runs as an unprivileged user; transparent mode needs `CAP_NET_ADMIN`
  only for the firewall rules, which are set up outside roxy.
- `panic = "abort"` is **not** used; panics in a connection task are caught
  and close that connection only. Fuzzing targets ensure the parsers do not
  panic at all.

---

## 13. Rust stack

| concern | crate | note |
|---|---|---|
| runtime | `tokio` | multi-thread |
| HTTP types | `http`, `bytes` | canonical model builds on `http::HeaderMap` with roxy's validation around it |
| h1 tokenising | `httparse` | strict token rules; roxy adds semantic validation and framing |
| h2 | `h2` | client-side h2 server |
| upstream client | `hyper` 1.x + `hyper-util` | pool; see §5.1 open item |
| TLS | `rustls` 0.23, `tokio-rustls`, `webpki-roots` | no OpenSSL anywhere |
| certs | `rcgen` | CA + leaves |
| DNS | `hickory-resolver` | |
| WASM | `wasmtime` (component-model, `wit-bindgen`) | |
| WebSocket | relay tier: `sha1`/`base64` for the handshake check only, then `tokio::io::copy_bidirectional`. Inspect tier (M3): own frame codec in `roxy-http` (~400 lines) | `tungstenite` considered for the inspect tier but its leniency knobs are insufficient |
| config | `serde`, `serde_yaml_ng` (or another maintained serde-yaml fork), `humantime-serde`, `bytesize` | |
| DSL | hand-written lexer + Pratt parser | tiny grammar, best diagnostics, no deps |
| matching | `regex`, `globset`, `ipnet` | linear-time regex |
| concurrency | `arc-swap`, `dashmap`, `parking_lot` | |
| reload | `notify` | |
| logs | `tracing`, `tracing-subscriber` (json) | |
| ids | `ulid` | sortable flow ids |
| CLI | `clap` | |
| errors | `thiserror` (libs), `anyhow` (bin) | |
| testing | `proptest`, `cargo-fuzz`, `criterion`, `insta` (golden tests) | |

Build: `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` static
binaries; `cargo deny` for licence/advisory checks; `clippy -D warnings`;
`#![forbid(unsafe_code)]` in every crate except where `SO_ORIGINAL_DST` needs
a `libc` call (isolated in one module of `roxy-proxy`).

---

## 14. Testing strategy

1. **Smuggling corpus** (`roxy-http/tests/corpus/`): CL.TE, TE.CL, TE.TE
   obfuscations (`chunked `, `xchunked`, `chunked, identity`, tab separators),
   duplicate CL, obs-fold, bare LF, `%2e%2e` path climbs, Host/authority
   mismatches, h2 pseudo-header abuse, CRLF in header values. Every case has
   an expected reason code. This corpus is the acceptance test for §5.
2. **Fuzz targets**: h1 request head, h1 chunked body, URL normaliser, DSL
   parser, WS frame codec, ClientHello sniffer. Run in CI for a fixed budget;
   nightly for longer.
3. **Property tests**: `normalise(normalise(p)) == normalise(p)`; serialise →
   parse round-trips to an equal canonical model.
4. **DSL golden tests** (`insta`): expression → AST → compiled plan; config →
   diagnostics.
5. **Integration tests** (`roxy/tests/`): spin up roxy, a local TLS upstream
   using a test CA, and clients (`reqwest` with h1 and h2, a WebSocket
   client). Exercise allow/deny/mutations/metrics/reload end to end.
6. **Transparent mode** (when built): a script using `unshare -n` + nftables,
   run in CI on a privileged job; skipped locally without `CAP_NET_ADMIN`.
7. **Benchmarks**: rule evaluation per request, h1 parse+serialise, leaf
   minting, with `criterion`. Target: rule evaluation < 5 µs for a 100-rule
   policy; proxy overhead < 1 ms p50 on localhost.

---

## 15. Milestones

Each milestone is a self-contained deliverable with tests. Crates in M0/M1 can
be built by separate agents in parallel because `roxy-http`, `roxy-tls` and
`roxy-rules` have no dependencies on each other.

| # | deliverable | parallelisable units |
|---|---|---|
| M0 | Workspace, CI, config schema + `roxy check`, CA generation + `roxy ca export`, tracing + FlowSink skeleton | — |
| M1 | **Usable MVP in explicit mode.** Strict h1 codec + canonical model + normaliser (`roxy-http`); leaf minting + rustls configs + ClientHello sniffer (`roxy-tls`); DSL + stateless rules + actions `allow/deny/set_header/remove_header/tag/log` (`roxy-rules`); then `roxy-proxy` wiring: CONNECT → MITM → request phase → hyper upstream (h1/h2 by ALPN) → response phase → JSONL log. WebSocket relay tier. Secrets + `${secret:}` injection. Default deny. Smuggling corpus passing. Then E: client-side HTTP/2 via `h2` with the shared validator. | A: `roxy-http`, B: `roxy-tls`, C: `roxy-rules`, then D: `roxy-proxy`, then E: h2 |
| M2 | Metrics + state store, response-phase rules, `redirect`, `rewrite_path`, query actions, hot reload, `roxy rule test`, address policy + denylists (§7.1) with `@list` DSL literals, proxy auth, `roxy.internal` CA endpoint | metrics (A) ∥ reload+CLI (B) ∥ connector policy + lists (C) |
| M3 | WebSocket inspect tier (frame codec, `ws` phase); RFC 8441 WebSocket-over-h2 if wanted | — |
| M4 | WASM host (`roxy-wasm`), WIT package, `roxy-addon` SDK, example Rust + Python addons, capability/fuel/timeout enforcement | host (A) ∥ SDK+examples (B) |
| M5 | Hardening: fuzz CI, limits audit, body capture, Prometheus endpoint, file log rotation | independent items |
| Later | Transparent mode (§4.2): `TransparentListener` with REDIRECT + `SO_ORIGINAL_DST`, classification, rule-gated passthrough, nftables docs, netns integration test; TPROXY | — |

---

## 16. Open decisions (proposed defaults)

| # | question | proposed default |
|---|---|---|
| 1 | Transparent-mode upstream target (§4.2) | `resolve`; decide when transparent mode is built |
| 2 | Rule evaluation: first terminal action wins, chain exhausted → deny (§6.1) | as stated |
| 3 | Addons run in-path at a configurable stage; rules always evaluate the final request (§11.1) | as stated |
| 4 | Deny response body includes rule id and flow id (§5.7) | yes, informative 403 by default |
| 5 | Size units 1024-based (§6.2) | yes |
| 6 | Licence and crate name on crates.io | MIT OR Apache-2.0; `roxy` availability to be checked |
| 7 | Connect-phase default when no rule matches: allow-to-inspect (§4.3) | as stated |
| 8 | Client-side h2 in M1 (§5.1a) | agreed: M1 unit E |

Resolved since the first draft: upstreams are trusted, so the upstream codec
is plain hyper (§2, §5.6); WebSockets default to a byte relay with inspection
opt-in (§8); transparent mode is deferred with hooks reserved (§4.2).

---

## 17. Glossary

- **Flow**: one request/response exchange (or one WebSocket session) within a
  client connection. Has a ULID.
- **Phase**: `connect`, `request`, `response`, `ws`. Each has its own rule chain.
- **Canonical**: roxy's validated, normalised, version-agnostic HTTP model.
- **Policy**: a compiled, immutable snapshot of config (rules, metrics,
  addons) swapped atomically on reload.
- **Passthrough**: transparent-mode-only relay of raw bytes to the original
  destination, permitted only by an explicit connect rule.
