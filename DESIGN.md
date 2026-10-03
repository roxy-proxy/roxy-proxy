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
9. **Streams, not messages.** A flow is a request head, a request body
   stream, a response head and a response body stream. Every stage of the
   pipeline, including addons, operates on those streams. Bodies are
   buffered only when a specific rule or addon declares it needs body
   content, and then only up to a cap. Nothing else in roxy ever holds a
   whole body.

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
                       │ CONNECT ── proxy auth, SNI must match CONNECT host     │
                       │   ▼                                                    │
                       │ TLS terminate (rustls, leaf minted by roxy CA)         │
                       │   ▼  ALPN → h1 | h2                                    │
                       │ Strict parse → CanonicalRequest                        │
                       │   ▼                                                    │
                       │ addons ─▶ rules at request head → forward or deny      │
                       │   ▼  allow(+mutations)                                 │
                       │ Upstream connector (own DNS, SSRF policy, rustls)      │
                       │   ▼  hyper client, HTTP/1.1                             │
                       │ Strict parse → CanonicalResponse                       │
                       │   ▼                                                    │
                       │ watching deny rules (body bytes, response, metrics)    │
                       │   ▼                                                    │
                       │ Re-serialise to client (h1 | h2)                       │
                       │                                                        │
                       │ FlowLog (JSONL) ◀── every stage emits events           │
                       └────────────────────────────────────────────────────────┘
```

### Crate layout (Cargo workspace)

| crate | responsibility |
|---|---|
| `roxy-http` | Canonical request/response model, strict HTTP/1.1 codec, h2 ↔ canonical mapping, URL normalisation, body framing with caps, WebSocket frame codec. No I/O policy. |
| `roxy-tls` | CA generation/persistence, leaf cert minting + cache, rustls server/client config builders, ClientHello sniffing (SNI, ALPN). |
| `roxy-rules` | Expression DSL (lexer, parser, type-checker, compiler), rule set, evaluation model, actions, metrics/state store, hot-reload-safe `Policy` snapshot. |
| `roxy-wasm` | wasmtime component host, WIT world, addon lifecycle, fuel/memory limits, host-call implementations. |
| `roxy-proxy` | Listeners, connection state machine, flow pipeline, upstream connector (DNS, SSRF policy, pool), WebSocket relay, flow log emission. |
| `roxy-log` | Buffered single-writer log destinations (§10.1): one writer thread, batching, backpressure, size rotation, compression. Knows bytes, not events; used by the flow log and later by body capture (§10.2). |
| `roxy` | Binary: CLI (`run`, `check`, `ca export`, `rule test`), config loading, reload watcher, wiring. |
| `roxy-addon` | SDK for Rust addon authors: generated WIT bindings + ergonomic wrappers. Published independently. |
| `wit/` | The `roxy:addon` WIT package. Language-agnostic contract for addons. |

Dependencies point downward: `roxy` → `roxy-proxy` → {`roxy-http`, `roxy-tls`,
`roxy-rules`, `roxy-wasm`}. `roxy-http` and `roxy-rules` have no network I/O and
are fully unit/fuzz-testable.

### Pipeline as stream stages

Every box in the diagram is a `Stage`: it receives `(head, body stream)` and
yields `(head', body stream')`. Rules are a stage that mostly rewrites the
head and passes the body through untouched; a body-inspecting rule inserts a
bounded buffering stage in front of itself. Addons are stages. The upstream
connector is the terminal stage that turns a request stream into a response
stream, and the response flows back through the stages in reverse. This is
what lets addons sit anywhere in the path without changing anything else.

### Key runtime types

```rust
// roxy-proxy
struct ClientConn { id, listener: ListenerId, peer: SocketAddr, mode: Mode,
                    user: Option<String>, original_dst: Option<SocketAddr> }

struct Flow { id, conn: Arc<ClientConn>, tls: Option<TlsInfo>,
              request: CanonicalRequest, response: Option<CanonicalResponse>,
              tags: Vec<String>, matched: Vec<RuleId>, decision: Decision }

enum Decision { Allow { mutations: Vec<Mutation> }, Deny { status, body },
                Passthrough /* transparent mode only, deferred */ }

// roxy-rules
struct Policy { rules: Vec<CompiledRule>,   // one ordered list (§6.1)
                head: Vec<RuleIdx>,         // rules taking part in the head decision
                watching: Vec<RuleIdx>,     // rules re-checked after forwarding
                watch_triggers: Reads,      // union of what the watching rules read
                default: DefaultDecision, metrics: MetricDefs }
// Each CompiledRule carries its kind (head | watching | head-and-watching)
// and a `Reads` bit mask of the watched values it reads, so "does any rule
// care about this body chunk?" is one mask test.
// Swapped atomically on reload: Arc<ArcSwap<Policy>>.

// roxy-proxy, per forwarded exchange
struct Watch { stop: CancellationToken, state: Mutex<WatchState /* fired
               rules, tags, byte counts, known values, the stop */> }
```

---

## 4. Modes and listeners

A config may define several listeners, each with a name and mode. Rules can
match on `listener.name`.

### 4.1 Explicit proxy mode (default)

Client speaks HTTP/1.1 to roxy on the proxy port.

- **Absolute-form requests** (`GET http://host/path HTTP/1.1`): plain HTTP.
  Parsed, canonicalised, evaluated. `Host` header must equal the URI authority.
- **CONNECT host:port**: roxy replies `200 Connection Established` (after
  proxy auth, if configured) and then **peeks the first bytes**:
  - TLS ClientHello → extract SNI and ALPN. SNI must equal the CONNECT host
    (`tls.require_sni_match`, default true; no-SNI uses the CONNECT host).
    Terminate TLS with a leaf cert for that host. Inner protocol must be
    HTTP/1.1 or HTTP/2 (ALPN); each request is decided by the rules.
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
- Connect-time rules and `dst.*` fields return with this mode (§6.1).
- `listener.mode` is a rule field from M1 with the single value `explicit`.
- The `passthrough` action is reserved in the action enum and rejected by the
  compiler with "requires a transparent listener" until the listener exists.

When built, traffic is steered to roxy by nftables/iptables REDIRECT or
TPROXY. roxy recovers the original destination via `SO_ORIGINAL_DST`
(`IP6T_SO_ORIGINAL_DST` for v6).

On accept, roxy peeks the first bytes and classifies:

| first bytes | default | rule-gated alternative |
|---|---|---|
| TLS ClientHello | MITM, require HTTP inside | `passthrough` (connect-time rule, requires `transparent.allow_passthrough: true`) |
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

### 4.3 CONNECT

A CONNECT is accepted for inspection whenever the listener's auth (if any)
passes: there are no connect-time rules (§6.1). The tunnel's first bytes
must be a TLS ClientHello whose SNI matches the CONNECT host (or plaintext
HTTP when `http.allow_plain_in_connect`), otherwise the connection is
closed. Every allow/deny decision is made on the requests inside.

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
  after the rules allow the request. Anything else → `417`.
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
A refused CONNECT (failed proxy auth) gets `407`. Transparent-mode refusals
before TLS is established can only close the socket.

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

default: deny                  # deny (default) | allow: what happens when no rule matches

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

  - id: log-upstream-5xx            # reads a response value, so it watches
    when: response.status >= 500
    then: { log: { level: warn, message: "upstream 5xx" } }

addons:                          # above the rules, in this order (§11.1)
  - name: pii-scan
    kind: wasm
    path: /etc/roxy/addons/pii_scan.wasm
    mode: enforce
    config: { threshold: 0.8 }
    capabilities: [state, record]
```

Relative paths in the config (`ca_dir`, secret files, addon paths, log and
capture paths) resolve against the process working directory.

#### How rules are evaluated

An exchange is a set of values that become known over time: the request
head, request body bytes as they stream, the response head, response body
bytes, WebSocket messages, and metric values that this exchange adds to.
Rules are **one ordered list** of conditions over those values. There are no
phases; when a rule runs follows from what it reads.

1. **The forwarding decision is made at the request head, and deny wins.**
   roxy evaluates every rule whose values are known at that point. If any
   matching rule denies, the request is denied. Otherwise, if any matching
   rule allows, it is allowed. Otherwise the default applies:
   `default: deny` (the default) denies and `default: allow` allows, both
   with rule id `_default`. Rule order does not affect the decision, so the
   usual shape is a set of allowed hosts plus denies that restrict them,
   anywhere in the list. A rule that reads a value not yet known is skipped
   here, not treated as false.
2. **After that, rules watch.** For the rest of the exchange, two kinds of
   rule are re-checked whenever a value they read becomes known or changes:
   rules that read a value known only after forwarding (the *watched*
   fields in §6.2), and `deny` rules that read a byte metric
   (`count: request_bytes` or `response_bytes`), which this exchange adds
   to as bytes stream. A deny reading a `requests`, `denied`, `errors` or
   `unique` metric is decided at the head only: re-checking it after this
   exchange's own count would deny the 30th request of a `>= 30` limit
   instead of the 31st (§6.4). If a deny matches, roxy stops the exchange: an error response if the
   response has not started, otherwise the connection (or HTTP/2 stream, or
   WebSocket) is closed. Nothing can override a deny at any point.
3. **Only rules decided at the request head can `allow`.** A rule that reads
   a value known only after forwarding (the table in §6.2) cannot allow, and
   cannot change the request (`set_header` on the request, `rewrite_path`,
   `redirect`, ...): both are compile errors, because the request is already
   on its way. It can deny, and it can add effects that still make sense:
   `log`, `tag`, `set_state`, and header changes on a response that has not
   yet been sent to the client.
4. **Non-terminal effects of a watching rule apply once**, the first time it
   matches.
5. **Order matters for effects, not decisions.** Rules are evaluated top to
   bottom, so a `tag` set by a matching rule is visible to rules below it.
   If the request is allowed, the non-terminal effects of every matching rule
   apply in list order; if two set the same header, the later one wins.
   Allow options (`upgrade`, `private_ok`) come from the first matching
   allow rule only. The flow log names the first matching deny (or allow)
   as `terminal_rule`.

A rule's `then` is a list of actions (or a single action): any number of
non-terminal actions (`set_header`, `tag`, `log`, ...) and at most one
terminal action (`allow` or `deny`), last. `roxy check` and
`roxy rule test` report, for each rule, whether it is decided at the request
head or watches later values.

**Unavailable inputs fail closed.** If evaluating a rule needs a metric value
or an address-list lookup and the store reports it unavailable (overloaded,
table full, list failed to load), the outcome is an immediate
`Deny { 503, "policy input unavailable" }` with `terminal_rule = "_fail_closed"`
and a `policy_input_unavailable` flow event. The same applies to a missing
secret at evaluation time. Nothing in the engine may turn "I could not
check" into "the predicate is false". (A field that is simply not present,
like an unsent header, is `null`; see §6.2.)

**A deny closes the connection.** Deny responses carry `connection: close`
(h1) or are followed by `GOAWAY` (h2) once written. Well-behaved clients
reconnect cheaply; a probing client loses its warm connection on every
attempt and cannot pipeline past a refusal.

There is no `phase` key; a config that sets one is rejected with a pointer
to this section. There are no connect-time rules: a CONNECT is always
accepted for inspection (subject to the listener's auth and the SNI check),
and every decision is made on the request inside it. Connect-time rules
return with transparent mode, where `passthrough` needs them (§4.2).

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
literal     := string | number [unit] | bool | list | cidr | bare_ident | "null"
list        := "[" literal ("," literal)* "]"
unit        := kb | mb | gb | ms | s | m | h          ; 1024-based sizes
bare_ident  := [A-Z][A-Z_]*                          ; HTTP method names only
```

Strings are double-quoted with `\"` and `\\` escapes. Comments `# ...` are
allowed inside multi-line YAML block scalars.

Fields. *Head* fields are known when the forwarding decision is made;
*watched* fields become known later, so rules that read them watch (§6.1).

| field | type | known |
|---|---|---|
| `client.ip`, `client.port`, `client.user` | ip, int, string | head |
| `listener.name`, `listener.mode` | string | head |
| `tls.sni`, `tls.alpn`, `tls.version` | string | head |
| `method`, `scheme`, `host`, `port`, `path`, `url` | string / int | head |
| `query["k"]`, `query.raw` | string | head |
| `header["name"]`, `header.all["name"]` | string, list | head |
| `body.size` | int: declared length, `null` if undeclared (chunked) | head |
| `body.text` | string; roxy buffers the body (up to the cap) before forwarding | head |
| `metric.<id>` | int | head, and watched as this exchange adds to it |
| `state["key"]`, `tag["name"]` | string, bool | head |
| `body.bytes` | int: request body bytes so far | watched |
| `response.status`, `response.header["name"]`, `response.header.all["name"]` | int, string, list | watched |
| `response.body.size` | int: declared length, `null` if undeclared | watched |
| `response.body.text` | string; roxy buffers the response body before sending it on | watched |
| `response.body.bytes` | int: response body bytes so far | watched |
| `ws.direction` (`c2s`/`s2c`), `ws.opcode`, `ws.size`, `ws.text` | string, string, int, string; per message | watched |
| `@<list>` (literal, not a field) | address list, on the right of `in` / `not in` with an ip field | — |

Type checking at compile time: `host under 443` is a config error, as is a
regex that fails to compile, a CIDR with a bad mask, or a `metric.foo` with no
such metric. `in` accepts a list of the operand's type, or a CIDR for ips.

**Missing values (`null`).** A value that is not present is `null`: an
unsent header or query parameter, an unset state key, `client.user` without
proxy auth, `tls.sni` from a client that sent none, `body.size` for a body
of undeclared length. One rule covers all of them:

> `null` is equal only to `null`, so `==`, `!=`, `in` and `not in` treat it
> as an ordinary value. Any other operator applied to `null` is an error,
> and an error fails the flow closed.

| expression, with `x` missing | result |
|---|---|
| `x == null` | true |
| `x != null` | false |
| `x == "a"`, `x in [...]` | false |
| `x != "a"`, `x not in [...]` | true |
| `x > 10`, `x contains "a"`, `x matches "..."`, `x under "..."`, `x in 10.0.0.0/8`, `x in @list` | fails closed: `_fail_closed`, reason `missing_value`, naming the field |

Because `and` short-circuits, a guard makes a rule apply only when the value
is present: `body.size != null and body.size > 10mb` skips bodies without a
declared length and compares the rest. Unguarded, `body.size > 10mb` cannot
answer for such a body and fails it closed. `null` may only appear as
`x == null` or `x != null`; anywhere else is a compile error.

**Body access.** `body.text` and `response.body.text` are the only things in
roxy that buffer. They force the rules stage to collect the body (up to
`limits.max_inspect_body_bytes`, default 1 MiB) for flows whose other
predicates match, evaluate, then replay the bytes downstream as a stream. A
body larger than the cap **fails closed**: the flow is denied with
`_fail_closed` and reason `body_too_large_to_inspect`, because "could not
check" must never become "the predicate is false" (§6.1). Operators who need
to inspect larger bodies raise the cap; operators who do not need body
predicates on large uploads scope the rule with
`body.size != null and body.size < 1mb and ...`, which short-circuits before
the body is touched.

`body.size` and `response.body.size` are the declared length (0 for an empty
body, `null` for a chunked one). The hard cap for every request, declared or
not, is `limits.max_request_body_bytes`, enforced while streaming. The
compiler determines per-rule whether the body is needed; rules without body
predicates never buffer and stream end-to-end.

### 6.3 Actions

Terminal:

| action | where | effect |
|---|---|---|
| `allow` | head rules only | forward. `allow: { upgrade: websocket }` also permits the upgrade (§8). |
| `deny` | all rules | `deny: { status: 403, message: "…" }`. At the head: refuse. Watching: stop the exchange (error response if the response has not started; otherwise h1 breaks the connection without completing the body, h2 resets the stream with `CANCEL` and sends `GOAWAY` if the deny closes). On the byte-level WebSocket relay (§8.1): close both sides (a close frame could land inside a half-relayed frame); with message rules (§8.2): close with `1008`. |
| `passthrough` | connect-time rules (transparent mode, deferred) | relay bytes to the original destination uninspected. Logged. Compiler rejects it until a transparent listener exists. |

Non-terminal (evaluation continues):

| action | where | effect |
|---|---|---|
| `set_header: { name: value }` | request: head rules; response: rules that read response values | set/replace. Values may reference `${secret:name}` (request headers, so head rules only). Validated as header values; invalid → flow denied. In a watching rule the target is the response, and every value the rule reads must be known before the response head is sent (`response.status`, `response.header[..]`, `response.body.size`, `response.body.text`); a rule that also reads `body.bytes`, `response.body.bytes` or a byte metric could match after the head went out, so that is a compile error, as is `set_header` in a watching rule that reads no response value. |
| `remove_header: [names]` | request, response | |
| `rewrite_path: { match: regex, to: replacement }` | request | `$1` groups; result re-normalised per §5.4 |
| `set_query: {k: v}` / `remove_query: [k]` | request | |
| `redirect: { host, port, scheme? }` | head rules | change the upstream target; the address floor and deny lists check the new target's IPs. `Host` header is unchanged unless `rewrite_host: true`. |
| `tag: name` | all | sets `tag["name"]` for later rules, addons and the log |
| `log: { level, message }` | all | emits an extra log event |
| `set_state: { key, value, ttl }` | all | writes to the state store (visible as `state["key"]`) |
| `capture: request | response | both` | request, response | writes bodies to the capture dir (§10) |
| `call: addon_name` | — | reserved; rejected by the compiler. Addons always run above the rules, in listed order (§11.1) |

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
    where: <expr>                 # head fields only; decides whether this exchange counts
    key: [<field>, ...]           # optional, head fields only; omitted = one global series
    window: <duration>            # optional; omitted = cumulative since start
```

Implementation: `DashMap<KeyTuple, SlidingWindow>` with fixed-bucket sliding
windows (window / 60 buckets, so a 1-minute window has 1-second resolution).
`unique` uses a HyperLogLog. Total keys across all metrics are bounded by
`limits.max_metric_keys`. **When the table is full, a flow that would need a
new key is denied** (`_fail_closed`, event `metric_table_full`) rather than
evicting an existing key: eviction would let an attacker reset their own
counter by varying the key. Keys are reclaimed only when their window has
fully expired. `requests` and `denied` are incremented after the
forwarding decision (denied flows count too, so probing is not free), and
read before it, so a rule `metric.x >= 30` denies the 31st request.
`request_bytes` and `response_bytes` are added as bytes stream, so a deny
rule reading them watches and can stop the exchange that crosses the limit.
A chunk is counted before it is checked, and is not forwarded if the check
stops the exchange, so a budget may be overcounted by at most one chunk
(the fail-closed direction). `errors` are counted when the exchange ends.
`where`, `key` and the field of `unique(<field>)` must be head fields, so
whether an exchange counts, and its series, are fixed at the request head.

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

- **Representation:** each list compiles into a sorted table of disjoint
  CIDR blocks per family, looked up by binary search: 8 bytes per v4 entry,
  32 per v6, no allocation per lookup. A million v4 plus 100k v6 entries is
  about 11 MiB, parses in about 170 ms, and looks up in 25–90 ns.
- **Two matching modes.** The deny floor (`upstream.deny_lists`) is broad: it
  matches the address as given, its IPv4-mapped form, and the IPv4 address a
  NAT64 (`64:ff9b::/96`) or 6to4 (`2002::/16`) address would reach, because
  matching more is the safe direction for a deny. Rule membership
  (`ip in @list`) is exact, with only the IPv4-mapped equivalence, because a
  rule might *allow* on membership: `client.ip in @internal → allow` must not
  treat a 6to4 address that embeds an internal IPv4 address as internal.
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
  is: `client.ip in @internal`, `client.ip not in @blocked`. Referencing an
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

An Upgrade is only honoured when the rule that allows the request says
`allow: { upgrade: websocket }`. Plain `allow` strips `Upgrade`/`Connection:
upgrade` and forwards an ordinary request (fail closed on the upgrade).

### 8.1 Relay

`allow: { upgrade: websocket }` at the request head. roxy forwards the upgrade
request to the upstream (after the usual header canonicalisation;
`Sec-WebSocket-*` headers and the client's extension offer pass through
untouched), checks that the upstream answered `101` with a correct
`Sec-WebSocket-Accept`, relays the `101` to the client, and then **splices
bytes in both directions** until either side closes. No frame parsing, no
re-masking, no reassembly. `permessage-deflate` and subprotocols work exactly
as negotiated end to end. Relayed bytes count towards `request_bytes` and
`response_bytes` as they flow, so a byte-budget rule closes a WebSocket
mid-stream. The flow log gets one `ws_open` and one `ws_close` event with
byte counts.

### 8.2 Message rules (not in this build)

After the `101`, messages are values that keep arriving: each brings
`ws.direction`, `ws.opcode`, `ws.size` and `ws.text`. Rules that read them
watch (§6.1) and are checked on every message. **`deny` closes the
WebSocket** with close code `1008` (policy violation) to both sides; there is
no per-message drop in the rule language, because silently dropping a
message corrupts most applications' protocol state (per-message editing is
for addons, via the `tunnel` export, §11). An allowlist is written as a deny
of everything else, e.g. `when: ws.opcode != "text"` → `deny`.

Message parsing is inferred: if any rule reads `ws.*` fields, WebSockets are
relayed through a frame codec (and compression extensions are stripped from
the offer, so messages stay readable); otherwise bytes are relayed
untouched. The codec:

- RSV bits must be zero; unknown opcodes → close `1002`.
- Client→server frames must be masked; server→client must not be.
- Control frames ≤ 125 bytes, not fragmented.
- Fragmented messages are reassembled up to `limits.max_ws_message_bytes`
  (default 16 MiB) for evaluation and forwarded as a single frame; over-size
  → close `1009`.
- Text frames must be valid UTF-8 → else close `1007`.
- Re-masking with roxy's own random mask on the way to the server.

Until the codec is built, `roxy run` refuses a policy whose rules read
`ws.*` (`roxy check` accepts it).

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
 "timing":{"total_ms":412,"upstream_connect_ms":38,"upstream_ttfb_ms":350},
 "terminal_rule":"github-writes","stage":"head"}
```

`stage` says where the terminal decision was made: `head` (the forwarding
decision), or where a watching rule stopped the exchange: `request_body`,
`response_head`, `response_body`, `websocket`. `terminal_rule` is the rule
that decided (`_default`, `_fail_closed`, `_address_policy` for built-in
decisions) and `reason` a stable code when it failed closed.

Event types: `connect`, `request`, `response_error`, `ws_message` (sampled or
denied only, configurable), `parse_error`, `upstream_error`, `layer_error`, `layer_record`, `endpoint_call`, `quarantined`,
`config_reloaded`, `config_reload_failed`, `passthrough`.

**Redaction:** every injected secret value is registered with a `Redactor`
that scrubs it from any logged string. Header values for `authorization`,
`proxy-authorization`, `cookie`, `set-cookie`, `x-api-key` are never logged
in full (`log.redact_headers` to extend). Query strings are logged with
values redacted by default.

Sinks implement `trait FlowSink` (`emit`, plus `poll_ready` for
backpressure, `flush` and `reopen`): `Stdout`, `File` (with size rotation),
later `UnixSocket` (live stream), `Otlp`.

**Writing** (the `roxy-log` crate).
Logging is a first-class product feature and an audit trail, so the write
path is built for many cores and heavy traffic, and it never drops:

- **One writer per sink.** A single task owns each file. Emitters serialise
  the event on their own thread and enqueue the bytes on a bounded
  multi-producer queue; they never touch the file or contend on its lock.
- **Batching.** The writer drains everything queued and issues one large
  write: under load each write carries everything queued since the last,
  at low load each line goes out as it arrives. Throughput scales with
  disk bandwidth rather than event rate. Dropping the sink writes what is
  left.
- **Backpressure, never loss.** Emitting never blocks and never drops.
  Instead, once unwritten bytes pass a high-water mark (8 MiB) the sink
  reports not-ready (`FlowSink::poll_ready`), and every traffic producer
  waits on it: the start of each exchange, each forwarded body chunk, each
  WebSocket read. So the wait propagates to the network: roxy stops
  reading from the client and the upstream until the log catches up,
  slowing traffic rather than losing records. Overshoot past the mark is
  bounded by what in-flight exchanges emit between two checks. A sink
  that fails (disk full, I/O error) stops traffic the same way; it is
  reported, never silently skipped.
- **Rotation** (`log.flow.max_file_bytes`, `max_files`, `compress`)
  happens in the writer thread at a batch boundary, so a record never
  spans two files. The file is renamed to `<path>.<UTC timestamp>-<seq>`
  (names sort in rotation order), a new one is opened, the oldest beyond
  `max_files` are deleted and rotated files are optionally gzipped in the
  background. A failed rotation is a failed write: traffic is held and it
  is retried. `SIGHUP` reopens the file for external rotation.
- **Shared with capture.** Body capture (§10.2) and any future "tee all
  traffic" mode use the same writer machinery and the same backpressure,
  fed from the body adapters that already see every forwarded chunk
  (the watcher's, §6.1), so what is captured is exactly what was relayed.

### 10.2 Body capture

`capture` action writes `<capture_dir>/<flow id>.req.body` /
`.res.body` plus a `.meta.json` with the canonical head. Captured bytes go through the buffered writer
above (one writer, batching, backpressure), keyed by flow id so they join
the JSONL events. Capped by
`limits.max_capture_body_bytes`. Off unless a rule asks for it. Secrets are
*not* redacted inside bodies (document loudly).

### 10.3 Operational logging and metrics

`tracing` for roxy's own logs (JSON or pretty, `RUST_LOG`). A Prometheus
`/metrics` endpoint on the `ca_server` listener is a later milestone; the
`metrics:` registry is designed so each user metric becomes a gauge there.

---

## 11. Layers and addons

### 11.1 The layer stack

An exchange passes through an ordered stack of **layers**. Each layer wraps
everything below it: it receives the request (head plus body stream), may
pass a request down with `next`, receives the response stream from below,
and returns a response stream upward. The request travels down the stack and
the response travels back up it in reverse order, so the first layer to see
the request is the last to see the response.

```
                 request ↓                                   ↑ response
 fixed   ┌─ CONNECT gate (proxy auth, SNI must match) ───────────────────┐
 fixed   ├─ quarantine gate (§11.3 terminate)                            │
 config  ├─ addon: sentinel        (wasm | service, enforce | observe)    │
 config  ├─ addon: redactor                                              │
 fixed   ├─ rules                  (request ↓ / response ↑)              │
 fixed   ├─ address floor + deny lists (on the IP actually dialled)      │
 fixed   └─ connector ──▶ origin ────────────────────────────────────────┘
```

**Addons always sit above the rules**, in the order they are listed under
`addons:`. The first addon sees each request first and each response last.
Nothing configurable runs between the rules and the network, so what the
rules judged is what leaves; there is no "after the rules" position.

Everything marked *fixed* is not configurable. The connect gate runs before
any addon sees bytes. The address floor and deny lists (§7, §7.1) are the
innermost layer because the IP is only known after DNS resolution, so they
always check the IP that is dialled.

**Invariants.**

1. **The rules evaluate every request that leaves for the network.** An
   addon can reshape traffic freely; its output is re-validated by the
   canonical model and then judged by the rules exactly as if the agent had
   sent it. On the way back, the response rules see the upstream's response
   before any addon does.
2. **Every layer is held to the workload's limits.** Whatever a layer passes
   on is treated as if a client sent it: header limits, body caps, idle
   timeouts.
3. **Failure is closed.** A layer that traps, exceeds a budget, or returns an
   invalid head denies the flow (or closes the connection if the response
   head is already out). There is no `on_error: pass`; see observe mode for
   the one safe way to run a layer whose failures do not matter.

There is no stage setting and no rule action that invokes an addon: either
would make it ambiguous what the rules enforced. `call:` stays a reserved
word in the rule grammar and is rejected by the compiler.

**Layer kinds.** A layer is either a **wasm** component running in-process
(§11.4) or a **service layer**: an external service that roxy streams the traffic through (§11.6). Both
implement the same contract and get the same host services.

**Modes.**

- `mode: enforce` (default). The layer is in the path and its decisions take
  effect.
- `mode: observe`. roxy **tees** both streams to the layer and discards
  anything it returns other than records (§11.3). The layer cannot change or
  delay traffic, so its failures cannot weaken containment: a trap or
  timeout is logged, not fatal, and if the layer falls behind roxy drops its
  copy (logging `observer_lagged`) rather than stall the flow. The tee buffer
  is bounded per flow. This is the right way to deploy an uncalibrated
  scoring monitor, which the sentinel design recommends as the proxy
  default.

**One exchange, one `next`.** A layer calls `next` at most once per
exchange. The stack carries the client's traffic and nothing else: a layer
never originates requests through the layers below it. Retrying,
regenerating or replaying is the client's (scaffold's) responsibility; a
layer that rejects something answers with a response the client can act on.
A layer that needs to talk to anything else makes an **independent call to a
named endpoint** (§11.3), in the manner of Envoy Lua's `httpCall`: it goes
straight to the connector, never through other layers or the rules, and is
governed by the endpoint's own configuration. A second `next` call traps.

**Full bidirectional access, low level.** A layer owns everything at its
position in both directions. It may read, rewrite, split, delay, inject into,
or replace any stream, chunk by chunk. roxy buffers nothing on a layer's
behalf; a layer that wants a whole body reads its stream to the end, up to
its `max_buffered_body_bytes`. For upgraded connections (the WebSocket relay
tier) a layer that exports `tunnel` gets the two raw byte streams after the
`101`. A layer without `tunnel` is not in that path, but the upgrade
*request* still passes through it, so it can refuse the upgrade.

Typical patterns:

- **Observe:** `next(req)`, return its response unchanged (or use observe mode).
- **Rewrite in flight:** wrap a body stream in a transform, chunk by chunk.
- **Withhold until cleared:** forward a streamed response's text events as
  they arrive, but hold back `tool_use` blocks until the layer has judged
  them. Envoy's buffered/streamed processing modes cannot express this; a
  streaming layer can.
- **Stream through an external transformer:** send the request head and
  body bytes to another service as they arrive, which may mutate them and
  streams the result back, then pass that on down; do the same with the
  response head and body on the way back up. This is a first-class use case
  and is exactly what a service layer is (§11.6); a wasm layer can
  do the same by piping into a named endpoint.
- **Deny or synthesise:** return a response without calling `next`.

roxy stays protocol-agnostic. It knows HTTP, not model APIs: parsing
Anthropic or OpenAI payloads into conversation steps is the layer's job.

### 11.2 Configuration

```yaml
addons:                               # above the rules, in this order
  - name: sentinel
    kind: wasm                        # wasm | service
    path: /etc/roxy/addons/sentinel.wasm
    mode: enforce                     # enforce | observe
    capabilities: [state, record, endpoints, terminate]
    endpoints:                        # named, not URLs (§11.3)
      monitor-model:
        url: https://api.anthropic.com/v1/messages
        headers: { x-api-key: "${secret:monitor_key}" }   # attached by roxy, never seen by the layer
        timeout: 10s
        retries: 2
      threat-intel:
        url: https://ti.internal:8443/score
        private_ok: true
        timeout: 500ms
    state:
      max_entries: 100000
      max_value_bytes: 64kb
      default_ttl: 6h
    limits:                           # defaults shown; raising one is logged at startup
      max_memory: 64mb
      max_buffered_body_bytes: 1mb    # defaults to limits.max_inspect_body_bytes
      step_cpu: 50ms                  # CPU between host calls
      max_exchange_time: 60s          # wall clock per exchange, including endpoint calls
      fuel_per_step: 100_000_000
      recycle_after_exchanges: 10000  # replace the instance (bounds linear-memory ratchet)
      recycle_above_memory: 48mb
    config: { reject_at: 0.8 }        # opaque JSON handed to the layer
```

An LLM-API sentinel will normally raise `max_buffered_body_bytes` (requests
resend the whole conversation and reach several MiB), `max_memory` (an
embedded CPython needs roughly 128–256 MiB), and `max_exchange_time` (judging
with a model takes 0.2–2 s).

### 11.3 Host services

Everything a layer can do to the world outside its streams is enumerable
from this list, and each item is a capability granted in config. An import
that is not granted fails immediately.

- **`endpoints` (named outbound calls).** A layer calls an endpoint by
  *name*; roxy resolves the name to a URL, attaches credentials from
  secrets, applies the timeout and retry policy, and enforces the address
  floor and deny lists. The layer cannot express a destination, so text
  injected into the traffic it inspects cannot steer it to an
  attacker-chosen host, and credentials never enter the layer. Calls are
  JSON-or-bytes over HTTP with streaming bodies. A deliberate `"*"` endpoint
  that accepts a URL can be configured but is not the default shape.
  Endpoint calls never pass through the layer stack, so a monitor's own
  model call cannot recurse through the sentinel. Each call emits an
  `endpoint_call` flow event (status, bytes, timing; bodies only with
  `record_bodies: true`, for replay).
- **`state` (keyed store).** A JSON-value store namespaced per layer, with
  per-entry TTL, a value size cap and an entry cap. A miss returns `none`,
  which the layer treats as "no history" (the sentinel design's degrade-to-
  pure-function rule). A write when full returns an error and the layer
  decides; nothing is evicted. Backed by `StateSource`, so a shared backend
  can replace it for multi-replica gateways.
- **Trusted identity.** `flow.current()` gives the principal as roxy
  established it: `client.user` from proxy auth, `client.ip`, listener, TLS
  SNI. These are the safe keys for per-principal state. A per-conversation
  key is the layer's job (the sentinel design fingerprints the stable head of
  the conversation), and a layer should strip any client-supplied session
  header rather than trust it.
- **`record` (structured events).** `flow.record(kind, json, audit: bool)`
  writes a structured, redacted event to the flow log with the flow id, the
  layer name and a timestamp. `audit: true` also sends it to the configured
  `audit_endpoint`. This is the sentinel `Recorder`: observations,
  decisions, failures and escalations land in the same JSONL stream as
  roxy's own events.
- **`terminate` (out-of-band).** `flow.terminate(scope, reason, ttl)` with
  scope `connection` or `principal`. `principal` adds the client's identity
  to the quarantine set, so the fixed quarantine gate denies every later
  request from it with rule `_quarantined` until the TTL expires or an
  operator clears it, and optionally notifies a `terminate_endpoint` (an
  orchestrator that can stop the agent). Returns whether it took effect. This
  answers the sentinel design's "what owns the lifecycle a proxy's terminate
  reaches": roxy does, locally, and can also tell whoever owns the agent.
- **`metrics` (read-only)** of the `metrics:` definitions, and `log`.
- **`secrets`** is still a capability but discouraged; endpoints attach
  credentials without exposing them.

Never hang a request. A layer that waits past `max_exchange_time` is
stopped and the flow denied or closed. Denial is an immediate response, so a
client sees a refusal rather than a stall that would trigger retries.

### 11.4 WASM layers: WIT sketch

roxy reuses the WASI 0.2 HTTP types for heads and bodies so existing
tooling applies.

```wit
package roxy:addon@0.1.0;

interface chain {
  use wasi:http/types@0.2.0.{outgoing-request, future-incoming-response, error-code};
  /// Pass this exchange's request to the layers below. At most once per
  /// exchange; a second call traps. Independent requests use `endpoints`.
  next: func(req: outgoing-request) -> result<future-incoming-response, error-code>;
}

interface endpoints {
  use wasi:http/types@0.2.0.{outgoing-request, future-incoming-response, error-code};
  /// Call a configured endpoint by name. The request's authority is ignored;
  /// path and query are appended to the endpoint's URL.
  call: func(name: string, req: outgoing-request) -> result<future-incoming-response, error-code>;
}

interface flow {
  record principal { client-ip: string, client-user: option<string>,
                     listener: string, tls-sni: option<string> }
  record flow-info { flow-id: string, conn-id: string, principal: principal,
                     tags: list<string> }
  enum scope { connection, principal }
  current: func() -> flow-info;
  add-tag: func(tag: string);
  log: func(level: u8, msg: string);
  record: func(kind: string, json: string, audit: bool);
  terminate: func(scope: scope, reason: string, ttl-ms: option<u64>) -> bool;
  state-get: func(key: string) -> option<string>;                         // JSON
  state-put: func(key: string, json: string, ttl-ms: option<u64>) -> result<_, string>;
  metric-get: func(id: string, key: list<string>) -> option<s64>;
  config: func() -> string;
}

interface tunnel {
  use wasi:io/streams@0.2.0.{input-stream, output-stream};
  on-tunnel: func(from-client: input-stream, to-upstream: output-stream,
                  from-upstream: input-stream, to-client: output-stream);
}

world layer {
  include wasi:cli/imports@0.2.0;        // clocks, random, streams; no fs, no sockets, no env
  import chain;
  import endpoints;
  import flow;
  export wasi:http/incoming-handler@0.2.0;
  export tunnel;                         // optional; detected at load time
  export init: func() -> result<_, string>;
}
```

Instances: one per worker thread per layer by default. A guest with its own
async runtime (for example CPython's asyncio over `wasi:io/poll`) can serve
several in-flight exchanges per instance; whether that works for CPython is
the sentinel design's open prototype question, and the host does not depend
on the answer. Instances are recycled after `recycle_after_exchanges` or when
their linear memory passes `recycle_above_memory`, which bounds the memory
ratchet the sentinel design warns about.

### 11.5 Safety

- **Capabilities** declared per layer; anything not granted fails at the
  call.
- **CPU per step** (epoch interruption plus fuel), **wall clock per
  exchange**, **memory per instance**, **buffered bytes per layer**. Each
  exceeded budget fails the flow closed in enforce mode and is logged.
- Any trap, an invalid head, or a `next` request that fails canonical
  validation denies the flow (or closes it if the response head is out).
- Layers see canonical heads and body streams, never raw wire bytes.
- No filesystem, sockets or environment inside the sandbox; all I/O is
  `next`, `endpoints` and `flow`.

### 11.6 Service layers (external services)

A `kind: service` layer is an external service in the stack. Its primary use
is to **stream** the exchange through a service that may mutate it: the
request head and body go to the service as they arrive, and the service
streams the (possibly changed) request back, which roxy passes down; on the
way back up the same happens with the response. This also covers the
sentinel design's sidecar deployment, Python with any dependencies, and any
other out-of-process logic, with no WASM toolchain.

```yaml
addons:
  - name: transformer
    kind: service
    endpoint: transformer-svc           # a named endpoint, as in §11.3
    directions: [request, response]     # which streams go through the service
    mode: enforce                       # enforce | observe
    limits:
      max_exchange_time: 60s
      first_byte_timeout: 2s            # service must start answering this fast
```

**Wire format: `message/http`.** For each direction roxy opens one call to
the endpoint over HTTP/2 (so both sides can stream at once) with
`content-type: message/http`. The request body roxy sends is the canonical
HTTP/1.1 message in transit, head then body bytes, written as they arrive.
The service answers `200` with `content-type: message/http` and streams back
the message it wants forwarded, again head first and body as it goes. It may
pass bytes through untouched, rewrite them, or emit something different.

- **Everything the service returns is re-parsed by roxy's strict codec**
  (§5), so a service cannot introduce smuggling or framing ambiguity, and
  its output is then subject to the same limits and, for layers above
  `rules`, the rules.
- **Head first.** roxy forwards nothing downstream until the service has
  returned a complete head, bounded by `first_byte_timeout`. Body bytes then
  flow with backpressure in both directions.
- **Decisions without a message.** Instead of a `message/http` reply, the
  service may answer with `content-type: application/roxy-decision+json`:
  `{deny: {status, message}}`, `{respond: {status, headers, body}}`, or
  `{terminate: {scope, reason}}`. For a response-direction call, `deny` and
  `respond` replace the response the client gets.
- **Metadata** (flow id, principal, tags, direction) travels in
  `roxy-flow-*` request headers on the call, so the service can key state.
- **Failure is closed** in enforce mode: a non-`200`, an unparseable
  message, a timeout, or a dropped stream denies the flow (or closes it if
  the response head is already out). In observe mode the service gets a copy
  and its failures are logged only.

The call goes straight to the connector like any endpoint call, so it never
passes through other layers or the rules. A service that only needs to
inspect, not mutate, can buffer on its side; roxy never buffers for it.

### 11.7 Sentinel substrate: mapping

How the inspect_sentinel proxy deployment maps onto roxy, so a sentinel can
be built on roxy without roxy knowing anything about model APIs.

| sentinel need | roxy provides |
|---|---|
| `BeforeGenerate` (request body) | request stream at the layer's position |
| `AfterGenerate` (response body) | response stream on the way back up |
| `BeforeToolCall` (tool_use in response) | the response stream; can withhold tool_use blocks while forwarding text |
| `AfterToolCall` (tool_result in next request) | next request's stream (lossy by nature, as the design notes) |
| `continue` / `modify` | pass through / rewrite the stream |
| `reject` | rewrite the response so the scaffold sees the rejection (e.g. a synthetic tool result or refusal); the scaffold regenerates. roxy never replays |
| error response | return a synthetic response |
| `terminate` | `flow.terminate` → quarantine gate, optional `terminate_endpoint` |
| `escalate` | the sentinel's own composition; roxy sees only the final action |
| `audit` / `Recorder` | `flow.record(..., audit: true)` into the flow log and `audit_endpoint` |
| `host.generate` with another model | named endpoint for the monitor model |
| `host.generate` as the agent's own model | a named endpoint pointing at the same model API (an independent call, not via the stack) |
| `host.fetch` with named endpoints | `endpoints.call` — same design, credentials attached by roxy |
| `host.get` / `put` keyed store | `flow.state-*`, JSON values, TTL, no eviction |
| trustworthy principal key | `flow.current().principal` from proxy auth / client IP |
| recursion guard for monitor inference | endpoint calls bypass the layer stack |
| never hang the request | `max_exchange_time`, immediate deny responses |
| fail open or closed when the processor is down | closed in enforce mode; observe mode for monitors whose failure must not block |
| sidecar deployment | `kind: service` layer, streaming `message/http` (§11.6) |
| embedded CPython in WASM | `kind: wasm` with raised memory/time budgets and instance recycling |
| observe-only default for uncalibrated scores | `mode: observe` (tee) |

### 11.8 Authoring

Rust is first class: small components, fast instantiation, real streaming.
`roxy-addon` wraps the bindings in a middleware trait:

```rust
use roxy_addon::prelude::*;

struct RedactTokens;
impl Layer for RedactTokens {
    fn handle(&mut self, req: Request, next: Next) -> Response {
        let req = req.map_body(|body| body.transform(redact_chunk));
        next.run(req)
    }
}
roxy_addon::export!(RedactTokens);
```

Other languages:

- **Go** (wasip2) and **JS** (`jco componentize`) work, with larger binaries
  and higher per-call cost.
- **Python in WASM** (`componentize-py`, or the sentinel project's embedded
  CPython) bundles an interpreter: tens of MiB, 128–256 MiB of memory,
  milliseconds to instantiate, pure-Python dependencies only. Viable for a
  sentinel whose cost is dominated by model inference anyway; give it the
  raised budgets above.
- **Python with native dependencies**, or anything else out of process,
  runs as a service layer (§11.6).

`examples/addons/` ships a Rust pass-through, a Rust streaming redactor, a
Rust layer that withholds `tool_use` blocks in a streamed response until a
named endpoint clears them, and a minimal Python service layer.

## 12. Resource limits and self-protection

**Fail-closed audit.** Security and containment take priority over
availability (availability should still be very high given roxy's light
footprint, but when the two conflict, containment wins). Every limit below
resolves in the closed direction, and the proxy pipeline has no code path
where an error on the request path results in forwarding: an `Err` anywhere
between accept and upstream connect produces a deny response or a closed
socket, never a pass-through. Specifically:

| condition | result |
|---|---|
| parse or canonicalisation error | close connection (400 if a response can still be written) |
| rule denies | deny response, then close |
| policy input unavailable (metric store, address list, secret) | deny `503`, `_fail_closed` |
| metric key table full | deny, `metric_table_full` |
| body or header limit exceeded mid-stream | close both sides |
| upstream connect/TLS/DNS failure | `502`, flow logged |
| layer trap, budget exceeded, or invalid mutation (enforce mode) | deny, `layer_error`; observe-mode layers log only |
| config reload fails | keep the old policy; never run without one |
| per-client or global connection cap | refuse new connections |
| flow log sink cannot write | log a warning, continue (the only soft failure: losing audit lines is preferable to losing containment, and metrics expose it) |

- Per-client-IP connection cap; global connection cap; accept backpressure.
- All reads bounded (head size, body size, ClientHello size, WS message size).
- Timeouts at every stage; idle keep-alive timeout for client connections.
- Metric/state key cardinality caps with **no eviction**: a full table denies flows needing a new key (§6.4).
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
| M3 | WebSocket message rules (frame codec, §8.2); RFC 8441 WebSocket-over-h2 if wanted | — |
| M4 | WASM host (`roxy-wasm`), WIT package, `roxy-addon` SDK, example Rust + Python addons, capability/fuel/timeout enforcement | host (A) ∥ SDK+examples (B) |
| M5 | Hardening: fuzz CI, limits audit, body capture, Prometheus endpoint, file log rotation | independent items |
| Later | Transparent mode (§4.2): `TransparentListener` with REDIRECT + `SO_ORIGINAL_DST`, classification, rule-gated passthrough, nftables docs, netns integration test; TPROXY | — |

---

## 16. Open decisions (proposed defaults)

| # | question | proposed default |
|---|---|---|
| 1 | Transparent-mode upstream target (§4.2) | `resolve`; decide when transparent mode is built |
| 2 | Rule precedence: any matching deny wins, then any matching allow, then `default` (deny unless set to allow) (§6.1) | as stated |
| 3 | Addons are layers above the rules, in listed order; rules evaluate every request that leaves; addons' own calls go to named endpoints (§11) | as stated |
| 4 | Deny response body includes rule id and flow id (§5.7) | yes, informative 403 by default |
| 5 | Size units 1024-based (§6.2) | yes |
| 6 | Licence and crate name on crates.io | MIT OR Apache-2.0; `roxy` availability to be checked |
| 7 | No connect-time rules in explicit mode; one rule list, decided at the request head, deny rules watch later values (§6.1) | as stated |
| 8 | Client-side h2 in M1 (§5.1a) | agreed: M1 unit E |

Resolved since the first draft: upstreams are trusted, so the upstream codec
is plain hyper (§2, §5.6); WebSockets default to a byte relay with inspection
opt-in (§8); transparent mode is deferred with hooks reserved (§4.2).

---

## 17. Glossary

- **Flow**: one request/response exchange (or one WebSocket session) within a
  client connection. Has a ULID.
- **Head rule / watching rule**: a rule decided at the request head (can allow or deny) versus one that reads values known only later (can only deny or add effects) (§6.1).
- **Canonical**: roxy's validated, normalised, version-agnostic HTTP model.
- **Policy**: a compiled, immutable snapshot of config (rules, metrics,
  addons) swapped atomically on reload.
- **Passthrough**: transparent-mode-only relay of raw bytes to the original
  destination, permitted only by an explicit connect rule.
