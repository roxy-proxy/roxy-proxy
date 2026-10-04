# Addons

roxy knows HTTP, not any particular application or API. Logic that needs to
understand the traffic goes in an addon: a layer above the rules that owns
both streams of every exchange. An addon is either:

- **a WASM layer** (`kind: wasm`): a WebAssembly component run in-process by
  `roxy-wasm`, written against the `roxy:addon` WIT package
  ([`wit/addon.wit`](../wit/addon.wit)); or
- **a service layer** (`kind: service`): an external service in the network
  path, which each exchange streams through over a WebSocket
  ([below](#service-layers)).

Both sit in the same stack and obey the same invariants.

## Layer stack

An exchange passes through an ordered stack of layers. Each layer wraps
everything below it: it receives the request (head and body stream), may
pass a request down with `next`, receives the response stream from below,
and returns a response stream upward. The first layer sees the request
first and the response last.

```
                 request ↓                                   ↑ response
 fixed   ┌─ CONNECT gate (proxy auth, SNI must match) ───────────────────┐
 config  ├─ addon: first listed                                          │
 config  ├─ addon: second listed                                         │
 fixed   ├─ rules                  (head decision ↓ / watching ↑)        │
 fixed   ├─ address floor + deny lists (on the IP actually dialled)      │
 fixed   └─ connector ──▶ origin ────────────────────────────────────────┘
```

**Addons always sit above the rules**, in the order listed under `addons:`.
Nothing configurable runs between the rules and the network, so what the
rules judged is what leaves. There is no setting or rule action that
places an addon anywhere else: either would make it ambiguous what the rules
enforced.

### Invariants

1. **The rules evaluate every request that leaves.** An addon can reshape
   traffic freely; its output is re-validated by the canonical model and
   then judged by the rules exactly as if the client had sent it. On the
   way back, the watching rules see the upstream's response before any
   addon does.
2. **Every layer is held to the workload's limits.** Whatever a layer passes
   on is treated as if a client sent it: header limits, body caps, idle
   timeouts.
3. **Failure is closed.** A layer that traps, exceeds a budget or returns an
   invalid head denies the flow, or cuts the exchange if the response head
   is already out. There is no "on error, pass"; observe mode is the one
   safe way to run a layer whose failures must not matter.

### One exchange, one `next`

A layer calls `next` at most once per exchange; a second call traps. The
stack carries the client's traffic and nothing else: a layer never
originates requests through the layers below it. Retrying, regenerating or
replaying is the client's job, and a layer that rejects something answers
with a response the client can act on. A layer that needs to talk to
anything else calls a [named endpoint](#endpoints), which goes straight to
the connector, never through other layers or the rules.

### Full access to both streams

A layer may read, rewrite, split, delay, inject into or replace either
stream, chunk by chunk. roxy buffers nothing on a layer's behalf; a layer
that wants a whole body reads it, up to its `max_buffered_body_bytes`.
Typical patterns:

- **Observe:** `next(req)`, then return its response unchanged (or use
  observe mode).
- **Rewrite in flight:** wrap a body stream in a transform.
- **Withhold until cleared:** forward a streamed response's text as it
  arrives, but hold back parts (say, tool calls) until the layer has judged
  them.
- **Deny or answer:** return a response without calling `next`.

For WebSockets, a layer that exports `tunnel` gets the two raw byte streams
after the `101`. A layer without `tunnel` is not in that path, but the
upgrade request still passes through it, so it can refuse the upgrade.

### Modes

- `mode: enforce` (default): the layer is in the path and its decisions
  take effect.
- `mode: observe`: roxy tees both streams to the layer through bounded
  channels and ignores anything it returns except host-service calls such
  as `record`. The layer cannot change or delay traffic, so its failures
  cannot weaken containment: a trap or timeout is logged, not fatal, and a
  copy the layer does not keep up with is cut (`observer_lagged`) rather
  than stalling the flow. This is the way to deploy an uncalibrated
  monitor.

### In the proxy

Both fronts (HTTP/1.1 and HTTP/2) share one exchange core, and the stack
sits in it.

- The front drives the client's request body into the first layer. The
  last layer's `next` runs the rest of the core: the rules, the upstream,
  then the watching rules on the response.
- What a layer passes on is re-validated as strictly as a client request:
  an absolute `http(s)` URI, `host` (if present) matching it,
  `content-length` checked against the body, hop-by-hop and framing fields
  refused, and the workload's limits applied. `chain.next` fills in the
  scheme and authority from the exchange when the layer leaves them unset.
- The flow log's `rules`, `decision` and `terminal_rule` describe the
  request that left; `req` still describes what the client sent. If a layer
  answered itself, the decision is `deny` with `terminal_rule:
  layer:<name>`.
- A layer failing before the response head denies with `503`,
  `terminal_rule: layer:<name>`, `reason: layer_error`, closes the
  connection, and emits a `layer_error` event whose `kind` is `trap`,
  `budget:<limit>`, `capability:<name>`, `invalid_request`,
  `invalid_response`, `no_response`, ... After the head, the body is cut
  (HTTP/1.1 breaks the connection, HTTP/2 resets the stream) and
  `layer_error` follows.
- A layer's response body to the client waits for the flow log like every
  forwarded body ([audit backpressure](flow-log.md#writing)).
- WebSocket `tunnel` layers are chained between the client and the relay,
  outermost first. The relay stays the hop next to the upstream, so byte
  budgets and [message rules](websockets.md#message-rules) see what leaves.
- Layers compile at config load and are cached across reloads while their
  file and settings are unchanged, so their instance pools stay warm. A
  reload swaps the stack for new exchanges; exchanges in flight finish on
  theirs.

## Configuration

```yaml
addons:                               # above the rules, in this order
  - name: sentinel
    kind: wasm
    path: /etc/roxy/addons/sentinel.wasm
    mode: enforce                     # enforce | observe
    capabilities: [state, record, endpoints]   # also: metrics, log
    audit_endpoint: audit-sink        # also receives record(.., audit: true)
    endpoints:                        # named, not URLs
      monitor-model:
        url: https://api.anthropic.com/v1/messages
        headers: { x-api-key: "${secret:monitor_key}" }   # attached by roxy, never seen by the layer
        timeout: 10s                  # per attempt, to the response head (default 30s)
        retries: 2                    # after a connection failure or 502/503/504 (default 0)
      threat-intel:
        url: https://ti.internal:8443/score
        private_ok: true              # may reach private addresses
    state:
      max_entries: 100000
      max_value_bytes: 64kb
      default_ttl: 6h
    limits:                           # defaults shown
      max_memory: 64mb
      max_buffered_body_bytes: 1mb    # default limits.max_inspect_body_bytes
      step_cpu: 50ms                  # CPU between host calls
      fuel_per_step: 100_000_000
      max_exchange_time: 60s          # wall clock per exchange, including endpoint calls
      recycle_after_exchanges: 10000
      recycle_above_memory: 48mb
      max_instances: 64               # concurrent exchanges
    config: { reject_at: 0.8 }        # opaque, handed to the layer as JSON
```

A layer that judges LLM traffic will usually raise `max_buffered_body_bytes`
(requests resend the whole conversation), `max_memory` (an embedded
interpreter needs 128–256 MiB) and `max_exchange_time` (calling a model
takes seconds).

`kind: service` addons take a different set of keys
([service layers](#service-layers)).

## Host services

Host services are for WASM layers; a service layer calls what it needs
itself. Everything a layer can do outside its own streams is on this list, and each
item is a capability granted in config. Every import is linked whatever the
grants, so one binary runs under any of them; calling one that was not
granted traps (`CapabilityDenied`) and fails the exchange. `flow.current`,
`flow.add-tag` and `flow.config` need no capability.

### Endpoints

`endpoints.call(name, request)`: roxy resolves the name to the configured
URL (appending the request's path and query), attaches the endpoint's
headers (replacing any the layer set), applies the timeout and retries, and
enforces the address floor and deny lists. The layer cannot express a
destination, so text injected into the traffic it inspects cannot steer it
to another host, and credentials never enter the layer. Calls never pass
through the layer stack, so a monitor's own model call cannot recurse
through it. The request body is buffered (up to 16 MiB) so a retry can
resend it; retries back off from 100 ms. An unknown name, a denied address,
a timeout and a failure reach the layer as distinct `error-code`s. Each call
emits an `endpoint_call` flow event.

### State

`flow.state-get` / `flow.state-put`: a JSON-value store namespaced per
layer, with per-entry TTL, a value size cap and an entry cap. A miss returns
`none`. A write when full returns an error and the layer decides; nothing is
evicted.

### Identity

`flow.current()` gives the flow id, connection id, tags, and the principal
as roxy established it: `client.user` from proxy auth, client IP, listener,
TLS SNI. These are the safe keys for per-principal state; a layer should
not trust client-supplied session headers.

### Record

`flow.record(kind, json, audit)` writes a `layer_record` event to the flow
log with the flow id, the layer name and a timestamp. String values pass
through the secret redactor, and a value that is not JSON fails the
exchange. Like any audit record it is never dropped: the call waits while
the flow log is behind. `audit: true` also POSTs the record to the layer's
`audit_endpoint`.

### Metrics and log

`flow.metric-get(id, [])` reads a metric for this flow's own key (the
metric's key fields evaluated on the client's request); explicit key values
are refused. `flow.log` writes to roxy's operational log with the flow id
and layer name.

There is no `secrets` capability (the config refuses it and points to
endpoint `headers`), and no way to terminate or quarantine a client
(issue #28): a layer denies the exchange and reports through `record` or an
endpoint.

## WIT package

[`wit/addon.wit`](../wit/addon.wit) defines `roxy:addon@0.1.0`. It reuses
the WASI 0.2 HTTP types for heads and bodies, vendored at 0.2.12 under
`wit/deps/`; a guest built against any 0.2.x links.

- **World `layer`** exports `wasi:http/incoming-handler` (the exchange) and
  `init` (called once per instance, with the config available through
  `flow.config`). It imports `chain` (`next`), `endpoints`, `flow`, and the
  WASI clocks, random, io, stdio and `wasi:http/types`.
- **World `tunnel-layer`** adds the `tunnel` export. The component model has
  no optional exports, so the host detects at load time which world a
  component implements.
- The host also links the rest of WASI 0.2 inertly: an empty environment, no
  arguments, no preopened directories, stdio closed, TCP, UDP and name
  lookup off, every socket address denied. Stock toolchains whose standard
  library imports more than it uses still load, and still reach nothing.
- `wasi:http/outgoing-handler` is never provided, so a component that
  imports it fails to link. Outbound calls go through `endpoints`.
- During `init` there is no exchange: `config` works, `log` goes to roxy's
  own log (the capability still applies), and every other `flow`, `chain`
  or `endpoints` call traps.

### Instances

A component is compiled and linked once per config load, on the blocking
pool, then one instance is started and its `init` run, so a broken layer
fails the load. Each exchange checks an instance out of the layer's pool for
its whole duration. `max_instances` caps the live instances, and so the
layer's concurrent exchanges; an exchange that finds none free waits within
its `max_exchange_time`. Instances are replaced after
`recycle_after_exchanges`, or when an exchange leaves their linear memory
above `recycle_above_memory`, which bounds linear-memory growth. An instance
that failed in any way is discarded, never reused.

## Safety

- **CPU per step.** A step is the guest's run between host calls: every
  call into the guest, and every host call returning to it, starts a new
  one. Each step gets `fuel_per_step` fuel and `step_cpu` of wall time. The
  time limit is checked on a 1 ms engine-wide epoch tick, which also yields
  to the async runtime, so a spinning guest neither stalls a worker thread
  nor escapes its clock.
- **Wall clock per exchange.** `max_exchange_time` runs from the start of
  the exchange until the guest's handler returns: waiting for an instance,
  `next`, endpoint calls and streaming both bodies. A streamed response
  longer than the limit is cut. Tunnels have no exchange clock; they live as
  long as the relay's idle timeout allows.
- **Memory per instance.** Linear memory, summed over the instance's
  memories, is capped at `max_memory`; table growth and the host resource
  table (4096 live resources) are capped too.
- **Buffered bytes.** `max_buffered_body_bytes` bounds, per direction, the
  bytes the guest has read from that direction's body minus the bytes it
  has passed on. A streaming layer stays near zero.
- **Every failure is closed.** A trap, an exceeded budget, a second `next`,
  a missing capability, a host failure, an unbuildable request, an error or
  missing response, a handler that returns while still holding resources,
  or a cancelled exchange is a `LayerError`, and the caller turns it into a
  deny (or a cut exchange).
- **No clean end for a failed body.** A guest body never ends cleanly once
  its exchange has failed: it ends with an error, and a response body holds
  its end until the handler returns, so a trap after the last byte still
  cuts it.
- **An abandoned request is cut, not failed.** A request body passed to
  `next` that the guest drops without `finish` never ends cleanly either:
  the upstream sees it cut. If the guest is still waiting on `next`'s
  response, the layer has failed (`invalid_request`). If it has dropped the
  response future, or already has the response, it has abandoned the
  forwarded request and may answer itself; its answer stands.
- Layers see canonical heads and body streams, never raw wire bytes, and
  have no filesystem, sockets or environment. All their I/O is `next`,
  `endpoints` and `flow`.

## Service layers

A `kind: service` layer is an external service in the network path, at its
position in the stack exactly as a WASM layer is. The request streams into
it as it arrives; it streams back the request to forward, which roxy passes
down the stack; the response from below streams into it, and it streams back
the response the client gets. It may pass bytes through untouched, rewrite
them, hold them back, answer itself, or deny. This runs out-of-process logic
(Python with any dependencies, say) with no WASM toolchain.

```yaml
addons:
  - name: sentinel
    kind: service
    endpoint: sidecar                   # one of this addon's endpoints
    mode: enforce                       # enforce | observe
    endpoints:
      sidecar: { url: "http://127.0.0.1:9000/layer", private_ok: true }
    limits:
      first_byte_timeout: 2s            # until each of the service's heads (default 30s)
      max_exchange_time: 60s            # the whole session
```

`path`, `capabilities`, `config`, `audit_endpoint` and the WASM limits are
refused on a service layer, and `first_byte_timeout` is refused on a WASM
layer.

**Transport: one WebSocket per exchange**, subprotocol `roxy.layer.v1`, to
the endpoint's URL (`http` → `ws`, `https` → `wss`). It is dialled through
the connector, so the address floor and deny lists apply, and it never
passes through other layers or the rules. The handshake carries the
endpoint's `headers` (credentials from secrets) and the flow metadata as
`roxy-flow-*` fields: `id`, `conn`, `layer`, `mode` (`enforce` or
`observe`), `client-ip`, `client-user`, `listener`, `sni`, `tags`. A service
that does not accept the subprotocol fails the handshake. Each session is
recorded as an `endpoint_call` event.

**Messages.** Text frames are JSON control messages; binary frames are body
bytes of the message whose head came last.

```text
roxy → service   {"type":"request","method":…,"url":…,"headers":[[n,v],…]}  bytes…  {"type":"request_end"}
service → roxy   one of:
                   {"type":"request",…}  bytes…  {"type":"request_end"}     forward this request (`next`)
                   {"type":"response","status":…,"headers":[…]}  bytes…  {"type":"response_end"}
                                                                          answer instead; nothing is forwarded
                   {"type":"deny","status":403,"message":"…"}             refuse (status 4xx/5xx, both optional)
then, if it forwarded:
roxy → service   {"type":"response","status":…,"headers":[…]}  bytes…  {"type":"response_end"}
service → roxy   {"type":"response",…}  bytes…  {"type":"response_end"}   the client's response
                 or {"type":"deny",…}
```

`url` is absolute and `headers` are end-to-end fields as a WASM layer sees
them (no hop-by-hop or framing fields). Heads carry `content-length` when
the length is known; a `content-length` the service sends back is enforced,
and more or fewer bytes than declared is a protocol violation. Both
directions stream at once: the service may start forwarding the request
before the client's body has ended, and the socket gives backpressure both
ways.

- **What the service forwards gets the same checks as a WASM layer's
  `next`**: re-validated as strictly as a client request, then judged by the
  rules. Its response is handled as a WASM layer's.
- **Deadlines.** `first_byte_timeout` bounds the connection and each of the
  service's heads (its first answer, and its response after roxy sent the
  upstream's head). `max_exchange_time` bounds the whole session.
- **Failure is closed** in enforce mode: a failed connection or handshake,
  a protocol violation (bad JSON, a message out of order, bytes before a
  head, an invalid head, a broken length), a missed deadline, or a lost
  socket denies the exchange (`503`, `layer:<name>`) before the response
  head and cuts the body after it. A body cut short never reaches the
  upstream or the client as complete. `layer_error.kind` is
  `service:connect`, `service:protocol`, `service:timeout` or
  `service:closed`.
- **Observe mode**: the service gets the same messages for copies of both
  streams, and whatever it sends back is read and ignored. It cannot change
  or delay traffic; its failures are logged only.
- **WebSocket upgrades.** The service sees the upgrade request; a `101`
  passes straight back, and the WebSocket's bytes do not go through it.

One connection per exchange keeps the protocol simple and a service
stateless per socket. [`examples/addons/service`](../examples/addons/service)
has `roxy_layer.py`, the service side of the protocol for asyncio, a
pass-through layer, and an inspect_sentinel sidecar.

## Authoring

Rust is first class: small components, fast instantiation, real streaming.
The [`roxy-addon`](../crates/roxy-addon) SDK wraps the bindings:

```rust
use roxy_addon::prelude::*;

struct RedactTokens;
impl Layer for RedactTokens {
    fn init(_config: &str) -> Result<Self, String> {   // `config:` as JSON
        Ok(RedactTokens)
    }
    fn handle(&mut self, req: Request, next: Next) -> Response {
        let req = req.map_body(|body| body.transform(redact_chunk));
        next.run(req)
    }
}
roxy_addon::export!(RedactTokens);
```

- `Body` is a pull-based sequence of chunks, read from the host only as the
  layer consumes it: `transform` (per chunk), `pipe` (a stateful
  `ChunkTransform` that may hold bytes back and flush them at the end) and
  `read_to_end(cap)`.
- `Next` is consumed by `run`, so the type system enforces one `next` per
  exchange. `next.run` returns once the response head arrives, while the
  rest of the request body is pumped as the layer reads the response, so a
  layer below that answers early cannot deadlock against the host's small
  body buffers.
- `flow::*` and `call_endpoint` wrap the host services. A panic traps, and
  the host fails the exchange closed.
- The SDK does not wrap `tunnel`; use the raw bindings.
- The crate carries a copy of `wit/` so it can be published; a test keeps
  the copy in sync.

Any language that targets the component model works against the WIT. Go
(wasip2) and JS (`jco componentize`) produce larger binaries with higher
per-call cost. Python in WASM (`componentize-py`) bundles an interpreter:
tens of MiB, 128–256 MiB of memory, pure-Python dependencies only; give it
raised budgets. Python with native dependencies, or anything else out of
process, is a [service layer](#service-layers).

[`examples/addons`](../examples/addons) has a streaming redactor built on
`roxy-addon`, and the service-layer examples.
