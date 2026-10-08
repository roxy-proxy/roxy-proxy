# Addon configuration

Addons are listed under `addons:`, in the order they wrap the exchange
([addon model](/design/addon-model)). Each entry is a WASM layer or a
service layer; the two kinds share most keys.

```yaml
addons:
  - name: sentinel
    kind: wasm
    path: /etc/roxy/addons/sentinel.wasm
    mode: enforce
    when: host == "api.anthropic.com" and path starts_with "/v1/messages"
    subscribe: { request: full, response: head }
    capabilities: [state, record, endpoints]
    endpoints:
      monitor-model:
        url: https://api.anthropic.com/v1/messages
        headers: { x-api-key: "${secret:monitor_key}" }
        timeout: 10s
      threat-intel:
        url: https://ti.internal:8443/score
        path: prefix
        private_ok: true
    state: { max_entries: 100000, max_value_bytes: 64kb, default_ttl: 6h }
    limits: { max_memory: 128mb, first_byte_timeout: 30s }
    config: { reject_at: 0.8 }

  - name: monitor
    kind: service
    endpoint: sidecar
    mode: observe
    sample: 0.1
    subscribe: { request: head, response: head }
    endpoints:
      sidecar: { url: "http://127.0.0.1:9000/layer", private_ok: true }
    limits: { first_byte_timeout: 2s, max_connections: 4, max_streams: 100 }
```

## Fields

Every key of an `addons:` entry. "kind" says which layer kinds take the
key; `roxy check` refuses a key on the other kind.

| key | kind | values | default | what it does |
|---|---|---|---|---|
| `name` | both | string, unique among addons | required | names the layer in the flow log (`addons`, `layer:<name>`, `layer_error`), in tags and in the service protocol |
| `kind` | both | `wasm`, `service` | `wasm` | how the layer runs: a WebAssembly component in-process, or an external service the exchange streams through ([service layer protocol](/reference/service-layers)) |
| `path` | wasm | file path | required | the component. It must exist at config load; the layer is compiled then, and cached across reloads while the file and its settings are unchanged |
| `endpoint` | service | one of this addon's `endpoints` | required | where the service is. The exchange streams through it over pooled WebSocket connections |
| `mode` | both | `enforce`, `observe` | `enforce` | `enforce`: the layer is in the path and its output is what goes on. `observe`: the layer gets copies and nothing it returns takes effect ([modes](/design/addon-model#modes)) |
| `when` | both | [rule language](/reference/rule-language) condition over head fields | every exchange | runs the layer only on the exchanges it matches; the rest pass it at no cost ([choosing exchanges](/reference/addon-configuration#choosing-exchanges)) |
| `sample` | both, observe only | number in (0, 1] | 1 | the share of matching exchanges the observer gets a copy of, drawn from the flow id |
| `subscribe.request` | both | `head`, `full` | `full` | what the layer sees of the request: the head only, or the head and the body ([what a layer sees](/reference/addon-configuration#what-a-layer-sees)) |
| `subscribe.response` | both | `head`, `full` | `full` | the same for the response |
| `capabilities` | wasm | list of `endpoints`, `state`, `record`, `metrics`, `log` | none | the [host services](/reference/host-services) the layer may call ([capabilities](/reference/addon-configuration#capabilities)) |
| `config` | wasm | any YAML value | `null` | handed to the layer as a JSON document through `flow.config`; roxy does not read it |
| `endpoints` | both | map of name to [endpoint](/reference/addon-configuration#endpoints) | none | named outbound targets. A WASM layer calls them with `endpoints.call`; a service layer's `endpoint` names one of them |
| `state` | wasm | [store limits](/reference/addon-configuration#state) | defaults below | the layer's keyed store (`state-get`, `state-put`) |
| `limits` | both | [limits](/reference/addon-configuration#limits) | defaults below | what the layer may cost roxy |

### `endpoints`

Each entry under `endpoints` is a URL roxy calls on the layer's behalf,
with credentials the layer never sees. Calls go straight to the connector,
never through other layers or the rules; the address floor and deny lists
apply, and each call is an `endpoint_call` flow event.

| key | values | default | what it does |
|---|---|---|---|
| `url` | `http(s)://host[:port][/path]` | required | the target. With `path: fixed` it is the whole target; with `path: prefix` the layer's path and query go under it |
| `path` | `fixed`, `prefix` | `fixed` | what the layer's request path contributes. `prefix` normalises the layer's path and refuses `..` |
| `headers` | map of header to value | none | attached by roxy, replacing any the layer set. Values may use `${secret:name}` ([secrets](/reference/secrets)) |
| `timeout` | duration, positive | `30s` | from the call to the response head; reading the layer's request body counts |
| `private_ok` | bool | `false` | the endpoint may be on a private, loopback or link-local address |

### `state`

The store takes JSON values under string keys, per layer, in memory.
Nothing is evicted: a write when full fails and the layer decides.

| key | values | default | what it does |
|---|---|---|---|
| `max_entries` | count | `100000` | most live entries |
| `max_value_bytes` | size | `64kb` | largest value |
| `default_ttl` | duration | `6h` | TTL for a `state-put` that gives none |

### `limits`

Limits catch a broken layer, not a slow one: a slow layer makes its
exchanges slow, never denied. Each is optional.

| key | kind | default | what it bounds |
|---|---|---|---|
| `first_byte_timeout` | both | `30s` | the layer's own time to its response head: starting an instance, its work, endpoint calls and reading the client's body count; time `next` spends below it does not. Overrun fails closed, `budget:first_byte_timeout`. On a service layer it bounds getting a stream and each of the service's heads. An observer that gets no instance within it loses its copy (`observer_lagged`, `no_instance`) |
| `max_memory` | wasm | `64mb` | linear memory per instance, summed over the instance's memories; table growth and the host resource table (4096 live resources: body streams, pollables, pending responses) are capped too. What a layer holds of a body lives here. An interpreter in WASM (Python) needs 128–256 MiB |
| `max_instances` | wasm | `1024` | live instances, so concurrent exchanges and, with `max_memory`, the layer's memory. An enforce exchange that finds none free waits without a deadline; an observer waits `first_byte_timeout`. Instances start on demand |
| `recycle_after_exchanges` | wasm | `10000` | an instance is replaced after this many exchanges; `0` replaces it after every exchange |
| `recycle_above_memory` | wasm | three quarters of `max_memory` | an instance whose memory passed this is replaced after its exchange. At most `max_memory` |
| `max_connections` | service | `4` | WebSocket connections to the endpoint |
| `max_streams` | service | `100` | exchanges at once on one connection; past `max_connections × max_streams` an exchange waits for a free stream within `first_byte_timeout` |

Bodies have no clock: once the head is out, a body streams for as long as
it takes (a WebSocket for as long as the relay's idle timeout allows); the
client's and upstream's idle timeouts still apply. CPU has no limit: a
guest yields to the runtime on a 1 ms engine-wide tick, so it never stalls
a worker thread and cancellation takes effect within a tick.

### Fixed caps

What the host holds for a guest outside `max_memory`, not configurable:

| cap | value | on overrun |
|---|---|---|
| a head a guest hands the host (`next`, `respond`, `call`) | 128 KiB: method, scheme, authority, path and query, and every header name and value together | `budget:fields`: fails the exchange |
| a flow's tags, across all its layers | 64 tags, 4 KiB together | `budget:tags`: fails the exchange |
| a `flow.log` message, or a `flow.record` kind and document together | 64 KiB | `budget:message`: fails the exchange |
| an endpoint call's request body | 16 MiB, read within the endpoint's timeout and charged to the [buffer budget](/reference/limits#buffer-budget) while the call runs | refuses the call |
| endpoint calls in flight per exchange | 8; further calls wait for a permit, within the timeout | refuses the call |
| a state key | 1 KiB | refuses the call |

### What `roxy check` refuses

A missing `path` or one that does not exist; `endpoint` not among the
addon's `endpoints`; a key of the other kind (`path`, `capabilities`,
`config`, `state` and the WASM limits on a service layer; `endpoint`,
`max_connections` and `max_streams` on a WASM layer); `sample` on an
enforcing layer, or outside (0, 1]; a zero `max_instances`, `max_memory`,
`recycle_above_memory`, `first_byte_timeout`, endpoint `timeout`,
`max_connections` or `max_streams`; `recycle_above_memory` above
`max_memory`; a `when` that reads `body.*`, `response.*` or `ws.*`, or an
unknown metric or list; a `subscribe` value other than `head` or `full`.

## Capabilities

A WASM layer has no access outside its own streams. `capabilities` grants it
named [host services](/reference/host-services):

| capability | grants |
|---|---|
| `endpoints` | `endpoints.call`: outbound calls to the layer's named `endpoints`, with roxy attaching the headers |
| `state` | `flow.state-get`, `flow.state-put`: the layer's keyed store, sized by `state` |
| `record` | `flow.record`: structured events in the flow log |
| `metrics` | `flow.metric-get`: read a metric for this flow's key |
| `log` | `flow.log`: roxy's operational log |

Every import is linked whatever is granted (one binary runs under any
set); an ungranted call traps with `CapabilityDenied` and fails the
exchange. `flow.current`, `flow.add-tag` and `flow.config` need no
capability; `flow.add-tag` from an observe layer is refused the same way,
since a tag steers the `when` of the layers below. There is no `secrets`
capability: credentials go on an endpoint's `headers`.

Service layers have no capabilities: a service gets the exchange, the
flow's identity on `open`, and the endpoint's `headers` on the handshake.

## Behaviour

### What a layer sees

`subscribe` names what the layer gets of each direction. With `full` (the
default) the layer owns that direction: it reads the body, chunk by chunk,
and what it passes on is the body that goes on. With `head` the layer gets
the head with an empty body and no `content-length`, and the body bypasses
it: whatever the layer passes on (the head it gives `next`, or the head it
answers with) carries the body it did not see, spliced on by roxy, with
the framing roxy knows.

- An enforce layer can still deny, rewrite or answer at a head it is
  subscribed to; the bodies stream past it at no cost in copies or
  buffering.
- A response head-only layer answers with the status it was given to pass
  the response on with its head edited; the body from below follows. Any
  other status is an answer of the layer's own: its body stands and the
  body from below is dropped, so a layer can refuse at the response head.
  A layer that answers without `next` resolving answers whole too, since
  there is no body from below.
- A layer that passes on bytes of a body it is not subscribed to fails the
  exchange closed: a `503` before the response head, a cut body after it,
  `layer_error` with `kind: unsubscribed:request` or
  `unsubscribed:response`.
- A head-only observer gets copies of the heads and no copy of the body,
  so neither the lag budget nor the buffer budget is touched for it.
- The rules are not affected: they judge the request that leaves the
  stack, head and body, whoever supplied each.
- Bodies are decoded for the layers, and a WebSocket relayed without
  extensions, only when some layer that runs is subscribed to a body
  ([content codings](/reference/addon-configuration#content-codings), [WebSockets](/reference/addon-configuration#websockets)).

### Choosing exchanges

`when` is a [rule language](/reference/rule-language) condition over head
fields. A layer runs only on the exchanges it matches; the rest pass it at
no cost (no instance, no body pumping, no service session).

- `when` sees the request as it reaches the layer: what the layer above
  passed on, re-validated. A layer above can steer a request into or out of
  a lower layer's `when`.
- It may read head fields, headers, the query, `state[..]`, `metric.<id>`
  and address lists. `body.*`, `response.*` and `ws.*` are config errors.
- `tag["x"]` sees tags set by enforce layers above, not the rules' tags
  (the rules run below the stack).
- An unavailable input (a metric, an address list, a missing value under an
  operator that cannot answer for `null`) fails the flow closed like a
  layer failure (`503`, `layer_error` with `kind: when:<code>`), never
  skips the layer. On an observe layer the failure is logged and the layer
  gets no copy.
- A layer `when` skipped on a WebSocket's upgrade request is not in that
  WebSocket's byte path.

`sample` (observe only) is drawn from the flow id, so it is the same for a
flow however often it is asked.

### In the proxy

The stack sits in the exchange core both fronts share: the front drives
the client's request body into the first layer, and the last layer's
`next` runs the rules, the upstream, then the watching rules on the
response.

- What a layer passes on is re-validated as strictly as a client request:
  an absolute `http(s)` URI; `host`, `content-length`, hop-by-hop and
  framing fields refused at the boundary (roxy derives them, and the body
  carries its own length); the workload's limits applied. `chain.next`
  fills in the scheme and authority from the exchange when the layer
  leaves them unset.
- A layer's answer must be a final response; a `1xx` other than the `101`
  of a relayed upgrade fails closed as `invalid_response`.
- A layer's response body to the client waits for the flow log like every
  forwarded body ([audit backpressure](/reference/flow-log#writing)).
- Layers compile at config load and are cached across reloads while their
  file and settings are unchanged, so instance pools stay warm. A reload
  swaps the stack for new exchanges; exchanges in flight finish on theirs.

In the flow log:

| field | with addons |
|---|---|
| `addons` | the layers that ran, in stack order; a layer its `when` or `sample` skipped is not in it |
| `rules`, `decision`, `terminal_rule` | the rules' decision on the request that left the stack; `req` is what the client sent. Metric keys (for the rules' samples and `metric-get`) also come from the request that left. A layer whose `next` returned the rules' `403` and then answered `200` itself is logged `decision: deny`, `res.status: 200` |
| `decision: answered`, `terminal_rule: layer:<name>` | a layer answered itself, whatever its status: the outermost layer that did not pass on the response from below (it never called `next`, or answered while `next` was pending, failed or dropped). If its request had already left, the forwarded request is abandoned (its body cut, never ended as complete) and the record keeps what the rules decided and the bytes sent, with `reason: upstream_aborted` |
| `503`, `terminal_rule: layer:<name>`, `reason: layer_error` | a layer failed before the response head; the connection is closed and a `layer_error` event follows with `kind` one of `trap`, `budget:<limit>`, `capability:<name>`, `invalid_request`, `invalid_response`, `no_response`, `unsubscribed:<direction>`, ... After the head, the body is cut (HTTP/1.1 breaks the connection, HTTP/2 resets the stream) and `layer_error` follows. Which layer, if any, is one rule ([who is blamed](/design/addon-model#who-is-blamed)) |

### Content codings

On a flow some layer runs on and is subscribed to the body, roxy decodes
the client's request body as the first such layer gets it and the response
before it reaches the innermost such layer, removing `content-encoding`;
the body's length becomes unknown. A body no running layer is subscribed
to is not decoded, and reaches the upstream or the client as sent.

- The client gets an uncompressed response and the upstream an
  uncompressed request body; the origin's response to roxy stays
  compressed. Nothing re-encodes.
- The codings and their strictness are the rules'
  ([HTTP](/reference/http#content-codings)). Data that does not decode, or
  a decoded body over `limits.max_request_body_bytes` or
  `limits.max_response_body_bytes`, cuts the exchange like any failed body,
  also on a flow only an observer runs on.
- A body in a coding roxy does not know passes through as it is, with its
  `content-encoding`; so does a `206` or any response with `content-range`.
- The rules below the stack read the response before any layer and decode
  it for themselves ([body rules](/reference/rule-language#body-rules)).
- No extension (`permessage-deflate` above all) is negotiated on a
  WebSocket a body-subscribed layer runs on ([WebSockets](/reference/websockets#extensions)).

`http.decode_for_addons: false` turns this off: layers see the bytes as
sent, with their `content-encoding`, and WebSockets negotiate whatever
extensions client and upstream agree on.

### WebSockets

A layer gets the upgrade request in `handle` and passes it on with `next`
(a service layer forwards it on its stream); the response from below is the
`101`. After it, the request body carries the client's bytes and the
response body the upstream's for as long as the WebSocket is open. A layer
reads, rewrites or holds back either direction as any body, refuses the
upgrade by answering without `next`, and is left out of the WebSocket when
its `when` skips the upgrade request or its subscription leaves out the
body.

- A layer that turns the upstream's `101` into another status fails the
  exchange closed (`503` from `layer:<name>`) and roxy closes the upstream
  WebSocket; a `101` with no upgrade from below fails closed too.
- Only `Upgrade: websocket` is an upgrade for the layers. A request asking
  for any other upgrade (`h2c`, say) is an ordinary request roxy forwards
  once it strips the upgrade, with its body and the usual body cap.
- The bodies carry raw WebSocket frames. Frames from the client are masked,
  so their payload reads as sent only from the upstream's side.
- A layer must stream both bodies at once: the request body ends only when
  the client closes, while the response streams all along (the
  `roxy-addon` SDK does this). Holding bytes back until more arrive stalls
  an interactive protocol.
- No clock runs on the bodies. When the relay ends, roxy closes the
  client's connection whether or not the layers have ended their bodies;
  bytes already on their way get a second to arrive.

### Failure

- **Every failure is closed.** A trap, an exceeded budget, a second `next`
  or `respond`, a missing capability, a host failure, a head the host
  refuses, a body stream that is not the host's, a missing response, bytes
  on an unsubscribed body, a handler that returns still holding a resource
  (an unfinished body, a pending response), or a cancelled exchange is a
  `LayerError`: a deny, or a cut exchange after the response head.
- **A client that gives up cancels the exchange.** The guest is stopped,
  its instance discarded, the slot freed. No `layer_error` is logged.
- **No clean end for a failed body.** A guest body ends with an error once
  its exchange has failed; a response body holds its end until the handler
  returns, so a trap after the last byte still cuts it. A streamed body is
  complete only through `finish`: dropped unfinished, it is cut, and a
  response body dropped unfinished fails the exchange.
- **An abandoned request is cut, not failed.** A request body passed to
  `next` that the guest drops without `finish` is cut at the upstream. If
  the guest is still waiting on `next`'s response, the layer has failed
  (`invalid_request`); if it has dropped the pending response or already
  has the response, it may answer itself and its answer stands. A body the
  guest passed through that fails behind it (the client gave up) is cut the
  same way.
- **An instance that failed is discarded**, never reused.
- Layers see canonical heads and body streams, never wire bytes, and have
  no filesystem, sockets or environment: all their I/O is `next`,
  `endpoints` and `flow`.
