# Addon configuration

Addons are listed under `addons:`, in the order they wrap the exchange
([addon model](/design/addon-model)). This is a WASM layer with every key;
[service layers](/reference/service-layers) take a smaller set.

```yaml
addons:                               # above the rules, in this order
  - name: sentinel
    kind: wasm
    path: /etc/roxy/addons/sentinel.wasm
    mode: enforce                     # enforce | observe
    when: host == "api.anthropic.com" and path starts_with "/v1/messages"   # default: every exchange
    capabilities: [state, record, endpoints]   # also: metrics, log
    audit_endpoint: audit-sink        # also receives record(.., audit: true)
    endpoints:                        # named, not URLs
      monitor-model:
        url: https://api.anthropic.com/v1/messages
        headers: { x-api-key: "${secret:monitor_key}" }   # attached by roxy, never seen by the layer
        timeout: 10s                  # per attempt, to the response head (default 30s)
        retries: 2                    # after a connection failure or 502/503/504 (default 0, at most 9)
      threat-intel:
        url: https://ti.internal:8443/score
        path: prefix                  # the layer's path goes under the URL (default fixed: the URL is the whole target)
        private_ok: true              # may reach private addresses
    state:
      max_entries: 100000
      max_value_bytes: 64kb
      default_ttl: 6h
    limits:                           # defaults shown
      max_memory: 64mb                # per instance; what the layer holds of a body lives here
      first_byte_timeout: 30s         # the layer's own time to its response head
      recycle_after_exchanges: 10000
      recycle_above_memory: 48mb      # default: three quarters of max_memory
      max_instances: 1024             # concurrent exchanges; waiting for one has no deadline
    config: { reject_at: 0.8 }        # opaque, handed to the layer as JSON
```

The limits catch a broken layer, not a slow one
([addon safety limits](/reference/addon-safety)). A layer that judges LLM
traffic will usually raise `max_memory` (requests resend the whole
conversation, and an embedded interpreter needs 128–256 MiB) and
`first_byte_timeout` if it calls a model before answering.

`roxy check` refuses: a zero `max_instances`, `max_memory`,
`recycle_above_memory`, `first_byte_timeout`, endpoint `timeout`, or
service `max_connections` or `max_streams`; a `recycle_above_memory` above
`max_memory`; and a `path` that does not exist. `recycle_after_exchanges:
0` recycles an instance after every exchange.

## Capabilities

A WASM layer runs with no access outside its own streams. `capabilities`
grants it named [host services](/reference/host-services):

| capability | grants |
|---|---|
| `endpoints` | `endpoints.call`: outbound calls to the layer's named `endpoints`, with roxy attaching the headers |
| `state` | `flow.state-get`, `flow.state-put`: the layer's keyed store, sized by `state` |
| `record` | `flow.record`: structured events in the flow log, and `audit_endpoint` |
| `metrics` | `flow.metric-get`: read a metric for this flow's key |
| `log` | `flow.log`: roxy's operational log |

Every import is linked whatever is granted, so one binary runs under any
set; a call the layer was not granted traps with `CapabilityDenied` and
fails the exchange. `flow.current`, `flow.add-tag` and `flow.config` need
no capability; `flow.add-tag` from an observe layer is refused the same
way, since a tag steers the `when` of the layers below. There is no
`secrets` capability: credentials go on an endpoint's `headers`, where the
layer never sees them.

Service layers have no capabilities. A service calls what it needs itself;
roxy gives it the exchange, the flow's identity on `open`, and the
endpoint's `headers` on the handshake.

## Choosing exchanges

`when` is a condition in the [rule language](/reference/rule-language) over
head fields. A layer runs only on the exchanges it matches. The rest go
straight to the layer below, as if the layer had passed both directions on
unchanged. A skipped layer costs nothing: no instance, no body pumping, no
service session.

- `when` sees the request as it reaches the layer: what the layer above
  passed on, re-validated like any request a layer passes on. A layer above
  can steer a request into or out of a lower layer's `when`.
- It may read head fields, headers, the query, `state[..]`, `metric.<id>`
  and address lists. `body.*`, `response.*` and `ws.*` are config errors:
  a layer owns the body, so nothing reads it first.
- `tag["x"]` sees tags set by enforce layers above; an observer cannot
  tag. The rules run below the stack, so their tags are not visible here.
- A `when` that reaches an unavailable input (a metric, an address list, a
  missing value under an operator that cannot answer for `null`) fails the
  flow closed like a layer failure (`503`, `layer_error` with `kind:
  when:<code>`). It never skips the layer. On an observe layer the failure
  is logged like any observer failure, and the layer gets no copy.
- A layer that `when` skipped on a WebSocket's upgrade request is not in
  that WebSocket's byte path.

`sample`, for `mode: observe` only, is the share of matching exchanges the
layer gets a copy of, in (0, 1]. It is drawn from the flow id, so it is the
same for a flow however often you ask. An enforcing layer cannot be
sampled.

```yaml
addons:
  - name: shadow-monitor
    path: /etc/roxy/addons/monitor.wasm
    mode: observe
    when: method == POST
    sample: 0.1                       # one matching exchange in ten
```

## In the proxy

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
- The flow log's `addons` lists the layers that ran on the exchange, in
  stack order; a layer its `when` or `sample` skipped is not in it.
- The flow log's `rules`, `decision` and `terminal_rule` describe the
  request that left; `req` still describes what the client sent. Metric
  keys, for the rules' samples and for `metric-get`, come from the request
  that left too. They record what the rules decided, not what the client
  got: a layer whose `next` returned the rules' `403` and then answered
  with a `200` of its own is logged with `decision: deny` and
  `res.status: 200`.
- A layer that answers itself is logged with `decision: answered` and
  `terminal_rule: layer:<name>`, whatever its status. The answering layer
  is the outermost one that did not pass on the response from below: it
  never called `next`, or answered while `next` was pending, failed or
  dropped. If its request had already left, the forwarded request is
  abandoned (its body is cut, never ended as if complete), and the record
  keeps what the rules decided and the bytes sent, with `reason:
  upstream_aborted`.
- A layer failing before the response head denies with `503`,
  `terminal_rule: layer:<name>`, `reason: layer_error`, closes the
  connection, and emits a `layer_error` event whose `kind` is `trap`,
  `budget:<limit>`, `capability:<name>`, `invalid_request`,
  `invalid_response`, `no_response`, ... After the head, the body is cut
  (HTTP/1.1 breaks the connection, HTTP/2 resets the stream) and
  `layer_error` follows. A failure found below the layer that caused it
  (a request a layer passed on that does not validate, say) is put down
  to the nearest enforcing layer above: an observer passes nothing on, so
  it is never the one blamed.
- A layer's answer must be a final response. A `1xx` other than the
  `101` of a relayed upgrade fails closed as `invalid_response`.
- A layer's response body to the client waits for the flow log like every
  forwarded body ([audit backpressure](/reference/flow-log#writing)).
- Layers compile at config load and are cached across reloads while their
  file and settings are unchanged, so their instance pools stay warm. A
  reload swaps the stack for new exchanges; exchanges in flight finish on
  theirs.

## Content codings

Layers see bodies decoded. roxy decodes on the way into the stack, for a
flow some layer runs on: the client's request body as the first layer that
runs gets it, and the response before it reaches the innermost layer. It
removes `content-encoding` as it does, and the body's length becomes
unknown. A flow no layer runs on (every `when` skipped it) is not decoded
at all.

- On a flow a layer runs on, the client gets an uncompressed response and
  the upstream an uncompressed request body. The origin's response to roxy
  stays compressed. Nothing re-encodes; a layer that wants a compressed
  body encodes it itself.
- The codings and their strictness are those the rules use
  ([HTTP](/reference/http#content-codings)). Data that does not decode, or a
  decoded body over `limits.max_request_body_bytes` or
  `limits.max_response_body_bytes`, cuts the exchange like any failed body.
  An observer counts as a layer that runs: on a flow only an observer
  runs on, the bodies are decoded for its copy, so a body that does not
  decode fails the exchange that would have been forwarded as it was.
- A body in a coding roxy does not know passes through as it is, with its
  `content-encoding`, for a layer to judge. So does a `206` or any response
  with `content-range`: part of an encoded body cannot be decoded on its
  own.
- The rules below the stack read the response before any layer, and decode
  it for themselves ([body rules](/reference/rule-language#body-rules)).
- A layer gets WebSocket messages it can read: no extension
  (`permessage-deflate` above all) is negotiated on a WebSocket a layer
  runs on ([WebSockets](/reference/websockets#extensions)).

`http.decode_for_addons: false` turns this off: layers then see the bytes
as sent, with their `content-encoding`, and WebSockets negotiate whatever
extensions client and upstream agree on.

## WebSockets

A layer gets the upgrade request in `handle` and passes it on with `next`
(a service layer forwards it on its stream); the response from below is
the `101`. After it, the request body carries the client's bytes and the
response body the upstream's, for as long as the WebSocket is open. A
layer reads, rewrites or holds back either direction as it would any
body, refuses the upgrade by answering without `next`, and is left out of
the WebSocket entirely when its `when` skips the upgrade request. A layer
that turns the upstream's `101` into another status fails the exchange
closed (a `503` from `layer:<name>`), and roxy closes the upstream
WebSocket. A `101` with no upgrade from below fails closed too. Only
`Upgrade: websocket` makes a request an upgrade for the layers; a request
asking for any other upgrade (`h2c`, say) is an ordinary request roxy
forwards once it strips the upgrade, with its body and the usual body cap.

- The bodies carry raw WebSocket frames. Frames from the client are
  masked, so their payload reads as sent only from the upstream's side.
- A layer must stream both bodies at once: the request body ends only
  when the client closes, while the response streams all along. The
  `roxy-addon` SDK does this.
- A transform that holds bytes back until more arrive stalls an
  interactive protocol: the peer waits for the held bytes.
- No clock runs on the bodies ([safety](/reference/addon-safety)): a
  WebSocket lives as long as the relay's idle timeout allows. When the
  relay ends, roxy closes the client's connection too, whether or not the
  layers have ended their bodies; bytes already on their way get a second
  to arrive.
