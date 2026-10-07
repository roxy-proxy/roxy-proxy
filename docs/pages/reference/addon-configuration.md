# Addon configuration

Addons are listed under `addons:`, in the order they wrap the exchange
([addon model](/design/addon-model)). This is a WASM layer with every key;
[service layers](/reference/service-layers) take a smaller set.

```yaml
addons:
  - name: sentinel
    kind: wasm
    path: /etc/roxy/addons/sentinel.wasm
    mode: enforce                     # enforce | observe
    when: host == "api.anthropic.com" and path starts_with "/v1/messages"   # default: every exchange
    sample: 0.1                       # observe only: share of matching exchanges copied, in (0, 1]
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
    limits:                           # defaults shown; see addon safety limits
      max_memory: 64mb                # per instance; LLM traffic usually needs more (an embedded interpreter 128–256 MiB)
      first_byte_timeout: 30s         # the layer's own time to its response head
      recycle_after_exchanges: 10000  # 0 recycles after every exchange
      recycle_above_memory: 48mb      # default: three quarters of max_memory
      max_instances: 1024
    config: { reject_at: 0.8 }        # opaque, handed to the layer as JSON
```

What each limit bounds is in [addon safety limits](/reference/addon-safety).
`roxy check` refuses: a zero `max_instances`, `max_memory`,
`recycle_above_memory`, `first_byte_timeout`, endpoint `timeout`, or
service `max_connections` or `max_streams`; `recycle_above_memory` above
`max_memory`; a `path` that does not exist; `sample` on an enforcing layer.

## Capabilities

A WASM layer has no access outside its own streams. `capabilities` grants it
named [host services](/reference/host-services):

| capability | grants |
|---|---|
| `endpoints` | `endpoints.call`: outbound calls to the layer's named `endpoints`, with roxy attaching the headers |
| `state` | `flow.state-get`, `flow.state-put`: the layer's keyed store, sized by `state` |
| `record` | `flow.record`: structured events in the flow log, and `audit_endpoint` |
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

## Choosing exchanges

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

## In the proxy

The stack sits in the exchange core both fronts share: the front drives
the client's request body into the first layer, and the last layer's
`next` runs the rules, the upstream, then the watching rules on the
response.

- What a layer passes on is re-validated as strictly as a client request:
  an absolute `http(s)` URI, `host` (if present) matching it,
  `content-length` checked against the body, hop-by-hop and framing fields
  refused, the workload's limits applied. `chain.next` fills in the scheme
  and authority from the exchange when the layer leaves them unset.
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
| `503`, `terminal_rule: layer:<name>`, `reason: layer_error` | a layer failed before the response head; the connection is closed and a `layer_error` event follows with `kind` one of `trap`, `budget:<limit>`, `capability:<name>`, `invalid_request`, `invalid_response`, `no_response`, ... After the head, the body is cut (HTTP/1.1 breaks the connection, HTTP/2 resets the stream) and `layer_error` follows. A failure found below the layer that caused it (a passed-on request that does not validate, say) is put down to the nearest enforcing layer above; an observer is never blamed |

## Content codings

On a flow some layer runs on, roxy decodes the client's request body as
the first running layer gets it and the response before it reaches the
innermost layer, removing `content-encoding`; the body's length becomes
unknown. A flow no layer runs on is not decoded.

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
  WebSocket a layer runs on ([WebSockets](/reference/websockets#extensions)).

`http.decode_for_addons: false` turns this off: layers see the bytes as
sent, with their `content-encoding`, and WebSockets negotiate whatever
extensions client and upstream agree on.

## WebSockets

A layer gets the upgrade request in `handle` and passes it on with `next`
(a service layer forwards it on its stream); the response from below is the
`101`. After it, the request body carries the client's bytes and the
response body the upstream's for as long as the WebSocket is open. A layer
reads, rewrites or holds back either direction as any body, refuses the
upgrade by answering without `next`, and is left out of the WebSocket when
its `when` skips the upgrade request.

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
- No clock runs on the bodies ([safety](/reference/addon-safety)). When the
  relay ends, roxy closes the client's connection whether or not the layers
  have ended their bodies; bytes already on their way get a second to
  arrive.
