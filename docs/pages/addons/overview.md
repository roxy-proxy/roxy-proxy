# Addons

roxy knows HTTP, not any particular application or API. Logic that needs to
understand the traffic goes in an addon: a layer above the rules that owns
both streams of every exchange. An addon is either:

- **a WASM layer** (`kind: wasm`): a WebAssembly component run in-process by
  `roxy-wasm`, written against the `roxy:addon` WIT package
  ([`wit/addon.wit`](https://github.com/roxy-proxy/roxy-proxy/blob/main/wit/addon.wit)); or
- **a service layer** (`kind: service`): an external service in the network
  path, which each exchange streams through over a WebSocket
  ([below](#service-layers)).

Both sit in the same stack and obey the same invariants.

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
A layer with a `when` runs only on the exchanges it matches, and the rest
pass it by ([choosing exchanges](/addons/configuration#choosing-exchanges)).
Nothing configurable runs between the rules and the network, so what the
rules judged is what leaves. There is no setting or rule action that
places an addon anywhere else: either would make it ambiguous what the rules
enforced.

The stack is a pipeline. Every layer runs at once, as its own task, so on
a long stream each one works on a different chunk at the same time. But
each chunk passes through the layers in order, and each layer sees what the
layer above passed on. Observe layers are the exception: they get copies,
so they run beside the stream rather than in it.

## Invariants

1. **The rules evaluate every request that leaves.** An addon can reshape
   traffic freely; its output is re-validated by the canonical model and
   then judged by the rules exactly as if the client had sent it. On the
   way back, the watching rules see the upstream's response before any
   addon does.
2. **Every layer is held to the workload's limits.** Whatever a layer passes
   on is treated as if a client sent it: header limits, body caps, idle
   timeouts. A layer cannot pass on `CONNECT`: a tunnel is something the
   client opens at the proxy port, never a request to forward.
3. **Failure is closed.** A layer that traps, exceeds a budget or returns an
   invalid head denies the flow, or cuts the exchange if the response head
   is already out. There is no "on error, pass"; observe mode is the one
   safe way to run a layer whose failures must not matter. `sample` gives
  it a share of the matching exchanges rather than all of them.

## One exchange, one `next`

A layer calls `next` at most once per exchange; a second call traps. The
stack carries the client's traffic and nothing else: a layer never
originates requests through the layers below it. Retrying, regenerating or
replaying is the client's job, and a layer that rejects something answers
with a response the client can act on. A layer that needs to talk to
anything else calls a [named endpoint](#endpoints), which goes straight to
the connector, never through other layers or the rules.

## Full access to both streams

A layer may read, rewrite, split, delay, inject into or replace either
stream, chunk by chunk. roxy buffers nothing on a layer's behalf; a layer
that wants a whole body reads it, within its `max_memory`.
Typical patterns:

- **Observe:** `next(req)`, then return its response unchanged (or use
  observe mode).
- **Rewrite in flight:** wrap a body stream in a transform.
- **Withhold until cleared:** forward a streamed response's text as it
  arrives, but hold back parts (say, tool calls) until the layer has judged
  them.
- **Deny or answer:** return a response without calling `next`.

## WebSockets

A WebSocket is an exchange like any other, only long-lived, and this
section applies to both kinds of layer. A layer gets the upgrade request
in `handle` and passes it on with `next` (a service layer forwards it on
its stream); the response from below is the `101`. After it, the request
body carries the client's bytes and the response body the upstream's, for
as long as the WebSocket is open. A layer reads, rewrites or holds back
either direction as it would any body, refuses the upgrade by answering
without `next`, and is left out of the WebSocket entirely when its `when`
skips the upgrade request. A layer that turns the upstream's `101` into another status
fails the exchange closed (a `503` from `layer:<name>`), and roxy closes
the upstream WebSocket. A `101` with no upgrade from below fails closed
too. Only `Upgrade: websocket` makes a request an upgrade for the layers.
A request asking for any other upgrade (`h2c`, say) is the ordinary
request roxy forwards once it strips the upgrade, with its body and the
usual body cap.

- The bodies carry raw WebSocket frames. Frames from the client are
  masked, so their payload reads as sent only from the upstream's side.
- A layer must stream both bodies at once: the request body ends only
  when the client closes, while the response streams all along. The
  `roxy-addon` SDK does this.
- A transform that holds bytes back until more arrive (to match across
  chunks, say) stalls an interactive protocol: the peer waits for the
  held bytes.
- No clock runs on the bodies ([safety](/addons/safety)): a WebSocket
  lives as long as the relay's idle timeout allows. When the relay ends,
  roxy closes the client's connection too, whether or not the layers have
  ended their bodies; bytes already on their way get a second to arrive.

## Content codings

Layers see bodies decoded, so none needs its own decompressors. roxy
decodes on the way into the stack, for a flow some layer runs on: the
client's request body as the first layer that runs gets it, and the
response before it reaches the innermost layer. It removes
`content-encoding` as it does, and the body's length becomes unknown. A
flow no layer runs on (every `when` skipped it) is not decoded at all.

- So on a flow a layer runs on, the client gets an uncompressed response
  and the upstream an uncompressed request body. The origin's response to roxy stays
  compressed. Nothing re-encodes; a layer that wants a compressed body
  encodes it itself.
- The codings and their strictness are those the rules use
  ([HTTP](/reference/http#content-codings)). Data that does not decode, or a
  decoded body over `limits.max_request_body_bytes` or
  `limits.max_response_body_bytes`, cuts the exchange like any failed body.
- A body in a coding roxy does not know passes through as it is, with its
  `content-encoding`, for a layer to judge. So does a `206` or any response
  with `content-range`: part of an encoded body cannot be decoded on its
  own.
- The rules below the stack read the response before any layer, and decode
  it for themselves ([rules](/policies/body-rules)).

- A layer gets WebSocket messages it can read: no extension
  (`permessage-deflate` above all) is negotiated on a WebSocket a layer
  runs on ([WebSockets](/policies/websockets#extensions)).

`http.decode_for_addons: false` turns this off: layers then see the bytes
as sent, with their `content-encoding`, and WebSockets negotiate whatever
extensions client and upstream agree on.

## Modes

- `mode: enforce` (default): the layer is in the path and its decisions
  take effect.
- `mode: observe`: roxy tees both streams to the layer and ignores
  anything it returns except host-service calls such as `record`. A layer
  that keeps up sees every body in full, however large: each copy is
  buffered for it, and `limits.max_observer_lag_bytes` (16 MiB by default,
  per direction) is how far behind the real exchange it may fall before
  its copy is cut. What a copy has queued is charged to
  `limits.max_buffered_bytes` as it queues and given back as the layer
  reads it, and a copy whose next frame the budget cannot cover is cut
  the same way. The layer cannot change or delay traffic, so its
  failures cannot weaken containment: a trap or missed deadline is logged,
  not fatal, and a cut copy is reported (`observer_lagged`, with the
  `reason`) rather than stalling the flow. This is the way to deploy an
  uncalibrated monitor.

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
  that left too.
- A layer that answers itself is logged with `decision: answered` and
  `terminal_rule: layer:<name>`, whatever its status: the status tells a
  block (`403`) from a served answer (`200`). The answering layer is the
  outermost one that did not pass on the response from below: it never
  called `next`, or answered while `next` was pending, failed or dropped.
  If its request had already left, the forwarded request is abandoned (its
  body is cut, never ended as if complete), and the record keeps what the
  rules decided and the bytes sent, with `reason: upstream_aborted`.
- A layer failing before the response head denies with `503`,
  `terminal_rule: layer:<name>`, `reason: layer_error`, closes the
  connection, and emits a `layer_error` event whose `kind` is `trap`,
  `budget:<limit>`, `capability:<name>`, `invalid_request`,
  `invalid_response`, `no_response`, ... After the head, the body is cut
  (HTTP/1.1 breaks the connection, HTTP/2 resets the stream) and
  `layer_error` follows.
- A layer's response body to the client waits for the flow log like every
  forwarded body ([audit backpressure](/operate/flow-log#writing)).
- A WebSocket runs through the layers that ran on its upgrade request,
  outermost first, in their bodies. The relay stays the hop next to the
  upstream, so byte budgets and
  [message rules](/policies/websockets#message-rules) see what leaves.
- Layers compile at config load and are cached across reloads while their
  file and settings are unchanged, so their instance pools stay warm. A
  reload swaps the stack for new exchanges; exchanges in flight finish on
  theirs.
