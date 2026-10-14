# Addon model

roxy knows HTTP, not any particular application or API. Logic that needs to
understand the traffic goes in an addon: a layer above the rules that owns
both streams of every exchange it runs on. An addon is either:

* **a WASM layer** (`kind: wasm`): a WebAssembly component run in-process by
  `roxy-wasm`, written against the `roxy:addon` WIT package
  ([`wit/addon.wit`](https://github.com/roxy-proxy/roxy-proxy/blob/main/wit/addon.wit)),
  which hands each head over as one record and each body as a stream; or
* **a service layer** (`kind: service`): an external service in the network
  path, which each exchange streams through over a WebSocket
  ([service layer protocol](/reference/service-layers)).

## The stack

Each layer wraps everything below it: it receives the request (head and
body stream), may pass a request down with `next`, and returns a response
stream upward.

```
                 request ↓                                   ↑ response
 fixed   ┌─ CONNECT gate (SNI must match) ───────────────────────────────┐
 config  ├─ addon: first listed                                          │
 config  ├─ addon: second listed                                         │
 fixed   ├─ rules                  (admission ↓ / in flight ↑)           │
 fixed   ├─ address floor + deny lists (on the IP actually dialled)      │
 fixed   └─ connector ──▶ origin ────────────────────────────────────────┘
```

Addons always sit above the rules, in the order listed under `addons:`. A
layer with a `when` runs only on the exchanges it matches
([choosing exchanges](/reference/addon-configuration#choosing-exchanges)).
Nothing configurable runs between the rules and the network, so what the
rules judged is what leaves.

The stack is a pipeline: every layer runs at once, as its own task, each
seeing what the layer above passed on, so on a long stream each works on a
different chunk at the same time. Observe layers get copies and run beside
the stream rather than in it.

## Ordering across layers

Two things come out of a layer, and roxy orders only one of them.

The exchange's bytes form a pipeline. A head or a chunk reaches layer B
only after layer A has sent it on, and A may hold, rewrite or drop it on
the way: what B reads is what A passed, in the order A passed it, and the
rules admit the request the last layer forwarded. The response is the same
pipeline the other way up: the rules see the upstream's bytes first, then
B, and A gets a chunk only after B has passed it. This holds for enforce
layers of either kind. An observer is in neither order: it reads a copy
beside the pipeline, holds nothing up, and can neither tag nor write
state, so the rest of this section is about enforce layers.

Host-service effects are not in that pipeline. `add_tag`, `state_put`,
`record` and `quarantine` go to the host beside the bytes, not down the
stack. A layer's calls on an exchange run on their own worker, in the
order the layer made them, and roxy orders nothing between one layer's call and another
layer's read: A's `state_put` and B's `state_get` are concurrent unless A
awaits its `result` before sending the bytes B will read. B cannot read on
a chunk it has not received, so the await puts A's write ahead of B's
read. A WASM layer's call is a synchronous function that returns before
the layer continues, so it has that order by construction; a service layer
sends the call as a message and awaits the `result` itself
([host services on a stream](/reference/service-layers#host-services)).

<img src={layerOrdering} alt="Two enforce layers, A and B, in roxy's request path, left to right, then the rules. The client's head (a solid line) and body bytes (a dashed line) run through A, then B, then to the rules; the gap between A and B is labelled: a chunk reaches B only after A sends it. Part-way through the body, A calls state_put, drawn as an arrow down to a host services strip along the bottom with a result arrow back up, and the note awaits result, then sends on; A's body line is broken at that point. In B, on the chunk that followed, a state_get arrow goes down to the strip and a result comes back, with the note on that chunk: sees A's write. A dotted line between the two calls says ordered only by A's await. The strip reads host services (add_tag, state_put, state_get, record, quarantine, and more): beside the pipeline. Under it: each layer's calls run on their own worker, so A's put lands before B's get only because A awaited its result; a write for this exchange's admission lands before the request is forwarded; any other is seen by the next rule that reads it: a tag in flight on this exchange, state there or at a later exchange's admission." />

So, to make an effect visible:

* **to the layers below**: await the `result` before sending the head or
  chunk whose handling should see it (a WASM layer's call has returned by
  the time it sends anything);
* **to this exchange's admission rules**: land it before the request is
  forwarded, so before the layer calls `next` or the service sends its
  forwarded `request` head;
* **otherwise**, the write is seen by the next rule that reads it. A tag
  lives on this exchange, so that is an in-flight re-check of it; state
  persists, so it is that or a later exchange's admission. The write does
  not itself trigger a re-check: a rule runs when a value it watches
  changes, and reads the tag or key then. A write never reopens a decision
  already made ([policy evaluation](/design/policy-evaluation#evaluation)).

## Invariants

1. **The rules evaluate every request that leaves.** An addon can reshape
   traffic freely; its output is re-validated by the canonical model and
   then judged by the rules exactly as if the client had sent it. On the
   way back, the in-flight rules see the upstream's response before any
   addon does.
2. **Every layer is held to the workload's limits.** Whatever a layer passes
   on is treated as if a client sent it: header limits, body caps, idle
   timeouts. A layer cannot pass on `CONNECT`: a tunnel is something the
   client opens at the proxy port, never a request to forward.
3. **Failure is closed.** A layer that traps, exceeds a budget or returns an
   invalid head denies the flow, or cuts the exchange if the response head
   is already out. There is no "on error, pass"; observe mode is the one
   safe way to run a layer whose failures must not matter.

## Who is blamed

When an exchange fails, one party is blamed, and the first fault recorded
stands. Every party records its own fault before anything downstream of it
can fail on it: a layer as it fails, before its bodies end; a body where it
enters the stack, before a layer reads it; the front as it gives the
exchange up. So what a layer makes of a body or a `next` that ended on
someone else's failure is a consequence, never a second fault.

* A layer's own failure (a trap, an exceeded budget, an invalid head, a
  service that broke its stream) is the layer's: `503` with
  `terminal_rule: layer:<name>` before the response head, a cut body after
  it, and one `layer_error` event either way. A failure found below the
  layer that caused it (a passed-on request that does not validate, say) is
  put down to the nearest enforcing layer above.
* A client upload that breaks is the client's, as without a stack: the
  connection closes on the parse error before the head, the body is cut
  after it, and no `layer_error` is logged however many layers fail on the
  cut body.
* An upstream response body that fails before any layer has answered with
  a head of its own is the upstream's: `502`, `reason: upstream_body_failed`.
* A body the [buffer budget](/reference/limits#limits) cannot cover on its
  way to a layer (a decoder's window) fails closed as the budget's:
  `reason: buffer_budget_exhausted`.
* An observer is never blamed, and a client that gives up is nobody's
  failure: nothing is logged.

## One exchange, one `next`

A layer calls `next` at most once per exchange; a second call traps. The
stack carries the client's traffic and nothing else: a layer never
originates requests through the layers below it, so retrying, regenerating
or replaying is the client's job, and a layer that rejects something
answers with a response the client can act on. Anything else a layer needs
to reach is a [named endpoint](/reference/host-services#endpoints-endpoints),
which goes straight to the connector, never through other layers or the
rules.

## A layer takes what it subscribes to

A layer subscribes to each direction in config: the head and the body
(`full`, the default) or the head only. Of a direction it has in full, a
layer may read, rewrite, split, delay, inject into or replace the stream,
chunk by chunk. roxy buffers nothing on a layer's behalf; a layer that
wants a whole body reads it, within its `max_memory`. The patterns:
observe (`next(req)`, return its response unchanged), rewrite in flight
(wrap a body stream in a transform), withhold until cleared (forward a
streamed response as it arrives but hold back parts, say tool calls, until
judged), and deny or answer (return a response without calling `next`).

A body a layer is not subscribed to bypasses it, as if the layer had
passed it on untouched: the layer sees the head with an empty body and
decides at admission, and roxy splices the body onto what it passes on. An
enforce layer still denies or rewrites at admission; an observer that wants
heads only costs no body copies
([what a layer sees](/reference/addon-configuration#what-a-layer-sees)).

A WebSocket is an exchange like any other, only long-lived: after the
`101`, the request body carries the client's bytes and the response body
the upstream's ([WebSockets through addons](/reference/addon-configuration#websockets)).
Layers see bodies decoded, so none needs its own decompressors
([content codings](/reference/addon-configuration#content-codings)).

## Modes

* `mode: enforce` (default): the layer is in the path and its decisions
  take effect.
* `mode: observe`: roxy tees both streams to the layer and ignores
  anything it returns except host-service calls such as `record`. The
  layer cannot change or delay traffic, so its failures cannot weaken
  containment: a trap or missed deadline is logged, not fatal, which makes
  it the way to deploy an uncalibrated monitor. `sample` gives it a share
  of the matching exchanges, and an observer may `record` but cannot tag
  the flow ([capabilities](/reference/addon-configuration#capabilities)).

  Each copy of a body the layer is subscribed to is buffered for it, so
  one that keeps up sees every body in full, however large. A copy is cut, and the flow goes on, when
  the layer falls `limits.max_observer_lag_bytes` behind, the
  [buffer budget](/reference/limits#limits) cannot cover its next frame,
  or no instance of the layer comes free within its `first_byte_timeout`
  (`observer_lagged`, with the `reason`). A request refused or answered
  below the observer without its body being read ends the copy where the
  reading stopped, without an error, and the observer sees the refusal
  from `next`; a copy that fails (the client went away mid-upload) ends
  with that failure, so the layer can tell the two apart.
