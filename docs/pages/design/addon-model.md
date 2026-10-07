# Addons

roxy knows HTTP, not any particular application or API. Logic that needs to
understand the traffic goes in an addon: a layer above the rules that owns
both streams of every exchange. An addon is either:

- **a WASM layer** (`kind: wasm`): a WebAssembly component run in-process by
  `roxy-wasm`, written against the `roxy:addon` WIT package
  ([`wit/addon.wit`](https://github.com/roxy-proxy/roxy-proxy/blob/main/wit/addon.wit)); or
- **a service layer** (`kind: service`): an external service in the network
  path, which each exchange streams through over a WebSocket
  ([below](/reference/service-layers)).

Both sit in the same stack and obey the same invariants.

An exchange passes through an ordered stack of layers. Each layer wraps
everything below it: it receives the request (head and body stream), may
pass a request down with `next`, receives the response stream from below,
and returns a response stream upward. The first layer sees the request
first and the response last.

```
                 request ↓                                   ↑ response
 fixed   ┌─ CONNECT gate (SNI must match) ───────────────────────────────┐
 config  ├─ addon: first listed                                          │
 config  ├─ addon: second listed                                         │
 fixed   ├─ rules                  (head decision ↓ / watching ↑)        │
 fixed   ├─ address floor + deny lists (on the IP actually dialled)      │
 fixed   └─ connector ──▶ origin ────────────────────────────────────────┘
```

**Addons always sit above the rules**, in the order listed under `addons:`.
A layer with a `when` runs only on the exchanges it matches, and the rest
pass it by ([choosing exchanges](/reference/addon-configuration#choosing-exchanges)).
Nothing configurable runs between the rules and the network, so what the
rules judged is what leaves.

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
anything else calls a [named endpoint](/reference/host-services#endpoints-endpoints), which goes straight to
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

## Modes

- `mode: enforce` (default): the layer is in the path and its decisions
  take effect.
- `mode: observe`: roxy tees both streams to the layer and ignores
  anything it returns except host-service calls such as `record`. The
  layer cannot change or delay traffic, so its failures cannot weaken
  containment: a trap or missed deadline is logged, not fatal. This is the
  way to deploy an uncalibrated monitor.

  Each copy is buffered for the layer, so one that keeps up sees every
  body in full, however large. A copy is cut, and the flow goes on, when
  the layer falls `limits.max_observer_lag_bytes` behind (16 MiB by
  default, per direction) or when the [buffer
  budget](/reference/limits#limits) cannot cover its next frame; either is
  reported as `observer_lagged` with the `reason`. A request refused or
  answered below the observer without its body being read ends the copy
  where the reading stopped, without an error, and the observer sees the
  refusal from `next`; a copy that fails (the client went away mid-upload)
  ends with that failure, so the layer can tell the two apart. An observer
  may `record` but cannot tag the flow
  ([capabilities](/reference/addon-configuration#capabilities)).
