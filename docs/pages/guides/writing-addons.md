# Writing addons

## Authoring

The [`roxy-addon`](https://github.com/roxy-proxy/roxy-proxy/blob/main/crates/roxy-addon)
SDK wraps the bindings for Rust:

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
- WebSockets need nothing extra: the request and response bodies carry
  them ([WebSockets](/reference/addon-configuration#websockets)).

Any language that targets the component model works against the WIT. Go
(wasip2) and JS (`jco componentize`) produce larger binaries with higher
per-call cost. Python in WASM (`componentize-py`) bundles an interpreter:
tens of MiB, 128–256 MiB of memory, pure-Python dependencies only; give it
raised budgets. Python with native dependencies, or anything else out of
process, is a [service layer](/reference/service-layers).

roxy-wasm's test component
[`redact`](https://github.com/roxy-proxy/roxy-proxy/tree/main/crates/roxy-wasm/test-components/redact)
is a streaming redactor built on `roxy-addon`.

## WIT package

[`wit/addon.wit`](https://github.com/roxy-proxy/roxy-proxy/blob/main/wit/addon.wit)
defines `roxy:addon`, unversioned until the contract is declared stable.
Heads are records of roxy's own: a
`request-head` (method, scheme, authority, path and query, and the header
list) and a `response-head` (status and headers), each crossing the guest
boundary in one call. Bodies are plain `wasi:io/streams` (vendored at
0.2.12 under `wit/deps/`; a guest built against any 0.2.x links). The
`roxy-addon` crate carries its own copy of `wit/`.

- **World `layer`** exports `handler` (`handle(request-head, input-stream)`,
  one call per exchange) and `init` (called once per instance, with the
  config available through `flow.config`). It imports `types`, `chain`
  (`next`, `respond`), `endpoints`, `flow`, and the WASI clocks, random, io
  and stdio interfaces.
- A layer answers with `chain.respond(response-head, body)`, once, before
  `handle` returns; `chain.next(request-head, body)` passes a request down,
  once. Neither waits on the other: a layer may answer and then forward,
  forward and answer before the response from below arrives, or answer
  without forwarding; its answer reaches the client as soon as it is made,
  and a forward it made runs to its end. Both take a `body`: `empty`, `bytes` (one piece, no stream),
  `passthrough` (a stream the host handed this layer, moved host-side
  without entering the guest) or `stream`, for which the call returns the
  `output-stream` to write. A streamed body must be ended with
  `types.finish`; dropped unfinished it is cut, never ended as complete.
- `next` and `endpoints.call` return a `pending-response`: `subscribe` and
  `get` to wait alongside other work, or `wait` to block and take the
  response head and body stream in one call.
- The host validates every head it is handed: names and values must parse,
  there may be no more than `limits.max_headers` of them, `host`,
  `content-length`, hop-by-hop and framing fields are refused (roxy derives
  them; the body carries its own length), and the whole record must fit in
  128 KiB. A refused head fails the exchange closed. Trailers on a body are
  dropped in both directions.
- The host links the rest of WASI 0.2 inertly: an empty environment, no
  arguments, no preopened directories, stdin closed, TCP, UDP and name
  lookup off, every socket address denied. Anything a guest writes to
  stdout or stderr is discarded; use `flow.log` to be heard. Stock
  toolchains whose standard library imports more than it uses still load,
  and still reach nothing.
- `wasi:http` is not provided, so a component that imports it fails to
  link. Outbound calls go through `endpoints`.
- During `init` there is no exchange: `config` works, `log` goes to roxy's
  own log (the capability still applies), and every other `flow`, `chain`
  or `endpoints` call traps.

The package carries no version: its contract is not yet declared stable,
and a component is built against the `wit/` of the roxy it runs on. A
component whose imports do not match fails at config load with the
component's imports named; rebuild it against the current `roxy-addon`.

### Instances

A component is compiled and linked once per config load, on the blocking
pool, then one instance is started and its `init` run, so a broken layer
fails the load. Each exchange checks an instance out of the layer's pool
for its whole duration; instances are replaced after
`recycle_after_exchanges` or above `recycle_above_memory`, and one that
failed in any way is discarded, never reused
([limits](/reference/addon-configuration#limits),
[configuration](/reference/addon-configuration)).
