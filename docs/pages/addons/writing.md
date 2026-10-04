# Writing addons

## Authoring

Rust is first class: small components, fast instantiation, real streaming.
The [`roxy-addon`](https://github.com/roxy-proxy/roxy-proxy/blob/main/crates/roxy-addon) SDK wraps the bindings:

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

roxy-wasm's test component
[`redact`](https://github.com/roxy-proxy/roxy-proxy/tree/main/crates/roxy-wasm/test-components/redact) is a streaming
redactor built on `roxy-addon`.

## WIT package

[`wit/addon.wit`](https://github.com/roxy-proxy/roxy-proxy/blob/main/wit/addon.wit) defines `roxy:addon@0.1.0`. It reuses
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
layer's concurrent exchanges; an exchange that finds none free waits until
one is. Instances are replaced after
`recycle_after_exchanges`, or when an exchange leaves their linear memory
above `recycle_above_memory`, which bounds linear-memory growth. An instance
that failed in any way is discarded, never reused.
