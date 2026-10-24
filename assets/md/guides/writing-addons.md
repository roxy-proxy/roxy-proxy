# Writing addons

A WASM addon is a WebAssembly component. Write one in Rust with the
[`roxy-addon`](https://github.com/roxy-proxy/roxy-proxy/blob/main/crates/roxy-addon)
SDK:

```rust
use roxy_addon::prelude::*;

struct RedactTokens;
impl Layer for RedactTokens {
    fn init(_config: &str) -> Result<Self, String> {   // the addon's `config:`, as JSON
        Ok(RedactTokens)
    }
    fn handle(&mut self, req: Request, next: Next) -> Response {
        let req = req.map_body(|body| body.transform(redact_chunk));
        next.run(req)
    }
}
roxy_addon::export!(RedactTokens);
```

* `handle` runs once per exchange. It can change the request, call
  `next.run` to pass it on and get the response, or answer the client
  itself.
* `Body` streams: read it as it arrives with `transform` (per chunk) or
  `pipe` (with state, able to hold bytes back), or collect it with
  `read_to_end(cap)`.
* `flow::*` and `call_endpoint` reach roxy's
  [host services](/reference/host-services): tags, state, records, and
  calls to configured endpoints.
* A panic fails the exchange closed.
* WebSockets need nothing extra: the request and response bodies carry
  them.

The test component
[`redact`](https://github.com/roxy-proxy/roxy-proxy/tree/main/crates/roxy-wasm/test-components/redact)
is a complete streaming redactor.

## Other languages

Any language that builds WebAssembly components can implement
[`wit/addon.wit`](https://github.com/roxy-proxy/roxy-proxy/blob/main/wit/addon.wit),
the `roxy:addon@0.3.0` package, whose comments document each call. Go and JavaScript produce larger, slower
components. Python in WASM bundles an interpreter and needs raised memory
limits. For Python with native dependencies, or anything that should run
in its own process, write a [service layer](/reference/service-layers)
instead.

A component has no network, filesystem or environment access. Outbound
calls go through named endpoints, and output to stdout or stderr is
discarded: use `flow.log`.

Build a component against the `wit/` of the roxy version it runs on. A
component built against another version fails when the config loads,
naming the imports that do not match.
