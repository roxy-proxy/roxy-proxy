# roxy-addon

Write [roxy](https://github.com/roxy-proxy/roxy-proxy) addon layers in Rust.

roxy is a TLS-inspecting HTTP firewall for AI agents. An addon is a
WebAssembly component that sits in each exchange's layer stack above
roxy's rules. It gets the request with a streaming body, may pass a request
down once, and returns a response, whose body also streams. Whatever it
passes down is still judged by the rules, and any failure (a panic, an
exceeded budget) denies the flow.

```rust
use roxy_addon::prelude::*;

/// Redacts a token in request bodies, chunk by chunk.
struct Redact {
    needle: Vec<u8>,
}

impl Layer for Redact {
    fn init(config: &str) -> Result<Self, String> {
        // `config` is the layer's `config:` value from roxy.yaml, as JSON.
        let needle = config.trim_matches('"').as_bytes().to_vec();
        Ok(Redact { needle })
    }

    fn handle(&mut self, req: Request, next: Next) -> Response {
        let needle = self.needle.clone();
        let req = req.map_body(|body| {
            body.transform(move |chunk| replace(&chunk, &needle, b"[redacted]"))
        });
        next.run(req)
    }
}

roxy_addon::export!(Redact);

fn replace(haystack: &[u8], needle: &[u8], with: &[u8]) -> Vec<u8> {
    // ... replace every occurrence of `needle` in `haystack` ...
    haystack.to_vec()
}
```

(A real redactor must also catch a needle split across two chunks; use
[`Body::pipe`] with a [`ChunkTransform`] that holds back a tail.)

## Building

```toml
[lib]
crate-type = ["cdylib"]

[dependencies]
roxy-addon = "0.1"
```

```sh
rustup target add wasm32-wasip2
cargo build --release --target wasm32-wasip2
```

The output, `target/wasm32-wasip2/release/<name>.wasm`, is a component.
Load it in roxy:

```yaml
addons:
  - name: redact
    kind: wasm
    path: /etc/roxy/addons/redact.wasm
    capabilities: []
    config: "sk-live-1234"
```

On other targets the crate builds too (imports panic if called), so the
logic of a layer can be unit-tested natively.

## What a layer can do

- **Streams.** [`Request`] and [`Response`] carry a [`Body`]: a pull-based
  sequence of chunks read from roxy only as the layer consumes it. A body
  the layer passes on without reading or transforming it never enters the
  guest: roxy moves it from stream to stream itself.
  - `transform` rewrites it chunk by chunk.
  - `pipe` runs it through a stateful [`ChunkTransform`] that can hold
    bytes back, for example to withhold part of a stream until it has been
    judged.
  - `read_to_end(cap)` buffers it, up to a cap. The layer's `max_memory`
    bounds it too.
- **Answer directly.** Return a [`Response`] without calling `next`:
  `Response::json(403, ...)`, `Response::text(...)`.
- **Host services** in [`flow`], each behind a capability granted in roxy's
  config:
  - `record` writes structured audit events to the flow log;
  - `state_get` and `state_put` read and write a keyed store with TTLs;
  - `metric_get` reads a metric;
  - `log` writes to roxy's operational log.
- **Named endpoints.** [`call_endpoint`] calls an endpoint configured in
  roxy by name. roxy attaches its credentials, so the layer never sees
  them, and the call bypasses the layer stack.

A layer handles one exchange at a time per instance. roxy runs several
instances, recycles them, and holds each to a memory cap and a deadline to
its response head ([addon safety](https://roxy-proxy.github.io/roxy-proxy/reference/addon-safety)).

A WebSocket reaches a layer as an ordinary exchange: after the `101`, the
request body carries the client's bytes and the response body the
upstream's. `Next::run` streams both at once.

## Example

roxy-wasm's test component
[`redact`](https://github.com/roxy-proxy/roxy-proxy/tree/main/crates/roxy-wasm/test-components/redact)
redacts literal strings from both bodies as they stream, holding back
only the bytes a needle could straddle.

## License

MIT OR Apache-2.0.
