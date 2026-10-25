# Writing addons

An addon sees each request on its way to the rules and each response on
its way back to the client ([addon model](/design/addon-model)). The
simplest addon passes both through unchanged. This page shows that
addon in each kind, as a starting point to change.

## A WASM layer

A WASM addon is a WebAssembly component. Write one in Rust with the
[`roxy-addon`](https://github.com/roxy-proxy/roxy-proxy/blob/main/crates/roxy-addon)
SDK. The crate is not on crates.io, so depend on it from the repository:

```toml
# Cargo.toml
[package]
name = "passthrough"
version = "0.1.0"
edition = "2024"

[lib]
crate-type = ["cdylib"]

[dependencies]
roxy-addon = { git = "https://github.com/roxy-proxy/roxy-proxy" }
```

```rust
// src/lib.rs
use roxy_addon::prelude::*;

struct Passthrough;

impl Layer for Passthrough {
    fn init(_config: &str) -> Result<Self, String> {   // the addon's `config:`, as JSON
        Ok(Passthrough)
    }

    fn handle(&mut self, req: Request, next: Next) -> Response {
        next.run(req)
    }
}

roxy_addon::export!(Passthrough);
```

Build it and point roxy at the component:

```sh
rustup target add wasm32-wasip2
cargo build --release --target wasm32-wasip2
```

```yaml
addons:
  - name: passthrough
    kind: wasm
    path: target/wasm32-wasip2/release/passthrough.wasm
```

`handle` runs once per exchange. It gets the client's request and a
`Next`, and returns the response for the client:

```rust
Request  { method, scheme, authority, path_with_query, headers, body }
Response { status, headers, body }
```

`next.run(req)` passes the request on to the next addon or the rules, and
returns the response that comes back. Returning that response unchanged
passes everything through. A body passed on without being read never
enters the component, so this costs almost nothing.

From there, a layer can change the request or the response, or answer
the client itself without calling `next.run`:

```rust
fn handle(&mut self, req: Request, next: Next) -> Response {
    let req = req.map_body(|body| body.transform(redact_chunk));
    next.run(req)
}
```

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

## A service layer

A service layer is a WebSocket server that roxy connects to. It must
accept the subprotocol `roxy.layer.v7`.

```yaml
addons:
  - name: passthrough
    kind: service
    endpoint: layer
    endpoints:
      layer: { url: "http://127.0.0.1:9000", private_ok: true }
```

Each exchange is a stream on the connection, and every message names its
stream. A `GET` arrives like this:

```json
{"stream":1,"type":"open","flow":"01M5…","layer":"passthrough","mode":"enforce", …}
{"stream":1,"type":"request","method":"GET","url":"http://example.com/","headers":[["accept","*/*"]]}
{"stream":1,"type":"request_end"}
```

The service sends back the request to pass on, in the same shape. When
the response comes back from upstream, roxy sends it the same way, and
the service sends back the response for the client:

```json
{"stream":1,"type":"response","status":200,"headers":[["content-type","text/html"]]}
{"stream":1,"type":"credit","dir":"response","bytes":262144}
{"stream":1,"type":"response_end"}
```

Body bytes come as binary frames between a head and its end: a 4-byte
stream id, a direction byte (`0` request, `1` response), then the bytes.
`credit` tells the service how many more body bytes roxy will take from
it.

To pass everything through unchanged, send every frame back exactly as it
arrived, except `open` and `reset`:

```python
import asyncio
import json

from websockets.asyncio.server import serve


async def layer(ws):
    async for frame in ws:
        if isinstance(frame, str) and json.loads(frame)["type"] in ("open", "reset"):
            continue
        await ws.send(frame)


async def main():
    async with serve(layer, "127.0.0.1", 9000, subprotocols=["roxy.layer.v7"]):
        await asyncio.Future()


asyncio.run(main())
```

This works because the service's replies have the same shape as what it
receives. Heads, body bytes, trailers and ends go back as the request and
response to pass on. Sending roxy's `credit` back gives roxy as much
credit as roxy gave the service, so roxy never sends more than the
service can pass on. `open` describes the exchange and needs no answer.
After a `reset` the stream is gone.

This is for `mode: enforce`. An observer gets a copy of the exchange and
sends none of it back. The [service layer protocol](/reference/service-layers)
covers both modes, flow control, errors and host-service calls.

A real service usually wants each exchange as one task. The
[quickstart](/quickstart)'s sidecar includes
[`roxy_layer.py`](https://github.com/roxy-proxy/roxy-proxy/blob/main/examples/quickstart/sentinel/roxy_layer.py),
a Python asyncio implementation of the protocol that handles the framing,
flow control and errors, and hands a handler one exchange at a time.

## Other languages

Any language that builds WebAssembly components can implement
[`wit/addon.wit`](https://github.com/roxy-proxy/roxy-proxy/blob/main/wit/addon.wit),
the `roxy:addon@0.3.0` package, whose comments document each call. Go and JavaScript produce larger, slower
components. Python in WASM bundles an interpreter and needs raised memory
limits. For Python with native dependencies, or anything that should run
in its own process, write a service layer instead.

A component has no network, filesystem or environment access. Outbound
calls go through named endpoints, and output to stdout or stderr is
discarded: use `flow.log`.

Build a component against the `wit/` of the roxy version it runs on. A
component built against another version fails when the config loads,
naming the imports that do not match.
