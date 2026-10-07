# Architecture

## Crates

Dependencies point downward: `roxy` → `roxy-proxy`, `roxy-http`,
`roxy-rules`, `roxy-tls`, `roxy-wasm`, `roxy-node`; `roxy-proxy` →
`roxy-http`, `roxy-tls`, `roxy-rules`, `roxy-wasm`, `roxy-log`;
`roxy-rules`, `roxy-wasm`, `roxy-tls` → `roxy-http`. `roxy-http`,
`roxy-log`, `roxy-addon` and `roxy-node` depend on no other roxy crate;
`roxy-node-spec` is tests-only. `roxy-http` and `roxy-rules` do no network
I/O and are unit-tested and fuzzed directly.

| crate | responsibility |
|---|---|
| `roxy` | The binary: CLI (`run`, `check`, `ca`, `rule test`, `health`), config loading and validation, secrets, address-list loading, reload, store wiring. |
| `roxy-proxy` | Listeners, connection state machines, exchange core, addon stack (including service layers), watcher, upstream connector and address floor, WebSocket relay, flow-log events and capture. |
| `roxy-http` | Canonical request/response model, strict HTTP/1.1 codec, h2 ↔ canonical mapping, URL normalisation, body framing with caps, content-coding decoders, WebSocket handshake checks and frame codec. No I/O policy. |
| `roxy-tls` | CA generation and persistence, leaf minting and cache (keyed on the canonical `Host`), rustls configs, ClientHello sniffing. |
| `roxy-rules` | Expression DSL (lexer, parser, type checker, compiler), policy evaluation, actions, metric and state stores. |
| `roxy-wasm` | wasmtime component host for WASM addons: linking, capabilities, budgets, instance pools. |
| `roxy-log` | Buffered single-writer log destinations: one writer thread, batching, backpressure, rotation, compression. Knows bytes, not events. |
| `roxy-addon` | SDK for Rust addon authors: generated WIT bindings and wrappers. |
| `roxy-node` | Node side of the control-plane protocol: enrolment and renewal, lease loop, flow spool and shipper. Knows nothing of the proxy; `roxy` applies leases through a handler. |
| `roxy-node-spec` | The node protocol's OpenAPI document (`spec/node-protocol/v1/openapi.yaml`) with validators for its body schemas, for tests. |
| `wit/` | The `roxy:addon` WIT package: the language-agnostic addon contract. |

`unsafe` is forbidden in every crate except the generated bindings modules
of `roxy-wasm` and `roxy-addon` (`wit-bindgen` and `wasmtime::bindgen!`
output).

## Glossary

- **Exchange / flow:** one request and its response (or one WebSocket
  session) within a client connection. Each has a ULID.
- **Canonical:** roxy's validated, normalised, version-agnostic HTTP model.
- **Head rule / watching rule:** decided at the request head (can allow or
  deny) versus reading values known only later (can only deny or add
  effects).
- **Policy:** a compiled, immutable snapshot of the config, swapped
  atomically on reload.
- **Layer:** one addon in the stack.
