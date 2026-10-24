# Architecture

## Crates

Dependencies point downward: `roxy` → `roxy-proxy`, `roxy-http`,
`roxy-rules`, `roxy-tls`, `roxy-wasm`, `roxy-node`; `roxy-proxy` →
`roxy-http`, `roxy-tls`, `roxy-rules`, `roxy-wasm`, `roxy-log`,
`roxy-state`; `roxy-rules`, `roxy-wasm`, `roxy-tls` → `roxy-http`;
`roxy-node` → `roxy-state`. `roxy-http`, `roxy-log`, `roxy-addon` and
`roxy-state` depend on no other roxy crate; `roxy-node-spec` is tests-only. `roxy-http` and `roxy-rules` do no network
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
| `roxy-state` | The state dir: its layout (node token, flow sequence, CA dir, quarantine marker) and the atomic writer the files it replaces (token, flow sequence, marker) go through. The CA dir's files are created once, never replaced, by `roxy-tls`. |
| `roxy-node-spec` | The node protocol's OpenAPI document (`spec/node-protocol/v1/openapi.yaml`) with validators for its body schemas, for tests. |
| `wit/` | The `roxy:addon` WIT package: the language-agnostic addon contract. |

`unsafe` is forbidden in every crate except the generated bindings modules
of `roxy-wasm` and `roxy-addon` (`wit-bindgen` and `wasmtime::bindgen!`
output).

## Why roxy parses HTTP/1.1 itself

The client-facing HTTP/1.1 codec in `roxy-http` is roxy's own, on
`httparse` for tokenising. Three things decide it.

hyper's server resolves the ambiguities RFC 9112 lets a server resolve.
`Transfer-Encoding` beside `Content-Length` drops the `Content-Length` and
reads the body as chunked; duplicate `Content-Length` fields with equal
values, comma-joined ones included, are accepted. roxy refuses both
(`cl_and_te`, `duplicate_content_length`): a proxy that resolves a framing
ambiguity makes one choice, and the origin behind it may make another.

hyper's parse errors are one private kind; the client gets a status, a
`400` for most, and nothing names the cause. Every refusal roxy makes
carries a stable reason code
([rejection rules](/reference/http#rejection-rules)). It is the `reason`
of the `parse_error` flow event, the body of the refusal
([deny responses](/reference/http#deny-responses)) and what
`quarantine_on.parse_errors` counts
([listener modes](/reference/http#listener-modes)).

Several refusals sit below hyper's API, where no setting reaches: a bare LF
anywhere in the head (`bare_lf`), a second `Host` (`multiple_host`), a body
on a bodiless method (`body_on_bodiless_method`), chunk extensions and
obs-text as opt-ins (`http.allow_chunk_extensions`, `http.allow_obs_text`),
a body idle timeout (`limits.body_idle_timeout`) apart from the header
timeout, a cap on how much of an abandoned request body is drained to keep
the connection alive and a lingering close when it is not, and a
`100 Continue` sent once the rules admit the request rather than when the
body is first polled ([headers](/reference/http#headers)).

HTTP/2 framing leaves nothing to resolve, so the `h2` crate parses it and
the same semantic validator follows
([HTTP/2 requests](/reference/http#http2-requests)). Upstreams are trusted
([threat model](/design/threat-model)), so hyper's client parses their
responses and roxy only re-frames them
([responses](/reference/http#responses)).

## Glossary

* **Exchange / flow:** one request and its response (or one WebSocket
  session) within a client connection. Each has a ULID.
* **Canonical:** roxy's validated, normalised, version-agnostic HTTP model.
* **Admission rule / in-flight rule:** decided before the request is
  forwarded (can allow or deny) versus re-checked as the exchange streams,
  reading values known only then (can only deny or add effects).
* **Policy:** a compiled, immutable snapshot of the config, swapped
  atomically on reload.
* **Layer:** one addon in the stack.
