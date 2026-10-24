# Architecture

## Crates

| crate | responsibility |
|---|---|
| `roxy` | The binary: the CLI, config loading and validation, secrets, reload. |
| `roxy-proxy` | Listeners, connections, the addon stack, the upstream connector and address floor, WebSocket relay, flow-log events and capture. |
| `roxy-http` | The canonical request and response model, the strict HTTP/1.1 parser, HTTP/2 mapping, URL normalisation, body framing, content decoding, WebSocket frames. No I/O. |
| `roxy-tls` | The CA, leaf certificates, TLS configs, ClientHello sniffing. |
| `roxy-rules` | The rule language, policy evaluation, metric and state stores. No I/O. |
| `roxy-wasm` | The host for WASM addons. |
| `roxy-log` | Log files: one writer thread, batching, backpressure, rotation. |
| `roxy-addon` | The SDK for Rust addons. |
| `roxy-node` | The node side of the control-plane protocol. |
| `roxy-state` | The state dir and its atomic file writer. |
| `roxy-node-spec` | The node protocol's OpenAPI document, for tests. |
| `wit/` | The `roxy:addon` WIT package: the addon contract. |

## Why roxy parses HTTP/1.1 itself

Common HTTP servers resolve framing ambiguities that the HTTP/1.1 spec
lets a server resolve, such as `Transfer-Encoding` alongside
`Content-Length`. A proxy that resolves an ambiguity one way while the
origin behind it resolves it another way can be used to smuggle requests.
roxy refuses these requests instead, and its own parser gives every
refusal a stable reason code
([rejection rules](/reference/http#rejection-rules)). HTTP/2 framing has
no such ambiguities, so roxy uses an existing HTTP/2 implementation.

## Glossary

* **Exchange:** one request and its response, or one WebSocket session.
  Also called a flow; each has an id in the flow log.
* **Canonical:** roxy's validated, normalised form of a request.
* **Admission rule, in-flight rule:** a rule decided before the request is
  forwarded, which can allow or deny, versus one checked as the exchange
  streams, which can only deny or add effects.
* **Policy:** the compiled config, swapped in whole on reload.
* **Layer:** one addon in the stack.
* **Address floor:** the check on every upstream address before roxy
  connects ([address floor](/reference/address-lists#address-floor)).
