# Architecture

## Exchange

```
  client ──TCP──▶  listener: explicit proxy
                     ▼
                   CONNECT: first bytes must be a TLS ClientHello
                     ▼      whose SNI matches the CONNECT host (the defaults:
                            http.allow_plain_in_connect, tls.require_sni_match)
                   TLS termination (leaf minted by roxy's CA), ALPN h1 | h2
                     ▼
                   strict parse → CanonicalRequest
                     ▼
                   addons (in config order)
                     ▼
                   rules: the head decision (forward or deny)
                     ▼
                   upstream connector: own DNS, address floor, rustls, h1 | h2
                     ▼
                   watching rules (body bytes, response, byte metrics)
                     ▼
                   addons (in reverse order), then re-serialised to the client

                   flow log ◀── every stage emits events
```

A client connection is accepted by a listener and, after CONNECT (on an
explicit listener) and TLS termination, carries a sequence of exchanges (HTTP/1.1 keep-alive) or
concurrent ones (HTTP/2 streams). Both fronts feed one transport-agnostic
exchange core (`roxy-proxy`'s `exchange` module):

1. The request head is parsed into the canonical model
   ([HTTP](/reference/http#canonical-request)). The body stays a stream.
2. The addon stack runs, outermost first ([addons](/addons/overview)). The last
   addon's `next` runs the rest of the core on what it passed on.
3. The request steps run, in a fixed order: a bounded body buffer only
   when a rule reads `body.text`, then the head decision and its effects
   ([rules](/policies/overview)). A step cannot forward anything itself;
   it returns a verdict, and the only verdict that leads to the upstream is
   `Continue`. Every error maps to a deny or a close. These steps are not
   an extension point: extensions are addons, above them.
4. The upstream connector resolves the host, checks every candidate IP
   against the address floor, and connects ([upstream](/reference/upstream)).
5. When the response head arrives, the response steps run: a bounded
   buffer of the response body only when a rule reads `response.body.text`,
   then the watching rules at the response head, which may still stop the
   exchange or change the head. For the rest of the exchange the watcher
   re-checks the watching rules as body bytes stream, records byte metrics,
   and holds each chunk until the flow log is ready
   ([audit backpressure](/operate/flow-log#writing)).
6. The response is re-framed for the client and passes back up the addon
   stack.

The compiled policy (rules, metrics, addons, address lists) is an immutable
snapshot swapped atomically on reload. An exchange runs to the end on the
snapshot it started with.

## Node mode

With `--control-plane` the binary has no config file
([node mode](/deploy/node-mode)). It opens bootstrap listeners that deny
everything, enrols with the control plane (or loads the certificate it
stored last time) and polls for a lease: a rendered `roxy.yaml`, the
secret values it names and how long it is good for
([node protocol](/reference/node-protocol)). The first lease replaces the
bootstrap listeners; later ones swap the policy snapshot, the secret map or
only `valid_until`, as a reload would. Every flow event also goes into an
in-memory spool, tagged with a per-node sequence number, and is shipped to
the control plane in batches until acknowledged.

## Crates

Dependencies point downward. `roxy` depends on `roxy-proxy`, `roxy-http`,
`roxy-rules`, `roxy-tls`, `roxy-wasm` and `roxy-node`; `roxy-proxy` on
`roxy-http`, `roxy-tls`, `roxy-rules`, `roxy-wasm` and `roxy-log`;
`roxy-rules`, `roxy-wasm` and `roxy-tls` on `roxy-http`. `roxy-http`,
`roxy-log`, `roxy-addon` and `roxy-node` depend on no other roxy crate;
`roxy-node-spec` is used only by tests. `roxy-http` and `roxy-rules` do no
network I/O, so they can be unit-tested and fuzzed directly.

| crate | responsibility |
|---|---|
| `roxy` | The binary: CLI (`run`, `check`, `ca`, `rule test`, `health`), config loading and validation, secrets, address-list loading, reload, store wiring. |
| `roxy-proxy` | Listeners, the connection state machines, the exchange core, the addon stack (including service layers), the watcher, the upstream connector and address floor, the WebSocket relay, flow-log events and capture. |
| `roxy-http` | The canonical request/response model, the strict HTTP/1.1 codec, the h2 ↔ canonical mapping, URL normalisation, body framing with caps, content-coding decoders, the WebSocket handshake checks and frame codec. No I/O policy. |
| `roxy-tls` | CA generation and persistence, leaf minting and cache (keyed on `roxy-http`'s canonical `Host`), rustls configs, ClientHello sniffing. |
| `roxy-rules` | The expression DSL (lexer, parser, type checker, compiler), policy evaluation, actions, the metric and state stores. |
| `roxy-wasm` | The wasmtime component host for WASM addons: linking, capabilities, budgets, instance pools. |
| `roxy-log` | Buffered single-writer log destinations: one writer thread, batching, backpressure, rotation, compression. Knows bytes, not events. |
| `roxy-addon` | SDK for Rust addon authors: generated WIT bindings and wrappers. |
| `roxy-node` | The node side of the control-plane protocol: enrolment and certificate renewal, the lease loop, the flow spool and shipper. Knows nothing of the proxy; `roxy` applies leases through a handler. |
| `roxy-node-spec` | The node protocol's OpenAPI document (`spec/node-protocol/v1/openapi.yaml`) with validators for its body schemas, for tests. |
| `wit/` | The `roxy:addon` WIT package: the language-agnostic contract for addons. |

`unsafe` is forbidden in every crate except the generated bindings modules
of `roxy-wasm` and `roxy-addon` (`wit-bindgen` and `wasmtime::bindgen!`
output), which allow it.

## Glossary

- **Exchange / flow:** one request and its response (or one WebSocket
  session) within a client connection. Each has a ULID.
- **Canonical:** roxy's validated, normalised, version-agnostic HTTP model.
- **Head rule / watching rule:** a rule decided at the request head (can
  allow or deny) versus one that reads values known only later (can only
  deny or add effects).
- **Policy:** a compiled, immutable snapshot of the config, swapped
  atomically on reload.
- **Layer:** one addon in the stack.
