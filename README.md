# roxy

roxy is a TLS-inspecting HTTP firewall for containing the network traffic of
(potentially adversarial) AI agents. It runs as an explicit `HTTP_PROXY`,
terminates TLS with leaf certificates minted by its own CA, parses every
request into a strict canonical model, and re-serialises it in one
unambiguous wire form, so smuggling and header-injection tricks never reach
the upstream. It fails closed: anything it cannot parse, verify or classify
is dropped, and an empty rule set denies everything.

Policy is a declarative YAML file: a small, statically typed expression
language for matching requests, stateful metrics (count, window, threshold)
for rate and budget rules, secret injection so the agent only ever holds
placeholders, and later sandboxed WASM addons. Every decision lands in a
structured JSONL flow log with the rule that made it. See
[DESIGN.md](DESIGN.md) for the full design, threat model and milestones.

**Status: M0: scaffolding.** The workspace, config schema and `roxy check`,
CA generation and export, and the flow-log skeleton exist. roxy does not
proxy any traffic yet.

## Quickstart

```sh
cargo build --release

# Validate a config (exit code 1 and `file:yaml.path: message` diagnostics on error)
./target/release/roxy check --config examples/roxy.yaml

# Generate the CA in `tls.ca_dir` and print it for injection into a sandbox
./target/release/roxy ca init --config examples/minimal.yaml
./target/release/roxy ca export --config examples/minimal.yaml > roxy-ca.pem

# Start (M0: loads config and CA, then waits for ctrl-c)
./target/release/roxy run --config examples/minimal.yaml
```

`examples/minimal.yaml` uses the default `tls.ca_dir` of `/var/lib/roxy/ca`;
set `tls.ca_dir` to a writable directory when trying it out locally.

## Workspace

| crate | responsibility |
|---|---|
| `crates/roxy` | binary: CLI, config loading and validation, secrets, wiring |
| `crates/roxy-proxy` | listeners, flow pipeline, upstream connector, flow log |
| `crates/roxy-tls` | CA, leaf minting, rustls configs, ClientHello sniffing |
| `crates/roxy-http` | canonical HTTP model, strict codecs, URL normalisation |
| `crates/roxy-rules` | expression DSL, rules, actions, metrics, policy snapshots |

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
