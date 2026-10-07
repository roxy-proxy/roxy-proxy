# roxy

> roxy is in early development. Expect frequent breaking changes to config,
> rules and interfaces.

roxy is a strict, programmable HTTP firewall: an egress proxy for untrusted
workloads, or a gateway in front of the APIs your clients call.

- **Strict.** roxy parses every request into one canonical form and
  forwards exactly that, so smuggling and header injection never reach the
  upstream. As a proxy it terminates TLS with its own CA.
- **Rules.** A YAML policy in a small, typed rule language. Deny always wins,
  anything no rule allows is denied, and rules can keep watching bodies as
  they stream. Metrics give rate limits and byte budgets, and secret
  injection means clients only hold placeholders.
- **Addons.** WASM components or external services that every exchange
  streams through. They can rewrite, withhold, answer or block, and the
  rules judge whatever they pass on.
- **Audit.** A JSONL flow log with the rule or addon behind every decision.
  It never drops a record: backpressure holds traffic until the log catches
  up.

It fails closed: anything roxy cannot parse, verify or classify is denied.

## Documentation

**[roxy-proxy.github.io/roxy-proxy](https://roxy-proxy.github.io/roxy-proxy/)**

- [Quickstart](https://roxy-proxy.github.io/roxy-proxy/quickstart): generated
  traffic through an auth gate, a token quota and an inspect_sentinel sidecar,
  with roxy in node mode leasing its policy from a minimal control plane
- [Configure policies](https://roxy-proxy.github.io/roxy-proxy/design/policy-evaluation),
  [addons](https://roxy-proxy.github.io/roxy-proxy/design/addon-model) and
  [reference](https://roxy-proxy.github.io/roxy-proxy/reference/configuration)
- Deploy it for
  [sandbox containment](https://roxy-proxy.github.io/roxy-proxy/guides/containment)
  or as an [HTTP gateway](https://roxy-proxy.github.io/roxy-proxy/guides/gateway)

The site's source is in [`docs/`](docs). Outstanding work is tracked in
[issues](https://github.com/roxy-proxy/roxy-proxy/issues).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
