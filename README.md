# roxy

roxy is a programmable, TLS-intercepting HTTP proxy built for streaming.
Each exchange flows through the addons that match it, which can rewrite,
answer or block it mid-stream, and a strict policy layer underneath decides
what actually leaves. It is meant for workloads you don't fully trust: AI
agents, CI jobs, sandboxes and third-party code.

- **Intercepting.** roxy terminates TLS with certificates from its own CA,
  parses every request into one canonical form and forwards exactly that, so
  smuggling and header injection never reach the upstream.
- **Streaming.** Bodies flow through chunk by chunk, in both directions.
  Nothing is buffered unless a layer or a rule asks to read a whole body or
  message. A server-sent event stream or a WebSocket is one long exchange,
  and a slow addon slows it down rather than cutting it off.
- **Addons.** WASM components or external services, each run on the requests
  its `when:` condition matches. They can rewrite, withhold, answer or block,
  and the rules judge whatever they pass on.
- **Rules.** A YAML policy in a small, typed rule language. Deny always wins,
  anything no rule allows is denied, and rules can keep watching bodies as
  they stream. Metrics give rate limits and byte budgets, and secret
  injection means clients only hold placeholders.
- **Audit.** A JSONL flow log with the rule or addon behind every decision.
  It never drops a record: backpressure holds traffic until the log catches
  up.

It fails closed: anything roxy cannot parse, verify or classify is denied.

## Documentation

**[roxy-proxy.github.io/roxy-proxy](https://roxy-proxy.github.io/roxy-proxy/)**

- [Quickstart](https://roxy-proxy.github.io/roxy-proxy/quickstart): Claude
  Code behind roxy and an inspect_sentinel sidecar, in about five minutes
- [Use cases](https://roxy-proxy.github.io/roxy-proxy/use-cases/ai-agents):
  AI agents, CI jobs
- [Configure policies](https://roxy-proxy.github.io/roxy-proxy/policies/overview),
  [addons](https://roxy-proxy.github.io/roxy-proxy/addons/overview),
  [deploy](https://roxy-proxy.github.io/roxy-proxy/deploy/overview) and
  [reference](https://roxy-proxy.github.io/roxy-proxy/reference/configuration)

The site's source is in [`docs/`](docs). Outstanding work is tracked in
[issues](https://github.com/roxy-proxy/roxy-proxy/issues).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
