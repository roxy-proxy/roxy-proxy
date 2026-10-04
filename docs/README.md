# roxy documentation

Reference for how roxy behaves today. The [project README](../README.md) is
the overview and quickstart; outstanding work is tracked in
[issues](https://github.com/roxy-proxy/roxy-proxy/issues).

| page | covers |
|---|---|
| [Principles](principles.md) | The threat model and the design principles behind everything else: fail closed, canonical re-serialisation, deny always wins, never evict, audit backpressure. |
| [Architecture](architecture.md) | How an exchange flows through roxy, the crates, a glossary. |
| [HTTP](http.md) | The explicit proxy, CONNECT, proxy auth, HTTP/2, the canonical model, rejection rules, URL normalisation, upstream serialisation, responses, deny responses. |
| [Rules](rules.md) | The config file, how rules are evaluated, the expression language and fields, actions, secrets, metrics and state, reload, the dry run. |
| [Upstream](upstream.md) | DNS, the address floor, address lists, upstream TLS, upstream errors. |
| [WebSockets](websockets.md) | Upgrades, the relay and message rules. |
| [TLS and the CA](tls.md) | CA generation, leaf certificates, client-facing TLS, CA distribution, ClientHello sniffing. |
| [Flow log and capture](flow-log.md) | Flow log events, redaction, the never-drop writer, rotation, traffic capture and its format. |
| [Addons](addons.md) | The layer stack, modes, configuration, host services, the WIT package, sandboxing, writing addons. |
| [Resource limits](limits.md) | Every limit, its default, and how each failure resolves closed. |
| [Deployment](deployment.md) | Containing a workload, the container image, running without Docker, operations. |
| [Development](development.md) | Checks, tests, fuzzing, releasing. |
