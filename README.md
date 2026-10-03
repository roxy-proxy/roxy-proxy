# roxy

roxy is a TLS-inspecting HTTP firewall for containing the network traffic of
(potentially adversarial) AI agents. It runs as an explicit `HTTP_PROXY`,
terminates TLS with leaf certificates minted by its own CA, parses every
request into a strict canonical model, and re-serialises it in one
unambiguous wire form, so smuggling and header-injection tricks never reach
the upstream. It fails closed: anything it cannot parse, verify or classify
is dropped, an empty rule set denies everything, and a policy input it
cannot read (a metric, a list, a body) denies rather than allows.

Policy is a YAML file with a small, statically typed rule language, stateful
metrics for rate and budget limits, address denylists, and secret injection
so the agent only ever holds placeholders. Every decision lands in a
structured JSONL flow log with the rule that made it. See
[DESIGN.md](DESIGN.md) for the design, threat model and roadmap.

## Status

Usable in explicit proxy mode. Built and tested:

- HTTP/1.1 and HTTPS via `CONNECT`, with TLS interception and strict
  parsing (a 168-case smuggling corpus). HTTP/2 from the client inside
  the tunnel, negotiated by ALPN; any client falls back to HTTP/1.1.
- Rules in four phases: connect, request, response and WebSocket.
- Header, path, query and redirect actions, and secret injection.
- Stateful metrics and a state store. Neither ever evicts: a full table
  denies.
- Address denylists, and a private-range floor on the IP actually dialled.
- WebSocket relay, proxy authentication, and a CA download endpoint.
- Hot reload, `roxy check`, and the `roxy rule test` dry run.

Deferred, with designs in DESIGN.md:

- WASM and service addons (§11). `roxy run` refuses a config that defines
  addons.
- Transparent mode (§4.2).
- WebSocket message inspection (§8.2).
- Body capture and a Prometheus endpoint.

## Quickstart

```sh
cargo build --release
B=./target/release/roxy

$B check --config examples/minimal.yaml      # validate; exits 1 with file:path diagnostics
$B run   --config examples/minimal.yaml      # starts the proxy; edits to the file hot-reload
```

`examples/minimal.yaml` allows `GET`/`HEAD` to `example.com` and denies
everything else. Set `tls.ca_dir` to a writable directory first. The CA is
generated there on first start and reused after that; roxy never silently
regenerates it.

`examples/roxy.yaml` is the full example. It shows metrics, secrets,
address lists, a size limit and the addon config shape. It passes `check`,
but `run` refuses it because addons are not in this build.

## Pointing an agent at roxy

The agent needs the proxy address and must trust roxy's CA. Get the CA
certificate in one of three ways:

```sh
roxy ca export --config roxy.yaml > roxy-ca.pem                     # at image build time
curl -s http://<ca_server.bind>/roxy-ca.pem > roxy-ca.pem           # from the CA server
curl -s -x http://<proxy> http://roxy.internal/roxy-ca.pem > roxy-ca.pem   # through the proxy
```

Then, in the agent's environment:

```sh
export HTTP_PROXY=http://<proxy> HTTPS_PROXY=http://<proxy>
export SSL_CERT_FILE=/path/roxy-ca.pem         # OpenSSL-based tools, Python ssl, Go
export REQUESTS_CA_BUNDLE=/path/roxy-ca.pem    # Python requests
export NODE_EXTRA_CA_CERTS=/path/roxy-ca.pem   # Node
export CURL_CA_BUNDLE=/path/roxy-ca.pem        # curl
```

Adding the certificate to the system trust store also works. For
containment, block every other egress path from the sandbox at the host
firewall, including direct TCP, UDP and DNS. roxy resolves DNS itself.

## Writing rules

Rules run top to bottom. The first terminal action (`allow`, `deny`) wins,
and a request no rule allows is denied.

```yaml
metrics:
  - id: github_writes
    count: requests
    where: host under "api.github.com" and method in [POST, PUT, PATCH, DELETE]
    key: [client.ip]
    window: 1m

address_lists:
  - name: blocked
    file: /etc/roxy/lists/blocked.txt     # one CIDR per line, `#` comments

upstream:
  deny_lists: [blocked]                   # hard floor on every connect

rules:
  - id: no-writes-burst
    when: metric.github_writes >= 30
    then: { deny: { status: 429 } }

  - id: openai
    when: host == "api.openai.com" and path starts_with "/v1/" and method == POST
    then:
      - set_header: { authorization: "Bearer ${secret:openai}" }   # agent never sees the key
      - allow

  - id: github-reads
    when: host under "github.com" and method in [GET, HEAD]
    then: allow
```

Try a rule without sending traffic:

```sh
roxy rule test --config roxy.yaml GET https://api.github.com/repos/a/b
roxy rule test --config roxy.yaml --metric github_writes=30 POST https://api.github.com/repos/a/b/issues
```

The dry run exits 0 on allow and 3 on deny, and prints the matched rules,
effects and decision. Metrics you do not pass default to 0. Passing
`--metric id=unavailable` exercises the fail-closed path.

The full language is in DESIGN.md §6. It covers operators (`== in under
like matches starts_with`...), fields by phase, units (`10mb`, `1m`), CIDRs,
`@list` membership, and every action.

## Flow log

One JSON object per line, to stdout or `log.flow.path`. Each request has a
`request` event:

```json
{"event":"request","flow":"01M4…","client":{"ip":"10.0.0.7"},"tls":{"sni":"example.com","alpn":"http/1.1"},
 "req":{"method":"GET","host":"example.com","path":"/","body_bytes":0},"res":{"status":200,"body_bytes":577},
 "decision":"allow","rules":["example"],"terminal_rule":"example","timing":{"total_ms":50}}
```

Denies carry `terminal_rule` (`_default`, `_fail_closed`,
`_address_policy`, or a rule id) and a `reason` when they fail closed.
Secrets and sensitive headers are redacted. Other events include
`parse_error`, `upstream_error`, `upstream_denied`,
`policy_input_unavailable`, `config_reloaded`, `config_reload_failed`,
`ws_open` and `ws_close`.

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace            # unit, corpus, property and end-to-end tests
```

| crate | responsibility |
|---|---|
| `crates/roxy` | binary: CLI, config, secrets, address-list loading, reload, store wiring |
| `crates/roxy-proxy` | listeners, pipeline, upstream connector, address floor, flow log |
| `crates/roxy-tls` | CA, leaf minting, rustls configs, ClientHello sniffing |
| `crates/roxy-http` | canonical HTTP model, strict h1 codec, h2 mapping, URL normalisation |
| `crates/roxy-rules` | rule DSL, policy evaluation, metric and state stores |

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
