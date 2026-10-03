# roxy

roxy is a TLS-inspecting HTTP firewall for containing the network traffic of
(potentially adversarial) AI agents. It runs as an explicit `HTTP_PROXY`,
terminates TLS with leaf certificates minted by its own CA, parses every
request into a strict canonical model, and re-serialises it in one
unambiguous wire form, so smuggling and header-injection tricks never reach
the upstream. It fails closed: anything it cannot parse, verify or classify
is dropped, the default is to deny anything no rule allows, and a policy
input it cannot read (a metric, a list, a body) denies rather than allows.

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
- Firewall-style rules: allows plus denies that always win, a configurable
  default, and rules that keep watching an exchange as its body and
  response stream (byte limits, response checks, byte budgets).
- Header, path, query and redirect actions, and secret injection.
- Stateful metrics and a state store. Neither ever evicts: a full table
  denies. Their sizes are set in `limits` (`max_metric_keys`,
  `max_metric_bytes`, `max_state_entries`).
- Address denylists, and a private-range floor on the IP actually dialled.
- WebSocket relay, proxy authentication, and a CA download endpoint.
- Hot reload, `roxy check`, and the `roxy rule test` dry run.
- Traffic capture: heads and bodies as forwarded, per rule or for all
  traffic, written with the same never-drop backpressure as the flow log.
- A hardened container image (`ghcr.io/roxy-proxy/roxy`, below).

Deferred, with designs in DESIGN.md:

- WASM and service addons (§11). `roxy run` refuses a config that defines
  addons.
- Transparent mode (§4.2).
- WebSocket message rules (§8.2). Byte budgets already apply to WebSockets.
- A Prometheus endpoint.

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
address lists, upload limits and the addon config shape. It passes `check`,
but `run` refuses it because addons are not in this build.

## Container image

`ghcr.io/roxy-proxy/roxy` is built from the `Dockerfile` for `linux/amd64`
and `linux/arm64`. Tags: `edge` (every push to `main`), and `vX.Y.Z`,
`X.Y` and `latest` for releases.

- A static musl binary on `gcr.io/distroless/static-debian12:nonroot`,
  about 15 MB unpacked. There is no shell and no package manager.
- Runs as UID/GID `65532` and works with a read-only root filesystem.
- Upstream TLS trusts the embedded Mozilla roots (`webpki-roots`) plus
  `tls.upstream.extra_roots`, so the image ships no CA bundle.
- Published images carry an SBOM and SLSA provenance and are signed with
  cosign (keyless). Every build is scanned with Trivy.

Run it with the hardening flags:

```sh
docker run -d --name roxy \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  -v roxy-ca:/var/lib/roxy/ca \
  -v ./roxy.yaml:/etc/roxy/roxy.yaml:ro \
  -p 3128:3128 -p 3130:3130 \
  ghcr.io/roxy-proxy/roxy:edge
```

| path | what |
|---|---|
| `/etc/roxy/roxy.yaml` | config; the default is [`examples/docker/roxy.yaml`](examples/docker/roxy.yaml). Mount your own read-only. |
| `/var/lib/roxy/ca` | volume: the CA key and certificate, generated on first start. **Keep it**: a new CA means every client must re-trust it. Owned by 65532, mode 0700. |
| `/var/log/roxy` | volume, for a config that sets `log.flow.path` (for example `/var/log/roxy/flow.jsonl`). The default config logs flows to stdout (`docker logs`). |
| `capture_dir` | traffic capture (§10.2) is off by default. If you set `capture_dir`, mount a volume there (for example `-v roxy-capture:/var/lib/roxy/capture`); the root filesystem is read-only. |

Ports: `3128` is the proxy listener and `3130` is `ca_server`
(`/roxy-ca.pem`, `/healthz`). Keep `3130` off networks the agent should not
reach if you do not want it to fetch the CA itself.

The image's `HEALTHCHECK` runs `roxy health`, a small built-in HTTP probe
(there is no curl), against `http://127.0.0.1:3130/healthz`. A config that
moves or removes `ca_server` needs `--health-cmd` or `--no-healthcheck`.
Other subcommands run the same way:

```sh
docker run --rm -v ./roxy.yaml:/etc/roxy/roxy.yaml:ro ghcr.io/roxy-proxy/roxy:edge \
  check --config /etc/roxy/roxy.yaml
docker run --rm -v roxy-ca:/var/lib/roxy/ca ghcr.io/roxy-proxy/roxy:edge \
  ca export --config /etc/roxy/roxy.yaml > roxy-ca.pem
```

Verify a published image's signature:

```sh
cosign verify ghcr.io/roxy-proxy/roxy:edge \
  --certificate-identity-regexp '^https://github.com/roxy-proxy/roxy-proxy/\.github/workflows/image\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

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

A policy is a list of allows plus denies that restrict them. Precedence, from
highest:

1. **Any matching `deny`.** A deny always wins, wherever it sits in the list.
2. **Any matching `allow`.**
3. **The default**: `default: deny` (the default) or `default: allow`.

Rule order does not change the decision. It only orders effects, such as
header changes, and makes tags set by one rule visible to the rules below it.

**When a rule runs** follows from what it reads. Most rules read the request
head (host, method, path, headers, metrics) and are decided before anything
is forwarded. A rule that reads something that only arrives later, such as
`body.bytes` as an upload streams, `response.status`, or the response body,
keeps watching the exchange and stops it the moment it matches. Watching
rules can only deny, since the request is already on its way. `roxy check`
says which kind each rule is.

```yaml
default: deny

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
  - id: github-reads
    when: host under "github.com" and method in [GET, HEAD]
    then: allow

  - id: openai
    when: host == "api.openai.com" and path starts_with "/v1/" and method == POST
    then:
      - set_header: { authorization: "Bearer ${secret:openai}" }   # agent never sees the key
      - allow

  - id: no-writes-burst                    # restricts the allows above
    when: metric.github_writes >= 30
    then: { deny: { status: 429 } }

  - id: upload-cap                         # watches the body as it streams
    when: host == "api.openai.com" and body.bytes > 10mb
    then: { deny: { status: 413 } }
```

**Missing values are `null`.** An unsent header, `client.user` without proxy
auth, and `body.size` for a chunked body are all `null`. `==`, `!=`, `in` and
`not in` treat `null` as an ordinary value. Any other operator on `null`
denies the request and names the field. Guard with `x != null and ...` when a
value may be absent:

```yaml
when: body.size != null and body.size > 10mb
```

Try a rule without sending traffic:

```sh
roxy rule test --config roxy.yaml GET https://api.github.com/repos/a/b
roxy rule test --config roxy.yaml --metric github_writes=30 POST https://api.github.com/repos/a/b/issues
```

The dry run exits 0 on allow and 3 on deny. It prints the matching rules, the
effects and the decision. Metrics you do not pass default to 0, and
`--metric id=unavailable` exercises the fail-closed path.

The full language is in DESIGN.md §6. That covers operators (`== in under like
matches starts_with`...), every field and when it is known, units (`10mb`,
`1m`), CIDRs, `@list` membership, and every action.

## Flow log

One JSON object per line, to stdout or `log.flow.path`. Each request has a
`request` event:

```json
{"event":"request","flow":"01M4…","client":{"ip":"10.0.0.7"},"tls":{"sni":"example.com","alpn":"http/1.1"},
 "req":{"method":"GET","host":"example.com","path":"/","body_bytes":0},"res":{"status":200,"body_bytes":577},
 "decision":"allow","rules":["example"],"terminal_rule":"example","stage":"head","timing":{"total_ms":50}}
```

Denies carry `terminal_rule` (`_default`, `_fail_closed`,
`_address_policy`, or a rule id) and a `reason` when they fail closed.
`stage` says where the decision was made: `head`, or where a watching rule
stopped the exchange (`request_body`, `response_head`, `response_body`,
`websocket`).
Secrets and sensitive headers are redacted. Other events include
`parse_error`, `upstream_error`, `upstream_denied`,
`policy_input_unavailable`, `config_reloaded`, `config_reload_failed`,
`ws_open` and `ws_close`.

The flow log is an audit trail, so roxy never drops a record. One writer
thread per destination batches writes. If the log falls behind (more than
`high_water` unwritten) or the disk fails, roxy holds traffic back until it
catches up rather than losing records. Files can rotate by size:

```yaml
log:
  flow:
    path: /var/log/roxy/flow.jsonl
    high_water: 8mb          # unwritten log at which traffic is held (default 8mb)
    max_file_bytes: 100mb    # rotate to flow.jsonl.<UTC timestamp>-<seq>
    max_files: 10            # keep the newest 10 rotated files
    compress: true           # gzip rotated files
```

`SIGHUP` also reopens the file, for external `logrotate`.

### Capturing traffic

roxy can tee the heads and bodies of exchanges to `<capture_dir>/capture.rxc`
exactly as forwarded. It captures exchanges a rule selects with
`capture: request | response | both`, or all traffic with
`log.capture.all: true`. Capture uses the same writer as the flow log: it
rotates, and it holds traffic back rather than drop data. Bodies are
captured unredacted. The format is in DESIGN.md §10.2.

```yaml
capture_dir: /var/lib/roxy/capture
log:
  capture:
    all: true
    max_file_bytes: 1gb
    max_files: 20
    compress: true
limits:
  max_capture_body_bytes: 16mb    # per direction per exchange; beyond it, `truncated`
```

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
| `crates/roxy-log` | buffered single-writer log destinations: batching, backpressure, rotation |
| `crates/roxy-tls` | CA, leaf minting, rustls configs, ClientHello sniffing |
| `crates/roxy-http` | canonical HTTP model, strict h1 codec, h2 mapping, URL normalisation |
| `crates/roxy-rules` | rule DSL, policy evaluation, metric and state stores |

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
