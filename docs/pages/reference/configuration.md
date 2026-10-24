# Configuration

One YAML file, starting `version: 1`. Each section is described on the
page the table names.

| key | page |
|---|---|
| `listeners`, `http` | [HTTP](/reference/http) |
| `ca_server`, `tls` | [managing the CA](/guides/ca-certificates), [TLS](/reference/tls) |
| `upstream` | [upstream](/reference/upstream), [address floor](/reference/address-lists#address-floor) |
| `address_lists` | [address lists](/reference/address-lists#address-lists) |
| `limits` | [resource limits](/reference/limits) |
| `rules` | [policy evaluation](/design/policy-evaluation), [rule language](/reference/rule-language) |
| `secrets` | [secrets](/reference/secrets) |
| `metrics` | [rate limits](/reference/rate-limits) |
| `addons` | [addon configuration](/reference/addon-configuration) |
| `log`, `capture_dir` | [flow log](/reference/flow-log) |
| `valid_until` | [lease](/guides/operations#lease) |

- Parsing is strict. An unknown key, or a key repeated in one map, is an
  error.
- Only `true` and `false` are booleans; `yes`, `no`, `on` and `off` are
  refused. Anchors and aliases work; merge keys (`<<`) and custom tags do
  not. A file holds one YAML document.
- Relative paths resolve against the working directory.
- `roxy check` refuses zero for a limit where zero would refuse every
  request. Body, message and capture caps and timeouts accept zero and
  mean it ([resource limits](/reference/limits#limits)).

```yaml
version: 1

listeners:
  - name: proxy
    mode: http_proxy      # the default; `http` serves origin-form requests directly
    bind: 0.0.0.0:3128

secrets:
  openai: { env: OPENAI_API_KEY }
  gh:     { file: /run/secrets/github_token }   # one trailing newline stripped
  lease:  { lease: true }                       # supplied by the control-plane lease; standalone `run` refuses it

metrics:
  - id: github_writes
    count: requests
    where: host under "api.github.com" and method in [POST, PUT, PATCH, DELETE]
    key: [client.ip]
    window: 1m

rules:
  - id: github-reads
    when: host under "github.com" and method in [GET, HEAD]
    then: allow

  - id: openai
    when: host == "api.openai.com" and path starts_with "/v1/" and method == POST
    then:
      - set_header: { authorization: "Bearer ${secret:openai}" }
      - allow

  - id: no-writes-burst
    when: metric.github_writes >= 30
    then: { deny: { status: 429 } }

  - id: upload-cap               # reads body.bytes: re-checked in flight
    when: host == "api.openai.com" and body.bytes > 10mb
    then: { deny: { status: 413 } }
```
