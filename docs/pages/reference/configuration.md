# Configuration

One YAML file, `version: 1`. Parsing is strict: an unknown key anywhere is
an error, not a silently ignored setting. Relative paths (`ca_dir`, `ca_cert`, `ca_key`, secret
files, list files, addon paths, log and capture paths) resolve against the
process's working directory. `roxy check` refuses a zero value for the
`limits` that would otherwise refuse every request, hold no connections or
fail every metric and state rule closed: `max_headers`, `max_header_bytes`,
`max_url_bytes`, `max_connections`, `max_connections_per_client`,
`h2_max_concurrent_streams`, `h2_max_header_list_bytes`, `max_metric_keys`,
`max_metric_bytes`, `max_state_entries`, `max_observer_lag_bytes` and
`max_address_list_bytes`. The body, message and capture caps and the
timeouts accept zero, and mean it. Each section is described on the page
the table names.

| key | page |
|---|---|
| `listeners`, `http` | [HTTP](/reference/http) |
| `ca_server`, `tls` | [managing the CA](/operate/ca-certificates), [TLS](/reference/tls) |
| `upstream` | [upstream](/reference/upstream), [address floor](/policies/address-lists#address-floor) |
| `dns` | [DNS steering](/deploy/dns-steering) |
| `address_lists` | [address lists](/policies/address-lists#address-lists) |
| `limits` | [resource limits](/reference/limits) |
| `default`, `rules` | [how policies work](/policies/overview), [rule language](/reference/rule-language) |
| `secrets` | [secrets](/policies/secrets) |
| `metrics` | [rate limits](/policies/rate-limits) |
| `addons` | [addons](/addons/overview) |
| `log`, `capture_dir` | [flow log](/operate/flow-log) |

```yaml
version: 1
default: deny                  # deny (the default) | allow: when no rule matches

secrets:
  openai: { env: OPENAI_API_KEY }
  gh:     { file: /run/secrets/github_token }   # one trailing newline stripped

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

  - id: upload-cap               # reads body.bytes, so it watches the upload
    when: host == "api.openai.com" and body.bytes > 10mb
    then: { deny: { status: 413 } }
```
