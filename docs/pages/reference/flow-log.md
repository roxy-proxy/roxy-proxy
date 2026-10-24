# Flow log and capture

## Flow log

The flow log is one JSON object per line, written to stdout or to
`log.flow.path`. Every exchange produces a `request` event:

```json
{"ts":"2026-10-03T10:12:00.123Z","event":"request","flow":"01J9…","conn":"01J9…",
 "listener":"proxy","client":{"ip":"10.0.0.7","peer":{"ip":"10.0.0.7","port":51234}},
 "tls":{"sni":"api.github.com","alpn":"h2","version":"1.3"},
 "req":{"method":"POST","host":"api.github.com","port":443,"path":"/repos/x/y/issues",
        "query":null,"headers_bytes":812,"body_bytes":1032,
        "body_sha256":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "content_type":"application/json"},
 "res":{"status":201,"headers_bytes":1420,"body_bytes":5120,
        "body_sha256":"60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752"},
 "decision":"allow","rules":["github-writes"],"tags":["billing"],
 "mutations":["set_header:authorization"],"addons":["redact"],
 "timing":{"total_ms":412,"upstream_connect_ms":38,"upstream_ttfb_ms":350},
 "terminal_rule":"github-writes","stage":"head"}
```

| field | meaning |
|---|---|
| `client.ip` | the client, as the rules see it |
| `client.peer` | the TCP peer the request came from. It differs from `client.ip` behind a load balancer ([HTTP](/reference/http#clients-behind-a-load-balancer)) |
| `req`, `res` | the request as the client sent it, and the response it got |
| `body_bytes` | body bytes forwarded in each direction |
| `body_sha256` | a SHA-256 of the body, only when a rule's `digest` action asked for it ([actions](/reference/rule-language#actions)) |
| `timing.upstream_connect_ms` | time to open the upstream connection; `null` if an existing one was reused |
| `timing.upstream_ttfb_ms` | time from forwarding the request to the response head |
| `decision` | `allow`, `deny`, or `answered` when an addon answered the request itself |
| `rules` | the rules that matched |
| `terminal_rule` | what decided: a rule id, or one of `_default`, `_fail_closed`, `_address_policy`, `_expired`, `_quarantined`, `_sign`, `_websocket` or `layer:<name>` |
| `stage` | `head`, or where a rule stopped the exchange: `request_body`, `response_head`, `response_body` or `websocket` |
| `addons` | the addons that ran, in order |
| `reason` | why the exchange was refused or failed, when it was |

Common reasons, by `terminal_rule`:

| `terminal_rule` | `reason` |
|---|---|
| `_fail_closed` | `metric_unavailable`, `metric_table_full`, `address_list_unavailable`, `secret_missing`, `secret_invalid`, `body_too_large_to_inspect`, `body_decode_failed`, `unsupported_content_encoding`, `buffer_budget_exhausted`, `missing_value`, `state_unavailable`, `sign_conflict`, `effect_invalid` |
| `_address_policy` | `address_policy` |
| `_expired` | `policy_expired` ([lease](/guides/operations#lease)) |
| `_quarantined` | `quarantined` ([quarantine](/guides/operations#quarantine)) |
| `_sign` | `sign_body_too_large`, `sign_header_invalid` ([signing AWS requests](/reference/secrets#signing-aws-requests)) |
| `_websocket` | `ws_bad_handshake` ([WebSockets](/reference/websockets)) |
| `layer:<name>` | `layer_error` |
| none, the upstream failed | the `upstream_error` reason ([upstream](/reference/upstream#errors)) |
| none, the exchange did not finish | `client_gone` (the client left), `client_stalled` (it stopped reading), `upstream_body_timeout` ([timeouts](/reference/limits#timeouts)), `aborted` (roxy stopped) |
| none, an addon gave up part of the exchange | `layer_aborted`: it ended the request it was passing on or the response it was giving early, or stopped reading the response from upstream |

### Events

| event | when |
|---|---|
| `request` | every exchange |
| `response_error` | the response could not be delivered after the request was allowed, for example because the client left or the upstream stalled |
| `parse_error` | the client sent a malformed request; `reason` says how |
| `upstream_error` | the upstream could not be reached ([upstream](/reference/upstream#errors)) |
| `upstream_denied` | the address floor refused an upstream address ([address floor](/reference/address-lists#address-floor)) |
| `policy_input_unavailable`, `metric_table_full` | an exchange was denied because a policy input was unavailable |
| `policy_expired` | the policy's `valid_until` passed ([lease](/guides/operations#lease)) |
| `quarantined` | roxy was quarantined, or started quarantined (`restored: true`), with the incident `id`, `since` and `cause` ([quarantine](/guides/operations#quarantine)) |
| `quarantine_released` | the control plane lifted the quarantine ([node mode](/guides/node-mode#the-lease)) |
| `upgrade_stripped` | a WebSocket upgrade was not allowed, so the request went upstream as plain HTTP |
| `ws_open`, `ws_close` | a WebSocket opened or closed, with byte counts |
| `ws_message` | a WebSocket message a rule denied, or one sampled by `log.flow.ws_message_every` ([WebSockets](/reference/websockets#message-rules)) |
| `log` | a rule's `log` action |
| `layer_error` | an addon failed; `kind` says how ([failure](/reference/addon-configuration#failure)) |
| `layer_record` | an addon's `flow.record` ([host services](/reference/host-services)) |
| `endpoint_call` | an addon called an endpoint |
| `observer_lagged` | an observing addon fell too far behind and stopped getting a copy |
| `connect` | a CONNECT, when `log.flow.connection_events` is on |
| `connection_refused` | a connection cap was reached ([limits](/reference/limits#connections)) |
| `config_loaded`, `config_reloaded`, `config_reload_failed` | startup and [reload](/guides/operations#reload) |

### Redaction

Secret values that roxy injects are masked in everything it logs: each
byte becomes `*`, so the text keeps its length. The values of
`authorization`, `proxy-authorization`, `cookie`, `set-cookie` and
`x-api-key` are never logged, and `log.redact_headers` adds more. These
values, and query values, are logged as `******`.

### Writing

The flow log never drops a record while roxy runs
([audit backpressure](/design/threat-model#audit-backpressure)).

- One thread writes each log file, in batches, so a record is written
  within a few milliseconds.
- When more than `log.flow.high_water` (8 MiB) is waiting to be written,
  or the disk fails, roxy holds traffic until the log catches up.
- With `max_file_bytes`, the file is rotated to
  `<path>.<UTC timestamp>-<seq>`, optionally gzipped, and files beyond
  `max_files` are deleted. `SIGHUP` reopens the file, for external
  rotation.
- On shutdown roxy writes everything queued, retrying a failing
  destination for up to 10 seconds. Records still unwritten after that are
  lost.
- roxy does not `fsync`, so a power loss can lose recent records.

```yaml
log:
  redact_headers: []
  flow:
    path: /var/log/roxy/flow.jsonl  # absent = stdout
    connection_events: false
    ws_message_every: 0             # also log every Nth WebSocket message; 0 = denied only
    high_water: 8mb                 # at least 64kb
    max_file_bytes: 100mb           # absent = never rotate
    max_files: 10                   # absent = keep all
    compress: true
```

Rotation needs `path`, since stdout cannot be rotated.

## Capture

Capture records whole requests and responses, as forwarded, to
`<capture_dir>/capture.jsonl`. It records the exchanges a rule selects
with `capture: request | response | both`, or every exchange with
`log.capture.all: true`. It is written like the flow log, with the same
batching, rotation and backpressure.

Secret values are masked in captured headers and URLs. **Bodies are
captured unredacted**, except a response that
[`http.redact_response_secrets.bodies`](/reference/secrets#redacting-responses)
masked. A body roxy decompressed for addons or for masking is captured
compressed again, as sent.

```yaml
capture_dir: /var/lib/roxy/capture   # absent = capture off; restart to change
log:
  capture:
    all: false
    high_water: 64mb
    max_file_bytes: 1gb
    max_files: 20
    compress: true
limits:
  max_capture_body_bytes: 16mb       # per direction per exchange
```

### Capture format

One JSON object per line:

```text
{"flow":"01J9…","dir":"request","kind":"head","seq":0,"head":{"headers":[["content-type","application/json"]],"method":"POST","url":"https://api.example.com/v1/x"}}
{"flow":"01J9…","dir":"request","kind":"data","seq":1,"data":"aGVsbG8="}
{"flow":"01J9…","dir":"request","kind":"end","seq":2,"bytes":5}
```

| field | meaning |
|---|---|
| `flow` | the exchange's id in the flow log |
| `dir` | `request` or `response` |
| `kind` | `head`, `data` (body bytes, base64), `truncated` (`max_capture_body_bytes` reached, or `reason: buffer_budget_exhausted` when the budget could not cover compressing a body again for the capture; nothing more is recorded) or `end` (with the total `bytes`, and `aborted: true` if the body did not complete) |
| `seq` | the record's position for this flow and direction |

A body is its `data` records joined in `seq` order. Each `data` record
holds at most 48 KiB of body, so lines stay under 64 KiB plus a little
JSON, apart from head lines, which can be up to `limits.max_header_bytes`.
