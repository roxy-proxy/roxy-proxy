# Flow log and capture

## Flow log

One JSON object per line, to stdout or `log.flow.path`. Every exchange
produces a `request` event:

```json
{"ts":"2026-10-03T10:12:00.123Z","event":"request","flow":"01J9…","conn":"01J9…",
 "listener":"proxy","client":{"ip":"10.0.0.7","port":51234},
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
| `req.body_bytes`, `res.body_bytes` | body bytes roxy forwarded in each direction |
| `req.body_sha256`, `res.body_sha256` | lower-case hex SHA-256 of those bytes, only for the sides a head rule's `digest` action selected ([actions](/reference/rule-language#actions)); present once the body completed, absent if the exchange ended first (a cut body, a watching stop, a client that left). An empty body has the empty-string digest; a relayed WebSocket has counts but no digests. Hashing is opt-in because a digest nobody compares against is wasted work: software SHA-256 costs about one core per 400 MB/s on CPUs without SHA-NI |
| `timing.upstream_connect_ms` | how long opening the upstream connection took (DNS, TCP and TLS); `null` when the request reused a pooled connection, or none was opened |
| `timing.upstream_ttfb_ms` | from the forwarding decision to the upstream's response head |
| `decision` | `allow`, `deny`, or `answered` when an addon layer answered itself |
| `terminal_rule` | what decided: a rule id, or `_default`, `_fail_closed`, `_address_policy`, `_expired`, `_sign`, `_websocket` or `layer:<name>` |
| `stage` | `head`, or where a watching rule stopped the exchange: `request_body`, `response_head`, `response_body`, `websocket` |
| `addons` | the layers that ran, outermost first; one skipped by its `when` or `sample` is not listed ([choosing exchanges](/reference/addon-configuration#choosing-exchanges)) |
| `rules`, `decision`, `terminal_rule` with addons | describe the request that left the stack; `req` is what the client sent and `res.status` what it got, which a layer above the rules may have replaced ([addons](/reference/addon-configuration#in-the-proxy)) |
| `reason` | a stable code when the exchange failed closed or failed, by `terminal_rule`: |

| `terminal_rule` | `reason` |
|---|---|
| `_fail_closed` | `metric_unavailable`, `metric_key_unavailable`, `metric_table_full`, `address_list_unavailable`, `secret_missing`, `secret_invalid`, `body_too_large_to_inspect`, `body_unavailable`, `buffer_budget_exhausted`, `unsupported_content_encoding`, `body_decode_failed`, `missing_value`, `wrong_type`, `effect_invalid`, `unsupported_effect`, `state_unavailable`, `capture_unavailable`, `sign_conflict`, `watch_missing`, `watch_stopped` |
| `_address_policy` | `address_policy` |
| `_expired` | `policy_expired` ([lease](/guides/operations#lease)) |
| `_sign` | `sign_body_too_large`, `sign_header_invalid` ([signing AWS requests](/reference/secrets#signing-aws-requests)) |
| `_websocket` | `ws_bad_handshake` ([WebSockets](/reference/websockets)) |
| `layer:<name>` | `layer_error` |
| an upstream failure | the `upstream_error` reason ([upstream](/reference/upstream#errors)) |
| roxy could not finish the exchange (its connection ended, or the server stopped, mid-flight) | `aborted` |
| an addon layer dropped the exchange after the rules had forwarded it | `upstream_aborted` |
| the client went away | `client_gone` |
| an HTTP/2 client stopped taking the response | `client_stalled` |

### Events

| event | when |
|---|---|
| `request` | every exchange |
| `response_error` | the response could not be written after the request was allowed; `reason` is `client_gone` (the client stopped reading or left), `client_stalled` (an HTTP/2 client kept its flow-control window shut for `limits.body_idle_timeout`), `response_body_timeout` (the upstream paused mid-body past `limits.response_body_idle_timeout`), `response_write_failed` (for example a body limit mid-stream) or `continue_write_failed` (roxy's `100 Continue` could not be written) |
| `parse_error` | the client sent something roxy refused to parse; `reason` is a stable code |
| `upstream_error`, `upstream_denied` | [upstream](/reference/upstream#errors) failures and address-floor hits; `upstream_denied.reason` is `private_range:<class>`, `deny_cidrs` or `list:<name>` ([address floor](/reference/address-lists#address-floor)) |
| `policy_input_unavailable`, `metric_table_full` | a flow failed closed for want of an input |
| `policy_expired` | the policy's `valid_until` passed; once per loaded policy, with `valid_until` ([lease](/guides/operations#lease)) |
| `upgrade_stripped` | an upgrade was not allowed, so the request went upstream as plain HTTP ([WebSockets](/reference/websockets)) |
| `ws_open`, `ws_close` | a relayed WebSocket, with byte counts; `ws_close` has `close_code` and `close_reason` when roxy ended it |
| `ws_message` | a WebSocket message a rule denied, or one sampled by `log.flow.ws_message_every` ([WebSockets](/reference/websockets#message-rules)) |
| `log` | a rule's `log` action |
| `layer_error`, `layer_record`, `endpoint_call` | [addons](/design/addon-model) |
| `observer_lagged` | an observe-mode addon's copy of a stream was cut; `reason` is `observer_behind` (it fell `max_observer_lag_bytes` behind), `buffer_budget_exhausted` (the [buffer budget](/reference/limits#limits) could not cover the copy) or `no_instance` (no instance of the layer came free within its `first_byte_timeout`) |
| `connect` | a CONNECT, when `log.flow.connection_events` is on or it was refused |
| `connection_refused` | a connection cap was hit ([limits](/reference/limits#connections)) |
| `config_loaded`, `config_reloaded`, `config_reload_failed` | startup and [reload](/guides/operations#reload) |

### Redaction

Every injected secret value is scrubbed from any logged string. Values of
`authorization`, `proxy-authorization`, `cookie`, `set-cookie` and
`x-api-key` are never logged; `log.redact_headers` adds more. Query values
are redacted.

### Writing

The write path never drops a record while roxy runs
([audit backpressure](/design/threat-model#audit-backpressure)).

- **One writer per destination.** Emitters serialise each event on their
  own thread and enqueue the bytes; one writer thread owns the file and
  writes everything queued in one batch. The writer waits a moment for
  more records before each write, so a burst is one write and a record is
  written within a couple of milliseconds of being emitted.
- **Backpressure.** Emitting never blocks or drops. Once unwritten bytes
  pass `log.flow.high_water` (8 MiB) the log reports not ready and every
  traffic producer waits for it: each new client connection, exchange and
  HTTP/2 stream, each forwarded body chunk and each WebSocket read. A
  failing destination (disk full, I/O error) holds traffic the same way, and
  is reported.
- **Rotation** happens at a batch boundary, so a record never spans two
  files: the file is renamed to `<path>.<UTC timestamp>-<seq>` (names sort
  in rotation order), a new one is opened, files beyond `max_files` are
  deleted, and rotated files are optionally gzipped in the background. Only
  files of that name shape count towards `max_files` or are deleted. A
  failed rotation is a failed write: traffic is held and it is retried.
  `SIGHUP` reopens the file, for external rotation.
- **Shutdown.** Everything queued is written before exit. A destination
  still failing after 10 seconds of retries is given up on: the unwritten
  batch (at most `high_water` bytes) is discarded and an error logged. This
  is the one point at which a record can be dropped.
- **Durability.** Each batch is flushed to the operating system, and
  `max_file_bytes` checked, at the batch boundary. roxy does not `fsync`: a
  roxy crash loses nothing queued; a kernel crash or power loss can lose
  batches the OS had not yet written to disk.

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

roxy's own operational logs go to stderr through `tracing`: `--log-format
json|pretty` and `--log-level` (or `RUST_LOG`).

## Capture

roxy tees the heads and bodies of exchanges, exactly as forwarded, to
`<capture_dir>/capture.rxc`: those a head rule selects with `capture:
request | response | both`, or every forwarded exchange with
`log.capture.all: true`. Capture is decided at the request head and covers
the exchange from its first byte; the taps sit after the watching rules
allowed a chunk. WebSocket relays are captured both ways at the relay next
to the upstream, not as an addon layer changes them for the client.

Capture is written like the flow log (one writer, batching, rotation,
backpressure). Injected secret values are scrubbed from captured heads;
nothing else is: the header-name redaction above is flow-log only, and
bodies are captured **unredacted**.

```yaml
capture_dir: /var/lib/roxy/capture   # absent = capture disabled; restart to change
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

Every `log.capture` setting needs `capture_dir`; `roxy check` reports
settings given without it.

### Capture format

A sequence of records, each one JSON header line, then `len` payload bytes,
then `\n`:

```text
{"flow":"01J9…","dir":"request","kind":"head","seq":0,"len":187}
{"method":"POST","url":"https://api.example.com/v1/x","headers":[["content-type","application/json"]]}
{"flow":"01J9…","dir":"request","kind":"data","seq":1,"len":5}
hello
{"flow":"01J9…","dir":"request","kind":"end","seq":2,"len":0,"bytes":5}
```

| field | meaning |
|---|---|
| `flow` | joins records to the flow log |
| `dir` | `request` (client to upstream) or `response` |
| `kind` | `head` (the canonical head as JSON, as forwarded), `data` (forwarded bytes), `truncated` (`limits.max_capture_body_bytes` reached for this direction; nothing more is captured; carries `cap`), or `end` (carries the total forwarded `bytes`, and `aborted: true` if the direction did not complete) |
| `seq` | counts records per flow and direction |
