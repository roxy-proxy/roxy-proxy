# Flow log and capture

## Flow log

One JSON object per line, to stdout or `log.flow.path`. Every exchange
produces a `request` event:

```json
{"ts":"2026-10-03T10:12:00.123Z","event":"request","flow":"01J9…","conn":"01J9…",
 "listener":"proxy","client":{"ip":"10.0.0.7","port":51234,"user":null},
 "tls":{"sni":"api.github.com","alpn":"h2","version":"1.3"},
 "req":{"method":"POST","host":"api.github.com","port":443,"path":"/repos/x/y/issues",
        "query":null,"headers_bytes":812,"body_bytes":1032,"content_type":"application/json"},
 "res":{"status":201,"headers_bytes":1420,"body_bytes":5120},
 "decision":"allow","rules":["github-writes"],"tags":["billing"],
 "mutations":["set_header:authorization"],"addons":["redact"],
 "timing":{"total_ms":412,"upstream_connect_ms":38,"upstream_ttfb_ms":350},
 "terminal_rule":"github-writes","stage":"head"}
```

- `terminal_rule` is what decided: a rule id, or `_default`,
  `_fail_closed`, `_address_policy` or `layer:<name>` for built-in
  decisions.
- `reason` is a stable code when the exchange failed closed or failed
  (`body_too_large_to_inspect`, `body_decode_failed`, `missing_value`,
  `upstream_timeout`, ...). An exchange roxy could not finish has
  `aborted` (its connection ended, or the server stopped, while it was in
  flight); an exchange cut short because the client went away has
  `client_gone`.
- `stage` says where the decision was made: `head` for the forwarding
  decision, or where a watching rule stopped the exchange: `request_body`,
  `response_head`, `response_body`, `websocket`.
- `addons` lists the addon layers that ran on the exchange, outermost
  first. A layer skipped by its `when` or `sample` is not in it
  ([choosing exchanges](/addons/configuration#choosing-exchanges)).
- `decision` is `allow` or `deny`, or `answered` when an addon layer
  answered itself ([addons](/addons/overview#in-the-proxy)).
- When an addon changed the request, `rules`, `decision` and
  `terminal_rule` describe the request that left, and `req` still describes
  what the client sent ([addons](/addons/overview#in-the-proxy)).

### Events

| event | when |
|---|---|
| `request` | every exchange |
| `response_error` | the response could not be written after the request was allowed; `reason` is `client_gone` (the client stopped reading or went away) or `response_write_failed` (for example, a body limit mid-stream) |
| `parse_error` | the client sent something roxy refused to parse; `reason` is a stable code |
| `upstream_error`, `upstream_denied` | [upstream](/reference/upstream#errors) failures and address-floor hits |
| `policy_input_unavailable`, `metric_table_full` | a flow failed closed for want of an input |
| `upgrade_stripped` | an upgrade was not allowed, so the request went upstream as plain HTTP ([WebSockets](/policies/websockets)) |
| `ws_open`, `ws_close` | a relayed WebSocket, with byte counts; `ws_close` has `close_code` and `close_reason` when roxy ended it |
| `ws_message` | a WebSocket message a rule denied, or one sampled by `log.flow.ws_message_every` ([WebSockets](/policies/websockets#message-rules)) |
| `log` | a rule's `log` action |
| `layer_error`, `layer_record`, `endpoint_call`, `observer_lagged` | [addons](/addons/overview) |
| `connect` | a CONNECT, when `log.flow.connection_events` is on or it was refused |
| `dns_query` | a query the [DNS listener](/deploy/dns-steering) answered, when `log.flow.dns_events` is on: `transport`, `client`, `name`, `qtype`, `rcode` and the `answers` |
| `connection_refused` | a connection cap was hit ([limits](/reference/limits#connections)) |
| `config_loaded`, `config_reloaded`, `config_reload_failed` | startup and [reload](/operate/operations#reload) |

### Redaction

Every injected secret value is scrubbed from any logged string. Values of
`authorization`, `proxy-authorization`, `cookie`, `set-cookie` and
`x-api-key` are never logged; `log.redact_headers` adds more. Query strings
are logged with their values redacted.

### Writing

The flow log is an audit trail, so the write path never drops a record and
is built to scale with cores and traffic (the `roxy-log` crate):

- **One writer per destination.** Emitters serialise each event on their own
  thread and enqueue the bytes; one writer thread owns the file.
- **Batching.** The writer drains everything queued and issues one write, so
  under load each write carries everything since the last, and at low load
  each line goes out as it arrives.
- **Backpressure, never loss.** Emitting never blocks and never drops.
  Once unwritten bytes pass `log.flow.high_water` (8 MiB) the log reports
  not ready, and every traffic producer waits for it: each new client
  connection, the start of each exchange and each HTTP/2 stream, each
  forwarded body chunk, each WebSocket read, and, with `dns_events`, each
  DNS answer. roxy stops
  reading from clients and upstreams until the log catches up, slowing
  traffic rather than losing records. A destination that fails (disk full,
  I/O error) holds traffic the same way, and is reported.
- **Rotation** happens in the writer thread at a batch boundary, so a
  record never spans two files. The file is renamed to
  `<path>.<UTC timestamp>-<seq>` (names sort in rotation order), a new one
  is opened, files beyond `max_files` are deleted, and rotated files are
  optionally gzipped in the background. A failed rotation is a failed
  write: traffic is held and it is retried. `SIGHUP` reopens the file, for
  external rotation.

```yaml
log:
  redact_headers: []
  flow:
    path: /var/log/roxy/flow.jsonl  # absent = stdout
    connection_events: false
    dns_events: false               # log every DNS listener answer
    ws_message_every: 0             # also log every Nth WebSocket message; 0 = denied only
    high_water: 8mb                 # at least 64kb
    max_file_bytes: 100mb           # absent = never rotate
    max_files: 10                   # absent = keep all
    compress: true
```

roxy's own operational logs go to stderr through `tracing`: `--log-format
json|pretty` and `--log-level` (or `RUST_LOG`).

## Capture

roxy can tee the heads and bodies of exchanges, exactly as forwarded, to
`<capture_dir>/capture.rxc`. It captures the exchanges a head rule selects
with `capture: request | response | both`, or every forwarded exchange with
`log.capture.all: true`. Capture is decided at the request head and covers
the exchange from its first byte. The taps sit after the watching rules
allowed a chunk and before it is handed on, so what is captured is what was
relayed. WebSocket relays are captured in both directions.

Capture is written like the flow log: one writer, batching, rotation, and
backpressure (a slow disk slows traffic; capture is never dropped).
Injected secrets are redacted in captured heads; bodies are captured
**unredacted**.

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

Every `log.capture` setting needs `capture_dir`: without it nothing is
captured, and `roxy check` reports the settings rather than leave them
looking active.

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

- `flow` joins records to the flow log.
- `dir` is `request` (client to upstream) or `response`.
- `kind` is `head` (the canonical head as JSON, as forwarded), `data`
  (forwarded bytes), `truncated` (`limits.max_capture_body_bytes` was
  reached for this direction and nothing more is captured; carries `cap`),
  or `end` (carries the total forwarded `bytes`, and `aborted: true` if the
  direction did not complete).
- `seq` counts records per flow and direction.
