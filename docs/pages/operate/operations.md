# Operations

## Operations

- **Reload:** edit the config, list files or addon files, or send
  `SIGHUP`. A bad config is rejected and the running one stays
  ([reload](/operate/operations#reload)). Some settings need a restart;
  [reload](/operate/operations#reload) lists them.
- **Logs:** the flow log goes to stdout or `log.flow.path`; roxy's own logs
  go to stderr (`--log-format json|pretty`, `--log-level` or `RUST_LOG`).
  `SIGHUP` also reopens log files.
- **Shutdown:** `SIGTERM` drains for up to 10 seconds
  ([limits](/reference/limits#connections)).

## Reload

`roxy check <config>` and reload share one path: parse, validate, compile,
returning diagnostics with the config path, rule id and position. roxy
watches the config file, the address-list files and the addon `.wasm`
files; a change, or `SIGHUP`, triggers a reload. On success the new policy
is swapped in atomically: exchanges in flight finish under the policy they
started with, and the next request on any connection uses the new one. On
failure the old policy stays, a `config_reload_failed` event carries the
diagnostics, and nothing is partially applied.

Some settings take effect only when roxy starts: `listeners` (including
`auth`), `ca_server`, `dns`, `tls`, `http.enable_h2`,
`limits.max_connections`, `limits.max_connections_per_client`,
`limits.max_state_entries`, `limits.max_capture_body_bytes`, `log.flow`,
`log.capture` and `capture_dir`. A reload keeps their running values,
applies everything else, and logs a warning naming each one that changed.
The new config is validated with those running values, so nothing is
half-applied.
