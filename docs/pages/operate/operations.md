# Operations

## Operations

- **Reload:** edit the config, list files or addon files, or send
  `SIGHUP`. A bad config is rejected and the running one stays
  ([reload](/operate/operations#reload)). Listener, TLS and capture settings need a
  restart.
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

Listener, TLS and capture settings need a restart.
