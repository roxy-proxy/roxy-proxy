# Operations

roxy's own logs go to stderr (`--log-format json|pretty`, `--log-level`
or `RUST_LOG`). The flow log goes to stdout or a file
([flow log](/reference/flow-log)). `SIGHUP` reloads the config and reopens
log files. `SIGTERM` or Ctrl-C stops accepting connections, lets
exchanges in flight finish for up to 10 seconds, and flushes the logs
before exiting.

## Health

The `ca_server` listener answers two checks:

| path | `200` when | otherwise |
|---|---|---|
| `/healthz` | the process is up | no answer |
| `/readyz` | a policy is loaded, it has not expired, and roxy is not quarantined | `503` with the reason: `no_policy`, `policy_expired` or `quarantined` |

`/healthz` also sends `x-roxy-policy: valid`, `expired` or `quarantined`.
Use `/healthz` for liveness and `/readyz` for readiness. An empty policy
counts as ready: it denies everything, on purpose. `no_policy` is only
seen in node mode, before the first lease arrives.

`roxy health` checks `http://127.0.0.1:3130/healthz` for images without
curl. `--ready` checks `/readyz` instead and `--url` sets the address. It
exits 0 on a `200` and 1 otherwise.

`ca_server` has its own connection cap. Keep its port reachable only from
the health checks and the workloads that fetch the CA, since a client that
fills the cap blocks the checks.

## Reload

`roxy check --config <file>` validates a config without starting roxy: it
parses it, compiles the rules and addons, and loads the address lists and
a provided CA. It does not read secrets from the environment.

roxy watches the config file, the address-list files and the addon
`.wasm` files, and reloads when one changes or on `SIGHUP`. A reload that
succeeds is applied at once: exchanges in flight finish under the old
policy, and the next request uses the new one. A reload that fails
changes nothing, and logs a `config_reload_failed` event with the
diagnostics.

Rate-limit counters survive a reload when their metric is unchanged
([metrics](/reference/rate-limits#metrics)).

### Restart-only settings

Some settings take effect only when roxy starts: `listeners`, `ca_server`, `tls.ca_dir`, `tls.ca_cert`, `tls.ca_key`, `tls.leaf_cache_size`, `tls.upstream`, `upstream.dns`, `limits.max_connections`, `limits.max_connections_per_client`, `limits.max_state_entries`, `limits.max_capture_body_bytes`, `log.flow`, `log.capture` and `capture_dir`. A reload keeps their running values, applies everything else, and warns about each one that changed.

Connection-level settings, such as the HTTP parsing limits and timeouts,
are fixed when a connection is accepted. A reload changes them for new
connections only.

## Lease

A top-level `valid_until: <RFC 3339 time>` makes the policy expire. From
that moment every request is denied with `terminal_rule: _expired`, and
open WebSockets are closed. `/healthz` stays up and `/readyz` answers
`503 policy_expired`.

To recover, load a config with a later `valid_until`, or none. There is
no fallback policy. In [node mode](/guides/node-mode) the control plane
sets `valid_until` from its lease.

## Quarantine

A quarantine makes roxy refuse every request, whatever the policy says,
until someone lifts it from outside the process. It is for a workload
that has shown itself hostile. It survives reloads and restarts.

Three things can trip it:

- a rule's `quarantine` action
  ([actions](/reference/rule-language#actions));
- an addon calling `flow.quarantine`
  ([host services](/reference/host-services#quarantine-quarantine));
- a listener's `quarantine_on.parse_errors` threshold: that many
  malformed requests within the window
  ([listener modes](/reference/http#listener-modes)). Timeouts and
  clients that disconnect do not count. Use it on a sandbox's listener,
  never a gateway's.

While quarantined, every request is refused with `403` and
`terminal_rule: _quarantined`. Open connections are closed after one
second. The trip is logged as a `quarantined` event with an incident id
([flow log](/reference/flow-log#events)). `/readyz` answers
`503 quarantined`, and the CA is still served.

A config that can quarantine needs `roxy run --state-dir DIR`. The trip
writes `DIR/quarantine`, and roxy starts quarantined while that file
exists. To lift it, stop roxy, remove `DIR/quarantine` and start it again.
In [node mode](/guides/node-mode#the-lease) the control plane lifts it
instead.
