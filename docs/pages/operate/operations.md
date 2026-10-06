# Operations

## Operations

- **Reload:** edit the config, list files or addon files, or send
  `SIGHUP`. A bad config is rejected and the running one stays
  ([reload](/operate/operations#reload)). Some settings need a restart;
  [reload](/operate/operations#reload) lists them.
- **Lease:** a config with `valid_until` denies everything once that
  instant passes, until a reload replaces it
  ([lease](/operate/operations#lease)).
- **Logs:** the flow log goes to stdout or `log.flow.path`; roxy's own logs
  go to stderr (`--log-format json|pretty`, `--log-level` or `RUST_LOG`).
  `SIGHUP` also reopens log files.
- **Shutdown:** `SIGTERM` drains for up to 10 seconds
  ([limits](/reference/limits#connections)).
- **Health:** `ca_server` serves `/healthz` (alive) and `/readyz` (a
  policy is in force); `roxy health [--ready]` probes them
  ([health](/operate/operations#health)).

## Health

The `ca_server` listener answers two probes, both plain HTTP `GET`:

| path | `200` when | otherwise |
|---|---|---|
| `/healthz` | the process is up and accepting connections | no answer |
| `/readyz` | a policy has been applied and its lease has not run out | `503` with a one-word reason: `no_policy` (nothing applied yet) or `policy_expired` ([lease](/operate/operations#lease)) |

Liveness is for restarting a stuck process. Readiness is for routing: a
roxy that has no policy in force should not receive traffic, and a
restart would not change that. Use `/readyz` for a compose `depends_on`
wait or a Kubernetes readiness probe, and `/healthz` for a liveness probe
or a container `HEALTHCHECK`. Readiness reads the policy the proxy is
evaluating against, so a reload with a later lease makes it ready without
a restart.

An empty policy is ready. It is a deny-all that someone applied, and its
refusals are served and logged like any other; a roxy that is quarantined
that way stays in rotation so they are audited rather than becoming
connection errors. Running from a config file, a policy is always applied
at startup, so `no_policy` is only seen by a node waiting for its first
lease from a control plane.

`roxy health` is the probe for images without a shell or curl: it `GET`s
`http://127.0.0.1:3130/healthz` (`--ready`: `/readyz`; `--url` names
another address) and exits 0 on a `200`, 1 on anything else, with the
reason on stderr.

## Reload

`roxy check <config>` runs the part of startup that opens no socket and
writes no file: parse, validate, compile the rules and the WASM addons, load
the address lists, load a provided CA (`tls.ca_cert`, `tls.ca_key`), read
`tls.upstream.extra_roots` and build the resolver. Diagnostics carry the
config path, rule id and position. `check` leaves to startup: resolving
`secrets` from the environment, generating a CA in `tls.ca_dir`, opening
`log.flow.path` and `capture_dir`, and binding the listeners. Reload shares
the same parse, validate and compile path. roxy
watches the config file, the address-list files and the addon `.wasm`
files; a change, or `SIGHUP`, triggers a reload. Each file is followed
through symlinks, so a file swapped underneath its path (a Kubernetes
`ConfigMap` mount) counts as changed too. On success the new policy is
swapped in atomically: exchanges in flight finish under the policy they
started with, and the next request on any connection uses the new one. On
failure the old policy stays, a `config_reload_failed` event carries the
diagnostics, and nothing is partially applied: not the policy, not the
metric store, and not the compiled addons the next reload reuses. A
shutdown signal during a reload is acted on at once: the reload is
abandoned and the running policy drains.

Metric series whose definition is unchanged survive a reload. When the
new config keeps every running metric (it only adds or leaves them), the
rebuilt store goes in before the policy swap, so no flow on either side of
the swap meets a metric its store does not know. When a metric is removed
or reshaped, the store follows the swap, and only an exchange that was
still finishing under the old policy can find its metric gone (and is then
failed closed).

Some settings take effect only when roxy starts: `listeners`, `ca_server`,
`dns`, `tls` (except `tls.require_sni_match`), `limits.max_connections`,
`limits.max_connections_per_client`, `limits.max_state_entries`,
`limits.max_capture_body_bytes`, `log.flow`, `log.capture` and
`capture_dir`. A reload keeps their running values, applies everything
else, and logs a warning naming each one that changed. The new config is
validated with those running values, so nothing is half-applied; when that
validation fails, the diagnostics name the restart-only settings the file
changed, since the failure may be theirs.

A connection takes `tls.require_sni_match`, `http.enable_h2`,
`http.allow_plain_in_connect` and the `limits` and `http` parsing settings
when it is accepted and keeps them; a reload changes them for new
connections only.

## Lease

A top-level `valid_until: <RFC 3339>` makes the loaded policy a lease.
Until that instant the policy applies as written. From it, every request
is denied with `terminal_rule: _expired` and reason `policy_expired`,
before the rules and the addons run, and an open WebSocket relay stops at
its next message. The check is a wall-clock comparison on each exchange:
`valid_until` is an absolute instant, so the host's clock is what it is
measured against. The first exchange that finds the policy expired logs
one `policy_expired` event; later ones are ordinary `_expired` denies.

An expired policy is a policy, not a fault. The listeners stay up,
`/healthz` keeps answering `200` and says `x-roxy-policy: expired` (it
says `valid` otherwise), and `roxy health` prints `ok (policy expired)`;
`/readyz` answers `503 policy_expired` ([health](/operate/operations#health)).
A document already past its `valid_until` loads and denies rather than
failing to start, so a stale lease on disk fails closed. `roxy check`
prints `valid until:` and warns when the instant has passed. In
[node mode](/deploy/node-mode) the control plane's lease sets it.

The way back is a reload: a config whose `valid_until` is later, or
absent, is swapped in like any other and traffic resumes under it. There
is no fallback policy: a policy that must not expire has no `valid_until`.
