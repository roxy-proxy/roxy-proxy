# Operations

roxy's own logs go to stderr (`--log-format json|pretty`, `--log-level` or
`RUST_LOG`); the flow log goes to stdout or `log.flow.path`
([flow log](/reference/flow-log)). `SIGHUP` reloads the config and reopens
log files. `SIGTERM` or ctrl-c stops accepting, drains exchanges in flight
for up to 10 seconds, and flushes the flow log and capture before exiting.

## Health

The `ca_server` listener answers two probes, both plain HTTP `GET`:

| path | `200` when | otherwise |
|---|---|---|
| `/healthz` | the process is up and accepting connections | no answer |
| `/readyz` | a policy has been applied and its lease has not run out | `503` with a one-word reason: `no_policy` (nothing applied yet) or `policy_expired` ([lease](/guides/operations#lease)) |

Use `/readyz` for a compose `depends_on` wait or a Kubernetes readiness
probe, and `/healthz` for a liveness probe or a container `HEALTHCHECK`.
Readiness reads the policy the proxy is evaluating against, so a reload
with a later lease makes it ready without a restart.

An empty policy is ready: it is a deny-all that someone applied, so a
quarantined roxy stays in rotation and its refusals are audited. From a
config file a policy is always applied at startup, so `no_policy` is only
seen by a node waiting for its first lease.

`roxy health` is the probe for images without a shell or curl: it `GET`s
`http://127.0.0.1:3130/healthz` (`--ready`: `/readyz`; `--url` names
another address) and exits 0 on a `200`, 1 on anything else, with the
reason on stderr.

## Reload

`roxy check --config <file>` runs the part of startup that opens no socket
and writes no file: parse, validate, compile the rules and the WASM
addons, load the address lists, load a provided CA (`tls.ca_cert`,
`tls.ca_key`), read `tls.upstream.extra_roots` and build the resolver. It
loads the CA through the same function startup does, so the warnings
startup logs about it (a key readable by others, a certificate close to
expiry) are printed by `check` as `warning:` lines. Diagnostics carry the
config path, rule id and position. It leaves to
startup resolving `secrets` from the environment, generating a CA in
`tls.ca_dir`, opening `log.flow.path` and `capture_dir`, and binding the
listeners.

Reload shares that path. roxy watches the config file, the address-list
files and the addon `.wasm` files, following symlinks, so a file swapped
underneath its path (a Kubernetes `ConfigMap` mount) counts as changed; a
change, or `SIGHUP`, triggers a reload. On success the new policy is
swapped in atomically: exchanges in flight finish under the policy they
started with, and the next request on any connection uses the new one. On
failure the old policy stays, a `config_reload_failed` event carries the
diagnostics, and nothing is partially applied: not the policy, not the
metric store, and not the compiled addons the next reload reuses. A
shutdown signal during a reload abandons it and drains the running policy.

Metric series whose definition is unchanged survive a reload. When the new
config keeps every running metric, the rebuilt store goes in before the
policy swap, so no flow on either side meets a metric its store does not
know. When a metric is removed or reshaped, the store follows the swap, and
only an exchange still finishing under the old policy can find its metric
gone (and is then failed closed).

### Restart-only settings

Some settings take effect only when roxy starts: `listeners`, `ca_server`,
`tls.ca_dir`, `tls.ca_cert`, `tls.ca_key`, `tls.leaf_cache_size`,
`tls.upstream`, `upstream.dns`, `limits.max_connections`,
`limits.max_connections_per_client`, `limits.max_state_entries`,
`limits.max_capture_body_bytes`, `log.flow`, `log.capture` and
`capture_dir`. A reload keeps their running values, applies everything
else, and warns naming each one that changed. The new config is validated
with the running values; when that fails, the diagnostics name the
restart-only settings the file changed.

The resolver is one of them: its cache serves every policy, so a reload
that touches only rules or lists keeps every cached answer. The upstream
connection pools are the snapshot's and start empty on each reload.

A connection takes `tls.require_sni_match`, `http.enable_h2`,
`http.allow_plain_in_connect` and the `limits` and `http` parsing settings
when it is accepted and keeps them; a reload changes them for new
connections only ([limits](/reference/limits#limits)).

## Lease

A top-level `valid_until: <RFC 3339>` makes the loaded policy a lease.
Until that instant the policy applies as written. From it, every request
is denied with `terminal_rule: _expired` and reason `policy_expired`,
before the rules and the addons run, and an open WebSocket relay stops at
its next message. The check is a wall-clock comparison on each exchange
against the host's clock, using the loaded policy's instant whichever
policy the exchange began under: a reload that moves it later keeps open
relays going, and one that moves it earlier stops them at their next
message. The first exchange that finds the policy expired logs one
`policy_expired` event; later ones are ordinary `_expired` denies.

An expired policy is a policy, not a fault. The listeners stay up,
`/healthz` keeps answering `200` with `x-roxy-policy: expired` (`valid`
otherwise), `roxy health` prints `ok (policy expired)`, and `/readyz`
answers `503 policy_expired`. A document already past its `valid_until`
loads and denies rather than failing to start. `roxy check` prints `valid
until:` and warns when the instant has passed. In
[node mode](/guides/node-mode) the control plane's lease sets it.

The way back is a reload: a config whose `valid_until` is later, or
absent, is swapped in like any other. There is no fallback policy: a policy
that must not expire has no `valid_until`.
