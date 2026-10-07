# Node mode

In node mode roxy has no config file. It enrols with a control plane, pulls
its policy and secrets from there as a lease, and ships its flow log back.
The control plane is any server that implements the
[node protocol](/reference/node-protocol).

```sh
roxy run --control-plane https://cp.example:8443 \
         --enrol-token-file /run/secrets/roxy-enrol-token \
         --state-dir /var/lib/roxy/node \
         --control-plane-ca /etc/roxy/cp-ca.pem
```

`--control-plane` and `--config` are mutually exclusive.

## Flags

| flag | meaning |
|---|---|
| `--control-plane URL` | The control plane's `https://` URL. Paths are under `/roxy/v1/`. |
| `--enrol-token-file PATH` | The enrolment token. Read once, on a start with no node certificate in the state dir. A later start does not need it. |
| `--state-dir DIR` | Where the node keeps its certificate and key. Created with mode `0700`. |
| `--control-plane-ca PATH` | PEM bundle to verify the control plane with. Default: the system roots. |
| `--bootstrap-bind ADDR` | Where the proxy listens before the first lease. Default `0.0.0.0:3128`. |
| `--bootstrap-ca-server ADDR` | Where `ca_server` listens before the first lease. Default `0.0.0.0:3130`. |
| `--interception-ca-cert PATH`, `--interception-ca-key PATH` | An interception CA pair to import into the state dir on a start where it holds none. See [the interception CA](/guides/node-mode#the-interception-ca). |
| `--replace-interception-ca` | Replace a stored interception CA that differs from the one given. |

The token is as sensitive as the lease secrets it unlocks: whoever holds a
token the control plane still accepts can enrol a node and receive the
fleet's secrets. Whether it is single-use, how long it lives and whether a
fleet shares one are the control plane's decisions; roxy does not delete
the token file after enrolment.

## The state dir

| file | contents |
|---|---|
| `node.crt` | The node certificate chain, PEM. Its URI SAN `urn:roxy:node:<id>` is the node id. |
| `node.key` | The node's PKCS#8 key, mode `0600`. Generated on the node; never sent anywhere. |
| `flow.seq` | The flow `seq` counter, reserved in blocks of 1024. A restart continues after the last block. |
| `ca/` | The interception CA, as `tls.ca_dir` holds it in file mode. |

Nothing else is written. The rendered config and the secret values stay in
memory, so a copy of the state dir gives an attacker a revocable node
identity and nothing else.

### The interception CA

The state dir is authoritative for the interception CA. The lease's `tls`
section cannot point the node at another one: `tls.ca_dir` is always
`<state-dir>/ca`, and `tls.ca_cert`/`tls.ca_key` in the rendered config are
ignored with a warning.

- No CA anywhere on first start: one is generated into `<state-dir>/ca`,
  as `tls.ca_dir` does in file mode.
- `--interception-ca-cert` and `--interception-ca-key` on a start where the
  state dir holds no CA: the pair is imported (key `0600`) and used. A later
  start without the flags uses the stored pair; it is never regenerated.
- The flags name a pair different from the stored one: roxy refuses to
  start and prints both fingerprints. Workloads already trust the stored
  CA, so replacing it is an explicit action: delete `roxy-ca.pem` and
  `roxy-ca.key` from `<state-dir>/ca`, or pass `--replace-interception-ca`.
- A stored pair that does not parse is fatal, as in file mode.

Workloads fetch the CA from `ca_server` as usual
([CA distribution](/guides/ca-certificates#ca-distribution)).

## Startup

1. The listeners open at once. Until the first lease is applied the node
   runs an empty policy: every request is denied with `terminal_rule:
   _default`, `/healthz` answers `200` and `/readyz` answers `503
   no_policy`. Before the first lease those listeners are the bootstrap
   ones: the proxy on `--bootstrap-bind` and `ca_server` on
   `--bootstrap-ca-server` (by default `0.0.0.0:3128` and `0.0.0.0:3130`).
2. With no `node.crt` in the state dir the node reads the token, generates
   a key pair and a CSR, and `POST`s `/roxy/v1/enrol`. The certificate and
   key are written to the state dir. A `401` here means the token was not
   accepted. The node retries with backoff for two minutes, in case the
   token has not reached every replica of the control plane, then exits
   non-zero with one error line, so an orchestrator sees a crash loop
   rather than a node that denies everything for ever. Any other failure is
   retried with backoff for as long as it lasts. With a `node.crt` present
   the token file is not read and nothing is enrolled.
3. The node `POST`s `/roxy/v1/lease` with its certificate and applies the
   lease. The first lease's `listeners`, `ca_server`, `tls`, connection
   limits and log destinations replace the bootstrap ones: the bootstrap
   listeners close and the lease's open. Later leases that change one of
   those settings are applied with the running value kept and a warning
   naming the field, exactly as a file reload does; a restart picks them up.

Every request reports `roxy_version` and `protocol_version`; a lease
fetch also reports the `lease_id` the node holds, its uptime, its policy
state (`none`, `loaded` or `expired`) and the spooled flow bytes.

## The lease

Every poll answers with the whole lease, and every lease is applied in
full or not at all. The rendered config goes through the same validation
as `roxy check`; a config it would reject, or a declared secret with no
value, is logged (`lease could not be applied`) and the running policy
stays. The node then reports the old `lease_id` on its next fetch, which
is how the control plane learns the lease did not take.

- `valid_for_seconds` becomes the policy's `valid_until`, counted on the
  node's own clock from just before the fetch was sent. Past it, with no
  newer lease, every request is denied with `terminal_rule: _expired`
  ([lease](/guides/operations#lease)).
- `refresh_after_seconds` is when the node polls next, never later than
  halfway through `valid_for_seconds`.
- The node compares `config` and `secrets` with the lease it runs. A
  changed `config` compiles and swaps the policy atomically, as a reload
  does. Changed `secrets` with the same `config` swap the secret map. A
  lease with neither changed only moves `valid_until`.
- A changed `state_epoch` clears every rule `set_state` entry and every
  metric window before the lease is applied. An unchanged epoch keeps them
  across a config change. The first lease sets the epoch without clearing.
- `secrets` supplies the values for the config's `secrets:` entries that
  declare `lease: true`. Entries with `env` or `file` sources are resolved
  on the node as in file mode. A name with no value from either refuses the
  lease.

### Responses

| response | what the node does |
|---|---|
| `200` | Applies what differs, moves `valid_until`, and polls again after `refresh_after_seconds`. |
| `410` | Revoked. Installs an empty, already expired policy at once (every request denied with `_expired`, `/readyz` `503 policy_expired`), ships the flow events still spooled, stops polling. `/healthz` stays `200`. Definite: a restart with the same state dir ends the same way. |
| `401` | The certificate is not recognised. Logged once per outcome change; the lease runs down. The node never re-enrols unasked: to re-enrol, empty the state dir and start with a new token. |
| `426` | The control plane will not serve this `protocol_version` or `roxy_version`. Logged once per outcome change, with the `missing` list; the lease runs down. |
| `5xx`, timeout, connection or TLS error | Retried with backoff (1 s doubling to 60 s, with jitter); the lease runs down. Unreachability is not itself a reason to deny; expiry is. |

A lease that runs down denies everything until a lease arrives; the next
`200` recovers the node without a restart.

### The node certificate

The enrolment response states `renew_after_seconds`. When it passes the
node `POST`s `/roxy/v1/renew` under its current certificate with a new CSR
for the same key, stores the new certificate and uses it from then on. The
old certificate stays in use until a renewal succeeds.

| response | what the node does |
|---|---|
| `410` | Revoked. The same as a `410` on the lease: empty policy at once, spooled flows shipped, polling stops. |
| `401`, `426`, other `4xx` | Logged once; renewal stops. The certificate serves until its `not_after`, then lease fetches fail and the lease runs down. |
| `5xx`, timeout, connection or TLS error | Retried with backoff (1 s doubling to 60 s, with jitter). |

A node whose certificate expires before a renewal succeeds denies
everything, which is the intended failure for a node the control plane will
not renew. To re-enrol it, empty the state dir and start with a new token.

## Flow shipping

Every flow-log event goes to the local `log.flow` destination of the
rendered config as usual, and into an in-memory spool tagged with a
per-node `seq`. The lease's `flow` settings say how the spool is shipped:

| setting | meaning |
|---|---|
| `ship` | `false` turns shipping off; nothing is spooled. |
| `batch_max_bytes` | A batch is sent when the spooled lines reach this size (measured on the JSON before compression). A `413` for a batch within it is treated as a server error and retried. |
| `flush_interval_seconds` | A partial batch is sent this long after its first event. |
| `spool_high_water_bytes` | Spooled but unacknowledged bytes at which `on_high_water` applies. |
| `on_high_water` | `hold`: traffic waits, through roxy's flow-log backpressure, until the control plane acknowledges enough to bring the spool under the high water. `spool`: traffic flows and the oldest spooled events are dropped, with one `flow spool over its high water` log line per episode. |

Delivery is at least once: a batch stays spooled until the control plane
acknowledges it, and a batch re-sent after a failure is deduplicated
server-side on `(node_id, seq)`. A `507` (quota exhausted) stops shipping
until a lease with a new `lease_id` arrives; meanwhile `on_high_water`
applies to what accumulates. A batch the control plane rejects (`400`) is
logged apart from an outage and retried all the same: it is unshipped
audit, so it stays spooled and under `hold` traffic stalls until the
control plane accepts it. Shutdown lets in-flight exchanges finish, then
ships what is spooled, for up to ten seconds.

Before the first lease the spool runs with `spool` mode, a 1 MiB batch and
an 8 MiB high water, so a control plane that is slow to answer cannot hold
traffic.

## Signals and health

`SIGHUP` reopens the local log destinations; there is no file to reload.
`SIGTERM` or ctrl-c shuts down as in file mode. `/healthz` and `/readyz` on
the lease's `ca_server` behave as described in
[operations](/guides/operations): ready means an unexpired lease is in
force.
