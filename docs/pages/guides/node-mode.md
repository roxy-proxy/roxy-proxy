# Node mode

In node mode roxy has no config file: it enrols with a control plane,
leases its policy and secrets from it, and ships its flow log back. The
control plane is any server that implements the
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
| `--interception-ca-cert PATH`, `--interception-ca-key PATH` | An interception CA pair to import ([the interception CA](/guides/node-mode#the-interception-ca)). |
| `--replace-interception-ca` | Replace a stored interception CA that differs from the one given. |

A token the control plane still accepts enrols a node and unlocks the
fleet's secrets. Its lifetime and reuse are the control plane's decisions;
roxy does not delete the token file after enrolment.

## The state dir

| file | contents |
|---|---|
| `node.crt` | The node certificate chain, PEM. Its URI SAN `urn:roxy:node:<id>` is the node id. |
| `node.key` | The node's PKCS#8 key, mode `0600`. Generated on the node; never sent anywhere. |
| `flow.seq` | The flow `seq` counter, reserved in blocks of 1024. A restart continues after the last block. |
| `ca/` | The interception CA, as `tls.ca_dir` holds it in file mode. |

Nothing else is written: the rendered config and the secret values stay in
memory, so a copy of the state dir is a revocable node identity and nothing
else.

### The interception CA

The state dir is authoritative for the interception CA: `tls.ca_dir` is
always `<state-dir>/ca`, and `tls.ca_cert`/`tls.ca_key` in the rendered
config are ignored with a warning.

- No CA anywhere on first start: one is generated into `<state-dir>/ca`,
  as `tls.ca_dir` does in file mode.
- `--interception-ca-cert` and `--interception-ca-key` on a start where the
  state dir holds no CA: the pair is imported (key `0600`) and used. A later
  start without the flags uses the stored pair; it is never regenerated.
- The flags name a pair different from the stored one: roxy refuses to
  start and prints both fingerprints, since workloads already trust the
  stored CA. To replace it, delete `roxy-ca.pem` and `roxy-ca.key` from
  `<state-dir>/ca`, or pass `--replace-interception-ca`.
- A stored pair that does not parse is fatal, as in file mode.

Workloads fetch the CA from `ca_server` as usual
([CA distribution](/guides/ca-certificates#ca-distribution)).

## Startup

1. The listeners open at once, on `--bootstrap-bind` and
   `--bootstrap-ca-server`, with an empty policy: every request is denied
   with `terminal_rule: _default`, `/healthz` answers `200` and `/readyz`
   answers `503 no_policy`.
2. With no `node.crt` in the state dir the node reads the token, generates
   a key pair and a CSR, and enrols; the certificate and key go to the state
   dir. A `401` is retried with backoff for two minutes, then the node exits
   non-zero, so an orchestrator sees a crash loop rather than a node that
   denies everything for ever. Any other failure is retried for as long as
   it lasts. With a `node.crt` present the token file is not read.
3. The node fetches its lease and applies it. The first lease's
   `listeners`, `ca_server`, `tls`, connection limits and log destinations
   replace the bootstrap ones. Later leases that change one of those
   settings keep the running value and warn, as a file reload does
   ([restart-only settings](/guides/operations#restart-only-settings)); a
   restart picks them up.

## The lease

Every poll answers with the whole lease, applied in full or not at all.
The rendered config goes through the same validation as `roxy check`; a
config it would reject, or a declared secret with no value, is logged
(`lease could not be applied`) and the running policy stays. The node then
reports the old `lease_id` on its next fetch, which is how the control
plane learns the lease did not take.

The fields are in the [lease body](/reference/node-protocol#lease-body).
`valid_for_seconds` becomes the policy's `valid_until`, on the node's own
clock from just before the fetch was sent ([lease](/guides/operations#lease));
the node polls again after `refresh_after_seconds`, never later than halfway
through. A changed `config` swaps the policy atomically as a reload does,
changed `secrets` alone swap the secret map, and a changed `state_epoch`
clears every rule `set_state` entry and metric window first. `secrets`
supplies the config's `secrets:` entries that declare `lease: true`; `env`
and `file` sources are resolved on the node as in file mode, and a name
with no value from either refuses the lease.

What the node does with each response code is in the
[errors table](/reference/node-protocol#errors). A `410` (revoked) installs
an empty, already expired policy at once, ships what is spooled and stops
polling; a restart with the same state dir ends the same way. A `401`,
`426` or unreachable control plane lets the lease run down: the node denies
everything from `valid_until` until the next `200`, which recovers it
without a restart. It never re-enrols unasked; to re-enrol, empty the state
dir and start with a new token.

## Flow shipping

Every flow-log event goes to the local `log.flow` destination as usual, and
into an in-memory spool tagged with a per-node `seq` that the lease's `flow`
settings say how to ship ([flow upload](/reference/node-protocol#flow-upload)).
At `spool_high_water_bytes` of unacknowledged events, `on_high_water: hold`
holds traffic through roxy's flow-log backpressure until the control plane
acknowledges enough; `spool` drops the oldest and logs once per episode. A
batch stays spooled until acknowledged, so a `400` or a `507` (quota
exhausted) leaves unshipped audit in the spool and `on_high_water` applies
to what accumulates. Shutdown lets in-flight exchanges finish, then ships
what is spooled, for up to ten seconds.

Before the first lease the spool runs in `spool` mode with a 1 MiB batch
and an 8 MiB high water, so a control plane that is slow to answer cannot
hold traffic.

## Signals and health

`SIGHUP` reopens the local log destinations; there is no file to reload.
`SIGTERM` or ctrl-c shuts down as in file mode. `/healthz` and `/readyz` on
the lease's `ca_server` behave as in [operations](/guides/operations#health):
ready means an unexpired lease is in force.
