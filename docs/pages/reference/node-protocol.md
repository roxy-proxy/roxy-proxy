# Node protocol

The protocol between a roxy node (a roxy process in node mode) and its
control plane (any server implementing these four operations). The contract
is
[`spec/node-protocol/v1/openapi.yaml`](https://github.com/roxy-proxy/roxy-proxy/blob/main/spec/node-protocol/v1/openapi.yaml):
the example bodies here are checked against its schemas in CI and titled
with the schema each satisfies.

A node enrols once with a bootstrap token and receives a certificate, then
authenticates with it to poll for its lease, ship its flow log and renew
the certificate. The lease is the whole policy: a rendered `roxy.yaml`, the
secret values it names, and how long it is good for. An expired lease
denies everything. The control plane never pushes; the node polls.

## Transport

- HTTP/1.1 or HTTP/2 over TLS; all paths start with `/roxy/v1/`. Bodies
  are JSON, `Content-Type: application/json`; unknown fields are ignored by
  both sides. The node's `User-Agent` is `roxy/<roxy_version>`.
- Enrolment authenticates with a bearer token; every other request with
  the node certificate (mutual TLS). The listener must accept connections
  without a client certificate, and answer any request other than enrolment
  that arrives without one with `401`.
- Bootstrap material, given out of band: the control plane URL, an
  enrolment token, and optionally a PEM bundle of CA certificates to verify
  the control plane with (otherwise the system roots). The node generates
  its own key pair; the key never leaves the node.

### Errors

Every non-`2xx` response carries an error body: `error` is a stable code,
`message` is for humans, and a `426` adds `missing`
([unsupported versions](/reference/node-protocol#unsupported-versions)). A
node acts on the status code, not the body.

```json title="Error"
{"error": "invalid_token", "message": "enrolment token not recognised"}
```

| status | meaning | node behaviour |
|---|---|---|
| `400` | malformed request; `error` says how | log; nothing is re-sent as it was, except a flow batch ([flow upload](/reference/node-protocol#flow-upload)) |
| `401` | at enrolment: the token was not accepted. Elsewhere: the certificate is not recognised as a node | enrolment: retry with backoff for two minutes (a new token may not have reached every replica), then exit non-zero. Elsewhere: log once per outcome change and let the lease run down. Never re-enrol unasked: re-enrolment is an operator action |
| `410` | the node is revoked; definite and terminal | write an empty policy at once, finish shipping what is spooled, stop polling, keep `/healthz` up and `/readyz` not ready |
| `426` | the server will not serve this node's `protocol_version` or `roxy_version` | treat as `5xx` for the lease; log the `missing` list distinctly |
| `507` | flow quota exhausted | stop shipping until a lease with a new `lease_id` arrives ([flow upload](/reference/node-protocol#flow-upload)) |
| `5xx`, timeout, connection or TLS error | the control plane is unavailable | retry with backoff; the lease runs down |

A TLS handshake the server rejects because of the client certificate is a
TLS error, not a `401`: the node cannot tell it from any other handshake
failure.

## Enrol

`POST /roxy/v1/enrol` with `Authorization: Bearer <token>` and no client
certificate.

```json title="EnrolRequest"
{
  "csr": "-----BEGIN CERTIFICATE REQUEST-----\nMIH...\n-----END CERTIFICATE REQUEST-----\n",
  "roxy_version": "0.1.0",
  "protocol_version": 1
}
```

| field | meaning |
|---|---|
| `csr` | PEM `CERTIFICATE REQUEST` for an ECDSA P-256 or Ed25519 key. The server verifies the signature, takes the public key, and ignores the subject and any requested extensions |
| `roxy_version` | the node's roxy release; a server may refuse one below its floor with `426` |
| `protocol_version` | `1`; a server that does not speak it answers `426` with `missing: ["protocol_version:1"]` |

```json title="EnrolResponse"
{
  "node_id": "node-7f3a9c",
  "certificate_chain": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
  "not_after": "2026-11-05T10:12:00Z",
  "renew_after_seconds": 1296000
}
```

| field | meaning |
|---|---|
| `node_id` | chosen by the server: 1 to 128 characters from `A-Z a-z 0-9 . _ -`; stable for the life of the node |
| `certificate_chain` | PEM: the node certificate first, then any intermediates up to but not including the control plane's node CA root. The node certificate's only SAN is the URI `urn:roxy:node:<node_id>`. The node presents the whole chain as its client certificate |
| `not_after` | the certificate's expiry, RFC 3339 in UTC, as in the certificate |
| `renew_after_seconds` | counted from receipt; once passed, the node [renews](/reference/node-protocol#renew). Well inside the certificate lifetime, so a failed renewal can be retried |

The token's lifetime and reuse (single-use, shared across a fleet) are the
control plane's decisions; single-use with a short expiry is recommended.
The node writes the certificate and key to its state directory: the only
secrets-adjacent material on disk, and a revocable per-node identity.

## Renew

`POST /roxy/v1/renew` with the node certificate and the enrol body; the
response has the enrolment response's shape, with `node_id` unchanged. The
old certificate stays valid until its own `not_after`; the node switches to
the new one on receipt.

`5xx`, timeout, connection and TLS errors are retried with backoff; `410`
is terminal; a `401`, `426` or other `4xx` is logged once and ends renewal,
and the certificate serves until its `not_after`. Once it expires the node
can no longer fetch leases, its lease runs down, and it denies everything.

## Lease

`POST /roxy/v1/lease` with the node certificate. The body is the node's
state:

```json title="NodeState"
{
  "lease_id": "lease-01J9Z8K3",
  "roxy_version": "0.1.0",
  "protocol_version": 1,
  "uptime_seconds": 86400,
  "policy_state": "loaded",
  "spooled_bytes": 0
}
```

| field | meaning |
|---|---|
| `lease_id` | the lease the node holds; `null` before the first. Lets the server notice a node that did not apply what it was sent |
| `roxy_version` | the node's release; the server may refuse to serve it with `426` |
| `policy_state` | `none` (no lease yet), `loaded` (a lease is in force) or `expired` (the lease ran down, or the node is revoked) |
| `spooled_bytes` | flow-log data accepted but not yet acknowledged |

The server answers `200` with the full lease on every poll (no conditional
fetch), or `410`, `401`, `426`, `5xx` as in the
[errors table](/reference/node-protocol#errors).

### Lease body

```json title="Lease"
{
  "lease_id": "lease-01J9Z8K3",
  "valid_for_seconds": 900,
  "refresh_after_seconds": 300,
  "config": "version: 1\nlisteners:\n  - name: proxy\n    bind: 0.0.0.0:8080\nsecrets:\n  github: { lease: true }\nrules:\n  - id: github\n    when: host == \"api.github.com\"\n    then: [allow]\n",
  "secrets": {
    "github": "ghp_example"
  },
  "state_epoch": "2026-10-06T09:00:00Z",
  "flow": {
    "ship": true,
    "batch_max_bytes": 1048576,
    "flush_interval_seconds": 5,
    "spool_high_water_bytes": 67108864,
    "on_high_water": "hold"
  }
}
```

| field | meaning |
|---|---|
| `lease_id` | opaque; changes whenever any other field changes. The node reports it on every poll and quotes it in flow batches |
| `valid_for_seconds` | a duration, not an instant: the node sets `valid_until = sent_at + valid_for_seconds` from its own clock, `sent_at` being just before it sent the request, so a slow answer shortens the lease and clock skew has no effect. The server's clock is never used |
| `refresh_after_seconds` | when to poll next, counted the same way; leave room for several retries before `valid_for_seconds` runs out (a third of it is reasonable). The node never polls later than halfway through the lease |
| `config` | a complete `roxy.yaml` as a string, with no secret values: every `secrets:` entry the lease supplies is `name: { lease: true }` |
| `secrets` | each secret name the config declares, to its value, a UTF-8 string |
| `state_epoch` | opaque. When it differs from the previous lease's, the node clears every rule `set_state` entry and every metric window before applying the lease (how a control plane lifts a quarantine a rule tripped locally); unchanged, state survives a config change. The first lease sets it without clearing anything |
| `flow` | [flow upload](/reference/node-protocol#flow-upload) settings. `ship: false` turns shipping off; the other fields are still required. `on_high_water` is `hold` (apply roxy's backpressure to traffic when the spool is full) or `spool` (drop the oldest spooled events, logging once) |
| `interception_ca` | reserved; a v1 server does not send it and a v1 node ignores it |

The node applies only what differs from what it holds: a changed `config`
rebuilds the policy (the atomic snapshot swap of a file reload); changed
`secrets` alone swap the in-memory secret map and update the redactor,
leaving rules, addons and upstream pools alone; neither changed only moves
`valid_until`. A lease is applied in full or not at all: a `config` that
`roxy check` would reject, or a `secrets` map missing a name the config
declares, is logged and discarded, and the node keeps the lease it has. A
node without a lease denies everything and reports not ready.

### Unsupported versions

A node reports `protocol_version` and `roxy_version` at enrolment, renewal
and every lease fetch. A server that does not speak the protocol version,
or will not serve nodes below some roxy release, answers `426` naming what
the node lacks:

```json title="Error"
{"error": "unsupported", "message": "roxy 0.1.0 is below this server's floor of 0.2.0", "missing": ["roxy_version:0.2.0"]}
```

There is no other capability negotiation: the node parses `config`
strictly, so a lease using something it does not understand fails to load,
and the `lease_id` on its next poll shows the server it was not applied.

## Flow upload

`POST /roxy/v1/flows` with the node certificate. The body may be gzip
compressed, signalled with `Content-Encoding: gzip`.

```json title="FlowBatch"
{
  "node_id": "node-7f3a9c",
  "lease_id": "lease-01J9Z8K3",
  "seq_first": 1042,
  "events": [
    {"seq": 1042, "ts": "2026-10-06T10:12:00.123Z", "event": "request", "flow": "01J9Z8", "decision": "deny", "terminal_rule": "_default"},
    {"seq": 1043, "ts": "2026-10-06T10:12:00.410Z", "event": "log", "flow": "01J9Z9", "rule": "audit"}
  ]
}
```

| field | meaning |
|---|---|
| `node_id` | must match the certificate, or the answer is `400 node_mismatch` |
| `lease_id` | the lease in force when the batch was assembled; any lease id issued to the node is accepted |
| `seq_first` | the `seq` of the first event; events are consecutive and in order from it, or the server answers `400` |
| `events` | [flow log](/reference/flow-log) records with `seq` added: a per-node counter that increases by one per shipped event, persisted in the state directory in blocks so it keeps increasing across restarts (a restart skips to the end of the last block) |

A batch is at most the lease's `batch_max_bytes` (the JSON before
compression); the node flushes when that is reached or
`flush_interval_seconds` has passed since the first unsent event. A server
that refuses a batch within the size it stated is treated as `5xx`.

```json title="FlowAck"
{"acked_through": 1043}
```

Delivery is at least once: the server stores the batch, deduplicating on
`(node_id, seq)`, and answers `200` with the highest `seq` it has stored
for the node; the node drops spooled events at or below `acked_through`. A
gap within one run means events were dropped (`spool` mode at the high
water): a server-side alert, not a protocol error. Restarts and `ship:
false` also leave gaps.

| response | node behaviour |
|---|---|
| `400` (`node_mismatch`, a `lease_id` the server never issued, events not consecutive) | logged apart from an outage; the batch is unshipped audit and stays spooled, so under `hold` traffic stalls until the control plane accepts it |
| `507` | log once and apply `on_high_water` to what accumulates until a new lease arrives; the control plane is expected to revoke the node or issue it a new lease |
| `410`, `401`, `5xx` | as in the [errors table](/reference/node-protocol#errors); on `410` the node ships what is spooled before it stops |
