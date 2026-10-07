# Node protocol

The protocol between a roxy node (a roxy process in node mode) and its
control plane (any server that implements these four operations). The
contract is the OpenAPI document at
[`spec/node-protocol/v1/openapi.yaml`](https://github.com/roxy-proxy/roxy-proxy/blob/main/spec/node-protocol/v1/openapi.yaml):
every operation, header, status code and body schema. The example bodies
here are checked against its schemas in CI; each is titled with the schema
it satisfies.

A node enrols once with a bootstrap token and receives a certificate; from
then on it authenticates with that certificate, polls for its lease, ships
its flow log, and renews the certificate before it expires. The lease
carries the whole policy: a rendered `roxy.yaml`, the secret values it
names, and how long it is good for. An expired lease denies everything. The
control plane never pushes; the node polls.

## Transport

- HTTP/1.1 or HTTP/2 over TLS. All paths start with `/roxy/v1/`.
- Bodies are JSON, `Content-Type: application/json`. Unknown fields are
  ignored by both sides.
- Enrolment authenticates with a bearer token; every other request with
  the node certificate (mutual TLS). The listener must accept connections
  without a client certificate, and answer requests other than enrolment
  that arrive without one with `401`.
- The node verifies the control plane with the CA bundle from its bootstrap
  material, or the system roots when none was given.
- The node's `User-Agent` is `roxy/<roxy_version>`.
- **Bootstrap material**, given out of band: the control plane URL, an
  enrolment token, and optionally a PEM bundle of CA certificates. The node
  generates its own key pair; the key never leaves the node.

### Errors

Every non-`2xx` response carries an error body. `error` is a stable code;
`message` is for humans; a `426` adds `missing`
([unsupported versions](/reference/node-protocol#unsupported-versions)). A
node acts on the status code, not the body.

```json title="Error"
{"error": "invalid_token", "message": "enrolment token not recognised"}
```

| status | meaning | node behaviour |
|---|---|---|
| `400` | malformed request; `error` says how | log. A flow batch stays spooled and is retried ([flow upload](/reference/node-protocol#flow-upload)); nothing else is re-sent as it was |
| `401` | at enrolment: the token was not accepted. Elsewhere: the certificate is not recognised as a node | enrolment: retry with backoff for two minutes (a new token may not have reached every replica), then exit non-zero. Elsewhere: log once per outcome change, keep the current lease and let it run down. Never re-enrol unasked: re-enrolment is an operator action |
| `410` | the node is revoked; definite and terminal | write an empty policy at once, finish shipping what is spooled, stop polling, keep `/healthz` up and `/readyz` not ready |
| `426` | the server will not serve this node's `protocol_version` or `roxy_version` | treat as `5xx` for the lease; log the `missing` list distinctly |
| `507` | flow quota exhausted | stop shipping until a new lease id arrives |
| `5xx`, timeout, connection or TLS error | the control plane is unavailable | retry with backoff; the lease runs down |

A TLS handshake the server rejects because of the client certificate is a
TLS error (retry with backoff), not a `401`: the node cannot tell a
rejected certificate from any other handshake failure.

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
| `csr` | a PEM `CERTIFICATE REQUEST` for an ECDSA P-256 or Ed25519 key. The server verifies the signature (proof the node holds the key), takes the public key, and ignores the subject and any requested extensions |
| `roxy_version` | the node's roxy release; a server may refuse a node below a version floor with `426` |
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
| `certificate_chain` | PEM: the node certificate first, then any intermediates up to but not including the control plane's node CA root. The node certificate's only SAN is the URI `urn:roxy:node:<node_id>`, so the server maps a certificate to a node from the certificate alone. The node presents the whole chain as its client certificate |
| `not_after` | the certificate's expiry, RFC 3339 in UTC, as in the certificate |
| `renew_after_seconds` | counted from receipt of the response; once passed, the node [renews](/reference/node-protocol#renew). Must be well inside the certificate lifetime so a failed renewal can be retried |

Whether the token is single-use, how long it lives and whether a fleet
shares one are the control plane's decisions; single-use with a short
expiry is the recommended default.

The node writes the certificate and key to its state directory: the only
secrets-adjacent material on disk, and a revocable per-node identity.

## Renew

`POST /roxy/v1/renew` with the node certificate and the same body as enrol.
The response has the same shape as the enrolment response, with `node_id`
unchanged. The old certificate stays valid until its own `not_after`; the
node switches to the new one on receipt.

A renewal the control plane cannot answer (`5xx`, timeout, connection or
TLS error) is retried with backoff. `410` is terminal. A `401`, `426` or
other `4xx` is logged once and ends renewal: the certificate serves until
its `not_after`, and if it expires before a renewal succeeds the node can
no longer fetch leases, its lease runs down, and it denies everything.

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
| `lease_id` | the lease the node holds; `null` before the first lease. Lets the server notice a node that did not apply what it was sent |
| `roxy_version` | the node's release; the server may refuse to serve it with `426` |
| `policy_state` | `none` (no lease yet), `loaded` (a lease is in force) or `expired` (the lease ran down, or the node is revoked) |
| `spooled_bytes` | flow-log data accepted but not yet acknowledged |

The server answers `200` with the full lease on every poll (there is no
conditional fetch), or `410`, `401`, `426`, `5xx` as in the
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
| `valid_for_seconds` | a duration, not an instant. The node sets `valid_until = sent_at + valid_for_seconds` from its own clock, where `sent_at` is the moment just before it sent the request, so a slow answer shortens the lease and clock skew between node and server has no effect. The server's clock is never used |
| `refresh_after_seconds` | when to poll next, counted the same way. Must leave room for several retries before `valid_for_seconds` runs out (a third of it is reasonable); the node never polls later than halfway through the lease, whatever the value |
| `config` | a complete `roxy.yaml` as a string, with no secret values: every `secrets:` entry the lease supplies is `name: { lease: true }` |
| `secrets` | each secret name the config declares, to its value, a UTF-8 string |
| `state_epoch` | opaque. When it differs from the previous lease's, the node clears every rule `set_state` entry and every metric window before applying the lease; an unchanged epoch keeps state across a config change, and the first lease sets it without clearing anything. This is how a control plane lifts a sticky quarantine a rule tripped locally |
| `flow` | [flow upload](/reference/node-protocol#flow-upload) settings. `ship: false` turns shipping off; the other fields are still required. `on_high_water` is `hold` (apply roxy's backpressure to traffic when the spool is full) or `spool` (drop the oldest spooled events, logging once) |
| `interception_ca` | reserved; a v1 server does not send it and a v1 node ignores it |

The node compares `config` and `secrets` with what it holds and applies only
what differs: a changed `config` rebuilds the policy (the atomic snapshot
swap, as a file reload does); changed `secrets` alone swap the in-memory
secret map and update the redactor, leaving rules, addons and upstream
pools alone; a lease with neither changed only moves `valid_until`.

A lease is applied in full or not at all. A `config` that `roxy check`
would reject, or a `secrets` map missing a name the config declares, is
logged and discarded, and the node keeps the lease it has. A node without a
lease denies everything and reports not ready.

### Unsupported versions

A node reports `protocol_version` and `roxy_version` at enrolment, renewal
and every lease fetch. A server that does not speak the protocol version,
or will not serve nodes below some roxy release, answers `426` naming what
the node lacks:

```json title="Error"
{"error": "unsupported", "message": "roxy 0.1.0 is below this server's floor of 0.2.0", "missing": ["roxy_version:0.2.0"]}
```

There is no other capability negotiation. The node parses the rendered
`config` strictly, so a lease using something the node does not understand
fails to load; the node keeps the lease it has, and the `lease_id` it
reports on the next poll shows the server that the new lease was not
applied.

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
| `lease_id` | the lease in force when the batch was assembled; the server accepts any lease id it has issued to the node |
| `seq_first` | the `seq` of the first event; events are consecutive and in order from it, or the server answers `400` |
| `events` | [flow log](/reference/flow-log) records with one field added, `seq`: a per-node counter that increases by one per shipped event and is persisted in the state directory in blocks, so it keeps increasing across restarts (a restart skips to the end of the last block) |

A batch is at most the lease's `batch_max_bytes` (the JSON body before
compression); the node flushes when that is reached or
`flush_interval_seconds` has passed since the first unsent event. A server
that refuses a batch within the size it stated is treated as `5xx`.

```json title="FlowAck"
{"acked_through": 1043}
```

Delivery is at least once. The server stores the batch, deduplicating on
`(node_id, seq)`, and answers `200` with the highest `seq` it has stored
for the node; the node drops spooled events at or below `acked_through` and
keeps the rest. A batch re-sent after a timeout stores nothing new and is
acknowledged at the same point. A gap within one run means events were
dropped (`spool` mode at the high water): a server-side alert, not a
protocol error. Restarts and `ship: false` also leave gaps.

| response | meaning | node behaviour |
|---|---|---|
| `400` | `node_mismatch`, a `lease_id` the server never issued, or events not consecutive | logged apart from an outage; the batch is unshipped audit and stays spooled, retried like any other failure, so under `hold` traffic stalls until the control plane accepts it |
| `507` | the node's flow quota is exhausted | stop shipping, log once, apply `on_high_water` to what accumulates (`hold` stalls traffic when the spool fills, `spool` drops oldest). Shipping resumes when a lease with a new `lease_id` arrives; the control plane is expected to revoke the node or issue it a new lease |
| `410`, `401`, `5xx` | as in the [errors table](/reference/node-protocol#errors) | on `410` the node ships what is spooled before it stops |
