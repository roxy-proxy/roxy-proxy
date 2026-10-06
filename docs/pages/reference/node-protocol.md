# Node protocol

The protocol between a roxy node and its control plane. A node is a roxy
process started in node mode; a control plane is any server that implements
these four operations. The contract is the OpenAPI document at
[`spec/node-protocol/v1/openapi.yaml`](https://github.com/roxy-proxy/roxy-proxy/blob/main/spec/node-protocol/v1/openapi.yaml):
every operation, header, status code and body schema. This page explains
it. The example bodies here are checked against the document's schemas in
CI, and each is titled with the schema it satisfies.

The flow is: a node enrols once with a bootstrap token and receives a
certificate; from then on it authenticates with that certificate, polls for
its lease, ships its flow log, and renews the certificate before it
expires. The lease carries the whole policy: a rendered `roxy.yaml`, the
secret values it names, and how long it is good for. An expired lease
denies everything. The control plane never pushes; the node polls.

## Transport

- HTTP/1.1 or HTTP/2 over TLS. All paths start with `/roxy/v1/`.
- Bodies are JSON, `Content-Type: application/json`. Unknown fields are
  ignored by both sides, so a server may add fields within a major version.
- Enrolment authenticates with a bearer token. Every other request
  authenticates with the node certificate (mutual TLS). The listener must
  therefore accept connections without a client certificate, and reject
  requests other than enrolment that arrive without one with `401`.
- The node verifies the control plane with the CA bundle from its bootstrap
  material, or the system roots when none was given.
- The node identifies itself in `User-Agent` as `roxy/<roxy_version>`.

### Bootstrap material

A node is given, out of band: the control plane URL, a single-use
enrolment token, and optionally a PEM bundle of CA certificates to verify
the control plane with. Nothing else. The node generates its own key pair
and the key never leaves the node.

### Errors

Every non-`2xx`, non-`304` response carries an error body:

```json title="Error"
{"error": "invalid_token", "message": "enrolment token already used"}
```

`error` is a stable code; `message` is for humans. A `426` adds `missing`
(see [features](#features)). A node acts on the status code, not the
body.

| status | meaning | node behaviour |
|---|---|---|
| `400` | the request was malformed; `error` says how | log; do not retry the same request |
| `401` | at enrolment: the token is unknown, used or expired. Elsewhere: the certificate is not recognised as a node | enrolment: fail. Elsewhere: log once per outcome change, keep the current lease and let it run down. Never re-enrol: the token is gone |
| `410` | the node is revoked. Definite and terminal | write an empty policy at once, finish shipping what is spooled, stop polling, keep health up |
| `413` | flow batch too large | halve the batch and retry |
| `426` | the server will not render for this node's version or features | treat as `5xx` for the lease; log the `missing` list distinctly |
| `507` | flow quota exhausted | stop shipping until a new lease id arrives |
| `5xx`, timeout, connection or TLS error | the control plane is unavailable | retry with backoff; the lease runs down |

A TLS handshake the server rejects because of the client certificate is
treated as `401`.

## Enrol

`POST /roxy/v1/enrol` with `Authorization: Bearer <token>` and no client
certificate.

```json title="EnrolRequest"
{
  "csr": "-----BEGIN CERTIFICATE REQUEST-----\nMIH...\n-----END CERTIFICATE REQUEST-----\n",
  "roxy_version": "0.1.0",
  "protocol_version": 1,
  "features": ["valid_until", "sourceless_secrets", "readyz", "action:deny", "addon:wasm"]
}
```

- `csr` is a PEM `CERTIFICATE REQUEST` for an ECDSA P-256 or Ed25519 key.
  The server verifies the signature (proof that the node holds the key),
  takes the public key, and ignores the subject and any requested
  extensions: it sets the subject and SAN itself.
- `protocol_version` is `1`. A server that does not speak the version
  answers `426` with `missing: ["protocol_version:1"]`.
- `features` is the node's [feature list](#features).

```json title="EnrolResponse"
{
  "node_id": "node-7f3a9c",
  "certificate_chain": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
  "not_after": "2026-11-05T10:12:00Z",
  "renew_after_seconds": 1296000
}
```

- `node_id` is chosen by the server: 1 to 128 characters from
  `A-Z a-z 0-9 . _ -`. It is stable for the life of the node.
- `certificate_chain` is PEM: the node certificate first, then any
  intermediates up to but not including the control plane's node CA root.
  The node certificate carries the node id as a URI SAN,
  `urn:roxy:node:<node_id>`, so the server maps a certificate to a node
  from the certificate alone, with no lookup table. It must have no other
  SANs. The node presents the whole chain as its client certificate.
- `not_after` is the certificate's expiry, RFC 3339 in UTC, the same value
  as in the certificate.
- `renew_after_seconds` is counted from the node's receipt of the response.
  Once it has passed the node [renews](#renew). It must be well inside the
  certificate lifetime, so that a failed renewal has time to be retried.

The token is consumed by a successful enrolment. A second use, a token the
server does not know, or an expired token is `401 invalid_token`. A node
that is handed a used token cannot recover; it logs and keeps denying
everything.

The node writes the certificate and key to its state directory. Those are
the only secrets-adjacent material on disk: a revocable per-node identity.

## Renew

`POST /roxy/v1/renew` with the node certificate and the same body as
enrol. The response has the same shape as the enrolment response, and
`node_id` is unchanged. The old certificate stays valid until its own
`not_after`; the node switches to the new one on receipt.

A renewal that fails for any reason is retried with backoff. If the
certificate expires before a renewal succeeds, the node can no longer fetch
leases, its lease runs down, and it denies everything. That is the intended
failure: a node the control plane will not renew stops serving.

## Lease

`GET /roxy/v1/lease` with the node certificate. The node reports its state
in one header, `Roxy-Node-State`, whose value is a compact JSON object:

```json title="NodeState"
{
  "lease_id": "lease-01J9Z8K3",
  "config_hash": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "secrets_hash": "v12",
  "roxy_version": "0.1.0",
  "protocol_version": 1,
  "features": ["valid_until", "sourceless_secrets", "readyz", "action:deny", "addon:wasm"],
  "uptime_seconds": 86400,
  "policy_state": "loaded",
  "spooled_bytes": 0
}
```

- `lease_id`, `config_hash` and `secrets_hash` are null before the first
  lease.
- `policy_state` is `none` (no lease yet), `loaded` (a lease is in force)
  or `expired` (the lease ran down, or the node is revoked).
- `spooled_bytes` is flow-log data accepted but not yet acknowledged.

The node sends `If-None-Match` with the `ETag` of the lease it holds. The
server answers:

- `200` with a lease body and an `ETag`. The node applies it.
- `304` when the lease the node holds is still the one the server would
  issue. The response has no body and carries `Roxy-Lease-Valid-For` and
  `Roxy-Lease-Refresh-After`, both in seconds, which the node applies
  exactly as it would `valid_for_seconds` and `refresh_after_seconds` from
  a `200`. An unchanged lease costs a request and a few headers, and is
  extended by it.
- `410`, `401`, `426`, `5xx` as in the [errors table](#errors).

The server renders the lease for the node's reported version and features
(see [features](#features)). It may also use the reported hashes to notice
a node that did not apply what it was sent.

### Lease body

```json title="Lease"
{
  "lease_id": "lease-01J9Z8K3",
  "issued_at": "2026-10-06T10:12:00Z",
  "valid_for_seconds": 900,
  "refresh_after_seconds": 300,
  "config": "listeners:\n  proxy: 0.0.0.0:8080\nsecrets:\n  github: {}\nrules:\n  - id: github\n    match: {host: api.github.com}\n    action: allow\n",
  "config_hash": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "secrets": {
    "github": "ghp_example",
    "hmac_key": {"b64": "AAECAwQFBgc="}
  },
  "secrets_hash": "v12",
  "state_epoch": "2026-10-06T09:00:00Z",
  "flow": {
    "ship": true,
    "batch_max_bytes": 1048576,
    "batch_max_events": 1000,
    "flush_interval_seconds": 5,
    "spool_high_water_bytes": 67108864,
    "on_high_water": "hold"
  }
}
```

- `lease_id` is opaque and changes whenever any other field changes. It is
  also the `ETag`. The node quotes it in flow batches.
- `valid_for_seconds` is a duration, not an instant. The node computes
  `valid_until = now + valid_for_seconds` from its own clock at the moment
  it receives the response, and writes that as the policy's `valid_until`.
  The server's clock is never used: a node whose clock is an hour ahead of
  the server's would otherwise expire an hour early, and one an hour behind
  would serve for an hour after the control plane meant it to stop.
  `issued_at` is the server's view, for logs only.
- `refresh_after_seconds` is when to poll next, counted the same way. It
  must leave room for several retries before `valid_for_seconds` runs out;
  a third of it is a reasonable choice. The node adds jitter.
- `config` is a complete `roxy.yaml` as a string, with no secret values in
  it: every `secrets:` entry is sourceless (`name: {}`), meaning the value
  comes from the lease. `config_hash` is `sha256:` followed by the
  lower-case hex SHA-256 of the UTF-8 bytes of `config`.
- `secrets` maps each secret name the config declares to its value: a
  string, or `{"b64": "..."}` (standard base64 with padding) for a value
  that is not UTF-8. `secrets_hash` is opaque: it changes whenever any
  value changes, and must not be a plain digest of the values, because the
  node reports and may log it. A version counter or a keyed hash is fine.
- The two hashes drive what the node does with a new lease. A changed
  `config_hash` rebuilds the policy: the atomic snapshot swap, as a file
  reload does. A changed `secrets_hash` alone swaps the in-memory secret
  map and updates the redactor; rules, addons and upstream pools are left
  alone. A lease with neither changed only moves `valid_until`.
- `state_epoch` is opaque. When it differs from the previous lease's, the
  node clears every rule `set_state` entry and every metric window before
  applying the lease. That is how a control plane lifts a sticky quarantine
  a rule tripped locally, once it has decided to: it changes the epoch. An
  unchanged epoch keeps state across a config change. The first lease sets
  the epoch without clearing anything.
- `flow` configures [flow upload](#flow-upload). `ship: false` turns it
  off; the other fields are still required. `on_high_water` is `hold`
  (apply roxy's backpressure to traffic when the spool is full) or `spool`
  (drop the oldest spooled events, logging once).
- `interception_ca` is reserved for a later version. A v1 server must not
  send it; a v1 node ignores it.

A lease is applied in full or not at all. A `config` that `roxy check`
would reject, or a `secrets` map missing a name the config declares, is
logged and discarded, and the node keeps the lease it has. A node without
a lease denies everything and reports not ready.

### Features

`features` is a list of strings naming what the node can run. A server
renders a lease only from features the node reported, and compares the
rendered document against the list before sending it. If the policy needs
something the node lacks, the answer is `426` whose body names it:

```json title="Error"
{"error": "unsupported", "message": "node lacks: addon:wasm", "missing": ["addon:wasm"]}
```

Feature names in v1:

- `valid_until`: the node honours a top-level `valid_until`.
- `sourceless_secrets`: the node accepts `secrets:` entries with no `env`
  or `file` source.
- `readyz`: the node serves `/readyz`.
- `action:<name>` for each rule action the node's compiler knows, for
  example `action:allow`, `action:deny`, `action:set_header`.
- `addon:<kind>` for each addon kind the node can load, for example
  `addon:wasm`.

A node reports the same list at enrolment, renewal and every lease fetch.
Feature names are case-sensitive. A server ignores names it does not know.
This is what lets a fleet of mixed roxy versions take a rollout: the
renderer can never send a node a policy it would fail to load.

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

- Each event is a [flow log](/operate/flow-log) record with one field
  added, `seq`: a per-node counter that increases by one per event and is
  persisted in the state directory, so it keeps increasing across
  restarts. A batch's events are consecutive, in order, starting at
  `seq_first`; a server rejects anything else with `400`.
- `node_id` must match the certificate, or the answer is `400
  node_mismatch`. `lease_id` is the lease in force when the batch was
  assembled; the server accepts any lease id it has issued to the node.
- The batch respects the lease's `batch_max_bytes` (the JSON body before
  compression) and `batch_max_events`. The node flushes when either is
  reached or `flush_interval_seconds` has passed since the first unsent
  event.

```json title="FlowAck"
{"acked_through": 1043}
```

Delivery is at least once. The server stores the batch, deduplicating on
`(node_id, seq)`, and answers `200` with the highest `seq` it has stored for
the node. The node drops spooled events with `seq` at or below
`acked_through` and keeps the rest for the next batch. A batch the node
re-sends after a timeout is therefore harmless: the server stores nothing
new and acknowledges the same point. A gap in a node's sequence is a
server-side alert, not a protocol error; in `spool` mode a node that
dropped events will have one.

Other responses:

- `413`: the batch is larger than the server will take. The node halves
  `batch_max_events` for its next attempts, down to one. A single event
  that is still `413` is dropped and logged once.
- `507`: the node's flow quota is exhausted. The node stops shipping, logs
  once, and applies `on_high_water` to what accumulates: `hold` stalls
  traffic when the spool fills, `spool` drops oldest. Shipping resumes when
  a lease with a new `lease_id` arrives. The control plane is expected to
  revoke the node or issue it a new lease.
- `410`, `401`, `5xx` as in the [errors table](#errors). On `410` the node
  attempts to ship what is spooled before it stops.

## A worked sequence

1. The node starts with a URL, a token and a state directory. It opens its
   listeners and denies everything. It generates a P-256 key and a CSR, and
   `POST`s `/roxy/v1/enrol` with the token. It gets `node-7f3a9c`, a
   certificate valid for 30 days, and `renew_after_seconds` of 15 days. It
   writes the certificate and key to the state directory.
2. It `GET`s `/roxy/v1/lease` with the certificate and `policy_state:
   none`. It gets `200`, lease `lease-01J9Z8K3`, `valid_for_seconds: 900`,
   `refresh_after_seconds: 300`. It sets `valid_until` to its own clock
   plus 900 s, loads the config, stores the secrets in memory, records the
   epoch, and reports ready.
3. Five minutes later it `GET`s the lease again with `If-None-Match:
   "lease-01J9Z8K3"`. It gets `304` with `Roxy-Lease-Valid-For: 900`. It
   moves `valid_until` forward 900 s from now. Nothing is rebuilt.
4. An operator rotates the GitHub token. The next poll gets `200`, lease
   `lease-01J9ZB7Q`, the same `config_hash`, a new `secrets_hash`. The node
   swaps the secret map. In-flight requests that already read the old
   value finish with it; the redactor scrubs both.
5. The operator revokes the node. The next poll gets `410`. The node
   writes an empty policy, denies everything, ships its spooled flow
   events, stops polling, and keeps `/healthz` up and `/readyz` not ready.

Had the control plane been unreachable at step 3 instead, the node would
have retried with backoff and kept serving until its `valid_until`, then
denied everything until a lease arrived.

## Not in v1

Push from the server to the node: polling at `refresh_after_seconds` is
enough. Secrets with their own expiry: the server re-leases before a
credential expires. Capture body upload: `capture_dir` is local. Server-side
storage, a UI, or any particular control plane: the control plane is
whatever implements these endpoints. Per-node interception CA issuance:
`interception_ca` is reserved for it.
