# Node protocol

The protocol between a roxy node (roxy in [node mode](/guides/node-mode))
and its control plane. Any server that implements these four operations
can be a control plane. The formal definition is
[`spec/node-protocol/v1/openapi.yaml`](https://github.com/roxy-proxy/roxy-proxy/blob/main/spec/node-protocol/v1/openapi.yaml),
and each example on this page is titled with the schema it matches.

A node enrols once with an enrolment token and gets a node token back. It
then uses the node token to poll for its lease, send its flow log and
renew the token. The lease is the node's whole policy: a `roxy.yaml`, the
secrets it needs, and how long it is valid. The control plane never
contacts the node; the node always polls.

## Transport

- HTTPS, HTTP/1.1 or HTTP/2. All paths start with `/roxy/v1/`. Bodies are
  JSON. Both sides ignore unknown fields.
- Every request carries `Authorization: Bearer <token>`: the enrolment
  token when enrolling, the node token otherwise. There are no client
  certificates, so the control plane can sit behind any TLS terminator.
- The operator gives the node the control plane's URL, an enrolment
  token, and optionally the CA certificates to verify the control plane
  with.

### Errors

Every error response has a body with a stable `error` code and a
`message`. The node acts on the status code, not the body.

```json title="Error"
{"error": "invalid_token", "message": "enrolment token not recognised"}
```

| status | meaning | what the node does |
|---|---|---|
| `400` | the request was malformed | Enrolment: retries for two minutes, then exits. Renewal: stops renewing. Lease: keeps polling, and the lease expires if this continues. |
| `401` | the token is not recognised | Enrolment: retries for two minutes, then exits. Renewal and flows: retries, since another replica may not know the new token yet. Lease: keeps polling, and the lease expires if this continues. The node never re-enrols by itself. |
| `410` | the node is revoked | Enrolment: exits. Otherwise: denies everything at once, forgets its secrets, stops polling, and tries for thirty seconds to send its remaining flow log. |
| `426` | the server will not serve this node's version | Enrolment: exits. Renewal: stops renewing. Lease: treated like `5xx`. |
| `507` | the node's flow quota is used up | stops sending flows until a new lease arrives |
| `5xx`, timeout, connection or TLS error | the control plane is unavailable | retries with backoff; the lease expires if this continues |

## Enrol

`POST /roxy/v1/enrol` with the enrolment token.

```json title="EnrolRequest"
{
  "roxy_version": "0.1.0",
  "protocol_version": 1
}
```

| field | meaning |
|---|---|
| `roxy_version` | the node's roxy version |
| `protocol_version` | `1` |

```json title="EnrolResponse"
{
  "node_id": "node-7f3a9c",
  "token": "nt1-9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "not_after": "2026-11-05T10:12:00Z",
  "renew_after_seconds": 1296000
}
```

| field | meaning |
|---|---|
| `node_id` | chosen by the server: 1 to 128 characters from `A-Z a-z 0-9 . _ -`, fixed for the life of the node |
| `token` | the node token: 1 to 512 characters valid in a bearer token. The node stores it and sends it unchanged |
| `not_after` | when the server stops accepting the token, in UTC |
| `renew_after_seconds` | when the node should [renew](/reference/node-protocol#renew) the token, counted from when it received it. The node renews no later than two thirds of the way to `not_after` whatever this says |

The control plane decides how long tokens last and how it stores them.
We recommend single-use enrolment tokens with a short expiry, and storing
node tokens hashed. The node keeps its token in its state dir (mode
`0600`).

## Renew

`POST /roxy/v1/renew` with the node token and the same body as enrolment.
The response has the same shape as the enrolment response, with the same
`node_id` and a new `token`. The server should keep accepting the old
token until its `not_after`, so that a renewal that reached one replica
but not another does not lock the node out.

If the token expires without being renewed, the node exits and needs a
new enrolment token and an empty state dir.

## Lease

`POST /roxy/v1/lease` with the node token. The body reports the node's
state:

```json title="NodeState"
{
  "lease_id": "lease-01J9Z8K3",
  "roxy_version": "0.1.0",
  "protocol_version": 1,
  "uptime_seconds": 86400,
  "policy_state": "loaded",
  "spooled_bytes": 0,
  "seq_unreserved": false,
  "quarantine": null
}
```

| field | meaning |
|---|---|
| `lease_id` | the lease the node has applied, or `null` before the first. A node that reports an old `lease_id` did not apply the latest lease |
| `policy_state` | `none` (no lease yet), `loaded` or `expired` |
| `spooled_bytes` | flow-log data waiting to be acknowledged |
| `seq_unreserved` | `true` if the node cannot save its flow sequence counter, so a restart might reuse sequence numbers. A node that reports this for long needs its state dir looked at |
| `quarantine` | the node's [quarantine](/guides/operations#quarantine), or `null` |

```json title="QuarantineReport"
{
  "id": "q-01J9ZB7QX4R2M8K3N5P6T7V8W9",
  "since": "2026-10-13T09:14:02Z",
  "cause": {"kind": "rule", "rule": "exfil-guard", "flow": "01J9ZB7P"}
}
```

| field | meaning |
|---|---|
| `id` | the incident's id, which a release must name |
| `since` | when it was tripped, by the node's clock |
| `cause` | what tripped it: `kind: rule` with the `rule` and `flow`, `kind: threshold` with the `listener` and its threshold, or `kind: layer` with the `layer` and `flow` |

The server answers `200` with the whole lease on every poll, or an
[error](/reference/node-protocol#errors).

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
  },
  "quarantine": {
    "release": ["q-01J9ZB7QX4R2M8K3N5P6T7V8W9"]
  }
}
```

| field | meaning |
|---|---|
| `lease_id` | any string that changes whenever anything else in the lease changes |
| `valid_for_seconds` | how long the lease is valid, measured by the node's own clock from just before it sent the request. Clock differences between the node and server do not matter |
| `refresh_after_seconds` | when to poll next. Leave room for several retries; a third of `valid_for_seconds` is reasonable. The node polls no later than halfway through the lease |
| `config` | a complete `roxy.yaml`. Secrets the lease supplies are declared as `name: { lease: true }` |
| `secrets` | the value of each `lease: true` secret |
| `state_epoch` | any string. When it changes, the node clears all rule state and metric counts before applying the lease, which is how a control plane lifts a lockout a rule imposed |
| `flow` | how to send the flow log ([flow upload](/reference/node-protocol#flow-upload)). `ship: false` turns it off. `on_high_water` says what happens when `spool_high_water_bytes` are waiting: `hold` holds traffic, `spool` drops the oldest events |
| `quarantine` | optional. `release` lists the quarantine ids the control plane has released. The node lifts its quarantine when its id is listed |
| `interception_ca` | reserved; not sent by a v1 server |

The node applies a lease in full or not at all. A lease whose `config`
`roxy check` would reject, or that lacks a secret the config declares, is
logged and ignored, and the node keeps the lease it has. A change to
`secrets` alone is applied without reloading the rest of the policy.

### Unsupported versions

The node sends its `protocol_version` and `roxy_version` with every
request. A server that will not serve it answers `426` and lists what the
node lacks:

```json title="Error"
{"error": "unsupported", "message": "roxy 0.1.0 is below this server's floor of 0.2.0", "missing": ["roxy_version:0.2.0"]}
```

There is no other capability negotiation. A lease that uses something the
node does not understand fails to load, and the `lease_id` on the next
poll shows it was not applied.

## Flow upload

`POST /roxy/v1/flows` with the node token. The body may be gzipped, with
`Content-Encoding: gzip`.

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
| `node_id` | must match the token's node, or the answer is `400 node_mismatch` |
| `lease_id` | the lease in force when the batch was put together |
| `seq_first` | the `seq` of the first event. Events are numbered consecutively from it |
| `events` | [flow log](/reference/flow-log) records, each with a `seq` that increases by one per event and keeps increasing across restarts |

The node sends a batch when it reaches `batch_max_bytes`, or
`flush_interval_seconds` after the oldest unsent event.

```json title="FlowAck"
{"acked_through": 1043}
```

Delivery is at least once. The server stores the batch, ignoring events
it already has for that `(node_id, seq)`, and answers with the highest
`seq` it has stored. The node then discards events up to that number. A
gap in `seq` within one run means the node dropped events under
`on_high_water: spool`. Restarts and `ship: false` also leave gaps.

A batch the server refuses with `400` stays queued on the node, so under
`hold` traffic stops until the server accepts it. A `507` means the
server wants no more flows until it sends a new lease. Other responses
are handled as in the [errors table](/reference/node-protocol#errors).
