# Rate limits and state

Metrics count exchanges or bytes over a sliding window, so rules can set
rate limits and byte budgets. State is a small key/value store that rules
write with `set_state` and read with `state["key"]`.

## Metrics

A metric is defined once and compared in rules (`metric.<id> >= 30`).

```yaml
metrics:
  - id: <string>
    count: requests | request_bytes | response_bytes | errors | denied | unique(<field>)
    where: <expr>        # head values only, no tags: whether this exchange counts
    key: [<field>, ...]  # scalar head fields only; omitted = one global series
    window: <duration>   # omitted = cumulative since start; 0 is a compile error
    max_keys: <n>        # series this metric alone may hold; omitted = limits.max_metric_keys
```

- **Windows** slide in 60 fixed buckets, so a 1-minute window has 1-second
  resolution. The store keeps the 60 complete buckets plus the current
  partial one, so a value counts every event younger than the window and
  may still include events up to one bucket older: at the edge a limit
  trips slightly early, never late. `unique` uses a HyperLogLog sketch per
  bucket.
- **What `where` and `key` may read.** `where` may read head fields,
  `header[..]`, `query[..]`, `state[..]`, `body.text` and metrics, so that
  whether an exchange counts is fixed at the request head. Not `tag[..]`:
  tags are set by rules and addons on each flow, and a flow is counted
  outside the rules, so a tag read would always be false. `key` and the
  field of `unique(..)` take scalar head fields only (`client.ip`, `host`,
  `tls.sni`, ...), not `header[..]` or any other indexed value.
  Anything else is a compile error.
- **Keys that can be `null`.** A flow whose key field is `null` cannot be
  counted and is denied (`_fail_closed`). So a key or `unique(..)` field
  that can be `null` on an ordinary flow (`tls.sni`, `tls.alpn` and
  `tls.version` on a plaintext connection, `query.raw` without a query,
  `body.size` for a chunked body) must be guarded by the metric's `where`:
  `where: tls.sni != null`, or an `and` with that as one of its top-level
  terms. Flows where the field is `null` are then not counted. Without the
  guard the metric does not compile; the error names the field and the
  guard. A rule that reads such a metric needs the same guard
  (`tls.sni != null and metric.by_sni > 30`), because reading it on a flow
  without the key fails closed too.
- **When counts move.** `requests` and `denied` are read before the
  forwarding decision and incremented after it (denied flows count too, so
  probing is not free); a rule `metric.x >= 30` therefore denies the 31st
  request. `request_bytes` and `response_bytes` grow as bytes stream, so a
  deny reading them watches and stops the exchange that crosses the limit.
  A chunk is counted before it is checked and is not forwarded if the check
  stops the exchange, so a budget may be overcounted by at most one chunk.
  `errors` are counted when the exchange ends.
- **Bounded, never evicting.** Series are capped by `limits.max_metric_keys`
  (100 000) across all metrics, by each metric's own `max_keys` (at most
  the shared limit, which is also its default) and, approximately, by
  `limits.max_metric_bytes` (256 MiB, at most 64 GiB; each series is
  charged for its key, its buckets and a fixed overhead). A flow that needs
  a new series when any of these is exhausted is denied (`_fail_closed`,
  reason `metric_table_full`). A byte metric that
  cannot record a chunk mid-stream stops the exchange the same way.
  Evicting would let a client reset its own counter by varying the key.
  Series are reclaimed only once their window has fully expired.
- **Reload.** Series whose metric definition (`count`, `key`, `window`) is
  unchanged carry over; series of a changed or removed metric are dropped
  without comment. Carried series may exceed a lowered `max_metric_keys`
  or `max_keys` until they expire (new series are refused meanwhile), but
  never the byte budget: a series that does not fit is dropped with a
  warning.

### Key cardinality

Every distinct key value is a series, and series are never evicted. Some
head fields are chosen by the client on each request: `host`, `path`,
`url`, `query.raw` and `client.port`. A metric keyed on one of them with no
`where` holds as many series as the client cares to send. Denied flows
count too, so a client sending junk `Host` values at a `key: [host]` metric
fills it without one request being allowed. Once a metric is at its
`max_keys`, or the store at `limits.max_metric_keys`, every flow that needs
a new series there is denied (`metric_table_full`) until series expire.

Bound such a key with the metric's `where`, so that only the values you
expect are counted:

```yaml
metrics:
  - id: github_requests
    count: requests
    where: host under "github.com"
    key: [host]
    window: 1m
```

`client.ip` is bounded by the addresses that can reach the proxy, and
`host` by a `where` like the one above. `path`, `url` and `query.raw` have
no such bound: a `where` on `host` limits whose paths are counted, not how
many. `roxy check` warns when a metric keys on one of them, or counts
`unique(..)` of one, with no `where` at all. A metric that must key on such
a field should also carry its own `max_keys`, so that filling it refuses
new series in that metric alone and not in every other.

## State

`state` is a bounded key/value map with per-entry TTL, written by
`set_state` and read as `state["key"]`. An entry lives for its `ttl`, or
one hour when the rule gives none; `ttl: 0` is a compile error. At most
`limits.max_state_entries` (100 000) live entries; a new key when full
denies the flow that tried with `503`, `_fail_closed`, reason
`state_unavailable`.
State is shared across flows, so reading it is order-dependent by design:
`state["key"]` sees what earlier flows wrote, and, within one flow, the
`set_state` of rules above the reader.
Addons have their own, separate store ([addons](/addons/host-services)).
