# Rate limits and state

Metrics count exchanges or bytes over a sliding window; state is a bounded
key/value store written with `set_state` and read as `state["key"]`.

## Metrics

Defined once, compared in rules (`metric.<id> >= 30`).

```yaml
metrics:
  - id: <string>
    count: requests | request_bytes | response_bytes | errors | denied | unique(<field>)
    where: <expr>        # head values only, no tags: whether this exchange counts
    key: [<field>, ...]  # scalar head fields only; omitted = one global series
    window: <duration>   # omitted = cumulative since start; 0 is a compile error
    max_keys: <n>        # series this metric alone may hold; omitted = limits.max_metric_keys
```

- **Windows** slide in 60 fixed buckets (1-second resolution for 1m). The
  store keeps 60 complete buckets plus the current partial one, so a value
  may include events up to one bucket older than the window: a limit trips
  slightly early, never late. `unique` is a HyperLogLog sketch per bucket.
- **`where`** may read head fields, `header[..]`, `query[..]`,
  `state[..]`, `body.text` and metrics; not `tag[..]` (counted outside the
  rules, a tag would always read false). **`key`** and the `unique(..)`
  field take scalar head fields only (`client.ip`, `host`, `tls.sni`, ...),
  not `header[..]` or other indexed values. Anything else is a compile
  error.
- **Nullable keys.** A flow whose key field is `null` is denied
  (`_fail_closed`). A key or `unique(..)` field nullable on an ordinary flow
  (`tls.sni`, `tls.alpn`, `tls.version` on plaintext; `query.raw` without a
  query; `body.size` when chunked) must be guarded in `where` (`tls.sni !=
  null`, or an `and` with that as a top-level term) or the metric does not
  compile; such flows are not counted. A rule reading the metric needs the
  same guard (`tls.sni != null and metric.by_sni > 30`).
- **When counts move.** `requests` and `denied` are read before the
  forwarding decision and incremented after it (denied flows count), so
  `metric.x >= 30` denies the 31st request. `request_bytes` and
  `response_bytes` grow as bytes stream: a deny reading them watches and
  stops the exchange that crosses the limit; a chunk is counted before it
  is checked, so a budget overcounts by at most one chunk. `errors` count
  when the exchange ends.
- **Bounds** ([never evict](/design/threat-model#never-evict)):
  `limits.max_metric_keys` (100 000) series across all metrics; each
  metric's `max_keys` (at most the shared limit, its default); and,
  approximately, `limits.max_metric_bytes` (256 MiB, at most 64 GiB; a
  series is charged for key, buckets and a fixed overhead). A flow needing
  a new series when any is exhausted is denied (`_fail_closed`, reason
  `metric_table_full`); a byte metric that cannot record a chunk mid-stream
  stops the exchange the same way. Series are reclaimed only once their
  window has fully expired.
- **Reload.** A metric keeps its series when its `id`, `count`, `where`,
  `key` and `window` are unchanged (`where` compared as written); any other
  change to it starts it empty, and a removed metric's series are dropped
  silently. Changing only `max_keys` carries over. Carried series may
  exceed a lowered `max_metric_keys` or `max_keys` until they expire (new
  series refused meanwhile), but never the byte budget: a series that does
  not fit is dropped with a warning.

### Key cardinality

`host`, `path`, `url`, `query.raw` and `client.port` are chosen by the
client per request, and denied flows count, so a metric keyed on one with
no `where` fills with as many series as the client sends, without one
request being allowed; then every flow needing a new series is denied
(`metric_table_full`) until series expire. Bound the key with `where`:

```yaml
metrics:
  - id: github_requests
    count: requests
    where: host under "github.com"
    key: [host]
    window: 1m
```

`client.ip` is bounded by who can reach the proxy; `host` by a `where` like
this. `path`, `url` and `query.raw` have no such bound (a `where` on `host`
limits whose paths count, not how many): `roxy check` warns when a metric
keys on one, or counts `unique(..)` of one, with no `where`. Give such a
metric its own `max_keys`, so filling it refuses new series in that metric
alone.

## State

A bounded key/value map with per-entry TTL: the rule's `ttl`, or one hour;
`ttl: 0` is a compile error. At most `limits.max_state_entries` (100 000)
live entries; a new key when full denies the flow (`503`, `_fail_closed`,
reason `state_unavailable`). State is shared across flows, so reads are
order-dependent: `state["key"]` sees what earlier flows wrote and, within
a flow, the `set_state` of rules above the reader. Addons have a separate
store ([host services](/reference/host-services#state-state)).
