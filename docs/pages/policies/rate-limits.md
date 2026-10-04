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
    where: <expr>        # head fields only: whether this exchange counts
    key: [<field>, ...]  # head fields only; omitted = one global series
    window: <duration>   # omitted = cumulative since start
```

- **Windows** slide in 60 fixed buckets, so a 1-minute window has 1-second
  resolution. `unique` uses a HyperLogLog sketch per bucket.
- **When counts move.** `requests` and `denied` are read before the
  forwarding decision and incremented after it (denied flows count too, so
  probing is not free); a rule `metric.x >= 30` therefore denies the 31st
  request. `request_bytes` and `response_bytes` grow as bytes stream, so a
  deny reading them watches and stops the exchange that crosses the limit.
  A chunk is counted before it is checked and is not forwarded if the check
  stops the exchange, so a budget may be overcounted by at most one chunk.
  `errors` are counted when the exchange ends.
- **Bounded, never evicting.** Series are capped by `limits.max_metric_keys`
  (100 000) and, approximately, by `limits.max_metric_bytes` (256 MiB, at
  most 64 GiB; each series is charged for its key, its buckets and a fixed
  overhead). A flow that needs a new series when either is exhausted is
  denied (`_fail_closed`, event `metric_table_full`). Evicting would let a
  client reset its own counter by varying the key. Series are reclaimed
  only once their window has fully expired.
- **Reload.** Series whose metric definition is unchanged carry over, while
  they fit the new byte budget; the rest are dropped with a warning.

## State

`state` is a bounded key/value map with per-entry TTL, written by
`set_state` and read as `state["key"]`. At most `limits.max_state_entries`
(100 000) live entries; a new key when full denies the flow that tried.
Addons have their own, separate store ([addons](/addons/host-services)).
