# Rate limits and state

Metrics count requests or bytes over a sliding window, for rules to
compare against. State is a key/value store that rules write with
`set_state` and read as `state["key"]`.

## Metrics

A metric is defined once and compared in rules, for example
`metric.github_writes >= 30`.

```yaml
metrics:
  - id: github_writes
    count: requests      # requests | request_bytes | response_bytes | errors | denied | unique(<field>)
    where: host under "api.github.com" and method in [POST, PUT, PATCH, DELETE]
    key: [client.ip]     # one count per client; omitted = one count for everything
    window: 1m           # omitted = since start
    max_keys: 10000      # optional; default limits.max_metric_keys
```

- **`count`** says what is counted. `unique(<field>)` counts distinct
  values, approximately.
- **`where`** says which exchanges count. It can read admission fields,
  state and other metrics, but not tags.
- **`key`** gives each distinct value its own count. It takes plain
  admission fields such as `client.ip` or `host`, not headers.
- **Windows** slide in 60 steps, so a 1-minute window moves every second.
  A limit can trip up to one step early, never late.
- **Request counts** are read before the decision and updated after it, so
  `metric.x >= 30` denies the 31st request. Denied requests count too.
- **Byte counts** grow as bodies stream. A `deny` that reads one is
  checked as bytes arrive, and stops the exchange that crosses the limit.
- **Nullable fields.** If a key can be `null`, such as `tls.sni` on plain
  HTTP, the metric must exclude those exchanges in `where`
  (`tls.sni != null`), or it does not compile. A rule that reads the
  metric needs the same guard.
- **Reload.** A metric keeps its counts across a reload if its `id`,
  `count`, `where`, `key` and `window` are unchanged.

### Key cardinality

Each key value is a separate series, and the number of series is bounded
by `limits.max_metric_keys` (100 000), each metric's `max_keys`, and
`limits.max_metric_bytes`. Nothing is evicted to make room: once a table
is full, any request that needs a new series is denied
(`metric_table_full`) until old series expire
([never evict](/design/threat-model#never-evict)).

So be careful keying on values the client chooses. `host`, `path`, `url`
and `query.raw` are all chosen by the client, and denied requests count,
so a client can fill a table keyed on one of them without a single
request being allowed. Limit the values with `where`:

```yaml
metrics:
  - id: github_requests
    count: requests
    where: host in ["api.github.com", "github.com"]
    key: [host]
    window: 1m
```

`host under "github.com"` does not limit `host`, since the client also
chooses subdomains. Where the values cannot be listed, give the metric its
own `max_keys`, so that filling it only affects that metric. `roxy check`
warns about a metric keyed on a client-chosen field with no `where`.

## State

State is a key/value store shared by all exchanges. Each entry expires
after the rule's `ttl`, or one hour by default. A rule sees what earlier
exchanges wrote, and, within an exchange, what rules above it wrote. When
the store holds `limits.max_state_entries` (100 000) entries, a request
that needs a new key is denied (`state_unavailable`). Addons can read and
write the same store ([host services](/reference/host-services#state-state)).
