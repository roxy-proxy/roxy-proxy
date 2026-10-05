# Configuring addons

Addons are listed under `addons:`, in the order they wrap the exchange. This
is a WASM layer with every key; [service layers](/addons/service-layers) take
a smaller set.

```yaml
addons:                               # above the rules, in this order
  - name: sentinel
    kind: wasm
    path: /etc/roxy/addons/sentinel.wasm
    mode: enforce                     # enforce | observe
    when: host == "api.anthropic.com" and path starts_with "/v1/messages"   # default: every exchange
    capabilities: [state, record, endpoints]   # also: metrics, log
    audit_endpoint: audit-sink        # also receives record(.., audit: true)
    endpoints:                        # named, not URLs
      monitor-model:
        url: https://api.anthropic.com/v1/messages
        headers: { x-api-key: "${secret:monitor_key}" }   # attached by roxy, never seen by the layer
        timeout: 10s                  # per attempt, to the response head (default 30s)
        retries: 2                    # after a connection failure or 502/503/504 (default 0)
      threat-intel:
        url: https://ti.internal:8443/score
        private_ok: true              # may reach private addresses
    state:
      max_entries: 100000
      max_value_bytes: 64kb
      default_ttl: 6h
    limits:                           # defaults shown
      max_memory: 64mb                # per instance; what the layer holds of a body lives here
      first_byte_timeout: 30s         # the layer's own time to its response head
      recycle_after_exchanges: 10000
      recycle_above_memory: 48mb      # default: three quarters of max_memory
      max_instances: 1024             # concurrent exchanges; waiting for one has no deadline
    config: { reject_at: 0.8 }        # opaque, handed to the layer as JSON
```

These limits catch a broken layer; they don't police a slow one
([safety](/addons/safety)). A layer that judges LLM traffic will usually
raise `max_memory` (requests resend the whole conversation, and an embedded
interpreter needs 128–256 MiB) and `first_byte_timeout` if it calls a model
before answering. Bodies have no clock, so a long generation streams
through whatever its length.

`roxy check` refuses what `roxy run` would refuse, or what could never act:
a zero `max_instances`, `max_memory`, `recycle_above_memory`,
`first_byte_timeout`, endpoint `timeout`, or service `max_connections` or
`max_streams`; a `recycle_above_memory` above `max_memory` (an instance
fails its exchange at `max_memory`, so it would never be recycled); and a
`path` that does not exist. `recycle_after_exchanges: 0` is accepted and
recycles an instance after every exchange.

`kind: service` addons take a different set of keys
([service layers](/addons/service-layers)).

## Choosing exchanges

`when` is a condition in the [rule language](/reference/rule-language) over
head fields. A layer runs only on the exchanges it matches. The rest go
straight to the layer below, as if the layer had passed both directions on
unchanged. A skipped layer costs nothing: no instance, no body pumping, no
service session.

- `when` sees the request as it reaches the layer: what the layer above
  passed on, re-validated like any request a layer passes on. A layer above
  can therefore steer a request into or out of a lower layer's `when`.
- It may read head fields, headers, the query, `state[..]`, `metric.<id>`
  and address lists. `body.*`, `response.*` and `ws.*` are config errors:
  a layer owns the body, so nothing reads it first.
- `tag["x"]` sees tags set by layers above. The rules run below the stack,
  so their tags are not visible here.
- A `when` that reaches an unavailable input (a metric, an address list, a
  missing value under an operator that cannot answer for `null`) fails the
  flow closed like a layer failure (`503`, `layer_error` with `kind:
  when:<code>`). It never skips the layer. On an observe layer the failure
  is logged like any observer failure, and the layer gets no copy.
- A layer that `when` skipped on a WebSocket's upgrade request is not in
  that WebSocket's byte path.

`sample`, for `mode: observe` only, is the share of matching exchanges the
layer gets a copy of, in (0, 1]. It is drawn from the flow id, so it is the
same for a flow however often you ask. An enforcing layer can't be sampled:
skipping it at random would let traffic past it.

```yaml
addons:
  - name: shadow-monitor
    path: /etc/roxy/addons/monitor.wasm
    mode: observe
    when: method == POST
    sample: 0.1                       # one matching exchange in ten
```

The flow log's `addons` lists the layers that ran on the exchange.
