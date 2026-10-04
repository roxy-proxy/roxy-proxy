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
      recycle_above_memory: 48mb
      max_instances: 1024             # concurrent exchanges; waiting for one has no deadline
    config: { reject_at: 0.8 }        # opaque, handed to the layer as JSON
```

These limits catch a broken layer; they don't police a slow one
([safety](/addons/safety)). A layer that judges LLM traffic will usually
raise `max_memory` (requests resend the whole conversation, and an embedded
interpreter needs 128–256 MiB) and `first_byte_timeout` if it calls a model
before answering. Bodies have no clock, so a long generation streams
through whatever its length.

`kind: service` addons take a different set of keys
([service layers](#service-layers)).
