# Host services

Host services are for WASM layers; a service layer calls what it needs
itself. Everything a layer can do outside its own streams is on this list, and each
item is a capability granted in config. Every import is linked whatever the
grants, so one binary runs under any of them; calling one that was not
granted traps (`CapabilityDenied`) and fails the exchange. `flow.current`,
`flow.add-tag` and `flow.config` need no capability.

## Endpoints

`endpoints.call(name, request)`: roxy resolves the name to the configured
URL (appending the request's path and query), attaches the endpoint's
headers (replacing any the layer set), applies the timeout and retries, and
enforces the address floor and deny lists. The layer cannot express a
destination, so text injected into the traffic it inspects cannot steer it
to another host, and credentials never enter the layer. Calls never pass
through the layer stack, so a monitor's own model call cannot recurse
through it. The request body is buffered (up to 16 MiB) so a retry can
resend it; retries back off from 100 ms. An unknown name, a denied address,
a timeout and a failure reach the layer as distinct `error-code`s. Each call
emits an `endpoint_call` flow event.

## State

`flow.state-get` / `flow.state-put`: a JSON-value store namespaced per
layer, with per-entry TTL, a value size cap and an entry cap. A miss returns
`none`. A write when full returns an error and the layer decides; nothing is
evicted.

Each layer's store is separate, so a full or busy store in one layer does
not slow another. Expired entries read as absent straight away. When a new
key meets a full store, expired entries are purged at most every 100 ms.

The store survives a reload. A reload that changes `state.max_entries` or
`state.default_ttl` applies to the live store: stored entries keep their
expiry, and a lower cap evicts nothing but refuses new keys until enough
entries expire.

## Identity

`flow.current()` gives the flow id, connection id, tags, and the principal
as roxy established it: `client.user` from proxy auth, client IP, listener,
TLS SNI. These are the safe keys for per-principal state; a layer should
not trust client-supplied session headers.

## Record

`flow.record(kind, json, audit)` writes a `layer_record` event to the flow
log with the flow id, the layer name and a timestamp. String values pass
through the secret redactor, and a value that is not JSON fails the
exchange. Like any audit record it is never dropped: the call waits while
the flow log is behind. `audit: true` also POSTs the record to the layer's
`audit_endpoint`.

## Metrics and log

`flow.metric-get(id, [])` reads a metric for this flow's own key (the
metric's key fields evaluated on the client's request); explicit key values
are refused. `flow.log` writes to roxy's operational log with the flow id
and layer name.

There is no `secrets` capability (the config refuses it and points to
endpoint `headers`), and no way to terminate or quarantine a client: a
layer denies the exchange and reports through `record` or an endpoint.
