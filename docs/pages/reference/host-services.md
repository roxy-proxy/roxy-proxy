# Host services

Host services are for WASM layers; a service layer calls what it needs
itself. Everything a layer can do outside its own streams is on this list,
and each item is a capability granted in config
([capabilities](/reference/addon-configuration#capabilities)). The caps on what the
host holds for a layer (tags, `fields`, `log` and `record` payloads) are in
[addon safety](/reference/addon-safety).

## Endpoints (`endpoints`)

`endpoints.call(name, request)`: roxy resolves the name to the configured
URL, attaches the endpoint's headers (replacing any the layer set), applies
the timeout and retries, and enforces the address floor and deny lists.
The layer cannot express a destination, and credentials never enter the
layer. Calls never pass through the layer stack, so a monitor's own model
call cannot recurse through it. The request body is buffered (up to 16 MiB)
so a retry can resend it, and reading it counts against the timeout; retries
back off from 100 ms. One exchange has at most 8 calls in flight at once;
further calls wait for a permit, also within the timeout. An unknown name, a
denied address, a refused path, a timeout and a failure reach the layer as
distinct `error-code`s. Each call emits an `endpoint_call` flow event.

What the request's path and query contribute is the endpoint's `path`
setting:

- `fixed` (the default): the configured URL is the whole target. The
  request's path and query are ignored.
- `prefix`: the request's path is normalised (percent-encodings
  canonicalised, `.` segments removed) and appended under the configured
  path; its query follows the endpoint's own. A path with a percent-encoded
  slash or backslash (`%2F`, `%5C`) is refused: an origin that decodes
  before routing would read it as a separator.

A path with a `..` segment, in any percent-encoded spelling, is refused in
both modes, whether or not it would have resolved inside the prefix. The
call fails with `HTTP-request-URI-invalid`, nothing is dialled, and the
`endpoint_call` event records the refusal.

Text injected into the traffic a layer inspects therefore cannot steer a
call to another host, and under `fixed` cannot steer it at all. Under
`prefix` it can pick any route below the configured path, with roxy's
credential attached, so a layer that reflects client-influenced text into
the path should only call a `prefix` endpoint whose routes it is content to
expose. Endpoint responses go back to the layer, not through the rules.

## State (`state`)

`flow.state-get` / `flow.state-put`: a JSON-value store namespaced per
layer, with per-entry TTL, a value size cap and an entry cap. A key is at
most 1 KiB. A miss returns `none`. A write when full, or with a longer key,
returns an error and the layer decides; nothing is evicted.

Each layer's store is separate, so a full or busy store in one layer does
not slow another. Expired entries read as absent straight away. When a new
key meets a full store, expired entries are purged at most every 100 ms.

The store survives a reload. A reload that changes `state.max_entries` or
`state.default_ttl` applies to the live store: stored entries keep their
expiry, and a lower cap evicts nothing but refuses new keys until enough
entries expire. The store of an addon a reload removes is dropped with it;
an addon added back later starts with an empty store.

## Identity

`flow.current()` gives the flow id, connection id, tags, and the principal
as roxy established it: client IP, listener, TLS SNI. These are the safe
keys for per-principal state; a layer should
not trust client-supplied session headers.

## Record (`record`)

`flow.record(kind, json, audit)` writes a `layer_record` event to the flow
log with the flow id, the layer name and a timestamp. String values pass
through the secret redactor, and a value that is not JSON fails the
exchange, as does a kind and document over 64 KiB together
(`budget:message`). Like any audit record it is never dropped: the call
waits while the flow log is behind. `audit: true` also POSTs the record to
the layer's `audit_endpoint`.

## Metrics and log (`metrics`, `log`)

`flow.metric-get(id, [])` reads a metric for this flow's own key (the
metric's key fields evaluated on the request that left the addon stack, so
after any layer changed it); explicit key values are refused. `flow.log` writes to roxy's operational log with the flow id
and layer name; a message over 64 KiB fails the exchange (`budget:message`).

There is no way to terminate or quarantine a client: a layer denies the
exchange and reports through `record` or an endpoint.
