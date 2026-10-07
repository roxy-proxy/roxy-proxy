# Host services

Everything a WASM layer can do outside its own streams, each a capability
granted in config
([capabilities](/reference/addon-configuration#capabilities)). The caps on
what the host holds for a layer (tags, `fields`, `log` and `record`
payloads) are in [addon safety limits](/reference/addon-safety).

## Endpoints (`endpoints`)

`endpoints.call(name, request)`: roxy resolves the name to the configured
URL, attaches the endpoint's headers (replacing any the layer set), applies
the timeout and retries, and enforces the address floor and deny lists. The
layer cannot express a destination, and credentials never enter it. Calls
never pass through the layer stack. Each call emits an `endpoint_call` flow
event; the response goes back to the layer, not through the rules.

- The request body is buffered (up to 16 MiB) so a retry can resend it;
  reading it counts against the timeout. Retries back off from 100 ms.
- One exchange has at most 8 calls in flight at once; further calls wait
  for a permit, also within the timeout.
- An unknown name, a denied address, a refused path, a timeout and a
  failure reach the layer as distinct `error-code`s.

The endpoint's `path` setting decides what the request's path and query
contribute:

| `path` | target |
|---|---|
| `fixed` (default) | the configured URL is the whole target; the request's path and query are ignored |
| `prefix` | the request's path is normalised (percent-encodings canonicalised, `.` segments removed) and appended under the configured path; its query follows the endpoint's own. A path with a percent-encoded slash or backslash (`%2F`, `%5C`) is refused |

A path with a `..` segment, in any percent-encoded spelling, is refused in
both modes, whether or not it would have resolved inside the prefix: the
call fails with `HTTP-request-URI-invalid`, nothing is dialled, and the
`endpoint_call` event records the refusal. Under `prefix`, text injected
into the traffic a layer inspects can pick any route below the configured
path, with roxy's credential attached, so a layer that reflects
client-influenced text into the path should only call a `prefix` endpoint
whose routes it is content to expose.

## State (`state`)

`flow.state-get` / `flow.state-put`: a JSON-value store namespaced per
layer, with per-entry TTL, a value size cap and an entry cap. A key is at
most 1 KiB. A miss returns `none`. A write when full, or with a longer key,
returns an error and the layer decides; nothing is evicted. Expired entries
read as absent straight away; when a new key meets a full store, expired
entries are purged at most every 100 ms.

The store survives a reload. A reload that changes `state.max_entries` or
`state.default_ttl` applies to the live store: stored entries keep their
expiry, and a lower cap evicts nothing but refuses new keys until enough
entries expire. The store of an addon a reload removes is dropped with it;
an addon added back later starts empty.

## Identity

`flow.current()` gives the flow id, connection id, tags, and the principal
as roxy established it: client IP, listener, TLS SNI. These are the keys for
per-principal state; client-supplied session headers are not.

## Record (`record`)

`flow.record(kind, json, audit)` writes a `layer_record` event to the flow
log with the flow id, the layer name and a timestamp. String values pass
through the secret redactor. A value that is not JSON fails the exchange,
as does a kind and document over 64 KiB together (`budget:message`). The
call waits while the flow log is behind; it is never dropped. `audit: true`
also POSTs the record to the layer's `audit_endpoint`.

## Metrics and log (`metrics`, `log`)

`flow.metric-get(id, [])` reads a metric for this flow's own key (the
metric's key fields evaluated on the request that left the addon stack);
explicit key values are refused. `flow.log` writes to roxy's operational
log with the flow id and layer name; a message over 64 KiB fails the
exchange (`budget:message`).

There is no way to terminate or quarantine a client: a layer denies the
exchange and reports through `record` or an endpoint.
