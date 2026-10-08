# Host services

Everything a WASM layer can do outside its own streams, each a capability
granted in config
([capabilities](/reference/addon-configuration#capabilities)). The caps on
each (payload sizes, calls in flight, key length) are in
[fixed caps](/reference/addon-configuration#fixed-caps).

## Endpoints (`endpoints`)

`endpoints.call(name, request)`: roxy resolves the name to the configured
URL, attaches the endpoint's headers (replacing any the layer set), applies
the timeout, and enforces the address floor and deny lists. The
layer cannot name a destination and never sees the credentials. Calls do not
pass through the layer stack, so a monitor's own model call cannot recurse
through it; the response goes back to the layer, not through the rules. Each call emits an `endpoint_call` flow event.

- The request body is buffered before the call (at most 16 MiB), and
  reading it counts against the timeout.
- An unknown name, a denied address, a refused path, a timeout and a
  failure reach the layer as distinct `error-code`s.

The endpoint's `path` setting:

| `path` | target |
|---|---|
| `fixed` (default) | the configured URL is the whole target; the request's path and query are ignored |
| `prefix` | the request's path, normalised (percent-encodings canonicalised, `.` segments removed), is appended under the configured path; its query follows the endpoint's own. A percent-encoded slash or backslash (`%2F`, `%5C`) is refused |

A segment that starts with `..`, in any percent-encoded spelling and
whatever follows the dots (`..;x`, which an origin that strips path
parameters reads as `..`), is refused in both modes: the call fails with
`HTTP-request-URI-invalid`, nothing is dialled, and the `endpoint_call`
event records the refusal. Under `prefix`, text a layer
reflects into the path can pick any route below the configured path, with
roxy's credential attached.

## State (`state`)

`flow.state-get` / `flow.state-put`: a JSON-value store namespaced per
layer, with per-entry TTL, a value size cap and an entry cap. A miss returns
`none`. A write when full, or with an over-long key, returns an error;
nothing is evicted. Expired entries read as absent at once; when a new key
meets a full store, expired entries are purged at most every 100 ms.

The store survives a reload. A changed `state.max_entries` or
`state.default_ttl` applies to the live store: entries keep their expiry,
and a lower cap evicts nothing but refuses new keys until enough expire. The
store of an addon a reload removes is dropped; an addon added back later
starts empty.

## Identity

`flow.current()`: the flow id, connection id, tags, and the principal as
roxy established it (client IP, listener, TLS SNI). Key per-principal state
on these, not on client-supplied session headers.

## Record (`record`)

`flow.record(kind, json)` writes a `layer_record` event to the flow
log with the flow id, layer name and timestamp. `kind` and every string
value in the document pass through the secret redactor; a document that
is not JSON fails the exchange. The call
waits while the flow log is behind and is never dropped.

## Metrics and log (`metrics`, `log`)

`flow.metric-get(id, [])` reads a metric for this flow's own key (the key
fields evaluated on the request that left the addon stack); explicit key
values are refused. A key with no entry reads `none` (a rule reads the same
key as 0); an unknown id, or a key field the request does not have, fails
the exchange. `flow.log` writes to roxy's operational log with the
flow id and layer name.

There is no way to terminate or quarantine a client: a layer denies the
exchange and reports through `record` or an endpoint.
