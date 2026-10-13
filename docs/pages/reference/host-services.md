# Host services

Everything a WASM layer can do outside its own streams, each a capability
granted in config
([capabilities](/reference/addon-configuration#capabilities)). The caps on
each (payload sizes, calls in flight, key length) are in
[fixed caps](/reference/addon-configuration#fixed-caps).

## Endpoints (`endpoints`)

`endpoints.call(name, head, body)`: roxy resolves the name to the configured
URL, attaches the endpoint's headers (replacing any the layer set), applies
the timeout, and enforces the address floor and deny lists. The
layer cannot name a destination and never sees the credentials. Calls do not
pass through the layer stack, so a monitor's own model call cannot recurse
through it; the response goes back to the layer, not through the rules. Each call emits an `endpoint_call` flow event.

- An exchange has at most 8 calls in flight. A further `endpoints.call`
  waits for one of them to be answered before it returns, and before roxy
  takes the call's body: a waiting call holds nothing.
- The request body is buffered before the call (at most 16 MiB), and
  reading it counts against the timeout.
- An unknown name, a denied address, a refused path, a timeout and a
  failure reach the layer as distinct `error` variants
  (`destination-not-found`, `destination-denied`, `request-uri-invalid`,
  `timeout`, `internal`), through the `pending-response` the call returns.

The endpoint's `path` setting:

| `path` | target |
|---|---|
| `fixed` (default) | the configured URL is the whole target; the request's path and query are ignored |
| `prefix` | the request's path, normalised (percent-encodings canonicalised, `.` segments removed), is appended under the configured path; its query follows the endpoint's own. A percent-encoded slash or backslash (`%2F`, `%5C`) is refused |

A segment that starts with `..`, in any percent-encoded spelling and
whatever follows the dots (`..;x`, which an origin that strips path
parameters reads as `..`), is refused in both modes: the call fails with
`request-uri-invalid`, nothing is dialled, and the `endpoint_call`
event records the refusal. Under `prefix`, text a layer
reflects into the path can pick any route below the configured path, with
roxy's credential attached.

## State (`state`)

`flow.state-get` / `flow.state-put`: the [state store](/reference/rate-limits#state)
the rules read as `state["key"]` and write with `set_state`. A key a layer
writes is the key a rule reads, so a layer can leave a mark for a rule to
deny on, and read what a rule left. Values are strings; a layer that wants
`state["k"] == "yes"` to match writes `yes`. A `state-put` without a TTL
gets the store's default (one hour). A miss returns `none`. A write when
full, or with a key over 1 KiB or a value over 64 KiB, returns an error;
nothing is evicted. The store survives a reload, under
`limits.max_state_entries`.

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

A layer cannot terminate a client or quarantine the proxy: it denies the
exchange and reports through `record` or an endpoint. Quarantine is a rule
action ([quarantine](/guides/operations#quarantine)).
