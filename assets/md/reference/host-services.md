# Host services

What an addon can ask roxy to do beyond handling its own traffic. Each
service needs a capability granted in the addon's config
([capabilities](/reference/addon-configuration#capabilities)). A WASM
addon calls them through the `flow` and `endpoints` imports. A service
layer sends the matching messages
([service layers](/reference/service-layers#host-services)). Either way
they behave the same. Size limits are in
[fixed caps](/reference/addon-configuration#fixed-caps).

## Endpoints (`endpoints`)

`endpoints.call(name, head, body)` sends a request to an endpoint named in
the addon's config. roxy adds the endpoint's configured headers, applies
its timeout, and checks the address floor. The addon cannot choose a
destination of its own and never sees the endpoint's credentials. The
call does not go through the addons or the rules, so a monitor's own
model call is not judged by itself. Each call is logged as an
`endpoint_call` event.

* An exchange can have up to 8 calls in progress. A further call waits for
  one to finish.
* The request body is buffered before the call, up to 16 MiB.
* Failures come back as distinct errors: `destination-not-found`,
  `destination-denied`, `request-uri-invalid`, `timeout` or `internal`.

The endpoint's `path` setting:

| `path` | target |
|---|---|
| `fixed` (default) | the configured URL; the path the addon gives is ignored |
| `prefix` | the addon's path, normalised, is appended to the configured path. An encoded slash or backslash (`%2F`, `%5C`) is refused |

A path segment starting with `..`, however it is encoded, is refused
(`request-uri-invalid`). With `prefix`, an addon that copies untrusted
text into the path can reach any route under the configured path, with
roxy's credentials attached.

## State (`state`)

`flow.state-get` and `flow.state-put` read and write the
[state store](/reference/rate-limits#state) that rules use. A key an
addon writes is the same key a rule reads as `state["key"]`, so an addon
can leave a mark for a rule to deny on. Values are strings. Entries
expire after one hour unless the addon sets a TTL. A full store fails the
exchange. Only enforcing addons can write.

## Identity and config

`flow.current()` returns the exchange's id, its tags, and the client as
roxy sees it: address, listener and SNI. Key per-client state on these
rather than on headers the client controls. `flow.config()` returns the
addon's `config:` as JSON.

## Record (`record`)

`flow.record(kind, json)` writes a `layer_record` event to the flow log.
Secret values are removed from it. It waits if the flow log is behind,
and is never dropped.

## Metrics and log (`metrics`, `log`)

`flow.metric-get(id, [])` reads a metric's value for this exchange's own
key. `flow.log` writes to roxy's own log, tagged with the exchange and the
addon.

## Quarantine (`quarantine`)

`flow.quarantine()` [quarantines](/guides/operations#quarantine) roxy:
the current exchange and every one after it are refused until an operator
or the control plane lifts it. Use it only when the workload must be
stopped; to refuse one request, answer it. Only enforcing addons can call
it, and a config that grants it needs `roxy run --state-dir`.
