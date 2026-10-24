# Addon configuration

Addons are listed under `addons:`, in the order the request passes through them
([addon model](/design/addon-model)). Each entry is a WASM layer or a
service layer; the two kinds share most keys.

```yaml
addons:
  - name: sentinel
    kind: wasm
    path: /etc/roxy/addons/sentinel.wasm
    mode: enforce
    when: host == "api.anthropic.com" and path starts_with "/v1/messages"
    subscribe: { request: full, response: head }
    capabilities: [state, record, endpoints]
    endpoints:
      monitor-model:
        url: https://api.anthropic.com/v1/messages
        headers: { x-api-key: "${secret:monitor_key}" }
        timeout: 10s
      threat-intel:
        url: https://ti.internal:8443/score
        path: prefix
        private_ok: true
    limits: { max_memory: 128mb, first_byte_timeout: 30s }
    config: { reject_at: 0.8 }

  - name: monitor
    kind: service
    endpoint: sidecar
    mode: observe
    sample: 0.1
    subscribe: { request: head, response: head }
    endpoints:
      sidecar: { url: "http://127.0.0.1:9000/layer", private_ok: true }
    limits: { first_byte_timeout: 2s, max_connections: 4, max_streams: 100 }
```

## Fields

"kind" says which kind of addon takes the key. `roxy check` refuses a key
on the other kind.

| key | kind | values | default | what it does |
|---|---|---|---|---|
| `name` | both | string, unique | required | names the addon in the flow log and in `layer:<name>` |
| `kind` | both | `wasm`, `service` | `wasm` | a WebAssembly component inside roxy, or an external service ([service layer protocol](/reference/service-layers)) |
| `path` | wasm | file path | required | the component. It is compiled when the config loads, and reused across reloads while it is unchanged |
| `endpoint` | service | one of this addon's `endpoints` | required | where the service is |
| `mode` | both | `enforce`, `observe` | `enforce` | whether the addon is in the path or gets a copy ([modes](/design/addon-model#modes)) |
| `when` | both | a rule condition | every exchange | runs the addon only on the exchanges it matches ([choosing exchanges](/reference/addon-configuration#choosing-exchanges)) |
| `sample` | both, observe only | number in (0, 1] | 1 | the share of matching exchanges an observer gets a copy of |
| `subscribe.request` | both | `head`, `full` | `full` | whether the addon sees the request body ([what a layer sees](/reference/addon-configuration#what-a-layer-sees)) |
| `subscribe.response` | both | `head`, `full` | `full` | the same for the response |
| `capabilities` | both | list | none | the [host services](/reference/host-services) the addon may use ([capabilities](/reference/addon-configuration#capabilities)) |
| `config` | both | any YAML value | `null` | passed to the addon as JSON; roxy does not read it |
| `endpoints` | both | map of name to [endpoint](/reference/addon-configuration#endpoints) | none | the URLs the addon may call |
| `limits` | both | [limits](/reference/addon-configuration#limits) | see below | what the addon may cost roxy |

### `endpoints`

Each endpoint is a URL roxy calls on the addon's behalf, with credentials
the addon never sees. Calls go straight to the upstream, not through
other addons or the rules, but the address floor still applies.

| key | values | default | what it does |
|---|---|---|---|
| `url` | `http(s)://host[:port][/path]` | required | the target |
| `path` | `fixed`, `prefix` | `fixed` | whether the addon's path is ignored or appended to the URL ([endpoints](/reference/host-services#endpoints-endpoints)) |
| `headers` | map of header to value | none | added by roxy, replacing any the addon set. Values may use `${secret:name}` ([secrets](/reference/secrets)) |
| `timeout` | duration | `30s` | from the call to the response head |
| `private_ok` | bool | `false` | allows a private, loopback or link-local address |

### `limits`

Limits are there to catch a broken addon, not a slow one. A slow addon
makes its exchanges slow, not refused.

| key | kind | default | what it bounds |
|---|---|---|---|
| `first_byte_timeout` | both | `30s` | how long the addon may hold a request or response head before passing it on or answering. Time spent waiting for the upstream does not count. It also bounds the wait for a free instance or connection. Going over fails the addon |
| `max_memory` | wasm | `64mb` | memory per instance. A Python interpreter in WASM needs 128 to 256 MiB |
| `max_instances` | wasm | `1024` | instances running at once, and so exchanges at once |
| `recycle_after_exchanges` | wasm | `10000` | an instance is replaced after this many exchanges; `0` replaces it after every one |
| `recycle_above_memory` | wasm | three quarters of `max_memory` | an instance using more memory than this is replaced after its exchange |
| `max_connections` | service | `4` | WebSocket connections to the service |
| `max_streams` | service | `100` | exchanges at once on one connection |

Once the addon has answered, its bodies are bound by the usual body idle
timeouts, not by `first_byte_timeout`. There is no total CPU budget.

### Fixed caps

These limits cannot be configured:

| cap | value | on overrun |
|---|---|---|
| a request or response head an addon passes on | 128 KiB, and at most [`limits.max_headers`](/reference/limits#limits) fields | fails the exchange |
| tags on an exchange, including the rules' | 64 tags, 4 KiB in all | fails the exchange |
| a log message, or a record | 64 KiB | fails the exchange |
| a body handed over in one piece | 1 MiB; larger bodies must be streamed | fails the exchange |
| an endpoint call's request body | 16 MiB | refuses the call |
| endpoint calls in progress per exchange | 8 | further calls wait |
| a state key, a state value | 1 KiB, 64 KiB | refuses the call |

`roxy check` refuses a `when` that reads `body.*`, `response.*` or
`ws.*`, a zero limit, `sample` on an enforcing addon, and
`recycle_above_memory` above `max_memory`.

## Capabilities

An addon can only reach roxy's host services that its `capabilities`
grant:

| capability | grants |
|---|---|
| `endpoints` | calls to the addon's `endpoints`. A service layer does not need it: it makes its own calls |
| `state` | reading and writing the [state store](/reference/rate-limits#state) |
| `record` | writing events to the flow log |
| `metrics` | reading metrics |
| `log` | writing to roxy's own log |
| `quarantine` | [quarantining](/guides/operations#quarantine) roxy; enforcing addons only |

Calling a service without its capability fails the addon. Reading the
exchange's details, adding tags and reading `config` need no capability,
but observers cannot add tags or write state. There is no capability for
secrets: credentials go in an endpoint's `headers`.

## Behaviour

### What a layer sees

`subscribe` sets what an addon gets of each direction. With `full`, the
default, the addon reads the body as it streams, and what it passes on is
the body that goes on. With `head`, the addon only gets the head, and the
body goes past it untouched.

- A head-only addon can still refuse, change or answer at the head. If it
  answers a response head with the status it was given, the upstream's
  body follows. If it answers with another status, its own (empty) body
  replaces the upstream's.
- A head-only addon cannot send a body of its own; trying to fails the
  exchange (`unsubscribed:request` or `unsubscribed:response`).
- A head-only observer costs no buffering.
- The rules judge the request that leaves the stack, head and body,
  whoever supplied each.

### Observers

An observer gets copies of the traffic and runs beside the exchange,
which does not wait for it. An observer that keeps up sees every body in
full. It loses its copy, and the exchange carries on, if it falls
`limits.max_observer_lag_bytes` behind, if the
[buffer budget](/reference/limits#buffer-budget) runs out, or if no
instance is free within its `first_byte_timeout`. Each of these logs an
`observer_lagged` event.

### Streaming protocols

Bodies stream through addons chunk by chunk, so streaming protocols work:

| protocol | notes |
|---|---|
| SSE, NDJSON, streaming JSON, multipart, HTTP-based MCP | Chunk boundaries need not match the protocol's messages, so an addon that edits messages has to parse them itself. |
| gRPC | Works, including trailers such as `grpc-status`. A WASM addon that copies a body into a new stream drops its trailers; passing the body through keeps them. |
| WebSockets | Supported over HTTP/1.1 ([below](/reference/addon-configuration#websockets)). |
| `1xx` responses | Not relayed. An addon sends one final response head. |
| other upgrades, raw TCP, WebTransport, HTTP/3 | Not supported. |

An addon that holds a streaming response for approval can send its own
`200 text/event-stream` head straight away, keep the connection alive
with SSE comments such as `: approval pending`, and then stream the
approved events. Once the head has gone, a refusal has to be an event in
the stream, not a new status.

### Choosing exchanges

`when` is a [rule language](/reference/rule-language) condition. An
addon runs only on the exchanges it matches, and the rest pass it at no
cost.

- `when` sees the request as it reaches the addon, after earlier addons
  have changed it.
- It can read request fields, state, metrics and address lists, but not
  bodies, responses or WebSocket messages.
- `tag["x"]` sees tags set by earlier addons, not by the rules, which run
  later.
- If an input it needs is unavailable, the exchange fails with `503`
  rather than skipping the addon.

`sample` is decided from the exchange's id, so the same exchange always
gets the same answer.

### In the flow log

| field | with addons |
|---|---|
| `addons` | the addons that ran, in order |
| `rules`, `decision`, `terminal_rule` | the rules' decision on the request that left the stack. `req` is what the client sent, and `res.status` what it got, which an addon may have changed |
| `decision: answered`, `terminal_rule: layer:<name>` | an addon answered the request itself |
| `terminal_rule: layer:<name>`, `reason: layer_error` | an addon failed; a `layer_error` event follows ([failure](/reference/addon-configuration#failure)) |

### Content codings

When an addon that reads bodies runs on an exchange, roxy decompresses
the bodies for it and removes `content-encoding`. Each body is compressed
again in its original coding as it leaves the addons, so the client and
the upstream get the coding they asked for
([content codings](/reference/http#content-codings)). An addon that sets
its own `content-encoding` has compressed the body itself, and roxy leaves
it as it is. A body in a coding roxy does not know, or a partial response
(`206`), passes through as it is.

`http.decode_for_addons: false` turns this off, so addons see bodies as
sent. The masking of secrets in responses
([redacting responses](/reference/secrets#redacting-responses)) decodes a
response whatever this switch says, and refuses one it cannot decode or a
`206`. Addons then get that response decoded, and its head without
`content-encoding`, even an addon that reads only heads.

### WebSockets

An addon gets a WebSocket's upgrade request like any other request, and
the upstream's `101` as the response. After that, the request body
carries the client's WebSocket frames and the response body the
upstream's, for as long as the WebSocket is open. The addon can read,
change or hold either direction, or refuse the upgrade by answering it.

- The addon must handle both directions at once, since the request body
  only ends when the client closes. The `roxy-addon` SDK does this.
- Frames from the client are masked, as the WebSocket protocol requires.
- An addon that turns the `101` into another status fails the exchange.

### Failure

Every failure is closed. If an enforcing addon crashes, goes over a
limit, uses a capability it lacks, passes on an invalid head, or never
answers, the exchange fails: with `503` and `terminal_rule:
layer:<name>` if the response has not started, and otherwise by closing
the connection before the response is complete. A `layer_error` event
records what went wrong in `kind`, such as `trap`, `budget:<limit>`,
`capability:<name>`, `invalid_request`, `invalid_response`,
`no_response` or `service:<code>`.

A client that disconnects cancels the exchange; that is not the addon's
failure. A WASM instance that failed is thrown away, never reused.

An addon that deliberately stops a body part way through, for example by
dropping a stream without finishing it, is not a failure. Nor is one that
stops reading the response from upstream, which cancels the request
upstream. The flow log records `layer_aborted`, and whoever reads that
body sees it end early.

#### Who is blamed

Only one party is blamed for a failed exchange: the first to fail.

- **An addon's own failure** is that addon's. A request an addon passed
  on that is invalid is blamed on that addon.
- **A client upload that breaks** is the client's, as without addons,
  even if an addon passed the broken body on.
- **An upstream response body that fails** is the upstream's
  (`upstream_body_failed`).
- **A body the buffer budget cannot cover** is the budget's
  (`buffer_budget_exhausted`).
- **An observer is never blamed.**
