# Service layer protocol

A `kind: service` layer is an external service at its position in the stack
exactly as a WASM layer is ([addon model](/design/addon-model)). The
exchange's two lanes stream through it: the request streams into it and it
streams back the request to forward, if it forwards one; the response from
upstream streams into it and it streams back the response the client gets.
It may pass bytes through, rewrite or hold them, or originate its own, on
either lane, at any time. Each lane each way is shaped like an HTTP/2
stream: a head, body bytes, trailers, and an end, or a cut; its reader may
stop it.

```yaml
addons:
  - name: sentinel
    kind: service
    endpoint: sidecar                   # one of this addon's endpoints
    mode: enforce                       # enforce | observe
    endpoints:
      sidecar: { url: "http://127.0.0.1:9000/layer", private_ok: true }
    limits:
      first_byte_timeout: 2s            # to get a stream, then to the service's answer, with no clock while its forward is upstream; an observer's end (default 30s)
      max_connections: 4                # per endpoint (default 4)
      max_streams: 100                  # exchanges at once per connection (default 100)
```

`path` and the WASM limits are refused on a service layer;
`max_connections` and `max_streams` are refused on a WASM layer, and at
zero. `capabilities` and `config` mean the same for both kinds
([host services](/reference/host-services)).

## Transport

Long-lived WebSocket connections to each endpoint, each carrying many
exchanges as **streams**.

- Subprotocol `roxy.layer.v0`; a service that does not accept it fails the
  handshake.
- The URL is the endpoint's (`http` → `ws`, `https` → `wss`, with the
  upstream's certificate verification), dialled through the connector (the
  address floor and deny lists apply), never through other layers or the
  rules. The handshake carries the endpoint's `headers`. Each connection is
  an `endpoint_call` event against the flow whose exchange opened it.
- **Pooling.** A new exchange takes a stream on an idle connection if
  there is one; otherwise it opens a connection while the endpoint has
  fewer than `max_connections`; otherwise it takes the connection with the
  fewest streams, and once every connection has `max_streams` streams it
  waits for a free one within `first_byte_timeout`. Concurrent exchanges
  spread across connections because each connection is one reader and
  one writer on each side: a service that handles each connection on one
  task gets one core per connection. Idle connections stay open. A
  connection that closes or fails fails its in-flight exchanges closed;
  later exchanges go to another connection.
- **Reload.** New exchanges get new connections, dialled under the new
  policy and secrets. Old connections take no new streams: an idle one
  closes at once, a busy one when its last exchange ends.

### Frames

Text frames are JSON control messages, each with a `stream` field. Binary
frames are body bytes: a 4-byte big-endian stream id, one direction byte
(`0` request body, `1` response body), then the bytes. roxy numbers the
streams on a connection from 1 upward and never reuses a number.

A stream opens with an `open` message from roxy:

```json
{"type":"open","stream":7,"flow":"01J…","conn":"01J…","layer":"sentinel",
 "mode":"enforce","subscribe":{"request":"full","response":"head"},
 "client_ip":"10.0.0.5","listener":"proxy",
 "sni":"api.example.com","tags":["a","b"],
 "capabilities":["state","record"],"config":{"reject_at":0.8}}
```

`client_ip` is `client.ip` as the rules see it
([fields](/reference/rule-language#fields)). `sni` is left out when there is
none. `capabilities` are the layer's grants, and `config` its `config:`
value, what a WASM layer reads through `flow.config`. `subscribe` is the
layer's
[subscription](/reference/addon-configuration#what-a-layer-sees): for a
direction it names `head`, roxy sends the head and its end with no bytes
between, and the service answers the same way; bytes the service sends for
that body fail the exchange closed (`unsubscribed:<direction>`), and the
body the service did not see goes on with the head it passed on, framed as
it came: its `content-length` is kept, as it is not for a WASM layer whose
own body is still open ([what a layer
sees](/reference/addon-configuration#what-a-layer-sees)). The pair (`flow`, `layer`) is unique
and stable (two layers using the same endpoint in one flow get separate
streams with different `layer`s), so a service can key its state on it.

Every message carries `stream`; it is left out below.

```text
roxy → service   {"type":"open",…}
                 {"type":"request","method":…,"url":…,"headers":[[n,v],…]}  bytes…  {"type":"request_end"}
service → roxy   {"type":"request",…}  bytes…  {"type":"request_end"}       forward this request (`next`), at most once
                 {"type":"request_end"} alone                             nothing forwarded
roxy → service   {"type":"response","status":…,"headers":[…]}  bytes…  {"type":"response_end"}
                                                                          the response from upstream to what it forwarded
                 {"type":"response_end"} alone, with or without "error"    nothing came back: it forwarded nothing, or its forward was cut
service → roxy   {"type":"response",…}  bytes…  {"type":"response_end"}   the client's response, exactly once
either way       {"type":"trailers","dir":"request"|"response","headers":[…]}  a body's trailers, after its bytes
                 an end may carry "error":"…": a cut, the body stopped short of it
                 {"type":"stop","dir":"request"|"response"}               the sender reads no more of that body
                 {"type":"credit","dir":"request"|"response","bytes":n}  flow control (below)
                 {"type":"reset","message":"…"}                           abandon the stream
service → roxy   host-service calls, any time the stream is open (below)
roxy → service   {"type":"result","id":n,"value":…} or {"type":"result","id":n,"error":"…"}
```

Each direction of the stream is a lane each way. A lane's events, in
order: at most one head, bytes, at most one `trailers`, then one end. An
end may come before a head: the lane then carries nothing. A lane whose
end carries `"error"` is cut: what came before it is not the whole. Trailers
are delivered to the consumer only after a clean end and successful length
validation, because sending HTTP trailers completes the message.

| rule | detail |
|---|---|
| heads | `url` is absolute; `headers` are end-to-end fields as a WASM layer sees them (no hop-by-hop or framing fields), at most [`limits.max_headers`](/reference/limits#limits) of them in a head the service sends: more is a protocol violation. `content-length` is present when the length is known and not zero; one the service sends is enforced: more or fewer bytes than declared is a protocol violation |
| header values | byte strings: each byte is the code point of the same value (ISO-8859-1), so obs-text bytes (`http.allow_obs_text`) read as Latin-1 and go back as the same bytes. A code point above U+00FF is a protocol violation |
| order | on each lane, from each side: head, bytes, trailers, end. Bytes or trailers before their head or after their end, a second head, a second `trailers`, a second end: each is a protocol violation. The two lanes are independent, and so are the two sides: roxy sends its `response` head as soon as the layer upstream answers, even while the client's body is still arriving; the service sends its `request` at most once and its `response` exactly once, in either order, and may send either while the other lane is still streaming. A `request_end` with no `request` before it forwards nothing. Answering says nothing about forwarding, and a service that wants nothing forwarded forwards nothing |
| cuts | an end that carries `"error"` cuts its lane: the bytes before it are not the whole. From roxy, the body stopped short on its way (an in-flight deny cut it, the upstream's body failed, the client gave up, the service's own forward was cut); the text is for diagnostics only, is not stable, and may be another layer's own. The stream, and the service's own lanes, go on. A `response_end` with `"error"` and no `response` before it says nothing came back for the forward: it was cut. From the service, a cut is its own doing and not a fault: the exchange's record says `forward_aborted` or `answer_aborted`, and what is downstream of the cut lane sees it cut. An error on the end of a head-only lane, which carries no body to cut, is a protocol violation |
| stop | `stop` says its sender reads no more of that body: the receiver sends no more of it, need not end it, and credits nothing for it. roxy sends `stop` for the request lane when the upstream stops reading the forward. A service that stops the response lane gives the forward up: nothing upstream carries a response nobody waits for, so the upstream request is cancelled. A service that stops the request lane keeps everything else |
| end | a stream ends when the service has ended both its lanes, or roxy has stopped them: the `response_end` of the client's response, and the `request_end` of the request it forwarded or of the forward it never made. Nothing is inferred from a last message. A forward is carried upstream only while the service waits for its response: a service that ends its stream without reading the upstream response gives that forward up. Keeping its request lane open permits forwarding to continue after answering. A service that forwards and never answers is failed by its clock once the response from upstream has reached it. Either side may end a stream early with `reset`; roxy resets a stream only when the layer is torn down (the client went away, the layer downstream let go of its answer, a deadline passed, the service broke the protocol) and sends nothing after the `reset`. A stream roxy gives up before its `open` has gone out is dropped without a `reset`. A service that resets an enforce stream fails that exchange closed. Each side ignores messages for a stream it has ended; roxy drops body bytes sent on an ended stream without crediting them back |
| flow control | per stream and per body, each way. Each body of a stream starts with 256 KiB of credit each way; the receiver grants more with `credit` as it consumes, and the sender may have no more bytes of that body outstanding than granted. roxy grants in steps of 64 KiB as the layer upstream (or the client) reads. Sending past credit is a protocol violation. Control messages are not counted |

### Host services

A service reaches the [host services](/reference/host-services) a WASM
layer has by message, each behind the same capability granted in the
layer's `capabilities`, and answered by the same host: a call means the
same, is refused for the same reasons and fails the layer with the same
`layer_error.kind` (and the exchange with it, in enforce mode), whichever
kind of layer makes it. Every call carries
an `id` of the service's choosing (an unsigned 64-bit integer) and is
answered with a `result` carrying the same `id`: `value` is what the call
returns (`null` for a call that returns nothing), `error` a refusal of what
the service passed.

| service → roxy | capability | roxy → service |
|---|---|---|
| `{"type":"log","id":n,"level":"info","message":"…"}` (`trace`, `debug`, `info`, `warn`, `error`) | `log` | `{"type":"result","id":n,"value":null}` |
| `{"type":"record","id":n,"kind":"…","data":<json>}` | `record` | `{"type":"result","id":n,"value":null}` |
| `{"type":"add_tag","id":n,"tag":"…"}` | none; enforce only | `{"type":"result","id":n,"value":null}` |
| `{"type":"state_get","id":n,"key":"…"}` | `state` | `{"type":"result","id":n,"value":"…"}` (`null` for a miss) |
| `{"type":"state_put","id":n,"key":"…","value":"…","ttl_ms":n?}` | `state`; enforce only | `{"type":"result","id":n,"value":null}`, or `"error"` for a key or value over its cap |
| `{"type":"metric_get","id":n,"metric":"…"}` | `metrics` | `{"type":"result","id":n,"value":n}` (`null` for a key with no entry) |
| `{"type":"quarantine","id":n}` | `quarantine`; enforce only | `{"type":"result","id":n,"value":null}`; the exchange, and every one after it, is refused `_quarantined` |

A call may be sent at any point while the stream is open, including
part-way through a body. Calls run in order, one at a time per stream,
beside the bodies: they neither wait for nor hold up the heads and bytes,
and roxy promises no order between a call and the heads or bytes the
service sends after it. The service orders it: it awaits the `result`
before sending whatever the effect must precede, be that the request, the
response or the rest of a body
([ordering across layers](/design/addon-model#ordering-across-layers)). A call's tag or state write is seen by
this exchange's admission rules only if it lands before the request is
forwarded; otherwise by the next rule that reads it: for a tag, which
lives on this exchange, an in-flight re-check of it; for state, which
persists, that or a later exchange's admission. A write does not itself
trigger a re-check ([#509](https://github.com/roxy-proxy/roxy-proxy/issues/509)).
At most 64 calls may be waiting, and more is a protocol violation. Calls
the service sent before the stream ended still run once it has (a `record`
sent just before its `response_end`, say): the effect stands, but the
`result` is not sent, and one that fails is logged (`layer_error`) without
stopping the rest; the stream keeps its place on the connection until they
have run. A call sent on a stream that has ended is dropped and never
answered.

A call without its capability, a `log` message or a `record` kind and
document together over 64 KiB, an `add_tag`, `state_put` or `quarantine`
from an observer, or a full state store fails the layer (`layer_error`,
kind `capability:<name>`, `budget:message`, `budget:tags` or `host`) and
resets the stream: in enforce mode that fails the exchange, in observe
mode the exchange goes on. The `result` `error` is only for what the
service passed.
roxy's own record of a call names its `id` as `call`: on the
`layer_record` a `record` writes, on the `layer_error` a failed call
causes, on the operational log line a `log` writes, and on the cause of
the `quarantined` event a `quarantine` trips. `endpoints.call`
has no message: a service calls what it needs itself.

## Semantics

- **The forwarded request** gets the same checks as a WASM layer's `next`:
  re-validated as strictly as a client request, then judged by the rules.
  What comes back on the response lane is whatever the upstream stages
  produced: the upstream's response, the rules' refusal, or an HTTP error
  response for a failure upstream. The service may pass on or reshape any
  of these responses. The service's own response is handled as a WASM layer's.
- **Deadlines.** `first_byte_timeout` bounds getting a stream, then the
  service's answer, as it does a WASM layer's: from roxy's `request` head
  until the service answers or forwards. The clock is suspended while its
  forward awaits an upstream outcome. A response head or a headless
  `response_end` restores the whole budget, unless the service has already
  answered; receiving a head does not wait for the response body to end.
  An observer gets that budget from roxy's last message to end its stream. A
  stream has no overall deadline. Body-idle and upstream timeouts still
  apply while the service's answer clock is suspended.
- **An early `response`** goes to the client at once, however far the
  forward upstream has got, and its body is the client's response from then
  on; the response from upstream still arrives on the service's lane for it
  to read. If the stack upstream fails after that, what arrives is the
  HTTP error response for that failure, or the lane ending with the error if its
  body had started; the service's answer stands either way. The forward
  runs on only while the service waits for its response (the end rule
  above).
- **Failure is closed** in enforce mode: a failed connection or handshake,
  a protocol violation (bad JSON, a message out of order, bytes of a body
  that is not open, an invalid head, a broken length, bytes past the
  credit), a missed deadline, a reset from the service or a lost connection
  denies the exchange (`503`, `layer:<name>`) before the response head and
  cuts the body after it; a body cut short never reaches the upstream or
  the client as complete. `layer_error.kind` is `service:connect`,
  `service:protocol`, `service:timeout` or `service:closed`; bytes of a
  head-only body are `unsubscribed:<direction>`. A `response_end` with no
  `response` before it is no answer: `no_response`.
- **A body that fails on its way to the service is not its failure**: its
  lane ends with the error, no `layer_error` is logged, and the stream
  goes on ([who is blamed](/design/addon-model#who-is-blamed)).
- **One stream's failure is its own**: a violation resets that stream
  only. Broken framing fails the whole connection: a text frame that is not
  a JSON object with a valid `stream`, a binary frame shorter than its
  5-byte prefix or with an unknown direction byte, or a stream id roxy
  never opened. Every exchange on it fails closed (`service:protocol`) and
  roxy closes it.
- **[Observe mode](/design/addon-model#modes)** uses the same streams: the
  service gets copies of both directions; `credit` is honoured, `reset`
  ends the stream and is logged (`layer_error`, `service:closed`),
  host-service calls run as in enforce mode (less the ones an observer may
  not make), and the heads, bytes and ends the service sends go nowhere.
  The stream ends as an enforce stream does, once the service has ended
  both its lanes (a `request_end` and a `response_end`, each with or
  without a head before it); a `stop` from the service ends roxy's copy.
  So a service can read the copies through and then `record` what it saw
  before ending the stream, as a WASM observer can. From roxy's last
  message the service has `first_byte_timeout` to end the stream, or roxy
  fails it (`service:timeout`); a cut copy (`observer_lagged`) is reset.
  Waiting for credit is falling behind, so grant extra credit as an observe
  stream opens (`roxy_layer.py` grants 16 MiB per body). Body bytes the
  service sends on an observe stream are discarded and credited back in
  steps of 64 KiB; past credit is still a violation.
- **WebSockets** run through the stream
  ([addon configuration](/reference/addon-configuration#websockets)). The
  `101` from upstream arrives as roxy's `response` head, and the service
  answers with a `101` of its own. At the client edge, only final statuses
  200–599 or a `101` for a real upstream upgrade are accepted; intermediate
  lane heads may be rewritten by a downstream layer before reaching it.
  After the upgrade, the request body carries the client's bytes and the
  response body the upstream's, with no length cap on either, until each side closes; the stream holds its place on the
  connection for as long as the WebSocket is open. roxy sends no
  `request_end` before the `101`, so a service that waits for the end of
  the request body never forwards an upgrade and fails on
  `first_byte_timeout`: forward as the request arrives. When the relay
  ends, roxy closes the client's connection and resets the stream if its
  bodies have not both ended.

The [quickstart](/quickstart)'s sidecar,
[`roxy_layer.py`](https://github.com/roxy-proxy/roxy-proxy/blob/main/examples/quickstart/sentinel/roxy_layer.py),
is the service side of the protocol for asyncio: it handles streams, credit
and resets and hands a handler one exchange at a time.

The Python helper exposes received trailers through `trailers` and
`response_trailers`. Its byte-iterator forwarding helpers do not send
trailers; a service using those helpers must not assume trailer-preserving
passthrough.
