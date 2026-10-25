# Service layer protocol

A `kind: service` addon is an external service that each exchange streams
through, at its place in the [stack](/design/addon-model). roxy streams
the request to the service, and the service streams back the request to
forward, if it forwards one. roxy then streams the response from upstream
to the service, and the service streams back the response the client
gets. The service can pass bytes through, change them, hold them, or send
its own, in either direction, at any time.

```yaml
addons:
  - name: sentinel
    kind: service
    endpoint: sidecar                   # one of this addon's endpoints
    mode: enforce                       # enforce | observe
    endpoints:
      sidecar: { url: "http://127.0.0.1:9000/layer", private_ok: true }
    limits:
      first_byte_timeout: 2s
      max_connections: 4                # per endpoint
      max_streams: 100                  # exchanges at once per connection
```

The other keys are as for any addon
([addon configuration](/reference/addon-configuration)). For a minimal
service and a Python implementation of this protocol, see
[writing addons](/guides/writing-addons#a-service-layer).

## Transport

roxy keeps long-lived WebSocket connections to the service, each carrying
many exchanges at once. Each exchange is a **stream** on a connection.

* The WebSocket subprotocol is `roxy.layer.v7`. A service that does not
  accept it fails the handshake.
* roxy connects to the endpoint's URL (`http` becomes `ws`, `https`
  becomes `wss`), checked by the address floor, with the endpoint's
  `headers`.
* A new exchange uses an idle connection if there is one, otherwise opens
  a new one up to `max_connections`, otherwise shares the least busy
  connection. Each connection is read and written in order, so a service
  that handles each connection on one task gets one core per connection.
* If a connection fails, the exchanges on it fail. Later exchanges use
  another connection.
* After a reload, new exchanges use new connections, and old connections
  close once their exchanges finish.

### Frames

Text frames are JSON messages, each with a `stream` field. Binary frames
are body bytes: a 4-byte big-endian stream id, one byte for the direction
(`0` request body, `1` response body), then the bytes. roxy numbers the
streams on a connection from 1 upwards and never reuses a number.

A stream starts with an `open` message from roxy:

```json
{"type":"open","stream":7,"flow":"01J…","conn":"01J…","layer":"sentinel",
 "mode":"enforce","subscribe":{"request":"full","response":"head"},
 "client_ip":"10.0.0.5","listener":"proxy",
 "sni":"api.example.com","tags":["a","b"],
 "capabilities":["state","record"],"config":{"reject_at":0.8}}
```

`client_ip` is `client.ip` as rules see it. `sni` is left out when there
is none. `capabilities` and `config` are the addon's. `flow` and `layer`
together identify the exchange and addon, so a service can key its state
on them.

The rest of the exchange, with `stream` left out:

```text
roxy → service   {"type":"request","method":…,"url":…,"headers":[[n,v],…]}  bytes…  {"type":"request_end"}
service → roxy   {"type":"request",…}  bytes…  {"type":"request_end"}       the request to forward, at most once
                 {"type":"request_end"} alone                             forward nothing
roxy → service   {"type":"response","status":…,"headers":[…]}  bytes…  {"type":"response_end"}
                                                                          the response to what the service forwarded
                 {"type":"response_end"} alone                            no response: nothing was forwarded, or the forward failed
service → roxy   {"type":"response",…}  bytes…  {"type":"response_end"}   the client's response, exactly once
either way       {"type":"trailers","dir":"request"|"response","headers":[…]}  trailers, after the body
                 {"type":"stop","dir":"request"|"response"}               "I will read no more of this body"
                 {"type":"credit","dir":"request"|"response","bytes":n}  flow control (below)
                 {"type":"reset","message":"…"}                           abandon the stream
service → roxy   host-service calls (below)
roxy → service   {"type":"result","id":n,"value":…} or {"type":"result","id":n,"error":"…"}
```

So each stream carries four HTTP messages: the request into the service,
the request out of it, the response into it and the response out of it.
Each message is a head, then body bytes, then optional trailers, then an
end, in that order.

| rule | detail |
|---|---|
| heads | `url` is absolute. `headers` are the end-to-end headers, with no hop-by-hop or framing fields, and at most [`limits.max_headers`](/reference/limits#limits) of them. If the service sends `content-length`, its body must match it |
| header values | strings in which each character is one byte (ISO-8859-1) |
| trailers | request trailers from the service follow the rules for a client's ([trailers](/reference/http#trailers)) |
| order | the four messages are independent. The service can send its response before, during or without forwarding the request |
| errors | an end message may carry `"error"`, meaning the body stopped early and is incomplete. When the service does this to its own message it is not a fault: the flow log records `layer_aborted`, unless a fault or the client leaving came first |
| stop | `stop` tells the other side to send no more of that body. When the service stops reading the response, the upstream request is cancelled |
| end of stream | the stream ends when all four messages have ended or been stopped and all host-service calls have been answered. Either side can abandon it with `reset`, and a reset from the service fails an enforcing exchange |
| flow control | each body starts with 256 KiB of credit in each direction. The receiver grants more with `credit` as it reads. Sending more than the credit allows is a protocol error. Messages other than body bytes are not counted |
| head-only | when `subscribe` is `head` for a direction, roxy sends only the head and the service answers with only a head (or with an end alone, to send nothing). The body bypasses the service. Bytes, trailers or an end after the head fail the exchange (`unsubscribed:<direction>`) |

### Host services

A service reaches the same [host services](/reference/host-services) as a
WASM addon, by message, with the same capabilities. Each call has an `id`
chosen by the service (an unsigned 64-bit integer), and roxy answers with
a `result` carrying the same `id`: `value` is the answer (`null` for
calls that return nothing), and `error` says the call was refused.

| service → roxy | capability | roxy → service |
|---|---|---|
| `{"type":"log","id":n,"level":"info","message":"…"}` (`trace`, `debug`, `info`, `warn`, `error`) | `log` | `{"type":"result","id":n,"value":null}` |
| `{"type":"record","id":n,"kind":"…","data":<json>}` | `record` | `{"type":"result","id":n,"value":null}` |
| `{"type":"add_tag","id":n,"tag":"…"}` | none; enforce only | `{"type":"result","id":n,"value":null}` |
| `{"type":"state_get","id":n,"key":"…"}` | `state` | `{"type":"result","id":n,"value":"…"}` (`null` if not set) |
| `{"type":"state_put","id":n,"key":"…","value":"…","ttl_ms":n?}` | `state`; enforce only | `{"type":"result","id":n,"value":null}` |
| `{"type":"metric_get","id":n,"metric":"…"}` | `metrics` | `{"type":"result","id":n,"value":n}` (`null` if no count yet) |
| `{"type":"quarantine","id":n}` | `quarantine`; enforce only | `{"type":"result","id":n,"value":null}` |

Calls can be sent at any time while the stream is open. They run one at a
time, in order, alongside the bodies, not in sequence with them. If an
effect must happen before something else, such as a tag before the
request is forwarded, wait for its `result` before sending that
([ordering across layers](/design/addon-model#ordering-across-layers)).
At most 64 calls can be waiting at once.

A call without its capability, a message over 64 KiB, or a tag or state
write from an observer fails the addon and resets the stream. The flow
log records the call's `id` as `call` on the events it causes. A service
makes endpoint calls itself, so there is no message for them.

### Versions

roxy offers only `roxy.layer.v7`. WASM addons use `roxy:addon@0.3.0`.

## Semantics

* **The forwarded request** is checked and judged by the rules, as a WASM
  addon's is. The response that comes back may be the upstream's, a
  refusal from the rules, or an error for a failure upstream. The service
  can pass any of these on or change them.
* **Deadlines.** `first_byte_timeout` runs from roxy's request head until
  the service answers or forwards. It pauses while the forwarded request
  is upstream, and starts again in full when the response arrives. There
  is no overall deadline on a stream, but body idle timeouts apply.
* **An early response** goes to the client at once. The upstream's
  response still arrives for the service to read, and the service's
  answer stands whatever happens upstream.
* **Failure is closed.** In enforce mode, a failed connection, a protocol
  error (bad JSON, a message out of order, a bad head, too many bytes), a
  missed deadline or a reset fails the exchange with `503` if the
  response has not started, and ends the response early if it has. The
  `layer_error` kind is `service:connect`, `service:protocol`,
  `service:timeout` or `service:closed`. A `response_end` with no
  `response` before it is `no_response`.
* **A body that fails on its way to the service is not its fault.** Its
  end carries the error, and the stream carries on.
* **A protocol error affects one stream**, unless the framing itself is
  broken (a text frame that is not a JSON object with a valid `stream`, a
  short binary frame, an unknown stream). Then the whole connection fails.
* **Observe mode** streams go one way. roxy sends copies of the request
  and response. The service sends only `credit`, `stop`, host-service
  calls, `reset`, and `{"type":"close"}` when it is done, which must come
  within `first_byte_timeout` of roxy's last message. Waiting for credit
  is falling behind, so grant generous credit when an observe stream
  opens.
* **WebSockets** run through the stream. The upstream's `101` arrives as
  the response head, and the service answers with a `101` of its own.
  After that, the request body carries the client's bytes and the
  response body the upstream's, until each side closes. roxy sends no
  `request_end` before the `101`, so the service must forward the upgrade
  as it arrives rather than waiting for the request to end.
