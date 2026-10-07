# Service layer protocol

A `kind: service` layer is an external service at its position in the stack
exactly as a WASM layer is ([addon model](/design/addon-model)). The
request streams into it; it streams back the request to forward, which roxy
passes down the stack; the response from below streams into it, and it
streams back the response the client gets. It may pass bytes through,
rewrite them, hold them back, answer itself, or deny.

```yaml
addons:
  - name: sentinel
    kind: service
    endpoint: sidecar                   # one of this addon's endpoints
    mode: enforce                       # enforce | observe
    endpoints:
      sidecar: { url: "http://127.0.0.1:9000/layer", private_ok: true }
    limits:
      first_byte_timeout: 2s            # to get a stream, then to each of the service's heads (default 30s)
      max_connections: 4                # per endpoint (default 4)
      max_streams: 100                  # exchanges at once per connection (default 100)
```

`path`, `capabilities`, `config`, `audit_endpoint` and the WASM limits are
refused on a service layer; `max_connections` and `max_streams` are refused
on a WASM layer and at zero.

## Transport

roxy keeps long-lived WebSocket connections to each service endpoint and
carries many exchanges over each as **streams**.

- Subprotocol `roxy.layer.v3`; a service that does not accept it fails the
  handshake.
- The URL is the endpoint's (`http` → `ws`, `https` → `wss`, with the
  upstream's certificate verification), dialled through the connector (the
  address floor and deny lists apply), never through other layers or the
  rules. The handshake carries the endpoint's `headers`.
- Each connection is recorded as an `endpoint_call` event against the flow
  whose exchange opened it.
- **Pooling.** A new exchange takes a stream on an open connection; roxy
  opens another only when every open one has `max_streams` streams, up to
  `max_connections`, and then the exchange waits for a free stream within
  `first_byte_timeout`. Idle connections stay open. A connection that
  closes or fails fails its in-flight exchanges closed; later exchanges go
  to another connection, so a service should not close a connection it is
  not done with.
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
 "mode":"enforce","client_ip":"10.0.0.5","listener":"proxy",
 "sni":"api.example.com","tags":["a","b"]}
```

`sni` is left out when there is none. The pair (`flow`, `layer`) is unique
and stable: two layers using the same endpoint in one flow get separate
streams with different `layer`s, so a service can key its state on the
pair.

Every message carries `stream`; it is left out below.

```text
roxy → service   {"type":"open",…}
                 {"type":"request","method":…,"url":…,"headers":[[n,v],…]}  bytes…  {"type":"request_end"}
service → roxy   one of:
                   {"type":"request",…}  bytes…  {"type":"request_end"}     forward this request (`next`)
                   {"type":"response","status":…,"headers":[…]}  bytes…  {"type":"response_end"}
                                                                          answer instead; nothing is forwarded
                   {"type":"deny","status":403,"message":"…"}             refuse (status 4xx/5xx, both optional)
then, if it forwarded:
roxy → service   {"type":"response","status":…,"headers":[…]}  bytes…  {"type":"response_end"}
service → roxy   {"type":"response",…}  bytes…  {"type":"response_end"}   the client's response
                 or {"type":"deny",…}
either way       {"type":"credit","dir":"request"|"response","bytes":n}  flow control (below)
                 {"type":"reset","message":"…"}                           abandon the stream
```

- `url` is absolute; `headers` are end-to-end fields as a WASM layer sees
  them (no hop-by-hop or framing fields).
- A header value is a byte string: each byte is the code point of the same
  value (ISO-8859-1), so obs-text bytes (`http.allow_obs_text`) read as
  Latin-1 and go back as the same bytes. A value with a code point above
  U+00FF is a protocol violation.
- Heads carry `content-length` when the length is known. A
  `content-length` the service sends is enforced: more or fewer bytes than
  declared is a protocol violation.
- **Order.** Within each body, from each side, messages are strictly head,
  bytes, end; bytes before their head or after their end are a protocol
  violation. The request body and the response body are independent, and
  so are the two sides: roxy sends its `response` head as soon as the layer
  below answers, even while the client's body is still arriving; a service
  may send its `response` (or `deny`) while still forwarding the request
  body, and may start forwarding the request before the client's body has
  ended.
- **End.** A stream ends when the service has sent its last message: the
  `response_end` of the client's response (or a `deny`), and the
  `request_end` of the request it forwarded if it was still sending that.
  roxy sends nothing more on it after that. Either side may end a stream
  early with `reset`; roxy resets when the client goes away, a deadline
  passes or the service broke the protocol, and sends nothing after the
  `reset`. A stream roxy gives up before its `open` has gone out is dropped
  without a `reset`. A service that resets an enforce stream fails that
  exchange closed. Each side ignores messages for a stream it has ended;
  roxy still credits back body bytes among them.
- **Flow control.** Body bytes are flow-controlled per stream and per
  body, each way. Each body of a stream starts with 256 KiB of credit each
  way; the receiver grants more with `credit` as it consumes, and the
  sender may have no more bytes of that body outstanding than granted. roxy
  grants credit as the layer below (or the client) reads, in steps of
  64 KiB. Sending past credit is a protocol violation. Control messages are
  not counted.

## Semantics

- **What the service forwards gets the same checks as a WASM layer's
  `next`**: re-validated as strictly as a client request, then judged by
  the rules. Its response is handled as a WASM layer's.
- **Deadlines.** `first_byte_timeout` bounds getting a stream and each of
  the service's heads: its first answer from roxy's `request` head, its
  second from roxy's `response` head (not from the end of the response
  body). A stream has no overall clock.
- **Failure is closed** in enforce mode: a failed connection or handshake,
  a protocol violation (bad JSON, a message out of order, bytes of a body
  that is not open, an invalid head, a broken length, bytes past the
  credit), a missed deadline, a reset from the service or a lost connection
  denies the exchange (`503`, `layer:<name>`) before the response head and
  cuts the body after it. `layer_error.kind` is `service:connect`,
  `service:protocol`, `service:timeout` or `service:closed`.
- **A body that fails on its way to the service is not its failure.** A
  client upload that breaks closes the connection as it would without the
  layer; an upstream response body that fails before the service's second
  head gets a `502` (`upstream_body_failed`). Neither logs a `layer_error`.
- **One stream's failure is its own.** A violation on one stream resets
  that stream only. Broken framing fails the whole connection: a text frame
  that is not a JSON object with a valid `stream`, a binary frame shorter
  than its 5-byte prefix or with an unknown direction byte, or a stream id
  roxy never opened. Every exchange on it then fails closed
  (`service:protocol`), and roxy closes it.
- **[Observe mode](/design/addon-model#modes)** uses the same streams: the
  service gets copies of both directions, and whatever it sends back other
  than `credit` and `reset` is ignored. The stream ends after roxy's
  `response_end` (or a `reset`); a copy that is cut (`observer_lagged`) is
  reset. Waiting for credit is falling behind, so a service that wants every
  copy in full grants extra credit as an observe stream opens
  (`roxy_layer.py` grants 16 MiB to each body). Body bytes the service
  sends on an observe stream are discarded and credited back in steps of
  64 KiB; sending past credit is still a protocol violation.
- **WebSockets** run through the stream as for every layer
  ([addon configuration](/reference/addon-configuration#websockets)). The
  `101` from below arrives as roxy's `response` head, and the service
  answers it with a `101` of its own (the one status outside 200–599 it may
  send, and only on a WebSocket upgrade). From then on the request body is
  the client's bytes and the response body the upstream's, with no length
  cap on either, until each side closes; the stream holds its place on the
  connection for as long as the WebSocket is open. roxy sends no
  `request_end` before the `101`, so a service that waits for the end of
  the request body before forwarding never forwards an upgrade and the
  exchange fails on `first_byte_timeout`: forward as the request arrives.
  When the relay ends, roxy closes the client's connection and resets the
  stream if its bodies have not both ended.

The [quickstart](/quickstart)'s sidecar,
[`roxy_layer.py`](https://github.com/roxy-proxy/roxy-proxy/blob/main/examples/quickstart/sentinel/roxy_layer.py),
is the service side of the protocol for asyncio: it handles streams, credit
and resets, and gives a handler one exchange at a time.
