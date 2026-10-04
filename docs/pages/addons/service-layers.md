# Service layers

A `kind: service` layer is an external service in the network path, at its
position in the stack exactly as a WASM layer is. The request streams into
it as it arrives; it streams back the request to forward, which roxy passes
down the stack; the response from below streams into it, and it streams back
the response the client gets. It may pass bytes through untouched, rewrite
them, hold them back, answer itself, or deny. This runs out-of-process logic
(Python with any dependencies, say) with no WASM toolchain.

```yaml
addons:
  - name: sentinel
    kind: service
    endpoint: sidecar                   # one of this addon's endpoints
    mode: enforce                       # enforce | observe
    endpoints:
      sidecar: { url: "http://127.0.0.1:9000/layer", private_ok: true }
    limits:
      first_byte_timeout: 2s            # until each of the service's heads (default 30s)
```

`path`, `capabilities`, `config`, `audit_endpoint` and the WASM limits are
refused on a service layer, and `max_connections` and `max_streams` are
refused on a WASM layer.

## Transport

roxy keeps a few long-lived WebSocket connections to each service endpoint
and carries many exchanges over each one, as **streams**. The subprotocol is
`roxy.layer.v2`; a service that does not accept it fails the handshake.
The URL is the endpoint's (`http` → `ws`, `https` → `wss`, with the
upstream's certificate verification). It is dialled through the connector,
so the address floor and deny lists apply, and it never passes through
other layers or the rules. The handshake carries the endpoint's `headers`
(credentials from secrets). Each connection is recorded as an
`endpoint_call` event, against the flow whose exchange opened it.

```yaml
    limits:
      max_connections: 4                # per endpoint (default 4)
      max_streams: 100                  # exchanges at once per connection (default 100)
```

**Pooling.** roxy opens a connection when it needs one and keeps it open
while idle. A new exchange takes a stream on an open connection; roxy opens
another connection only when every open one has `max_streams` streams. With
`max_connections` connections all full, the exchange waits for a free
stream, within `first_byte_timeout`. A connection that closes or fails
fails its in-flight exchanges closed, and later exchanges go to another
connection. A service should not close a connection it is not done with:
an exchange roxy started on it as it closed fails.

A reload gives new exchanges new connections, dialled under the new policy
and secrets. The old connections take no new streams: an idle one closes at
once, a busy one when its last exchange ends.

### Frames

Text frames are JSON control messages, each with a `stream` field. Binary
frames are body bytes: a 4-byte big-endian stream id, then the bytes, which
belong to the message whose head came last on that stream. roxy numbers the
streams on a connection from 1 upward and never reuses a number.

A stream opens with an `open` message from roxy, carrying the exchange's
metadata, then the request:

```json
{"type":"open","stream":7,"flow":"01J…","conn":"01J…","layer":"sentinel",
 "mode":"enforce","client_ip":"10.0.0.5","client_user":"alice",
 "listener":"proxy","sni":"api.example.com","tags":["a","b"]}
```

`mode` is `enforce` or `observe`. `client_user` and `sni` are left out when
there is none. `stream` is roxy's, but the pair (`flow`, `layer`) is unique
and stable: two layers that use the same endpoint in one flow get separate
streams with different `layer`s, so a service can key its state on the pair.

Every message below carries `stream`; it is left out here.

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
either way       {"type":"credit","bytes":n}                              flow control (below)
                 {"type":"reset","message":"…"}                           abandon the stream
```

`url` is absolute and `headers` are end-to-end fields as a WASM layer sees
them (no hop-by-hop or framing fields). Heads carry `content-length` when
the length is known; a `content-length` the service sends back is enforced,
and more or fewer bytes than declared is a protocol violation.

**Order on a stream.** Body frames carry only a stream id, so on each
stream, in each direction, the messages are strictly in the order above: a
head, its bytes, its end, then the next head. roxy sends its `response`
head only after its `request_end`, even when the layer below answered
while the client was still uploading, and a service must do the same
(a `response` before `request_end` is a protocol violation). The two
directions are independent: the service may start forwarding the request
before the client's body has ended, and roxy forwards it as it arrives.

**End of a stream.** A stream ends with the service's last message: the
`response_end` of the client's response, or a `deny`. roxy sends nothing
more on it after that (a request body the service did not wait for is not
sent on). Either side may end a stream early with `reset`. roxy resets a
stream when the client goes away, a deadline passes, the service broke the
protocol on it, or the upstream switched protocols (a `101`). A service
that resets an enforce stream fails that exchange closed. Each side
ignores messages that arrive for a stream it has already ended; roxy still
credits back the body bytes among them, so a service that was mid-send
when the stream ended is not left waiting for credit.

**Flow control.** Body bytes are flow-controlled per stream, in each
direction, so a slow body on one stream does not hold up the others. Each
stream starts with 256 KiB of credit each way. The receiver grants more
with `{"type":"credit","stream":…,"bytes":n}` as it consumes what it got;
the sender may have no more body bytes outstanding than it has been granted.
roxy grants credit as the layer below (or the client) reads what the
service sent. A service that sends past its credit breaks the protocol on
that stream. Control messages are not counted.

- **What the service forwards gets the same checks as a WASM layer's
  `next`**: re-validated as strictly as a client request, then judged by the
  rules. Its response is handled as a WASM layer's.
- **Deadlines.** `first_byte_timeout` bounds getting a stream (connecting,
  or waiting for a free one) and each of the service's heads: its first
  answer, from roxy's `request` head, and its second, from roxy's
  `response` head (which follows `request_end`). A stream has no overall
  clock: bodies stream for as long as they take, and an upstream that
  answers early waits for the upload to finish.
- **Failure is closed** in enforce mode: a failed connection or handshake,
  a protocol violation (bad JSON, a message out of order, bytes before a
  head, an invalid head, a broken length, bytes past the credit), a missed
  deadline, a reset from the service or a lost connection denies the
  exchange (`503`, `layer:<name>`) before the response head and cuts the
  body after it. A body cut short never reaches the upstream or the client
  as complete. `layer_error.kind` is `service:connect`, `service:protocol`,
  `service:timeout` or `service:closed`.
- **One stream's failure is its own.** A violation on one stream resets
  that stream only; the connection and its other streams carry on. Broken
  framing fails the whole connection: a text frame that is not a JSON
  object with a valid `stream`, a binary frame shorter than its 4-byte
  prefix, or a stream id roxy never opened. Every exchange on it then fails
  closed (`service:protocol`), and roxy closes it.
- **Observe mode** uses the same streams: the service gets the same
  messages for copies of both directions, and whatever it sends back other
  than `credit` and `reset` is ignored. The stream ends after roxy's
  `response_end` (or a `reset`). It cannot change or delay traffic; its
  failures are logged only. The real exchange never waits for an observer:
  a stream whose copies fall behind it is cut and reset on its own
  (`observer_lagged`). Waiting for credit is falling behind, so a service
  that wants whole copies of large bodies grants extra credit as an observe
  stream opens (`roxy_layer.py` grants 16 MiB). Body bytes the service
  sends on an observe stream are discarded, and credited back in steps of
  64 KiB as they are, so the service never waits on its own answers;
  sending past its credit is a protocol violation, as on any stream.
- **WebSocket upgrades.** The service sees the upgrade request; a `101`
  passes straight back, roxy resets the stream, and the WebSocket's bytes
  do not go through it.

The [quickstart](/quickstart)'s sidecar is a service layer in Python:
[`roxy_layer.py`](https://github.com/roxy-proxy/roxy-proxy/blob/main/examples/quickstart/sentinel/roxy_layer.py)
is the service side of the protocol for asyncio. It handles streams, credit
and resets, and gives a handler one exchange at a time.
