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
refused on a service layer.

**Transport: one WebSocket per exchange**, subprotocol `roxy.layer.v1`, to
the endpoint's URL (`http` → `ws`, `https` → `wss`). It is dialled through
the connector, so the address floor and deny lists apply, and it never
passes through other layers or the rules. The handshake carries the
endpoint's `headers` (credentials from secrets) and the flow metadata as
`roxy-flow-*` fields: `id`, `conn`, `layer`, `mode` (`enforce` or
`observe`), `client-ip`, `client-user`, `listener`, `sni`, `tags`. A service
that does not accept the subprotocol fails the handshake. Each session is
recorded as an `endpoint_call` event.

**Messages.** Text frames are JSON control messages; binary frames are body
bytes of the message whose head came last.

```text
roxy → service   {"type":"request","method":…,"url":…,"headers":[[n,v],…]}  bytes…  {"type":"request_end"}
service → roxy   one of:
                   {"type":"request",…}  bytes…  {"type":"request_end"}     forward this request (`next`)
                   {"type":"response","status":…,"headers":[…]}  bytes…  {"type":"response_end"}
                                                                          answer instead; nothing is forwarded
                   {"type":"deny","status":403,"message":"…"}             refuse (status 4xx/5xx, both optional)
then, if it forwarded:
roxy → service   {"type":"response","status":…,"headers":[…]}  bytes…  {"type":"response_end"}
service → roxy   {"type":"response",…}  bytes…  {"type":"response_end"}   the client's response
                 or {"type":"deny",…}
```

`url` is absolute and `headers` are end-to-end fields as a WASM layer sees
them (no hop-by-hop or framing fields). Heads carry `content-length` when
the length is known; a `content-length` the service sends back is enforced,
and more or fewer bytes than declared is a protocol violation. Both
directions stream at once: the service may start forwarding the request
before the client's body has ended, and the socket gives backpressure both
ways.

- **What the service forwards gets the same checks as a WASM layer's
  `next`**: re-validated as strictly as a client request, then judged by the
  rules. Its response is handled as a WASM layer's.
- **Deadlines.** `first_byte_timeout` bounds the connection and each of the
  service's heads (its first answer, and its response after roxy sent the
  upstream's head). The session has no overall clock: bodies stream for as
  long as they take.
- **Failure is closed** in enforce mode: a failed connection or handshake,
  a protocol violation (bad JSON, a message out of order, bytes before a
  head, an invalid head, a broken length), a missed deadline, or a lost
  socket denies the exchange (`503`, `layer:<name>`) before the response
  head and cuts the body after it. A body cut short never reaches the
  upstream or the client as complete. `layer_error.kind` is
  `service:connect`, `service:protocol`, `service:timeout` or
  `service:closed`.
- **Observe mode**: the service gets the same messages for copies of both
  streams, and whatever it sends back is read and ignored. It cannot change
  or delay traffic; its failures are logged only.
- **WebSocket upgrades.** The service sees the upgrade request; a `101`
  passes straight back, and the WebSocket's bytes do not go through it.

One connection per exchange keeps the protocol simple and a service
stateless per socket. The [quickstart](/quickstart)'s sidecar is a service
layer in Python: [`roxy_layer.py`](https://github.com/roxy-proxy/roxy-proxy/blob/main/examples/quickstart/sentinel/roxy_layer.py)
is the service side of the protocol for asyncio.
