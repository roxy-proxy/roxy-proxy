# WebSockets

An upgrade is honoured only when the rule that allows the request says
`allow: { upgrade: websocket }`. A plain `allow` strips `Upgrade` and
`Connection: upgrade` and forwards an ordinary request, emitting an
`upgrade_stripped` event: the upgrade fails closed.

## Relay

roxy forwards the upgrade request to the upstream over HTTP/1.1, after the
usual header canonicalisation; `Sec-WebSocket-*` headers and the client's
extension offer pass through untouched. It checks that the upstream answered
`101` with a correct `Sec-WebSocket-Accept`, relays the `101` to the client,
and then splices bytes in both directions until either side closes. There is
no frame parsing, re-masking or reassembly, so `permessage-deflate` and
subprotocols work exactly as negotiated end to end.

- Relayed bytes count towards `request_bytes` and `response_bytes` metrics
  as they flow, so a byte-budget deny rule closes a WebSocket mid-stream.
  Because a close frame could land inside a half-relayed frame, a deny
  closes both sides at the transport.
- Each chunk waits for the flow log like any forwarded body
  ([audit backpressure](flow-log.md#writing)), and capture records both
  directions.
- A relayed WebSocket closes after `limits.idle_timeout` (300 s) with no
  traffic either way.
- The flow log gets one `ws_open` and one `ws_close` event, with byte
  counts.
- Addons that export `tunnel` are chained between the client and the relay
  ([addons](addons.md#layer-stack)).

HTTP/2 clients cannot open a WebSocket over HTTP/2 (RFC 8441); they open a
separate HTTP/1.1 connection for it, which mainstream libraries do
automatically.
