# WebSockets

An upgrade is honoured only when the rule that allows the request says
`allow: { upgrade: websocket }`.

A plain `allow` permits the request but not the upgrade. roxy drops
`Upgrade` and `Connection: upgrade`, as any intermediary may (they are
hop-by-hop headers), forwards the request as plain HTTP and emits an
`upgrade_stripped` event. The client gets whatever the upstream answers to
that request, typically a `200`, `400` or `426` rather than a `101`, and its
WebSocket library reports a failed handshake. No rule grants a long-lived
byte stream by accident. Upgrades to anything other than `websocket` (for
example `h2c`) are always stripped this way.

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
