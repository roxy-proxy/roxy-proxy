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
usual header canonicalisation; `Sec-WebSocket-*` headers pass through. It
checks that the upstream answered `101` with a correct
`Sec-WebSocket-Accept`, relays the `101` to the client, and then relays
traffic in both directions until either side closes. Connecting, the
upgrade request and taking over the upgraded connection share one
`limits.response_header_timeout`; the client is sent the `101` only once
roxy holds the upstream side, so a failed upgrade is a `502`, not a `101`
followed by a close.

How it relays depends on the policy. If no rule reads a `ws.*` field, roxy
splices bytes: no frame parsing, re-masking or reassembly. Subprotocols
work exactly as negotiated end to end, and so do extensions unless
something must read the messages ([below](#extensions)). If any rule reads
`ws.*`, roxy checks every message ([message rules](#message-rules)).

Either way:

- Relayed bytes count towards `request_bytes` and `response_bytes` metrics
  as they flow, so a byte-budget deny rule closes a WebSocket mid-stream.
  The byte splice closes both sides at the transport, because a close frame
  could land inside a half-relayed frame. With message rules, both sides get
  a `1008` close frame first.
- Each chunk waits for the flow log like any forwarded body
  ([audit backpressure](/operate/flow-log#writing)), and capture records both
  directions as relayed.
- A relayed WebSocket closes after `limits.idle_timeout` (300 s) with no
  traffic either way.
- The flow log gets one `ws_open` and one `ws_close` event, with byte
  counts. When roxy ended the WebSocket with a close frame, `ws_close` has
  `close_code` and `close_reason`.
- Addons that export `tunnel` are chained between the client and the relay
  ([addons](/addons/overview)), so message rules see what the layers
  pass on.

## Extensions

A compressed message (`permessage-deflate`) cannot be read without the
compression state of every message before it. So when something reads the
messages, roxy makes sure no extension is negotiated: it removes
`Sec-WebSocket-Extensions` from the upgrade request, and refuses with `502`
a `101` that accepts an extension anyway. Every WebSocket server must work
without extensions, so this costs only compression. roxy does this when:

- a rule reads `ws.*` ([message rules](#message-rules)); or
- the addon stack has a `tunnel` layer and `http.decode_for_addons` is on
  (the default), so the layer gets readable messages
  ([addons](/addons/overview#content-codings)).

Otherwise the client's offer and the upstream's answer pass through
untouched.

## Message rules

Rules that read `ws.direction`, `ws.opcode`, `ws.size` or `ws.text` are
watching rules ([evaluation](/policies/overview)), checked on every
message after the `101`:

```yaml
rules:
  - id: chat
    when: host == "chat.example.com"
    then: { allow: { upgrade: websocket } }
  - id: no-binary
    when: ws.opcode == 2
    then: deny
  - id: no-keys-out
    when: ws.direction == "c2s" and ws.opcode == 1 and ws.text matches ".*sk-[A-Za-z0-9]{20,}.*"
    then: deny
```

| field | value |
|---|---|
| `ws.direction` | `c2s` (client to upstream) or `s2c` |
| `ws.opcode` | 1 text, 2 binary, 8 close, 9 ping, 10 pong |
| `ws.size` | the message's payload length in bytes |
| `ws.text` | a text message's text; `null` for every other opcode |

`ws.text` is `null` on binary and control messages, and an operator other
than `==` or `!=` on `null` fails closed. Guard text rules with
`ws.opcode == 1 and ...`, or the first ping closes the WebSocket.

Control messages (close, ping, pong) are checked like data messages, so
their payloads cannot carry what a rule forbids. An allowlist is a deny of
everything else; write it so it lets control messages through:
`ws.opcode == 2` denies binary messages, while `ws.opcode != 1` would also
deny every ping.

A matching deny closes both sides with `1008` (policy violation). There is
no way to drop or edit a single message from a rule: dropping one silently
corrupts most protocols. Per-message editing is for addons, through
`tunnel`. A watching rule's `log`, `tag` and `set_state` effects apply once
per WebSocket, the first time it matches.

### Parsing

With message rules, roxy:

- makes sure no extension is negotiated ([above](#extensions)), so every message stays
  readable;
- decodes each direction strictly (RFC 6455 §5). RSV bits must be zero,
  opcodes must be known, client frames must be masked and server frames
  must not be, lengths must use the shortest encoding, and control frames
  must be unfragmented and at most 125 bytes. A close frame must carry a
  valid code and a UTF-8 reason, and nothing may follow it;
- reassembles a fragmented message before checking it, up to
  `limits.max_ws_message_bytes` (16 MiB). A control frame in the middle of
  a fragmented message is checked and relayed on its own;
- checks that a text message is UTF-8;
- re-encodes each message it relays as one unfragmented frame, masked
  toward the upstream with roxy's own random key. What leaves roxy is the
  canonical form of what was checked.

A protocol error closes both sides with its code: `1002` for a framing
error, `1007` for invalid UTF-8, `1009` for a message over the limit.
Checking a message means buffering it, so a message reaches the other side
only once it is complete.

### Logging

A denied message is logged as a `ws_message` event with its direction,
opcode, size and the denying rule. `log.flow.ws_message_every: N` also logs
every Nth checked message of each WebSocket (`0`, the default, logs only
denied ones). Message payloads are never logged.

HTTP/2 clients cannot open a WebSocket over HTTP/2 (RFC 8441); they open a
separate HTTP/1.1 connection for it, which mainstream libraries do
automatically.
