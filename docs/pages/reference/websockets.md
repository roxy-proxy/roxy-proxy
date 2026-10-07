# WebSockets

An upgrade is honoured only when the rule that allows the request says
`allow: { upgrade: websocket }`. Under a plain `allow`, roxy drops `Upgrade`
and `Connection: upgrade` (hop-by-hop headers), forwards the request as
plain HTTP and emits an `upgrade_stripped` event; the client gets whatever
the upstream answers (typically `200`, `400` or `426`, not `101`) and its
WebSocket library reports a failed handshake. Upgrades to anything other
than `websocket` (`h2c`, say) are always stripped this way.

## Relay

roxy forwards the upgrade request to the upstream over HTTP/1.1, after the
usual header canonicalisation; `Sec-WebSocket-*` headers pass through. It
checks that the upstream answered `101` with a correct
`Sec-WebSocket-Accept`, relays the `101`, then relays traffic both ways
until either side closes. Connecting, the upgrade request and taking over
the upgraded connection share one `limits.response_header_timeout`, and the
client gets the `101` only once roxy holds the upstream side, so a failed
upgrade is an error response, never a `101` followed by a close:

| failure | result |
|---|---|
| the client's upgrade is not a valid WebSocket handshake (not `GET`, not HTTP/1.1, a body, `Sec-WebSocket-Version` other than 13, a missing or repeated `Sec-WebSocket-Key`) | `400`, `terminal_rule: _websocket`, reason `ws_bad_handshake` |
| `response_header_timeout` runs out | `504` |
| the upstream answers anything other than `101` | relayed as it is, like any response |
| a `101` with a wrong `Sec-WebSocket-Accept`, or one that accepts an extension when none may be negotiated ([below](/reference/websockets#extensions)) | `502`, `upstream_error`, reason `protocol_error` |

If no rule reads a `ws.*` field, roxy splices bytes: no frame parsing,
re-masking or reassembly, and subprotocols and extensions pass end to end.
If any rule reads `ws.*`, roxy checks every message
([message rules](/reference/websockets#message-rules)). Either way:

- Relayed bytes count towards `request_bytes` and `response_bytes` metrics
  as they flow, so a byte-budget deny closes a WebSocket mid-stream. The
  byte splice closes both sides at the transport (a close frame could land
  inside a half-relayed frame); with message rules both sides get a `1008`
  close frame first.
- Each chunk waits for the flow log like any forwarded body
  ([audit backpressure](/reference/flow-log#writing)), and capture records
  both directions as relayed.
- [Addon layers](/reference/addon-configuration#websockets) carry the
  WebSocket in their bodies, between the client and the relay. The relay is
  the hop next to the upstream, so message rules and capture see what the
  layers pass on, not what a layer changes on the way to the client.
- A relayed WebSocket closes after `limits.idle_timeout` (300 s) with no
  traffic either way.
- The flow log gets one `ws_open` event, naming the `host`, and one
  `ws_close` with `bytes_c2s` and `bytes_s2c`, plus `close_code` and
  `close_reason` when roxy ended the WebSocket with a close frame. The
  exchange's `request` event follows `ws_close`, with `res.status: 101` and
  the relayed byte totals as its request and response `body_bytes`.

HTTP/2 clients cannot open a WebSocket over HTTP/2 (RFC 8441); they open a
separate HTTP/1.1 connection for it.

## Extensions

A compressed message (`permessage-deflate`) cannot be read without the
compression state of every message before it, so when something reads the
messages roxy removes `Sec-WebSocket-Extensions` from the upgrade request
and refuses with `502` a `101` that accepts an extension anyway. That is
when:

- a rule reads `ws.*` ([message rules](/reference/websockets#message-rules)); or
- an addon layer runs on the upgrade request (its `when` matched) and
  `http.decode_for_addons` is on (the default)
  ([addons](/reference/addon-configuration#content-codings)).

Otherwise the client's offer and the upstream's answer pass through
untouched.

## Message rules

Rules that read `ws.direction`, `ws.opcode`, `ws.size` or `ws.text` are
watching rules ([evaluation](/design/policy-evaluation)), checked on every
message after the `101`:

```yaml
rules:
  - id: chat
    when: host == "chat.example.com"
    then: { allow: { upgrade: websocket } }
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

`==`, `!=`, `in` and `not in` treat `null` as an ordinary value; any other
operator on it fails closed
([missing values](/reference/rule-language#missing-values-null)). Guard text
rules with `ws.opcode == 1 and ...`, or the first ping closes the
WebSocket.

Control messages (close, ping, pong) are checked like data messages. An
allowlist is a deny of everything else, so write it to let control messages
through: `ws.opcode == 2` denies binary messages, while `ws.opcode != 1`
also denies every ping.

A matching deny closes both sides with `1008` (policy violation). A rule
cannot drop or edit a single message; per-message editing is for addons. A
watching rule's `log`, `tag` and `set_state` effects apply once per
WebSocket, the first time it matches.

### Parsing

With message rules, roxy:

- makes sure no extension is negotiated ([above](/reference/websockets#extensions));
- decodes each direction strictly (RFC 6455 §5): RSV bits zero, known
  opcodes, client frames masked and server frames not, shortest length
  encoding, control frames unfragmented and at most 125 bytes, a close
  frame with a valid code and a UTF-8 reason and nothing after it;
- reassembles a fragmented message before checking it, up to
  `limits.max_ws_message_bytes` (16 MiB). A control frame in the middle of
  a fragmented message is checked and relayed on its own;
- checks that a text message is UTF-8;
- re-encodes each relayed message as one unfragmented frame, masked toward
  the upstream with roxy's own random key: what leaves roxy is the
  canonical form of what was checked.

A protocol error closes both sides with its code: `1002` for a framing
error, `1007` for invalid UTF-8, `1009` for a message over the limit. A
message is buffered to be checked, so it reaches the other side only once
it is complete.

### Logging

A denied message is logged as a `ws_message` event with its `direction`,
`opcode`, `size`, `decision` and the `rules` that matched.
`log.flow.ws_message_every: N` also logs every Nth checked message of each
WebSocket (`0`, the default, logs only denied ones). Message payloads are
never logged.
