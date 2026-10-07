# WebSockets

An upgrade is honoured only when the allowing rule says
`allow: { upgrade: websocket }`. Under a plain `allow`, roxy drops `Upgrade`
and `Connection: upgrade`, forwards the request as plain HTTP and emits
`upgrade_stripped`; the client gets whatever the upstream answers (typically
`200`, `400` or `426`) and its WebSocket library reports a failed
handshake. Upgrades to anything other than `websocket` (`h2c`, say) are
always stripped.

## Relay

roxy forwards the upgrade request over HTTP/1.1 after the usual header
canonicalisation; `Sec-WebSocket-*` headers pass through. Connecting, the
upgrade request and taking over the upgraded connection share one
`limits.response_header_timeout`; the client gets the `101` only once roxy
holds the upstream side, so a failed upgrade is an error response, never a
`101` followed by a close:

| failure | result |
|---|---|
| the client's upgrade is not a valid handshake (not `GET`, not HTTP/1.1, a body, `Sec-WebSocket-Version` other than 13, a `Sec-WebSocket-Key` missing, repeated or not the base64 of 16 bytes) | `400`, `terminal_rule: _websocket`, reason `ws_bad_handshake` |
| `response_header_timeout` runs out | `504` |
| the upstream answers anything other than `101` | relayed as it is |
| a `101` with a wrong `Sec-WebSocket-Accept`, or accepting an extension when none may be negotiated ([below](/reference/websockets#extensions)) | `502`, `upstream_error`, reason `protocol_error` |

Through an `http_proxy` listener a `ws://` URL means a `CONNECT` tunnel
with a plaintext upgrade inside it, which roxy refuses unless
`http.allow_plain_in_connect` is on (the tunnel is closed, `parse_error`
reason `non_http_in_connect`; [CONNECT](/reference/http#connect)). Use
`wss://`. On an `http` listener the upgrade arrives as plain HTTP and
needs nothing.

If no rule reads a `ws.*` field, roxy splices bytes: no frame parsing,
re-masking or reassembly; subprotocols and extensions pass end to end. If
any rule reads `ws.*`, every message is checked
([message rules](/reference/websockets#message-rules)). Either way:

- Relayed bytes count towards `request_bytes` and `response_bytes` metrics
  as they flow; a byte-budget deny closes a WebSocket mid-stream (the byte
  splice at the transport, message rules with a `1008` close frame first).
- Each chunk waits for the flow log ([audit backpressure](/reference/flow-log#writing));
  capture records both directions as relayed.
- [Addon layers](/reference/addon-configuration#websockets) sit between the
  client and the relay, so message rules and capture see what the layers
  pass on, not what a layer changes on the way to the client.
- A relayed WebSocket with no traffic either way for `limits.idle_timeout`
  (1 h) is closed with a `1001` close frame to both sides (`close_reason`
  `idle timeout`).
- The flow log gets one `ws_open` (naming the `host`) and one `ws_close`
  with `bytes_c2s` and `bytes_s2c`, plus `close_code` and `close_reason`
  when roxy ended it with a close frame. The exchange's `request` event
  follows, with `res.status: 101` and the relayed byte totals as its
  `body_bytes`.

WebSockets over HTTP/2 (RFC 8441) are not supported; HTTP/2 clients use a
separate HTTP/1.1 connection.

## Extensions

A compressed message (`permessage-deflate`) cannot be read without the
compression state of every message before it, so when something reads the
messages roxy removes `Sec-WebSocket-Extensions` from the upgrade request
and refuses with `502` a `101` that accepts an extension anyway. That is
when a rule reads `ws.*`, or an addon layer runs on the upgrade request
(its `when` matched) with `http.decode_for_addons` on (the default;
[addons](/reference/addon-configuration#content-codings)). Otherwise the
client's offer and the upstream's answer pass through untouched.

## Message rules

Rules that read `ws.*` are watching rules
([evaluation](/design/policy-evaluation)), checked on every message after
the `101`:

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
| `ws.size` | payload length in bytes |
| `ws.text` | a text message's text; `null` for every other opcode |

`==`, `!=`, `in` and `not in` treat `null` as an ordinary value; any other
operator on it fails closed
([missing values](/reference/rule-language#missing-values-null)), so guard
text rules with `ws.opcode == 1 and ...` or the first ping closes the
WebSocket. Control messages (close, ping, pong) are checked like data
messages: `ws.opcode == 2` denies binary messages, while `ws.opcode != 1`
also denies every ping.

A matching deny closes both sides with `1008`. A rule cannot drop or edit a
single message (that is for addons). A watching rule's `log`, `tag` and
`set_state` effects apply once per WebSocket, the first time it matches.

### Parsing

With message rules, roxy:

- negotiates no extension ([above](/reference/websockets#extensions));
- decodes each direction strictly (RFC 6455 §5): RSV bits zero, known
  opcodes, client frames masked and server frames not, shortest length
  encoding, control frames unfragmented and at most 125 bytes, a close
  frame with a valid code and a UTF-8 reason and nothing after it;
- reassembles a fragmented message before checking it, up to
  `limits.max_ws_message_bytes` (16 MiB); a control frame inside a
  fragmented message is checked and relayed on its own;
- checks that a text message is UTF-8;
- re-encodes each relayed message as one unfragmented frame, masked toward
  the upstream with its own random key.

A protocol error closes both sides with its code: `1002` framing, `1007`
invalid UTF-8, `1009` over the limit. A message is relayed only once
complete.

### Logging

A denied message is logged as `ws_message` with its `direction`, `opcode`,
`size`, `decision` and the `rules` that matched.
`log.flow.ws_message_every: N` also logs every Nth checked message of each
WebSocket (`0`, the default: denied only). Payloads are never logged.
