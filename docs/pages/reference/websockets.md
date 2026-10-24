# WebSockets

roxy only allows a WebSocket upgrade when the allowing rule says
`allow: { upgrade: websocket }`. Under a plain `allow`, roxy removes the
upgrade headers and forwards the request as ordinary HTTP, so the
client's WebSocket library reports a failed handshake. Upgrades to other
protocols are always removed.

## Relay

roxy forwards the upgrade over HTTP/1.1 and sends the client the `101`
only once the upstream has accepted, so a failed upgrade is always an
error response.

| failure | result |
|---|---|
| the client's upgrade request is not a valid WebSocket handshake | `400`, `terminal_rule: _websocket`, reason `ws_bad_handshake` |
| the upstream does not answer within `limits.response_header_timeout` | `504` |
| the upstream answers something other than `101` | passed to the client as it is |
| the upstream's `101` is invalid | `502` |

Through a proxy listener, use `wss://`. A `ws://` URL means plain HTTP
inside a CONNECT tunnel, which roxy refuses unless
`http.allow_plain_in_connect` is on. WebSockets over HTTP/2 are not
supported, so clients use HTTP/1.1 for them.

If no rule reads a `ws.*` field, roxy passes the bytes through as they
are. Either way:

- WebSocket bytes count towards byte metrics, so a byte limit can close a
  WebSocket.
- Capture records both directions.
- Addons sit between the client and the relay, so rules and capture see
  what the addons pass on.
- A WebSocket with no traffic for `limits.idle_timeout` (1 h) is closed.
- The flow log records `ws_open` and `ws_close`, with byte counts.

## Extensions

A compressed WebSocket message cannot be read on its own, so when
anything needs to read messages, roxy removes the client's offer of
compression. That is when a rule reads `ws.*`, or when an addon runs on
the upgrade and decodes bodies (the default;
[addons](/reference/addon-configuration#content-codings)). Otherwise
extensions pass through.

## Message rules

Rules that read `ws.*` are checked on every message after the upgrade:

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
| `ws.text` | a text message's text; `null` for other messages |

`ws.text` is `null` for pings and other control messages, so start text
rules with `ws.opcode == 1 and ...`
([missing values](/reference/rule-language#missing-values-null)).
Otherwise the first ping closes the WebSocket.

A matching deny closes both sides with code `1008`. Rules cannot drop or
change a single message; that needs an addon.

### Parsing

With message rules, roxy checks each message strictly against the
WebSocket spec, reassembles fragmented messages up to
`limits.max_ws_message_bytes` (16 MiB), and checks that text is valid
UTF-8. It forwards each message once it is complete, as a single frame.
A protocol error closes both sides with `1002`, `1007` for invalid UTF-8,
or `1009` for a message over the limit.

### Logging

A denied message is logged as a `ws_message` event. With
`log.flow.ws_message_every: N`, every Nth message is logged as well.
Message contents are never logged.
