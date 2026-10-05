# Resource limits

Containment takes priority over availability. Every limit resolves in the
closed direction, and there is no code path where an error on the request
path leads to forwarding: an error anywhere between accept and the upstream
connect produces a deny response or a closed socket.

## Fail-closed outcomes

| condition | result |
|---|---|
| parse or canonicalisation error | close the connection (`400` if a response can still be written), `parse_error` |
| a rule denies | deny response, then close |
| policy input unavailable (metric store, address list, secret) | `503`, `_fail_closed` |
| metric key table full or byte budget exhausted | deny, `metric_table_full` |
| body too large to inspect, as sent or decoded | deny, `_fail_closed`, `body_too_large_to_inspect` |
| body to inspect cannot be decoded | deny, `_fail_closed`, `body_decode_failed` or `unsupported_content_encoding` |
| body or header limit exceeded mid-stream | close both sides |
| upstream DNS, connect or TLS failure | `502`, `upstream_error` |
| address floor | `403`, `_address_policy` |
| addon trap, budget exceeded or invalid output (enforce mode) | deny, `layer_error`; observe-mode addons only log |
| config reload fails | keep the old policy |
| connection cap | refuse the new connection |
| flow log or capture behind, or its disk failing | hold traffic until it catches up; never drop records |
| WebSocket message that breaks the protocol or is over `max_ws_message_bytes`, when rules read messages | close both sides with `1002`, `1007` or `1009` ([WebSockets](/policies/websockets#message-rules)) |

## Limits

All under `limits:`; defaults shown. Sizes are 1024-based.

```yaml
limits:
  # client requests (HTTP)
  max_header_bytes: 64kb
  max_url_bytes: 8kb
  max_headers: 100
  max_request_body_bytes: 1gb
  header_timeout: 10s
  body_idle_timeout: 30s
  idle_timeout: 300s              # keep-alive idle; also a relayed WebSocket's idle timeout
  h2_max_concurrent_streams: 100
  h2_max_header_list_bytes: 64kb

  # responses
  max_response_body_bytes: 1gb
  response_header_timeout: 60s    # from when the request body has been sent; a WebSocket upgrade's whole upstream handshake

  # buffering
  max_inspect_body_bytes: 1mb     # body.text / response.body.text, and addons' default
  max_capture_body_bytes: 16mb    # per direction per exchange
  max_ws_message_bytes: 16mb      # a reassembled WebSocket message, when rules read ws.*
  max_observer_lag_bytes: 16mb    # an observe-mode addon's copy of a body, per direction

  # connections
  max_connections: 10000
  max_connections_per_client: 256

  # policy state
  max_metric_keys: 100000
  max_metric_bytes: 256mb         # at most 64gb
  max_state_entries: 100000
  max_address_list_bytes: 256mb
```

Addons have their own limits ([addon safety](/addons/safety)).
`max_ws_message_bytes` applies only when rules read WebSocket messages
([WebSockets](/policies/websockets#message-rules)); a message over it closes both
sides with `1009`. `max_observer_lag_bytes` is how far behind the real
exchange an observe-mode addon may fall: its copy of each body is buffered
up to that many bytes, and an observer further behind has the copy cut
([addon modes](/addons/overview#modes)).

The limits that shape the client-facing codec (`max_header_bytes`,
`max_url_bytes`, `max_headers`, `max_request_body_bytes`, `header_timeout`,
`body_idle_timeout`, the keep-alive `idle_timeout`, the `h2_*` limits) and
the `http.*` flags are fixed for a connection when it is accepted, on
HTTP/1.1 and HTTP/2 alike; a reload changes them for new connections only.
Everything decided per exchange (`max_inspect_body_bytes`,
`max_response_body_bytes`, `response_header_timeout`, the WebSocket limits,
`max_observer_lag_bytes`, the policy itself) comes from the snapshot the exchange starts under, so an
exchange on an old connection runs under the current values.

## Connections

- A connection over `max_connections` or `max_connections_per_client` (per
  client IP) is accepted and closed at once, with a `connection_refused`
  event.
- Every read is bounded (head size, body size, ClientHello size), and every
  stage has a timeout.
- Nothing is allocated in proportion to an attacker-supplied number before
  it is validated (`content-length: 10^18` does not pre-allocate).
- Bounded policy tables (metrics, state, addon state) never evict
  to make room: a flow that needs a new entry in a full table is denied
  ([never evict](/principles#never-evict)).
- The proxy port serves only proxy semantics and `roxy.internal`. Health
  and CA download live on the separate `ca_server` listener, so they can be
  firewalled differently.
- A panic in a connection task closes that connection only. The parsers are
  fuzzed so they do not panic at all.
- On `SIGTERM` or Ctrl-C roxy stops accepting, drains exchanges in flight
  for up to 10 seconds, and flushes the flow log and capture before
  exiting.
