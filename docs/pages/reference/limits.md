# Resource limits

Every limit resolves in the closed direction: an error anywhere between
accept and the upstream connect produces a deny response or a closed socket
([fail closed](/design/threat-model#fail-closed)).

## Fail-closed outcomes

| condition | result |
|---|---|
| parse or canonicalisation error | close the connection (`400` if a response can still be written), `parse_error` |
| a rule denies | deny response, then close |
| policy input unavailable (metric store, address list, secret) | `503`, `_fail_closed` |
| metric key table full or byte budget exhausted | deny, `metric_table_full` |
| body too large to inspect, as sent or decoded | deny, `_fail_closed`, `body_too_large_to_inspect` |
| body to inspect cannot be decoded | deny, `_fail_closed`, `body_decode_failed` or `unsupported_content_encoding` |
| body to sign over `max_sign_body_bytes` | `413`, `_sign`, `sign_body_too_large` |
| buffer budget cannot cover the exchange's inspection, signing or WebSocket buffers | deny, `_fail_closed`, `buffer_budget_exhausted`; an observer's copy is cut instead (`observer_lagged`) |
| body or header limit exceeded mid-stream | close both sides |
| upstream DNS, connect or TLS failure | `502`, `upstream_error` |
| upstream connect or response-header timeout | `504`, `upstream_error`, reason `timeout` |
| address floor | `403`, `_address_policy` |
| addon trap, budget exceeded or invalid output (enforce mode) | deny, `layer_error`; observe-mode addons only log |
| config reload fails | keep the old policy |
| connection cap | refuse the new connection |
| flow log or capture behind, or its disk failing | hold traffic until it catches up; never drop records |
| WebSocket message that breaks the protocol or is over `max_ws_message_bytes`, when rules read messages | close both sides with `1002`, `1007` or `1009` ([WebSockets](/reference/websockets#message-rules)) |

The reason codes appear in the flow log only, never in the deny response
([deny responses](/reference/http#deny-responses)).

## Limits

All under `limits:`; defaults shown. Sizes are 1024-based.

```yaml
limits:
  # client requests (HTTP)
  max_header_bytes: 64kb
  max_url_bytes: 8kb
  max_headers: 100
  max_request_body_bytes: 1gb
  header_timeout: 10s             # the slowloris guard: a request head must arrive in full
  body_idle_timeout: 10m          # the client's stall: sending its body, or taking the response
  idle_timeout: 1h                # keep-alive idle; also a relayed WebSocket's idle timeout
  h2_max_concurrent_streams: 100
  h2_max_header_list_bytes: 64kb

  # responses
  max_response_body_bytes: 1gb
  response_header_timeout: 15m    # from when the request body has been sent; a WebSocket upgrade's whole upstream handshake
  response_body_idle_timeout: 30m # the upstream's stall between parts of the response body

  # buffering
  max_inspect_body_bytes: 1mb     # body.text / response.body.text, and addons' default
  max_sign_body_bytes: 100mb      # a request body hashed for sign: aws_sigv4; larger is 413
  max_capture_body_bytes: 16mb    # per direction per exchange
  max_ws_message_bytes: 16mb      # a reassembled WebSocket message, when rules read ws.*
  max_observer_lag_bytes: 16mb    # how far behind an observe-mode addon may fall, per direction
  max_buffered_bytes: 1gb         # all of the above together, across the process

  # connections
  max_connections: 10000
  max_connections_per_client: 10000   # per client IP; equal to max_connections, so off unless lowered

  # policy state
  max_metric_keys: 100000
  max_metric_bytes: 256mb         # at most 64gb
  max_state_entries: 100000
  max_address_list_bytes: 256mb
```

| limit | on overrun |
|---|---|
| `body_idle_timeout` | the request is cut (`parse_error`, `body_timeout`) or the response is cut (`response_error`, `client_gone`) |
| `response_body_idle_timeout` | the exchange ends (`response_error`, `response_body_timeout`): the connection closes on HTTP/1.1, the stream is reset with `CANCEL` on HTTP/2 |
| `max_ws_message_bytes` | both sides close with `1009`; applies only when rules read messages ([WebSockets](/reference/websockets#message-rules)) |
| `max_observer_lag_bytes` | the observer's copy is cut ([addon modes](/design/addon-model#modes)) |

Addons have their own limits, and fixed caps on what the host holds for a
guest ([addon safety limits](/reference/addon-safety)).

### Timeouts

The timeouts are permissive by default: roxy decides what passes, not how
long a well-behaved exchange may take, and a model call with minutes to its
first byte, a quiet WebSocket or a stream with long gaps should not hit one
unless the operator chose it. Only `header_timeout` is tight. Memory is
bounded by the buffer budget and the per-connection caps, not by the
timeouts, so a long timeout costs only the idle connection it keeps:

| timeout | a long value holds |
|---|---|
| `header_timeout` | a connection slot (one of `max_connections`) and its socket, with no request to show for it |
| `body_idle_timeout` | a connection slot and the exchange's buffers (its reservations under `max_buffered_bytes`, and up to 4 MiB of HTTP/2 receive window) while the client is silent |
| `idle_timeout` | a connection slot and its socket between requests, or a relayed WebSocket's two sockets and its reserved message buffers while nothing is sent |
| `response_header_timeout` | a connection slot, the upstream connection, and the exchange's buffers while the upstream thinks |
| `response_body_idle_timeout` | the same as above while the upstream pauses mid-body |

Tightening one trades those idle connections for cut exchanges; raise
`max_connections` instead if idle connections are what runs out.

### Buffer budget

`max_buffered_bytes` bounds the inspection, signing, WebSocket and observer
buffers in aggregate. An exchange reserves before it fills a buffer; a
reservation the budget cannot cover fails at once, with no waiting and no
eviction (`503`, `_fail_closed`, `buffer_budget_exhausted`).

| buffer | reservation |
|---|---|
| a body a rule reads (`body.text`, `response.body.text`) | `max_inspect_body_bytes`, or its `content-length` if smaller; nothing for a body known to be empty (no request body, a `HEAD` response, a `1xx`, `204` or `304`). Once buffered, it shrinks to what is held (the body as sent, or its decoded text if larger) and stays until the exchange ends |
| a request body hashed for `sign: aws_sigv4` | its `content-length` (at most `max_sign_body_bytes`) up front; a chunked body reserves chunk by chunk up to that cap and is refused at the chunk the budget cannot cover. Held until the exchange ends. `unsigned_payload: true` reserves nothing ([signing AWS requests](/reference/secrets#signing-aws-requests)) |
| a WebSocket whose messages rules read | twice `max_ws_message_bytes` at the upgrade, held for the session. Reading bodies but not messages holds nothing for a WebSocket |
| an observer's copy | the bytes queued and not yet read, frame by frame, given back as the observer reads them (or drops the copy). A copy whose next frame would overrun the budget is cut (`observer_lagged`, `reason: buffer_budget_exhausted`): the budget bounds how far behind observers are in total, not how many exchanges are observed |

Budget ÷ cap is how many exchanges can hold a buffer at once (defaults:
1024 bodies of unknown length under inspection, 32 WebSockets with message
rules, 1 GiB of unread observer copy). It must be at least the largest
single reservation.

### Reload

| setting | takes effect |
|---|---|
| `max_header_bytes`, `max_url_bytes`, `max_headers`, `max_request_body_bytes`, `header_timeout`, `body_idle_timeout`, `response_body_idle_timeout`, `idle_timeout`, the `h2_*` limits, the `http.*` flags | fixed when a connection is accepted; new connections only |
| `max_inspect_body_bytes`, `max_sign_body_bytes`, `max_response_body_bytes`, `response_header_timeout`, the WebSocket limits, `max_observer_lag_bytes`, the policy itself | per exchange, from the snapshot the exchange starts under, on old connections too |
| `max_buffered_bytes` | process-wide: each reservation is checked against the value in force at that moment; reservations already held stay as they are |

## Connections

- A connection over `max_connections` or `max_connections_per_client` (per
  client IP) is accepted and closed at once, with a `connection_refused`
  event.
- Every read is bounded (head size, body size, ClientHello size) and every
  stage has a timeout. Nothing is allocated in proportion to an
  attacker-supplied number before it is validated (`content-length: 10^18`
  does not pre-allocate).
- Request bytes in flight on an HTTP/2 connection (sent by the client, not
  yet taken by the upstream) sit outside `max_buffered_bytes`: the
  connection's receive window caps them at 4 MiB, so one client IP can hold
  at most `max_connections_per_client` × 4 MiB. The default equals
  `max_connections`, so behind a load balancer (one source IP for every
  client) the cap is the fleet's; lower it on a proxy port where each client
  has its own address.
- Bounded policy tables (metrics, state, addon state) never evict
  ([never evict](/design/threat-model#never-evict)).
- The proxy port serves only proxy semantics and `roxy.internal`; health
  and CA download live on the separate `ca_server` listener.
- A panic in a connection task closes that connection only.
- On `SIGTERM` or Ctrl-C roxy stops accepting, drains exchanges in flight
  for up to 10 seconds, and flushes the flow log and capture before
  exiting.
