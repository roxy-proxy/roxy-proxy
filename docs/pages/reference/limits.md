# Resource limits

Every limit resolves in the closed direction: an error anywhere between
accept and the upstream connect produces a deny response or a closed
socket.

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

The reason codes above are flow-log values. A deny response carries the
status, the rule id and the flow id, never the reason
([Deny responses](/reference/http#deny-responses)).

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
  body_idle_timeout: 30s          # the client's stall: sending its body, or taking the response
  idle_timeout: 300s              # keep-alive idle; also a relayed WebSocket's idle timeout
  h2_max_concurrent_streams: 100
  h2_max_header_list_bytes: 64kb

  # responses
  max_response_body_bytes: 1gb
  response_header_timeout: 60s    # from when the request body has been sent; a WebSocket upgrade's whole upstream handshake
  response_body_idle_timeout: 5m  # the upstream's stall between parts of the response body

  # buffering
  max_inspect_body_bytes: 1mb     # body.text / response.body.text, and addons' default
  max_sign_body_bytes: 100mb      # a request body hashed for sign: aws_sigv4; larger is 413
  max_capture_body_bytes: 16mb    # per direction per exchange
  max_ws_message_bytes: 16mb      # a reassembled WebSocket message, when rules read ws.*
  max_observer_lag_bytes: 16mb    # how far behind an observe-mode addon may fall, per direction
  max_buffered_bytes: 1gb         # all of the above together, across the process

  # connections
  max_connections: 10000
  max_connections_per_client: 256

  # policy state
  max_metric_keys: 100000
  max_metric_bytes: 256mb         # at most 64gb
  max_state_entries: 100000
  max_address_list_bytes: 256mb
```

The two body idle timeouts bound the two ends of an exchange.
`body_idle_timeout` is the client's: how long it may go without sending the
next part of its request body, or without taking the next part of the
response. It is short because the client is untrusted. A client that
overruns it has its request cut off (`parse_error`, `body_timeout`) or its
response cut off (`response_error`, `client_gone`).
`response_body_idle_timeout` is the upstream's: how long it may pause
between parts of the response body. It is generous so that gRPC server
streams, server-sent events and long polls go through. An upstream that
overruns it ends the exchange (`response_error`, `response_body_timeout`):
on HTTP/1.1 the connection closes so the client cannot take the body for
complete, on HTTP/2 the stream is reset with `CANCEL`.

Addons have their own limits, and fixed caps on what the host holds for a
guest ([addon safety limits](/reference/addon-safety)). `max_ws_message_bytes` applies
only when rules read WebSocket messages
([WebSockets](/reference/websockets#message-rules)); a message over it
closes both sides with `1009`. `max_observer_lag_bytes` is how many bytes
of its copy an observe-mode addon may leave unread, per direction, before
the copy is cut ([addon modes](/design/addon-model#modes)).

`max_buffered_bytes` bounds those buffers in aggregate; each is
bounded per exchange, and without it the only bound on exchanges is the
connection caps. An exchange reserves before it fills a buffer, and a
reservation the budget cannot cover fails at once, with no waiting and no
eviction: the exchange fails closed (`503`, `_fail_closed`,
`buffer_budget_exhausted`). What is reserved, and when:

- A body a rule reads (`body.text`, `response.body.text`) reserves
  `max_inspect_body_bytes`, or its `content-length` if that is smaller.
  A body known to be empty reserves nothing: a request without a body, a
  `HEAD` response, a `1xx`, `204` or `304`. Once the body is buffered the
  reservation shrinks to what is held (the body as sent, or its decoded
  text if larger), and that stays reserved until the exchange ends, since
  the text stays with the exchange for its rules and log.
- A request body hashed for `sign: aws_sigv4` reserves its
  `content-length` (at most `max_sign_body_bytes`) up front; a chunked body
  reserves what it has read, chunk by chunk, up to that cap, and is refused
  (`buffer_budget_exhausted`) at the chunk the budget cannot cover. Either
  way the reservation is held until the exchange ends
  ([signing AWS requests](/reference/secrets#signing-aws-requests)). With
  `unsigned_payload: true` the body streams and reserves nothing.
- A WebSocket whose messages rules read reserves twice
  `max_ws_message_bytes` at the upgrade and holds it for the session. A
  WebSocket under a policy that reads bodies but not messages holds
  nothing.

The budget divided by a cap is how many exchanges can hold that buffer at
once (with the defaults: 1024 bodies of unknown length being inspected, 32
WebSockets with message rules), so size it, or the caps, for the traffic
that needs them. It must be at least the largest of those reservations.

An observer's copy is charged for the bytes queued and not yet read, frame
by frame as they queue, and the charge is given back as the observer reads
them (or drops the copy). A copy whose next frame would take the budget
over `max_buffered_bytes` is cut (`observer_lagged`, `reason:
buffer_budget_exhausted`). So the number of observed exchanges is not
bounded by the budget: what is bounded is how far behind their observers
can be in total. With the defaults, observers can hold up to 1 GiB of
unread copy between them, each at most 16 MiB per direction; an observer
that keeps up costs the budget nothing.

The limits that shape the client-facing codec (`max_header_bytes`,
`max_url_bytes`, `max_headers`, `max_request_body_bytes`, `header_timeout`,
`body_idle_timeout`, `response_body_idle_timeout`, the keep-alive
`idle_timeout`, the `h2_*` limits) and
the `http.*` flags are fixed for a connection when it is accepted, on
HTTP/1.1 and HTTP/2 alike; a reload changes them for new connections only.
Everything decided per exchange (`max_inspect_body_bytes`,
`max_sign_body_bytes`, `max_response_body_bytes`, `response_header_timeout`, the WebSocket limits,
`max_observer_lag_bytes`, the policy itself) comes from the snapshot the exchange starts under, so an
exchange on an old connection runs under the current values.
`max_buffered_bytes` is process-wide: each reservation is checked against
the value in force at that moment, so a reload applies to every exchange's
next reservation, and the reservations already held stay as they are (a
smaller budget admits nothing new until enough of them end).

## Connections

- A connection over `max_connections` or `max_connections_per_client` (per
  client IP) is accepted and closed at once, with a `connection_refused`
  event.
- Every read is bounded (head size, body size, ClientHello size), and every
  stage has a timeout.
- Nothing is allocated in proportion to an attacker-supplied number before
  it is validated (`content-length: 10^18` does not pre-allocate).
- What exchanges buffer (inspection, WebSocket reassembly, observer
  copies) is bounded in aggregate by `max_buffered_bytes`, not only per
  exchange. Request bytes in flight on an HTTP/2 connection (sent by the
  client, not yet taken by the upstream) sit outside that budget: the
  connection's receive window caps them at 4 MiB, so one client IP can
  hold at most `max_connections_per_client` × 4 MiB (1 GiB by default).
- Bounded policy tables (metrics, state, addon state) never evict
  to make room: a flow that needs a new entry in a full table is denied
  ([never evict](/design/threat-model#never-evict)).
- The proxy port serves only proxy semantics and `roxy.internal`. Health
  and CA download live on the separate `ca_server` listener, so they can be
  firewalled differently.
- A panic in a connection task closes that connection only. The parsers are
  fuzzed so they do not panic at all.
- On `SIGTERM` or Ctrl-C roxy stops accepting, drains exchanges in flight
  for up to 10 seconds, and flushes the flow log and capture before
  exiting.
