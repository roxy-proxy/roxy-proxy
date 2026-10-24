# Resource limits

When something goes wrong, roxy refuses the request or closes the
connection rather than letting traffic through
([fail closed](/design/threat-model#fail-closed)).

## Fail-closed outcomes

| condition | result |
|---|---|
| roxy is quarantined | `403`, `_quarantined` ([quarantine](/guides/operations#quarantine)) |
| a malformed request | the connection is closed, with a `400` if possible, and a `parse_error` event |
| a rule denies | the deny response, then the connection is closed |
| a metric, address list or secret is unavailable | `503`, `_fail_closed` |
| a metric table is full | `503`, `_fail_closed`, `metric_table_full` |
| a body is too large to inspect, or cannot be decoded | `503`, `_fail_closed` |
| a body to sign is over `max_sign_body_bytes` | `413`, `_sign` |
| the buffer budget is used up | `503`, `_fail_closed`, `buffer_budget_exhausted` |
| a body or header limit is exceeded mid-stream | both sides are closed |
| the upstream cannot be resolved or reached, or fails TLS | `502` ([upstream](/reference/upstream#errors)) |
| the upstream times out | `504` |
| the address floor refuses the upstream | `403`, `_address_policy` |
| an enforcing addon fails | `503`, `layer:<name>` |
| a config reload fails | the old policy stays |
| a connection cap is reached | the new connection is refused |
| the flow log or capture falls behind | traffic waits until it catches up |

Reason codes are in the flow log only, never in the response.

## Limits

All are under `limits:`. Defaults are shown. Sizes are 1024-based.

```yaml
limits:
  # client requests
  max_header_bytes: 64kb
  max_url_bytes: 8kb
  max_headers: 100
  max_request_body_bytes: 1gb
  header_timeout: 10s             # to send each request head (and CONNECT, and the TLS handshake)
  body_idle_timeout: 10m          # the client stalls sending its body, or reading the response
  idle_timeout: 1h                # an idle keep-alive connection or WebSocket
  h2_max_concurrent_streams: 100
  h2_max_header_list_bytes: 64kb

  # responses
  max_response_body_bytes: 1gb
  response_header_timeout: 15m    # the upstream's response head, once the request body is sent
  response_body_idle_timeout: 30m # the upstream stalls mid-body

  # buffering
  max_inspect_body_bytes: 1mb     # body.text, response.body.text, and addons' default
  max_sign_body_bytes: 100mb      # a body hashed for sign: aws_sigv4
  max_capture_body_bytes: 16mb    # per direction per exchange
  max_ws_message_bytes: 16mb      # a WebSocket message, when rules read messages
  max_observer_lag_bytes: 16mb    # how far an observing addon may fall behind
  max_buffered_bytes: 1gb         # all of the above together, across the process

  # connections
  max_connections: 10000
  max_connections_per_client: 10000   # per client IP; defaults to max_connections

  # policy state
  max_metric_keys: 100000
  max_metric_bytes: 256mb
  max_state_entries: 100000
  max_address_list_bytes: 256mb
```

The upstream connection timeout is `upstream.connect_timeout`
([upstream](/reference/upstream)). Addons have their own limits
([addon limits](/reference/addon-configuration#limits)).

### Timeouts

The timeouts are generous by default. roxy decides what passes, not how
long a well-behaved exchange may take: a model call that takes minutes to
start answering, or a quiet WebSocket, should not hit one. Only
`header_timeout` is tight, to stop clients that open connections and send
nothing. A long timeout costs a connection slot, not memory, so if idle
connections run out, raise `max_connections` rather than shortening the
timeouts.

If the upstream answers before it has read the whole upload, and then
stops reading it for twice `body_idle_timeout`, roxy cancels the upload
and records `upstream_body_timeout`.

### Buffer budget

`max_buffered_bytes` bounds everything roxy buffers to inspect or copy:
bodies that rules read, bodies being decoded or signed, WebSocket messages
that rules read, endpoint call bodies, and copies for observing addons.
Each exchange reserves what it needs before it buffers. If the budget
cannot cover a reservation, the exchange fails at once
(`buffer_budget_exhausted`). Nothing waits and nothing is evicted.

A body of unknown length that a rule reads reserves the whole
`max_inspect_body_bytes`, so the defaults allow 1024 such bodies at once.
The budget is not a cap on the process's memory: socket buffers, streaming
buffers and addon memory are separate.

## Connections

- A connection over `max_connections` or `max_connections_per_client` is
  closed at once and logged as `connection_refused`. The per-client cap
  counts TCP peers, so behind a load balancer it counts the load
  balancer.
- The `ca_server` listener has a separate cap of `max_connections`.
- Each HTTP/2 connection can hold up to 4 MiB of request data not yet
  sent upstream, outside the buffer budget.
- Metric and state tables never evict entries
  ([never evict](/design/threat-model#never-evict)).
