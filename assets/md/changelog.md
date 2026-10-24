# Changelog

User-facing changes in each release, newest first. Each release has a
short summary; expand it for the itemised entries, where breaking changes
come first. Each release's GitHub page lists every merged pull request.

## Unreleased

The request trailers a service layer passes on are validated as a client's before they reach an origin, and captures are written as JSON lines for line-oriented shippers.

<details>
  <summary>Details</summary>

  ### Breaking

  * The service layer protocol is `roxy.layer.v7`, incompatible with `roxy.layer.v6`. A direction subscribed `head` is a head alone each way, with no end message after it, and an observe stream is one way: the service sends no heads, bytes or ends on it, and sends `close` when it is done. A WASM layer subscribed `head` passes on that direction's head alone: bytes or trailers in the body it gives fail the exchange closed. A service subscribed `head` no longer gets a `content-length` on that direction's head, as a WASM layer never did ([#592](https://github.com/roxy-proxy/roxy-proxy/issues/592)).
  * The flow log's `forward_aborted`, `answer_aborted` and `upstream_aborted` reasons are one, `layer_aborted`. A cut that follows a fault or the client's loss is no longer a layer's abort, so a body cut on its way through a layer is the client's or the upstream's. A layer's answer is its own when it gives it before taking the response from upstream, whether or not that response had arrived ([#593](https://github.com/roxy-proxy/roxy-proxy/issues/593)).
  * A raw backtick in an HTTP/1 request path is rejected with `invalid_path` instead of being percent-encoded; HTTP/2 already refused it. In a query it is still percent-encoded to `%60` ([#582](https://github.com/roxy-proxy/roxy-proxy/pull/582)).
  * Capture is written to `capture.jsonl` with one JSON object per line, in place of `capture.rxc` and its length-framed records: the head nested under `head`, body bytes base64 under `data`, and at most 48 KiB of body per line. A line-oriented shipper such as Vector or Fluent Bit can take the file as it is ([#527](https://github.com/roxy-proxy/roxy-proxy/issues/527)).

  ### Fixed

  * A service layer's request trailers are held to a client's rules on their way to an origin: refused without `http.allow_request_trailers`, held to `limits.max_header_bytes`, and never a framing, routing, authentication or `content-*` field. A section that breaks them is the layer's `invalid_request`: the exchange is refused `503` `layer_error`, or the error is logged if the origin has already answered, and the origin never sees the request complete. More than `limits.max_headers` fields is a service protocol violation ([#581](https://github.com/roxy-proxy/roxy-proxy/pull/581)).
  * An HTTP/2 client's request trailer section is held to `limits.max_header_bytes`, as an HTTP/1.1 client's chunked trailer section is; one over it is a stream reset, `parse_error` reason `head_too_large` ([#581](https://github.com/roxy-proxy/roxy-proxy/pull/581)).
  * HTTP/1.1 request trailers also meet the byte limit after normalisation, so a pass-through layer is not blamed for the client's oversized section (`431`, `parse_error` reason `head_too_large`).
  * A request held across the policy's `valid_until`, by an addon or while its body is buffered for inspection, is denied `_expired` when it reaches the rules, as a request sent after the instant is ([#568](https://github.com/roxy-proxy/roxy-proxy/issues/568)).
  * Without `forwarded_for`, `client.ip` is the canonical TCP peer address: an IPv4 client on a dual-stack `[::]` listener is `a.b.c.d`, not `::ffff:a.b.c.d`, in metric keys, the flow log and the addon principal. Rule comparisons already treated the two as one address. `client.peer.ip` in the flow log keeps the socket's form ([#579](https://github.com/roxy-proxy/roxy-proxy/pull/579)).
  * JSON the node cannot parse, whether the `node.token` record, an enrolment or renewal response, a lease or a flow upload's acknowledgement, is reported by the kind of fault and its line and column, never by quoting the input, which could put a token or a lease secret in the log ([#532](https://github.com/roxy-proxy/roxy-proxy/issues/532)).
</details>

## [0.3.0 (2026-10-15)](https://github.com/roxy-proxy/roxy-proxy/releases/tag/v0.3.0)

Addons can now answer early and hold a request or response for approval, with the request and response lanes of an exchange living independent lives. This is a breaking change for addons: the service protocol is `roxy.layer.v6` and the WASM interface is `roxy:addon@0.3.0`.

<details>
  <summary>Details</summary>

  ### Breaking

  * The service layer protocol is `roxy.layer.v6`. It is incompatible with `roxy.layer.v5` and the experimental `roxy.layer.v0`, and roxy does not accept a v5 peer: both sides must handle `stop`, `trailers`, explicit ends in both directions and headless completion. The bundled Python helper implements the new contract ([#558](https://github.com/roxy-proxy/roxy-proxy/pull/558)).
  * The WASM addon interface is `roxy:addon@0.3.0`. Components built against `0.2.x` or the unversioned package must be rebuilt with the matching SDK and WIT ([#558](https://github.com/roxy-proxy/roxy-proxy/pull/558)).

  ### Added

  * An addon can answer before forwarding, hold a request or an upstream response while it decides, and stream approved content into an answer it has already started. An approval addon can send `200 text/event-stream` with keepalive comments while it holds a request or a tool-call event, then approve, edit or deny it ([#558](https://github.com/roxy-proxy/roxy-proxy/pull/558)).
  * The request and response lanes of an exchange have independent lifetimes: a layer can end or stop one without the other, and an upstream head that arrives after an early answer is still delivered to the addon ([#558](https://github.com/roxy-proxy/roxy-proxy/pull/558)).
  * Trailers pass through service layers and WASM host-side passthrough, so gRPC status trailers survive an addon stack. WASM byte-stream rewriting has no trailer API and the Python forwarding helpers do not send trailers ([#558](https://github.com/roxy-proxy/roxy-proxy/pull/558)).

  ### Changed

  * Upstream informational responses such as `103 Early Hints` are discarded, with or without addons, and an addon cannot publish an informational head ([#558](https://github.com/roxy-proxy/roxy-proxy/pull/558)).

  * A WebSocket upgrade reserves its relay resources before the `101` reaches the client ([#558](https://github.com/roxy-proxy/roxy-proxy/pull/558)).

  * Publishing a second outgoing head on a lane is a layer failure and cuts an answer already in progress ([#558](https://github.com/roxy-proxy/roxy-proxy/pull/558)).

  * A layer that fails while handling a core denial may produce a `503`, but the flow record keeps the original deny rule and reason; the layer fault gets its own event ([#558](https://github.com/roxy-proxy/roxy-proxy/pull/558)).

  * The final flow record for an exchange waits for both lanes' bodies, their validation and every accepted host call to finish ([#558](https://github.com/roxy-proxy/roxy-proxy/pull/558)).

  * The quickstart's sentinel sidecar streams a model response to the agent as it arrives, holding only each tool call's block while the sentinel judges it, instead of the whole response until the stream ends. A rejected call is replaced by its note in place, and `modify` now works on streamed responses ([#563](https://github.com/roxy-proxy/roxy-proxy/pull/563)).

  * A body that streams through a layer costs more CPU per byte than it did; the fixed cost of a layer is unchanged. Tracked in [#561](https://github.com/roxy-proxy/roxy-proxy/issues/561).

  ### Security

  * rustls 0.23.46 (RUSTSEC-2026-0346 to 0349) and wasmtime 49.0.3 (RUSTSEC-2026-0352 to 0364) ([#557](https://github.com/roxy-proxy/roxy-proxy/pull/557)).
</details>

## [0.2.0 (2026-10-14)](https://github.com/roxy-proxy/roxy-proxy/releases/tag/v0.2.0)

Quarantine, a bearer-token node protocol, host services for service layers and `X-Forwarded-For` support, plus two security fixes (GHSA-4297-w88p-8xqv, GHSA-pwq9-p79h-pg35). Breaking for control planes, service layers (`roxy.layer.v5`), `client.port` users and the per-addon state store.

<details>
  <summary>Details</summary>

  ### Breaking

  * Node protocol: a node's credential is a rotating bearer token instead of a client certificate. Enrolment returns `token`, `not_after` and `renew_after_seconds`; later requests send `Authorization: Bearer`; the state dir holds `node.token` in place of `node.crt` and `node.key`. A control plane built for mutual TLS no longer works ([#528](https://github.com/roxy-proxy/roxy-proxy/pull/528)).
  * The service layer protocol is `roxy.layer.v5`: the `open` message carries the layer's grants and `config`, and a service may send host-service calls on its stream ([#526](https://github.com/roxy-proxy/roxy-proxy/pull/526)).
  * `client.port` is removed as a rule field and metric key. The flow log keeps the TCP peer as `client.peer: { ip, port }`, so `client.port` moves to `client.peer.port` in the log ([#525](https://github.com/roxy-proxy/roxy-proxy/pull/525)).
  * The per-addon state store and the `addons[].state` block are gone: a WASM layer's `state-get` and `state-put` use the store the rules read with `state[..]`, sized by `limits.max_state_entries`. A `state-put` without a TTL gets one hour, not six ([#511](https://github.com/roxy-proxy/roxy-proxy/pull/511)).
  * Stricter YAML: `yes`, `no`, `on` and `off` are not booleans, `<<` merge keys and custom tags are errors, and a file holds one document ([#482](https://github.com/roxy-proxy/roxy-proxy/pull/482)).

  ### Added

  * Quarantine: a rule's `quarantine` action or a listener's `quarantine_on.parse_errors` threshold puts the proxy into a durable state where every exchange is refused `403 _quarantined`. The trip is written to `<state-dir>/quarantine` and survives a restart; an operator removes the marker, or in node mode the control plane names the incident in the lease's `quarantine.release` list. `roxy run --config` accepts `--state-dir`, required when the config uses quarantine ([#505](https://github.com/roxy-proxy/roxy-proxy/pull/505)).
  * A layer of either kind can quarantine the proxy through the new `quarantine` capability: `flow.quarantine` for WASM, a `quarantine` message for a service ([#529](https://github.com/roxy-proxy/roxy-proxy/pull/529)).
  * Service layers get the host services WASM layers have: `log`, `record`, `add_tag`, `state_get`, `state_put` and `metric_get` messages, each answered with a `result`; `capabilities` and `config` are accepted on a service layer ([#526](https://github.com/roxy-proxy/roxy-proxy/pull/526)).
  * An `http` listener takes `forwarded_for: { trusted_hops: N }` to recover the client IP from `X-Forwarded-For`; the result is `client.ip` everywhere. A header with too few entries or a malformed trusted entry is refused `400 forwarded_for_invalid`. The setting is a config error on an `http_proxy` listener ([#525](https://github.com/roxy-proxy/roxy-proxy/pull/525)).
  * Node protocol: the lease poll reports `seq_unreserved` when the node could not persist its flow sequence counter ([#502](https://github.com/roxy-proxy/roxy-proxy/pull/502)).
  * The docs site publishes each release under `/vX.Y/` with a version menu ([#522](https://github.com/roxy-proxy/roxy-proxy/pull/522)).

  ### Changed

  * The rule language calls a field *admission* when it is known at the forwarding decision and *in-flight* when it is re-checked as the exchange streams, in place of "head" and "watched"; `roxy check`, `rule test` and the compiler diagnostics use the new words ([#524](https://github.com/roxy-proxy/roxy-proxy/pull/524)).
  * A tag an enforce layer adds is visible to `tag[..]` in admission and in-flight rules and to the `when` of the layers below; the 64-tag / 4 KiB cap now counts the rules' tags too ([#534](https://github.com/roxy-proxy/roxy-proxy/pull/534)).
  * The wait for a busy layer instance is bounded by the layer's `first_byte_timeout`; past it the exchange fails closed with `layer_error` kind `no_instance` ([#513](https://github.com/roxy-proxy/roxy-proxy/pull/513)).
  * The health and CA listener has its own connection cap, so a client filling `limits.max_connections` on the proxy port cannot starve `/healthz` ([#503](https://github.com/roxy-proxy/roxy-proxy/pull/503)).
  * `roxy check` warns about a metric keyed on `host` or `client.port` without a `where`, with field-specific advice, and no longer warns for `unique(..)` fields ([#497](https://github.com/roxy-proxy/roxy-proxy/pull/497)).
  * The WIT package is `roxy:addon@0.2.1`, an additive bump that `0.2.0` components still load. The SDK's `flow::metric_get` loses its `key` parameter ([#542](https://github.com/roxy-proxy/roxy-proxy/pull/542)).
  * Node mode: a `401` on `/renew` is retried with backoff rather than ending renewal; `410` or `426` at enrolment is reported as a refusal ([#546](https://github.com/roxy-proxy/roxy-proxy/pull/546)).
  * A service observe stream ends on the service's last message rather than roxy's, with `first_byte_timeout` to send it, so a service observer can read a body and then `record`. Host calls queued before a stream ends still run ([#548](https://github.com/roxy-proxy/roxy-proxy/pull/548)).
  * A layer's own body that is still open splices the bypassed body as unknown length, so a held-back end or a failure is always a visible cut. A head-only WASM request layer that passes a stream to `next` now sends a chunked request upstream ([#543](https://github.com/roxy-proxy/roxy-proxy/pull/543)).
  * The node reserves flow sequence numbers off the emit path, so a slow disk no longer stalls every emitter ([#485](https://github.com/roxy-proxy/roxy-proxy/pull/485)).

  ### Fixed

  * A WebSocket through a layer subscribed to `(request: full, response: head)` no longer stalls ([#516](https://github.com/roxy-proxy/roxy-proxy/pull/516)).
  * A service-layer head with too many header fields is refused at `limits.max_headers` instead of panicking ([#499](https://github.com/roxy-proxy/roxy-proxy/pull/499)).
  * Client parse-error detail is redacted in the operational log as it is in the flow log ([#498](https://github.com/roxy-proxy/roxy-proxy/pull/498)).

  ### Security

  * GHSA-4297-w88p-8xqv: `Host: [::ffff:1.2.3.4]` bypassed a deny on `1.2.3.4`. An IPv4-mapped IPv6 literal now parses as the IPv4 address it embeds, and a `host` or `tls.sni` literal written in the mapped form is a compile error ([#506](https://github.com/roxy-proxy/roxy-proxy/pull/506)).
  * GHSA-pwq9-p79h-pg35: with `http.allow_obs_text: true`, a header value holding a byte of `0x80` or above was invisible to an equality rule but forwarded. Rules now read header values as the bytes that are forwarded, one character per byte ([#507](https://github.com/roxy-proxy/roxy-proxy/pull/507)).
  * YAML is read with `serde-saphyr`; the unmaintained `unsafe-libyaml` (RUSTSEC-2024-0449) is gone ([#482](https://github.com/roxy-proxy/roxy-proxy/pull/482)). `ruzstd` 0.9.1 for RUSTSEC-2026-0344 ([#505](https://github.com/roxy-proxy/roxy-proxy/pull/505)).
</details>

## [0.1.1 (2026-10-12)](https://github.com/roxy-proxy/roxy-proxy/releases/tag/v0.1.1)

Heads cross the WASM boundary as records and bodies as bare streams (`roxy:addon@0.2.0`), layers subscribe to only the directions they need, and a batch of host hardening fixes. Breaking for WASM components and service layers (`roxy.layer.v4`).

<details>
  <summary>Details</summary>

  ### Breaking

  * The WASM addon interface is `roxy:addon@0.2.0`: a head crosses the guest boundary as one record per direction and bodies are bare `wasi:io` streams; the `wasi:http` import is gone. Components must be rebuilt against SDK 0.2.0, which is source-compatible ([#424](https://github.com/roxy-proxy/roxy-proxy/pull/424)).
  * The service layer protocol is `roxy.layer.v4`: the `deny` message is gone (a service refuses by answering with a `response`) and `open` carries the layer's subscription ([#420](https://github.com/roxy-proxy/roxy-proxy/pull/420)).
  * Removed `audit_endpoint`, the `audit` flag of `flow.record`, endpoint `retries` and the `attempts` field of the `endpoint_call` event ([#420](https://github.com/roxy-proxy/roxy-proxy/pull/420)).
  * Removed the dead transparent-listener keys (`mode: transparent`, `allow_passthrough`, `upstream_target`); they are now unknown-field errors ([#457](https://github.com/roxy-proxy/roxy-proxy/pull/457)).
  * A `host` or `tls.sni` literal that can never match (trailing dot, non-ASCII, bracketed IPv6) is a compile error with a rewrite hint ([#463](https://github.com/roxy-proxy/roxy-proxy/pull/463)).

  ### Added

  * A layer declares what it wants of each direction with `subscribe: { request: head | full, response: head | full }`. A body a layer is not subscribed to bypasses it; bytes it passes on for that body fail the exchange closed ([#420](https://github.com/roxy-proxy/roxy-proxy/pull/420)).
  * `SECURITY.md`, pointing at private vulnerability reporting ([#464](https://github.com/roxy-proxy/roxy-proxy/pull/464)).

  ### Changed

  * `first_byte_timeout` is one budget per head, request and response alike, for WASM layers as it already was for service layers ([#431](https://github.com/roxy-proxy/roxy-proxy/pull/431)).
  * Service layer streams spread across up to `max_connections` connections instead of filling one, and writes are flushed in batches ([#423](https://github.com/roxy-proxy/roxy-proxy/pull/423)).
  * The addon SDK moves bodies and heads a layer does not touch host-side, cutting a no-op layer's cost ([#418](https://github.com/roxy-proxy/roxy-proxy/pull/418)).
  * A fault after the response head carries its own reason into the `request` event (`buffer_budget_exhausted`, `upstream_body_failed`, `layer_error` or the client's parse reason) instead of `response_write_failed` ([#419](https://github.com/roxy-proxy/roxy-proxy/pull/419)).
  * `like` patterns are capped at 1 KiB and compiled with the same limits as `matches`; `?` matches one character, as documented ([#459](https://github.com/roxy-proxy/roxy-proxy/pull/459)).

  ### Fixed

  * A guest head with tens of thousands of header fields is refused at `limits.max_headers` instead of panicking the host ([#458](https://github.com/roxy-proxy/roxy-proxy/pull/458)).
  * A guest that writes to stdout or stderr no longer fails every exchange through its layer ([#469](https://github.com/roxy-proxy/roxy-proxy/pull/469)).
  * A handler that returns without responding is treated like a trap: the instance is discarded and the exchange fails ([#460](https://github.com/roxy-proxy/roxy-proxy/pull/460)).
  * An endpoint call waits for its in-flight permit before its body leaves the guest ([#465](https://github.com/roxy-proxy/roxy-proxy/pull/465)).
  * A service connection whose write side has died fails its exchanges at once with `service:closed` instead of after `first_byte_timeout` ([#461](https://github.com/roxy-proxy/roxy-proxy/pull/461)).
  * Body frames on an ended service stream are dropped without crediting, so a misbehaving service cannot grow roxy's memory ([#462](https://github.com/roxy-proxy/roxy-proxy/pull/462)).
  * `response_body_idle_timeout` applies while a response body is collected for inspection; a stalled upstream under a body rule gets a `504` ([#467](https://github.com/roxy-proxy/roxy-proxy/pull/467)).
  * The reference says what the code does where it overclaimed: timeouts, drain and linger limits, the hop-by-hop list, node `410` handling and lease fields ([#457](https://github.com/roxy-proxy/roxy-proxy/pull/457)); HTTP/1.0 close-delimited responses are documented ([#466](https://github.com/roxy-proxy/roxy-proxy/pull/466)).
</details>

## [0.1.0 (2026-10-08)](https://github.com/roxy-proxy/roxy-proxy/releases/tag/v0.1.0)

The first release: a strict, programmable HTTP firewall.

* Two ways to deploy it: as an egress proxy for a workload you don't trust (`mode: http_proxy`, with TLS terminated by roxy's own CA), or as a gateway in front of the APIs your clients call (`mode: http`).
* One canonical form: every request is parsed into one strict model and re-serialised, over HTTP/1.1 and HTTP/2, with WebSockets relayed. Anything roxy cannot parse, verify or classify is denied.
* A typed YAML rule language where deny always wins and nothing unlisted passes; rules can watch bodies and WebSocket messages as they stream. Metrics give rate limits and byte budgets; secret injection and AWS SigV4 signing mean clients hold only placeholders.
* Addons above the rules, as WASM components in process or external services streamed over WebSocket: they can rewrite, withhold, answer or block, and the rules judge whatever they pass on.
* A JSONL flow log naming the rule or addon behind every decision, with optional body capture and digests; backpressure holds traffic until the log catches up.
* Node mode: roxy enrols with a control plane, leases its policy and secrets into memory, and ships its flow log.
