# Rule language

The `when` / `where` expression language and the actions of `then`.
Evaluation is in [policy evaluation](/design/policy-evaluation).

## Expressions

Statically typed; no user-defined functions; linear-time matching (`regex`
crate, no backtracking).

```
expr        := or
or          := and ( "or" and )*
and         := not ( "and" not )*
not         := "not" not | primary
primary     := "(" expr ")" | comparison | predicate
comparison  := operand OP operand
predicate   := field                         ; boolean field
operand     := field | field "[" string "]" | literal
OP          := "==" | "!=" | "<" | "<=" | ">" | ">="
             | "in" | "not in"
             | "starts_with" | "ends_with" | "contains"
             | "like"        ; glob, full match ( * ? )
             | "matches"     ; regex, full match
             | "under"       ; host == X or host ends_with "." + X
literal     := string | number [unit] | bool | list | cidr | @list | method | "null"
list        := "[" literal ("," literal)* "]"
unit        := kb | mb | gb | ms | s | m | h      ; sizes are 1024-based (kb and kib are the same)
method      := [A-Z][A-Z_]*                       ; HTTP method names only
```

- Strings: double-quoted, `\"` and `\\` escapes. `# ...` comments are
  allowed in multi-line YAML block scalars.
- Comparison is byte-exact, except: `host`, `tls.sni` and `scheme` operands
  compare ASCII case-insensitively under every operator (`like`, `matches`,
  `in` included); `under` is case-insensitive whatever its left operand;
  `header["X-Y"]` names are case-insensitive, values not. `method` is
  exact: method `get` is forwarded as an extension method, may carry a
  body, and matches neither `method == GET` nor `method in [GET, HEAD]`.
- Compile errors: type mismatch (`host under 443`), a regex that does not
  compile, a bad CIDR mask, `metric.foo` with no such metric, an undefined
  `@list`. `in` takes a list of the operand's type, a CIDR, or an `@list`
  for ip fields.

### Fields

*Head* fields are known at the forwarding decision; rules reading *watched*
fields watch.

| field | type | known |
|---|---|---|
| `client.ip`, `client.port` | ip, int | head |
| `listener.name` | string | head |
| `tls.sni`, `tls.alpn`, `tls.version` | string | head |
| `method`, `scheme`, `host`, `port`, `path`, `url` | string / int | head |
| `query["k"]`, `query.raw` | string | head |
| `header["name"]`, `header.all["name"]` | string, list | head |
| `body.size` | int: declared length, `null` if undeclared (chunked) | head |
| `body.text` | string: the buffered body, up to the cap | head |
| `metric.<id>` | int | head; a `deny` reading a byte metric also watches it ([rate limits](/reference/rate-limits#metrics)) |
| `state["key"]`, `tag["name"]` | string, bool | head |
| `body.bytes` | int: request body bytes so far | watched |
| `response.status`, `response.header["name"]`, `response.header.all["name"]` | int, string, list | watched |
| `response.body.size` | int: declared length, `null` if undeclared | watched |
| `response.body.text` | string: the buffered response body | watched |
| `response.body.bytes` | int: response body bytes so far | watched |
| `ws.direction`, `ws.opcode`, `ws.size`, `ws.text` | string, int, int, string: the WebSocket message being checked | watched, per message ([WebSockets](/reference/websockets#message-rules)) |

`path` is normalised ([HTTP](/reference/http#url-normalisation)). Any rule
reading `ws.*` makes roxy decode every WebSocket message and strip
WebSocket extensions.

### Missing values (`null`)

An absent value is `null`: an unsent header or query parameter, an unset
state key, `tls.sni` when none was sent, `body.size` for a chunked body.
`tag["x"]` is never `null`: `false` until set. `==`, `!=`, `in` and `not
in` treat `null` as a value; any other operator on it fails closed.

| expression, with `x` missing | result |
|---|---|
| `x == null` | true |
| `x != null` | false |
| `x == "a"`, `x in [...]` | false |
| `x != "a"`, `x not in [...]` | true |
| `x > 10`, `x contains "a"`, `x matches "..."`, `x under "..."`, `x in 10.0.0.0/8`, `x in @list` | fails closed: `_fail_closed`, reason `missing_value`, naming the field |

`and` short-circuits: `body.size != null and body.size > 10mb`. `null` may
appear only in `x == null` / `x != null`. A metric keyed on a nullable field
needs the same guard in its `where` ([rate limits](/reference/rate-limits#metrics)).

## Actions

`then` is required: one action, or a list with at most one terminal action
(`allow` or `deny`), last. An action is a bare word or a single-key map of
name to argument; a multi-key map, an unknown action, a wrong-shaped
argument or anything after a terminal action is a compile error.

```yaml
then: allow
then: { deny: { status: 451, message: "no" } }
then:
  - set_header: { authorization: "Bearer ${secret:openai}" }
  - remove_header: [x-debug]
  - tag: billing
  - allow: { upgrade: websocket }
```

Terminal:

| action | where | effect |
|---|---|---|
| `allow` | head rules | Forward. `upgrade: websocket` permits a WebSocket upgrade; `private_ok: true` lets the flow reach private addresses ([address floor](/reference/address-lists#address-floor)). |
| `deny` | all rules | `deny: { status, message, close }`; status 403 by default, 4xx or 5xx. At the head: refuse ([deny responses](/reference/http#deny-responses)) and close unless `close: false`. Watching: stop the exchange ([evaluation](/design/policy-evaluation#evaluation)). On a WebSocket: close both sides, with a `1008` frame when rules read messages ([WebSockets](/reference/websockets#message-rules)). |

Non-terminal:

| action | where | effect |
|---|---|---|
| `set_header: { name: value }` | request: head rules; response: watching rules | Set or replace. Request values may use `${secret:name}`; an invalid value denies the flow. A response rule may read only values known before the response head is sent (`response.status`, `response.header[..]`, `response.body.size`, `response.body.text`); `body.bytes`, `response.body.bytes`, `ws.*` or a byte metric is a compile error. |
| `remove_header: [names]` | as `set_header` | |
| `rewrite_path: { match, to }` | head rules | Anchored regex (as `matches`), `$1` / `${name}` groups; result re-normalised. |
| `set_query: { k: v }`, `remove_query: [k]` | head rules | |
| `redirect: { host, port, scheme?, rewrite_host? }` | head rules | Change the upstream target. `host`: DNS name, dotted-quad IPv4 or bracketed IPv6 (`[::1]`); anything else, or port `0`, is a config error. The new IPs pass the address floor and deny lists. `Host` is unchanged unless `rewrite_host: true`, and while unchanged the request goes upstream over HTTP/1.1 (HTTP/2 needs `:authority` and `host` to agree). |
| `tag: name` | all | Sets `tag["name"]` for later rules, addons and the log. |
| `log: { level, message }` | all | Emits a `log` flow event. |
| `set_state: { key, value, ttl? }` | all | Writes the [state store](/reference/rate-limits#state). |
| `capture: request \| response \| both` | head rules | Tees the exchange, as forwarded, to the [capture log](/reference/flow-log#capture). |
| `digest: request \| response \| both` | head rules | Hashes the selected bodies, as forwarded, into the flow record's [`body_sha256`](/reference/flow-log#flow-log). Nothing is hashed without it. |
| `sign: { aws_sigv4: { service, region, access_key_id, secret_access_key, session_token?, unsigned_payload? } }` | head rules | AWS Signature Version 4 over the forwarded request, after every other head effect ([signing AWS requests](/reference/secrets#signing-aws-requests)). |

Anything richer is an addon. `call` and `passthrough` are rejected with a
reason naming why.

## Body rules

`body.text` and `response.body.text` are the only fields that buffer. If
any rule reads `body.text`, roxy collects every request body up to
`limits.max_inspect_body_bytes` (1 MiB) before the head decision, then
streams it on; `response.body.text` likewise for every response body. A
body over the cap is unavailable: a rule reading it fails closed
(`_fail_closed`, reason `body_too_large_to_inspect`). Raise the cap, or
scope the rule (`body.size != null and body.size < 1mb and ...`) so it
short-circuits before the text; that avoids the fail-closed, not the
buffering. No body rule, no buffering.

The text is the body decoded by its `content-encoding`
([content codings](/reference/http#content-codings)), as lossy UTF-8; the
forwarded bytes are the bytes received. The cap applies to the decoded text
too. An undecodable body fails closed: `body_decode_failed` (corrupt,
truncated, or bytes after the end of the stream) or
`unsupported_content_encoding`.
