# Rule language

## Expressions

Readable, small and statically typed, with no user-defined functions (that
is what addons are for) and linear-time matching (the `regex` crate, no
backtracking).

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
unit        := kb | mb | gb | ms | s | m | h      ; sizes are 1024-based
method      := [A-Z][A-Z_]*                       ; HTTP method names only
```

Strings are double-quoted with `\"` and `\\` escapes. `# ...` comments are
allowed inside multi-line YAML block scalars. Size units are 1024-based
(`kb` and `kib` are the same).

String comparisons are byte-exact, with one exception: operands involving
`host`, `tls.sni` or `scheme` compare ASCII case-insensitively (for every
operator, including `like`, `matches` and `in`). `under` is ASCII
case-insensitive whatever its left operand, because it compares domain
names. `method` compares exactly,
because HTTP methods are case-sensitive: a request with method `get` is
forwarded as an extension method, may carry a body, and does not match
`method == GET` or `method in [GET, HEAD]`. Header names in `header["X-Y"]`
are case-insensitive; header values are not.

Type errors are compile errors: `host under 443`, a regex that does not
compile, a CIDR with a bad mask, a `metric.foo` with no such metric, an
`@list` that is not defined. `in` takes a list of the operand's type, a
CIDR, or an `@list` for ip fields.

### Fields

*Head* fields are known when the forwarding decision is made. *Watched*
fields become known later, so rules that read them watch.

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

`path` is the normalised path ([HTTP](/reference/http#url-normalisation)), so a
rule matches exactly what is forwarded. A policy with any rule that reads
`ws.*` makes roxy decode and check every WebSocket message, and strips
WebSocket extensions so messages stay readable.

### Missing values (`null`)

A value that is not present is `null`: an unsent header or query parameter,
an unset state key, `tls.sni` from a client that sent none, `body.size`
for a chunked body. A tag is never `null`: `tag["x"]` is `false` until a
rule or addon sets it, so `tag["x"] == null` is always false.

> `null` is equal only to `null`, so `==`, `!=`, `in` and `not in` treat it
> as an ordinary value. Any other operator on `null` is an error, and an
> error fails the flow closed.

| expression, with `x` missing | result |
|---|---|
| `x == null` | true |
| `x != null` | false |
| `x == "a"`, `x in [...]` | false |
| `x != "a"`, `x not in [...]` | true |
| `x > 10`, `x contains "a"`, `x matches "..."`, `x under "..."`, `x in 10.0.0.0/8`, `x in @list` | fails closed: `_fail_closed`, reason `missing_value`, naming the field |

`and` short-circuits, so a guard applies a rule only when the value is
present: `body.size != null and body.size > 10mb`. `null` may only appear
in `x == null` or `x != null`. A metric keyed on a field that can be `null`
must carry the same guard in its `where`
([rate limits](/reference/rate-limits#metrics)).

## Actions

`then` is one action or a list: any number of non-terminal actions and at
most one terminal action (`allow` or `deny`), last. An action is a bare word
(`allow`, `deny`) or a single-key map of the action name to its argument.

```yaml
then: allow
then: { deny: { status: 451, message: "no" } }
then:
  - set_header: { authorization: "Bearer ${secret:openai}" }
  - remove_header: [x-debug]
  - tag: billing
  - allow: { upgrade: websocket }
```

A map with more than one key, an unknown action, an argument of the wrong
shape, or anything after a terminal action is a compile error. `then` is
required.

Terminal:

| action | where | effect |
|---|---|---|
| `allow` | head rules | Forward. `allow: { upgrade: websocket }` also permits a WebSocket upgrade; `private_ok: true` lets this flow reach private addresses ([address floor](/reference/address-lists#address-floor)). |
| `deny` | all rules | `deny: { status, message, close }`. Status defaults to 403 and must be 4xx or 5xx. At the head: refuse ([deny responses](/reference/http#deny-responses)); the connection is closed afterwards unless `close: false`. Watching: stop the exchange, as in [evaluation](/design/policy-evaluation#evaluation). On a WebSocket: close both sides (with a `1008` close frame when rules read messages, [WebSockets](/reference/websockets#message-rules)). |

Non-terminal:

| action | where | effect |
|---|---|---|
| `set_header: { name: value }` | request: head rules; response: watching rules | Set or replace. Request values may use `${secret:name}`. Invalid values deny the flow. On the response, every value the rule reads must be known before the response head is sent (`response.status`, `response.header[..]`, `response.body.size`, `response.body.text`); reading `body.bytes`, `response.body.bytes`, `ws.*` or a byte metric as well is a compile error. |
| `remove_header: [names]` | same as `set_header` | |
| `rewrite_path: { match, to }` | head rules | Regex (anchored, like `matches`) with `$1` / `${name}` groups. The result is re-normalised. |
| `set_query: { k: v }`, `remove_query: [k]` | head rules | |
| `redirect: { host, port, scheme?, rewrite_host? }` | head rules | Change the upstream target. `host` follows the same rules as a request's host: a DNS name, a dotted-quad IPv4 address or a bracketed IPv6 address (`[::1]`). Anything else, and port `0`, is a config error. The address floor and deny lists check the new target's IPs. `Host` is unchanged unless `rewrite_host: true`; while it is unchanged, the request goes upstream over HTTP/1.1, because HTTP/2 needs `:authority` and `host` to agree. |
| `tag: name` | all | Sets `tag["name"]` for later rules, addons and the log. |
| `log: { level, message }` | all | Emits a `log` flow event. |
| `set_state: { key, value, ttl? }` | all | Writes the [state store](/reference/rate-limits#state). |
| `capture: request \| response \| both` | head rules | Tees the exchange, as forwarded, to the [capture log](/reference/flow-log#capture). |
| `sign: { aws_sigv4: { service, region, access_key_id, secret_access_key, session_token?, unsigned_payload? } }` | head rules | Signs the forwarded request with AWS Signature Version 4, after every other head effect; the credentials may use `${secret:name}` ([signing AWS requests](/reference/secrets#signing-aws-requests)). |

The actions are a small closed set on purpose: anything richer is an addon.
Two words are reserved and rejected with the reason: `call` (addons run
above the rules, not from one) and `passthrough` (reserved; roxy has no
transparent listener).

## Body rules

`body.text` and `response.body.text` are the only fields that buffer. If
any rule reads `body.text`, roxy collects every request body up to
`limits.max_inspect_body_bytes` (1 MiB) before the head decision, evaluates,
then streams the bytes on; `response.body.text` does the same for every
response body. A body over the cap is **unavailable**, and a rule that
reads it **fails closed** (`_fail_closed`, reason
`body_too_large_to_inspect`). Raise the cap to inspect larger bodies, or
scope the rule (`body.size != null and body.size < 1mb and ...`) so it
short-circuits before reading the text: that avoids the fail-closed, not
the buffering. A policy with no rule reading a body never buffers.

The text is the body decoded by its `content-encoding` (`gzip`, `deflate`,
`br`, `zstd`, stacked or not; [HTTP](/reference/http#content-codings)), then read
as lossy UTF-8. Decoding is for the rules only: the bytes forwarded are the
bytes received. The cap applies to the decoded text too, so a small body
that inflates past it fails closed with `body_too_large_to_inspect`. A body
that cannot be decoded fails closed as well: `body_decode_failed` for
corrupt or truncated data or bytes after the end of the stream,
`unsupported_content_encoding` for a coding roxy does not know.
