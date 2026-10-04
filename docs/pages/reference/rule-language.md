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
operator, including `like`, `matches` and `in`). `method` compares exactly,
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
| `client.ip`, `client.port`, `client.user` | ip, int, string | head |
| `listener.name`, `listener.mode` (`explicit` or `direct`) | string | head |
| `tls.sni`, `tls.alpn`, `tls.version` | string | head |
| `method`, `scheme`, `host`, `port`, `path`, `url` | string / int | head |
| `query["k"]`, `query.raw` | string | head |
| `header["name"]`, `header.all["name"]` | string, list | head |
| `body.size` | int: declared length, `null` if undeclared (chunked) | head |
| `body.text` | string: the buffered body, up to the cap | head |
| `metric.<id>` | int | head, and watched for byte metrics |
| `state["key"]`, `tag["name"]` | string, bool | head |
| `body.bytes` | int: request body bytes so far | watched |
| `response.status`, `response.header["name"]`, `response.header.all["name"]` | int, string, list | watched |
| `response.body.size` | int: declared length, `null` if undeclared | watched |
| `response.body.text` | string: the buffered response body | watched |
| `response.body.bytes` | int: response body bytes so far | watched |
| `ws.direction`, `ws.opcode`, `ws.size`, `ws.text` | string, int, int, string: the WebSocket message being checked | watched, per message ([WebSockets](/policies/websockets#message-rules)) |

`path` is the normalised path ([HTTP](/reference/http#url-normalisation)), so a
rule matches exactly what is forwarded. A policy with any rule that reads
`ws.*` makes roxy decode and check every WebSocket message, and strips
WebSocket extensions so messages stay readable.

### Missing values (`null`)

A value that is not present is `null`: an unsent header or query parameter,
an unset state key, `client.user` without proxy auth, `tls.sni` from a
client that sent none, `body.size` for a chunked body.

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
in `x == null` or `x != null`.

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
| `allow` | head rules | Forward. `allow: { upgrade: websocket }` also permits a WebSocket upgrade; `private_ok: true` lets this flow reach private addresses ([address floor](/policies/address-lists#address-floor)). |
| `deny` | all rules | `deny: { status, message, close }`. Status defaults to 403 and must be 4xx or 5xx. At the head: refuse ([deny responses](/reference/http#deny-responses)); the connection is closed afterwards unless `close: false`. Watching: stop the exchange, as in [evaluation](#evaluation). On a WebSocket: close both sides (with a `1008` close frame when rules read messages, [WebSockets](/policies/websockets#message-rules)). |

Non-terminal:

| action | where | effect |
|---|---|---|
| `set_header: { name: value }` | request: head rules; response: watching rules | Set or replace. Request values may use `${secret:name}`. Invalid values deny the flow. On the response, every value the rule reads must be known before the response head is sent (`response.status`, `response.header[..]`, `response.body.size`, `response.body.text`); reading `body.bytes`, `response.body.bytes` or a byte metric as well is a compile error. |
| `remove_header: [names]` | same as `set_header` | |
| `rewrite_path: { match, to }` | head rules | Regex (anchored, like `matches`) with `$1` / `${name}` groups. The result is re-normalised. |
| `set_query: { k: v }`, `remove_query: [k]` | head rules | |
| `redirect: { host, port, scheme?, rewrite_host? }` | head rules | Change the upstream target. The address floor and deny lists check the new target's IPs. `Host` is unchanged unless `rewrite_host: true`; while it is unchanged, the request goes upstream over HTTP/1.1, because HTTP/2 needs `:authority` and `host` to agree. |
| `tag: name` | all | Sets `tag["name"]` for later rules, addons and the log. |
| `log: { level, message }` | all | Emits a `log` flow event. |
| `set_state: { key, value, ttl? }` | all | Writes the [state store](#state). |
| `capture: request \| response \| both` | head rules | Tees the exchange, as forwarded, to the [capture log](/operate/flow-log#capture). |

The actions are a small closed set on purpose: anything richer is an addon.
`call` is reserved and rejected (addons always run above the rules).
`passthrough` is reserved for transparent mode and rejected (issue #15).
