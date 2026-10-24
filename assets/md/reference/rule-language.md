# Rule language

The expressions used in a rule's `when` and a metric's `where`, and the
actions of a rule's `then`. How rules are evaluated is in
[policy evaluation](/design/policy-evaluation).

## Expressions

Expressions are statically typed, and regular expressions run in linear
time.

```
expr        := or
or          := and ( "or" and )*
and         := not ( "and" not )*
not         := "not" not | primary
primary     := "(" expr ")" | comparison | predicate
comparison  := operand OP operand
predicate   := field | bool                  ; boolean field, or a literal (`where: true`)
operand     := field | field "[" string "]" | literal
OP          := "==" | "!=" | "<" | "<=" | ">" | ">="
             | "in" | "not in"
             | "starts_with" | "ends_with" | "contains"
             | "like"        ; glob, full match ( * ? )
             | "matches"     ; regex, full match
             | "under"       ; host == X or host ends_with "." + X
literal     := string | number [unit] | bool | list | ip | cidr | @list | method | "null"
list        := "[" literal ("," literal)* "]"
unit        := kb | mb | gb | ms | s | m | h      ; sizes are 1024-based
method      := [A-Z][A-Z_]*                       ; HTTP method names only
```

* A rule without `when` matches everything. So does a metric without
  `where`.
* Strings are double-quoted, with `\"` and `\\` escapes.
* Comparison is exact, except that `host`, `tls.sni` and `scheme` compare
  without regard to case, and so do header names. Header values are
  compared exactly. `method` is case-sensitive: `get` does not match
  `GET`.
* Mistakes are compile errors: a type mismatch (`host under 443`), a
  regex that does not compile, an unknown metric or `@list`, a
  `${secret:name}` placeholder in a condition, or a comparison that can
  never match, such as a `host` with a trailing dot or in upper case.

### Fields

*Admission* fields are known when roxy decides whether to forward the
request. *In-flight* fields become known later, and a rule that reads one
is checked as the exchange streams
([evaluation](/design/policy-evaluation#when-rules-run)).

| field | type | known |
|---|---|---|
| `client.ip` | ip | admission |
| `listener.name` | string | admission |
| `tls.sni`, `tls.alpn`, `tls.version` | string | admission |
| `method`, `scheme`, `host`, `port`, `path`, `url` | string / int | admission |
| `query["k"]`, `query.raw` | string | admission |
| `header["name"]`, `header.all["name"]` | string, list | admission |
| `body.size` | int: declared length, `null` if not declared | admission |
| `body.text` | string: the buffered body | admission |
| `metric.<id>` | int | admission ([rate limits](/reference/rate-limits#metrics)) |
| `state["key"]`, `tag["name"]` | string, bool | admission |
| `body.bytes` | int: request body bytes so far | in-flight |
| `response.status`, `response.header["name"]`, `response.header.all["name"]` | int, string, list | in-flight |
| `response.body.size` | int: declared length, `null` if not declared | in-flight |
| `response.body.text` | string: the buffered response body | in-flight |
| `response.body.bytes` | int: response body bytes so far | in-flight |
| `ws.direction`, `ws.opcode`, `ws.size`, `ws.text` | string, int, int, string | in-flight, per WebSocket message ([WebSockets](/reference/websockets#message-rules)) |

`client.ip` is the client's address, or behind a load balancer the one
`X-Forwarded-For` names
([HTTP](/reference/http#clients-behind-a-load-balancer)). `host` and
`tls.sni` are lower-case, without a trailing dot, with internationalised
names as `xn--` labels and IPv6 addresses without brackets. `path` is
normalised ([URL normalisation](/reference/http#url-normalisation)).

**Path rules are fragile.** An upstream may interpret a path differently
from roxy, for example by decoding `%2F` to `/` or merging `//`. Then
`/a/..%2Fsecret` does not start with `/secret` for roxy, but reaches
`/secret` upstream. Prefer allowing exact paths. If you allow a prefix,
also exclude the forms the upstream reinterprets (`not path contains
"%2F"`, and likewise `"%5C"`, `"//"`, `";"` and `"%3B"`). Treat a `deny`
on a path as defence in depth.

### Missing values (`null`)

A value that is absent is `null`: a header or query parameter that was not
sent, an unset state key, `tls.sni` when none was sent, `body.size` for a
chunked body. Tags and metrics are never `null`.

| expression, with `x` missing | result |
|---|---|
| `x == null` | true |
| `x != null` | false |
| `x == "a"`, `x in [...]` | false |
| `x != "a"`, `x not in [...]` | true |
| any other operator, such as `x > 10` or `x contains "a"` | the exchange is denied: `_fail_closed`, reason `missing_value` |

`and` and `or` stop as soon as the result is known, so test for `null`
first: `body.size != null and body.size > 10mb`, or
`body.size == null or body.size > 1`.

## Actions

`then` is one action, or a list ending with at most one of `allow`, `deny`
or `quarantine`.

```yaml
then: allow
then: { deny: { status: 451, message: "no" } }
then:
  - set_header: { authorization: "Bearer ${secret:openai}" }
  - remove_header: [x-debug]
  - tag: billing
  - allow: { upgrade: websocket }
```

These decide the exchange:

| action | where | effect |
|---|---|---|
| `allow` | admission rules | Forward the request. `upgrade: websocket` allows a WebSocket upgrade. `private_ok: true` allows private addresses ([address floor](/reference/address-lists#address-floor)). |
| `deny` | all rules | Refuse, with `status` (default 403), `message` and `close` ([deny responses](/reference/http#deny-responses)). In flight, it stops the exchange. On a WebSocket, it closes both sides. |
| `quarantine` | all rules | Deny, and [quarantine](/guides/operations#quarantine) roxy so it refuses every later request. Needs `--state-dir`. |

These add effects:

| action | where | effect |
|---|---|---|
| `set_header: { name: value }` | request: admission rules; response: in-flight rules | Set or replace a header. Request values may use `${secret:name}` ([secrets](/reference/secrets)). |
| `remove_header: [names]` | as `set_header` | Remove headers. |
| `rewrite_path: { match, to }` | admission rules | Rewrite the path with a regex; `$1` and `${name}` refer to groups. |
| `set_query: { k: v }`, `remove_query: [k]` | admission rules | Change the query. |
| `redirect: { host, port, scheme?, rewrite_host? }` | admission rules | Send the request to another upstream. `Host` is unchanged unless `rewrite_host: true`. The new address still passes the address floor. |
| `tag: name` | all | Set `tag["name"]`, for later rules, addons and the log. |
| `log: { level, message }` | all | Write a `log` event to the flow log. |
| `set_state: { key, value, ttl? }` | all | Write to the [state store](/reference/rate-limits#state). |
| `capture: request \| response \| both` | admission rules | Record the exchange in the [capture log](/reference/flow-log#capture). |
| `digest: request \| response \| both` | admission rules | Record a SHA-256 of the bodies in the [flow log](/reference/flow-log#flow-log). |
| `sign: { aws_sigv4: { ... } }` | admission rules | Sign the request for AWS ([signing AWS requests](/reference/secrets#signing-aws-requests)). |

Anything more complex needs an addon.

## Body rules

`body.text` and `response.body.text` are the only fields that make roxy
buffer. If any rule reads `body.text`, roxy buffers every request body, up
to `limits.max_inspect_body_bytes` (1 MiB), before deciding, then streams
it on. `response.body.text` does the same for responses.

A body over the cap cannot be inspected, and a rule that reads it denies
the exchange (`body_too_large_to_inspect`). To let large bodies through,
raise the cap, or check the size before the text:

```yaml
when: body.size != null and body.size < 1mb and body.text contains "secret"
```

The text is the body decoded from its `content-encoding`
([content codings](/reference/http#content-codings)). A body that cannot
be decoded also denies the exchange.
