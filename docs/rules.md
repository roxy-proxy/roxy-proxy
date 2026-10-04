# Rules

The policy: what roxy forwards, what it denies, and what it changes on the
way. The engine lives in `roxy-rules`.

## Config file

One YAML file, `version: 1`. Parsing is strict: an unknown key anywhere is
an error, not a silently ignored setting. Relative paths (`ca_dir`, `ca_cert`, `ca_key`, secret
files, list files, addon paths, log and capture paths) resolve against the
process's working directory. [`examples/roxy.yaml`](../examples/roxy.yaml)
shows every section.

| key | page |
|---|---|
| `listeners`, `http` | [HTTP](http.md) |
| `ca_server`, `tls` | [TLS](tls.md) |
| `upstream`, `address_lists` | [upstream](upstream.md) |
| `limits` | [resource limits](limits.md) |
| `secrets`, `default`, `metrics`, `rules` | this page |
| `addons` | [addons](addons.md) |
| `log`, `capture_dir` | [flow log](flow-log.md) |

```yaml
version: 1
default: deny                  # deny (the default) | allow: when no rule matches

secrets:
  openai: { env: OPENAI_API_KEY }
  gh:     { file: /run/secrets/github_token }   # one trailing newline stripped

metrics:
  - id: github_writes
    count: requests
    where: host under "api.github.com" and method in [POST, PUT, PATCH, DELETE]
    key: [client.ip]
    window: 1m

rules:
  - id: github-reads
    when: host under "github.com" and method in [GET, HEAD]
    then: allow

  - id: openai
    when: host == "api.openai.com" and path starts_with "/v1/" and method == POST
    then:
      - set_header: { authorization: "Bearer ${secret:openai}" }
      - allow

  - id: no-writes-burst
    when: metric.github_writes >= 30
    then: { deny: { status: 429 } }

  - id: upload-cap               # reads body.bytes, so it watches the upload
    when: host == "api.openai.com" and body.bytes > 10mb
    then: { deny: { status: 413 } }
```

## Evaluation

An exchange is a set of values that become known over time: the request
head, request body bytes as they stream, the response head, response body
bytes, and the metric values this exchange adds to. Rules are **one ordered
list** of conditions over those values. There are no phases: when a rule
runs follows from what it reads.

1. **The forwarding decision is made at the request head, and deny wins.**
   roxy evaluates every rule whose values are known at that point. If any
   matching rule denies, the request is denied. Otherwise, if any matching
   rule allows, it is allowed. Otherwise `default` applies, with rule id
   `_default`. Rule order does not affect the decision. A rule that reads a
   value not yet known is skipped here, not treated as false.
2. **After that, rules watch.** For the rest of the exchange, two kinds of
   rule are re-checked whenever a value they read becomes known or changes:
   rules that read a *watched* field ([fields](#fields)), and `deny` rules
   that read a byte metric (`count: request_bytes` or `response_bytes`),
   which this exchange adds to as bytes stream. A deny reading a
   `requests`, `denied`, `errors` or `unique` metric is decided at the head
   only: re-checking it after this exchange's own count would deny the 30th
   request of a `>= 30` limit instead of the 31st. If a watching deny
   matches, roxy stops the exchange: an error response if the response has
   not started, otherwise HTTP/1.1 breaks the connection without finishing
   the body and HTTP/2 resets the stream. Nothing overrides a deny.
3. **Only head rules can `allow`.** A rule that reads a watched field cannot
   allow and cannot change the request (`set_header` on the request,
   `rewrite_path`, `redirect`, ...): the request is already on its way, so
   both are compile errors. It can deny, and add effects that still make
   sense: `log`, `tag`, `set_state`, and header changes on a response that
   has not been sent yet.
4. **A watching rule's non-terminal effects apply once**, the first time it
   matches.
5. **Order matters for effects, not decisions.** Rules are evaluated top to
   bottom, so a `tag` set by one rule is visible to the rules below it. If
   the request is allowed, the effects of every matching rule apply in list
   order; if two set the same header, the later wins. Allow options
   (`upgrade`, `private_ok`) come from the first matching allow only. The
   flow log names the first matching deny (or allow) as `terminal_rule`.

`roxy check` and `roxy rule test` report whether each rule is decided at the
head or watches. There is no `phase` key and there are no connect-time
rules: a config that sets `phase` is rejected.

**Unavailable inputs fail closed.** If evaluating a rule needs a metric
value, an address-list lookup or a secret and it is unavailable (store
overloaded, table full, list failed to load), the flow is denied with
`503 policy input unavailable`, `terminal_rule: _fail_closed`, and a
`policy_input_unavailable` event. A field that is simply absent, like an
unsent header, is not unavailable: it is `null`.

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
| `ws.direction`, `ws.opcode`, `ws.size`, `ws.text` | string, int, int, string: the WebSocket message being checked | watched, per message ([WebSockets](websockets.md#message-rules)) |

`path` is the normalised path ([HTTP](http.md#url-normalisation)), so a
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

### Body access

`body.text` and `response.body.text` are the only fields that buffer. For an
exchange whose other predicates match, roxy collects the body up to
`limits.max_inspect_body_bytes` (1 MiB), evaluates, then streams the bytes
on. A larger body **fails closed** (`_fail_closed`, reason
`body_too_large_to_inspect`). Raise the cap to inspect larger bodies, or
scope the rule (`body.size != null and body.size < 1mb and ...`) so it
short-circuits before the body is touched. Rules that do not read a body
never buffer.

The text is the body decoded by its `content-encoding` (`gzip`, `deflate`,
`br`, `zstd`, stacked or not; [HTTP](http.md#content-codings)), then read
as lossy UTF-8. Decoding is for the rules only: the bytes forwarded are the
bytes received. The cap applies to the decoded text too, so a small body
that inflates past it fails closed with `body_too_large_to_inspect`. A body
that cannot be decoded fails closed as well: `body_decode_failed` for
corrupt or truncated data or bytes after the end of the stream,
`unsupported_content_encoding` for a coding roxy does not know.

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
| `allow` | head rules | Forward. `allow: { upgrade: websocket }` also permits a WebSocket upgrade; `private_ok: true` lets this flow reach private addresses ([address floor](upstream.md#address-floor)). |
| `deny` | all rules | `deny: { status, message, close }`. Status defaults to 403 and must be 4xx or 5xx. At the head: refuse ([deny responses](http.md#deny-responses)); the connection is closed afterwards unless `close: false`. Watching: stop the exchange, as in [evaluation](#evaluation). On a WebSocket: close both sides (with a `1008` close frame when rules read messages, [WebSockets](websockets.md#message-rules)). |

Non-terminal:

| action | where | effect |
|---|---|---|
| `set_header: { name: value }` | request: head rules; response: watching rules | Set or replace. Request values may use `${secret:name}`. Invalid values deny the flow. On the response, every value the rule reads must be known before the response head is sent (`response.status`, `response.header[..]`, `response.body.size`, `response.body.text`); reading `body.bytes`, `response.body.bytes` or a byte metric as well is a compile error. |
| `remove_header: [names]` | same as `set_header` | |
| `rewrite_path: { match, to }` | head rules | Regex (anchored, like `matches`) with `$1` / `${name}` groups. The result is re-normalised. |
| `set_query: { k: v }`, `remove_query: [k]` | head rules | |
| `redirect: { host, port, scheme?, rewrite_host? }` | head rules | Change the upstream target. The address floor and deny lists check the new target's IPs. `Host` is unchanged unless `rewrite_host: true`. |
| `tag: name` | all | Sets `tag["name"]` for later rules, addons and the log. |
| `log: { level, message }` | all | Emits a `log` flow event. |
| `set_state: { key, value, ttl? }` | all | Writes the [state store](#state). |
| `capture: request \| response \| both` | head rules | Tees the exchange, as forwarded, to the [capture log](flow-log.md#capture). |

The actions are a small closed set on purpose: anything richer is an addon.
`call` is reserved and rejected (addons always run above the rules).
`passthrough` is reserved for transparent mode and rejected (issue #15).

## Secrets

`secrets:` maps names to an environment variable or a file. `${secret:name}`
in a request `set_header` value (or an addon endpoint's `headers`) injects
the value, so the client only ever holds a placeholder. Secrets are resolved
when roxy starts and on reload; a missing one at evaluation time fails the
flow closed. Every injected value is redacted from the flow log and capture
heads. `roxy check` and `roxy rule test` do not resolve secrets.

## Metrics

A metric is defined once and compared in rules (`metric.<id> >= 30`).

```yaml
metrics:
  - id: <string>
    count: requests | request_bytes | response_bytes | errors | denied | unique(<field>)
    where: <expr>        # head fields only: whether this exchange counts
    key: [<field>, ...]  # head fields only; omitted = one global series
    window: <duration>   # omitted = cumulative since start
```

- **Windows** slide in 60 fixed buckets, so a 1-minute window has 1-second
  resolution. `unique` uses a HyperLogLog sketch per bucket.
- **When counts move.** `requests` and `denied` are read before the
  forwarding decision and incremented after it (denied flows count too, so
  probing is not free); a rule `metric.x >= 30` therefore denies the 31st
  request. `request_bytes` and `response_bytes` grow as bytes stream, so a
  deny reading them watches and stops the exchange that crosses the limit.
  A chunk is counted before it is checked and is not forwarded if the check
  stops the exchange, so a budget may be overcounted by at most one chunk.
  `errors` are counted when the exchange ends.
- **Bounded, never evicting.** Series are capped by `limits.max_metric_keys`
  (100 000) and, approximately, by `limits.max_metric_bytes` (256 MiB, at
  most 64 GiB; each series is charged for its key, its buckets and a fixed
  overhead). A flow that needs a new series when either is exhausted is
  denied (`_fail_closed`, event `metric_table_full`). Evicting would let a
  client reset its own counter by varying the key. Series are reclaimed
  only once their window has fully expired.
- **Reload.** Series whose metric definition is unchanged carry over, while
  they fit the new byte budget; the rest are dropped with a warning.

## State

`state` is a bounded key/value map with per-entry TTL, written by
`set_state` and read as `state["key"]`. At most `limits.max_state_entries`
(100 000) live entries; a new key when full denies the flow that tried.
Addons have their own, separate store ([addons](addons.md#host-services)).

## Reload

`roxy check <config>` and reload share one path: parse, validate, compile,
returning diagnostics with the config path, rule id and position. roxy
watches the config file, the address-list files and the addon `.wasm`
files; a change, or `SIGHUP`, triggers a reload. On success the new policy
is swapped in atomically: exchanges in flight finish under the policy they
started with, and the next request on any connection uses the new one. On
failure the old policy stays, a `config_reload_failed` event carries the
diagnostics, and nothing is partially applied.

Listener, `dns`, TLS and capture settings need a restart.

## Dry run

```sh
roxy rule test --config roxy.yaml GET https://api.github.com/repos/a/b
roxy rule test --config roxy.yaml --metric github_writes=30 POST https://api.github.com/repos/a/b/issues
```

`roxy rule test` evaluates a synthetic request with no network I/O and
prints the matching rules, the effects and the decision. It exits 0 on
allow and 3 on deny. Metrics you do not pass are 0, and
`--metric id=unavailable` exercises the fail-closed path. Flags set the
client, headers and body, and `--body-bytes`, `--response-status`,
`--response-header` and `--response-body-bytes` run the watching rules
that read them. `--ws-text`, `--ws-opcode`, `--ws-size` and
`--ws-direction` describe one WebSocket message and run the rules that
read `ws.*`. The request arrives on the config's first listener, which
sets `listener.name` and `listener.mode`. An IP-literal URL also shows an
address-floor hit. See `roxy rule test --help`.
