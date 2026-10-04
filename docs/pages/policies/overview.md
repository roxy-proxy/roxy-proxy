# How policies work

The policy decides what roxy forwards, what it denies, and what it changes
on the way. It is a list of rules in the config file, plus a `default` for
anything no rule decides:

```yaml
default: deny                  # deny (the default) | allow

rules:
  - id: github-reads
    when: host under "github.com" and method in [GET, HEAD]
    then: allow

  - id: no-admin-paths
    when: path starts_with "/admin"
    then: deny
```

Each rule has an `id`, a `when` condition in the
[rule language](/reference/rule-language), and a `then` with one or more
[actions](/reference/rule-language#actions). This page covers how roxy
evaluates them. The engine lives in `roxy-rules`.

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
   bottom, so a `tag` set by one rule is visible to the rules below it. A
   rule that reads a tag must come after every rule that sets it (a head
   rule above it, or, for a watching rule, any head rule); otherwise the
   config is rejected, since moving a rule would change what it sees. A
   tag set by a watching rule can be read by no other rule: watching rules
   fire when the values they read arrive, not in list order, so whether
   the tag was visible would depend on timing. A rule may read its own
   tag, and a tag no rule sets (from an addon). If
   the request is allowed, the effects of every matching rule apply in list
   order; if two set the same header, the later wins. If it is denied, or a
   change to it fails (which denies it with `_fail_closed`), the `log` and
   `set_state` effects of the matching rules still apply, and the request's
   metric samples count it as denied. Allow options
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
