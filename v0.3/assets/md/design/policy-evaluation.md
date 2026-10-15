# Policy evaluation

The policy decides what roxy forwards, what it denies, and what it changes
on the way. It is a list of rules in the config file, each with an `id`, a
`when` condition in the [rule language](/reference/rule-language) and a
`then` with one or more [actions](/reference/rule-language#actions).
Anything no rule allows is denied:

```yaml
rules:
  - id: github-reads
    when: host under "github.com" and method in [GET, HEAD]
    then: allow

  - id: no-admin-paths
    when: path starts_with "/admin"
    then: deny
```

## Evaluation

An exchange is a set of values that become known over time: the request
head, request body bytes as they stream, the response head, response body
bytes, and the metric values this exchange adds to. Rules are **one ordered
list** of conditions over those values. There are no phases: when a rule
runs follows from what it reads.

<img src={requestTiming} alt="The request phase of one exchange through roxy, left to right. The client's request head (a solid line) travels first and its body bytes (a dashed line) stream behind it, through layer A (enforce), past layer B (observe, which gets a copy beside the path), through layer C (enforce) and the rules, then on to the upstream. Each layer's when is evaluated on the head as it reaches the layer. At the rules the admission decision is made once, on the head, after the stack and before anything is forwarded (when a rule reads body.text, the body is buffered first): allow, deny or change the request. As body bytes stream past the rules they are re-checked in flight (body.bytes, byte metrics), which can deny or quarantine but never allow or change the request." />

A request is judged at two points. Each layer's `when` is checked on the
head as it arrives; the rules decide the head once, after the whole stack
and before anything is forwarded (if a rule reads `body.text`, the body is
buffered up to the cap first: [body rules](/reference/rule-language#body-rules)),
then re-check the body as its bytes stream past. When a layer's tag or
state write becomes visible to the rules, and to the layers upstream of it, is a
matter of [ordering across layers](/design/addon-model#ordering-across-layers).

1. **The forwarding decision is made at the request head, and deny wins.**
   roxy evaluates every rule whose values are known at that point. If any
   matching rule denies, the request is denied; otherwise, if any matching
   rule allows, it is allowed; otherwise it is denied with rule id
   `_default`, so an empty rule set denies everything. To let traffic
   through while you find out what a workload reaches, say so with a rule:
   `{ id: discover, then: allow }` (no `when` matches everything). Rule order does
   not affect the decision. A rule that reads a value not yet known is
   skipped here, not treated as false. `quarantine` is a deny that also
   puts the proxy into [quarantine](/guides/operations#quarantine): a
   matching one trips it whichever deny decided the request, a fail-closed
   included, and from the next exchange on nothing here runs at all.
2. **After that, rules run in flight.** For the rest of the exchange, two
   kinds of rule are re-checked whenever a value they read becomes known or
   changes: rules that read an *in-flight* field
   ([fields](/reference/rule-language#fields)), and `deny` or `quarantine`
   rules that read a byte metric (`count: request_bytes` or
   `response_bytes`), which this exchange adds to as bytes stream. A deny
   reading a `requests`, `denied`, `errors` or `unique` metric is decided at
   admission only: re-checking it after this exchange's own count would deny
   the 30th request of a `>= 30` limit instead of the 31st. `body.bytes` is
   first checked when the request body's first bytes arrive, so a rule that
   reads only it never fires for an empty body; `response.body.bytes` is
   checked at the response head, where it is `0`, and again as the body
   streams. If an in-flight deny matches, roxy stops the
   exchange: an error response if the response has not started, otherwise
   HTTP/1.1 breaks the connection without finishing the body and HTTP/2
   resets the stream. Nothing overrides a deny.
3. **Only admission rules can `allow`.** A rule that reads an in-flight
   field cannot allow, change the request (`set_header` on the request,
   `rewrite_path`, `redirect`, ...), `capture` or `digest`: the request is
   already on its way, so each is a compile error. It can deny or
   quarantine, and add effects that still make sense: `log`, `tag`,
   `set_state`, and header changes on a response that has not been sent
   yet.
4. **An in-flight rule's non-terminal effects apply once**, the first time it
   matches.
5. **Order matters for effects, not decisions.** Rules are evaluated top to
   bottom. If the request is allowed, the effects of every matching rule
   apply in list order; if two set the same header, the later wins. A deny
   does not cut evaluation short, at admission or in flight: every
   rule the pass checks still runs. If the request is denied, or a change
   to it fails (which denies it with `_fail_closed`, reason
   `effect_invalid`), the `log` and `set_state` effects of the matching
   rules still apply, and the request's metric samples count it as denied.
   An unavailable input is the exception: it stops admission evaluation at that
   rule, so the rules below it do not run, their `log` and `set_state` do
   not apply, and `rules` in the flow log lists only the rules above it.
   Allow options (`upgrade`, `private_ok`) come from the first matching
   allow only. The flow log names the first matching deny (or allow) as
   `terminal_rule`.
6. **A tag is visible to the rules below the rule that set it.** A rule
   that reads a tag must come after every rule that sets it (an admission
   rule above it, or, for an in-flight rule, any admission rule); otherwise
   the config is rejected, since moving a rule would change what it sees. A
   tag set by an in-flight rule can be read by no other rule: in-flight
   rules fire when the values they read arrive, not in list order, so
   whether the tag was visible would depend on timing. A deny or
   quarantine that reads a byte metric can fire in flight too, so an
   in-flight rule cannot read its tag; an admission rule below it can. A
   rule may read its own tag, and a
   tag no rule sets (from an addon).

`roxy check` and `roxy rule test` report whether each rule is decided at
admission or in flight.

**Unavailable inputs fail closed.** If a rule needs a metric value, an
address-list lookup or a secret and it is unavailable (store overloaded,
table full, list failed to load), the flow is denied with `503`,
`terminal_rule: _fail_closed`, and a `policy_input_unavailable` event. So
is a field whose value is not of its documented type (reason `wrong_type`):
that is a bug in roxy, and a predicate over it has no answer. A field that
is simply absent, like an unsent header, is not unavailable: it is `null`
([missing values](/reference/rule-language#missing-values-null)).
