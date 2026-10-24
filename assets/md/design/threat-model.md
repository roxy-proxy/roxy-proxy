# Threat model and guarantees

roxy is a security boundary for the HTTP traffic that reaches it. The
guarantees on this page decide the behaviour described everywhere else.

## Threat model

**The attacker is the client.** It controls every byte it sends to roxy,
may run arbitrary code, and may have root inside its own container or VM.

**Trusted:** the host, roxy's binary and config (addons included), the
secrets roxy holds, the public CA roots used to verify upstreams, the
upstreams the rules allow, and the load balancers a listener's
`forwarded_for` counts. Upstream responses are not treated as hostile,
but roxy still bounds their size and time and re-frames them.

**For traffic that reaches it, roxy prevents:**

* reaching any destination the rules do not allow, including through
  Host or SNI spoofing, DNS rebinding, redirects to private addresses,
  CONNECT to arbitrary ports, or non-HTTP protocols inside CONNECT;
* request smuggling and desync through ambiguous framing, on either side
  of roxy;
* exfiltrating real credentials: with secret injection the client only
  holds placeholders;
* unbounded memory or connection use from slow clients, huge headers,
  huge bodies and key churn, within the configured limits;
* learning anything from a deny beyond the rule id.

**roxy does not prevent** traffic that never reaches it, timing or DNS
side channels from the workload, compromise of an upstream the rules
allow, or compromise of the host. WASM addons have memory and time limits
but no total CPU budget, so addon configuration must be trusted.

## Which use case claims what

roxy decides what passes through it. It cannot stop traffic that goes
around it.

* **Sandbox containment** claims that all of the workload's traffic goes
  through roxy. The network makes that true: the workload must have no
  route out except roxy's proxy port
  ([sandbox containment](/guides/containment)).
* **An HTTP gateway** makes no such claim. It governs the requests sent to
  it, and clients keep any other routes they have
  ([HTTP gateway](/guides/gateway)).

## Node identity

In [node mode](/guides/node-mode) a node proves who it is with a bearer
token that the control plane issued at enrolment. The token stops a host
that was never enrolled, or one that has been revoked, from getting a
policy or secrets. It does not protect against the host roxy runs on:
whatever can read the state dir can use the token until it expires or the
node is revoked.

## Fail closed

Anything roxy cannot parse, verify or classify is refused. An empty rule
set denies everything, and so does an expired policy. A config that fails
to load is not applied, and a failed reload keeps the running policy. A
policy input that is unavailable, such as a full metric table, denies the
exchange rather than making a condition false. An enforcing addon that
fails denies the exchange. [Resource limits](/reference/limits#fail-closed-outcomes)
lists every case.

## Canonical re-serialisation

roxy parses each request into a strict model and writes it out again in
one unambiguous form. Nothing the client sends reaches the upstream
byte for byte, and what the rules match is exactly what is forwarded
([HTTP](/reference/http)).

## Deny always wins

A matching deny wins over any matching allow, wherever it sits in the
list. Rule order affects effects, never decisions, so adding a deny can
only narrow what passes ([policy evaluation](/design/policy-evaluation)).

## Never evict

Bounded tables, such as metric series and the state store, never evict
entries to make room. A request that needs a new entry in a full table is
denied, so a client cannot reset its own rate limit by churning keys.

## Audit backpressure

The flow log and capture never drop a record. When a log falls behind or
its disk fails, roxy holds traffic until it catches up
([flow log](/reference/flow-log#writing)).

## The rules judge everything that leaves

Addons run before the rules and can reshape traffic freely. Whatever they
pass on is validated like a client request and judged by the rules as if
the client had sent it. Nothing configurable runs between the rules and
the network, and the address floor checks the address actually dialled.

An addon can still change the response the client gets, including a
refusal from the rules: addons are trusted, the request did not leave,
and the flow log records the rules' decision.

## Streams, not messages

A body is buffered only when a rule or addon needs to read it, up to a
cap, and all buffers together stay within one process-wide budget
([limits](/reference/limits#buffer-budget)). Memory use does not grow with
body size.

## Well-behaved clients work

Strictness is aimed at malformed or ambiguous traffic. A conforming client
doing ordinary things (large uploads, keep-alive, `100-continue`,
WebSockets, compression) through an allowed rule should notice nothing
except the CA. A default that breaks a conforming client is a bug.
