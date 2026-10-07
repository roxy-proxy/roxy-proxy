# Threat model and guarantees

roxy is a security boundary for the HTTP traffic that reaches it. These
guarantees decide every behaviour described in the other pages; where a
page says "fails closed" or "deny wins", this is why.

## Threat model

**Attacker:** the client. It controls every byte it sends to roxy, may run
arbitrary code, and may have root inside its own container or VM.

**Trusted:** the host, roxy's binary and config, the secrets roxy holds, the
public CA trust store used to verify upstreams, and the upstreams the rules
allow. roxy does not treat upstream responses as adversarial. It applies the
size and time limits that protect its own resources, and re-frames responses
so the client sees one clean wire form.

**For traffic that reaches it, in a [sandbox](/guides/containment) and a
[gateway](/guides/gateway) alike, roxy prevents:**

- reaching any destination the rules do not allow, including through
  Host/SNI spoofing, DNS rebinding, redirects to private ranges, CONNECT to
  arbitrary ports, or non-HTTP protocols tunnelled through CONNECT;
- desync and smuggling between roxy and the upstream, or between roxy and
  the client, through ambiguous framing;
- exfiltrating real credentials: with secret injection the client only ever
  holds placeholders;
- exhausting roxy's memory, CPU or file descriptors: slowloris, huge
  headers, unbounded bodies, cardinality attacks on metric keys, runaway
  addons;
- learning anything useful from a deny beyond the rule id.

**roxy does not try to prevent** traffic that never reaches it, timing or
DNS side channels from the workload (block DNS egress at the network layer;
roxy resolves names itself), compromise of an upstream the rules already
allow, or compromise of the host running roxy.

## Which use case claims what

roxy is not a transparent proxy. It decides what passes through it, and it
cannot stop traffic that never reaches it.

- **Sandbox containment** claims that all of the workload's traffic goes
  through roxy. That claim is the network's: the workload must have no
  route out except roxy's proxy port, with direct TCP, UDP and DNS blocked
  at the boundary ([sandbox containment](/guides/containment)). The proxy
  variables and the CA only tell a well-behaved client where roxy is.
- **An HTTP gateway** makes no such claim. It governs the requests its
  clients send to it, and the clients keep whatever other routes they have
  ([HTTP gateway](/guides/gateway)).

roxy speaks HTTP/1.1, HTTP/2 and WebSockets to clients. Raw TCP does not
pass.

## Fail closed

Anything roxy cannot parse, verify or classify is dropped. An empty rule
set denies everything, and so does a policy past its `valid_until`
([lease](/guides/operations#lease)). A config that fails to compile is not
loaded, and a failed reload keeps the running policy. An addon in
`enforce` mode that fails denies the flow; an `observe` addon cannot
affect traffic, so its failure is logged and the flow goes on. A policy
input that is unavailable denies the flow rather than making a predicate
false. [Resource limits](/reference/limits#fail-closed-outcomes) lists
every case.

## Canonical re-serialisation

Requests are parsed into a strict internal model and re-emitted in one
unambiguous wire form; nothing the client sends reaches the upstream
byte-for-byte. Ambiguous input is rejected rather than resolved, and what
the rules match is exactly what is forwarded ([HTTP](/reference/http)).
After a WebSocket upgrade the connection carries only that WebSocket;
when a rule reads messages, each is decoded strictly and re-encoded in one
form ([WebSockets](/reference/websockets#message-rules)).

## Deny always wins

Any matching deny wins over any matching allow, wherever it sits in the
list, and nothing overrides a deny at any later point in an exchange. Rule
order orders effects, never decisions, so adding a deny can only narrow
what passes ([policy evaluation](/design/policy-evaluation)).

## Never evict

Bounded tables (metric series, rule state, addon state) never evict to make
room. A flow that needs a new entry in a full table is denied instead, so a
client cannot reset its own counter by churning keys
([rate limits](/reference/rate-limits#metrics)).

## Audit backpressure

The flow log and traffic capture never drop a record. When a log falls
behind or its disk fails, roxy holds traffic back until it catches up
([flow log](/reference/flow-log#writing)).

## The rules judge everything that leaves

Addons sit above the rules and can reshape traffic freely, but what they
pass on is re-validated as strictly as a client request and then judged by
the rules as if the client had sent it. Nothing configurable runs between
the rules and the network, and the address floor checks the IP actually
dialled ([addon model](/design/addon-model)).

## Streams, not messages

An exchange is a request head, a request body stream, a response head and a
response body stream. A body is buffered only when a rule or addon needs
its content, up to a cap, and the buffers of all exchanges together stay
within one process-wide budget ([limits](/reference/limits#limits)). Memory
use grows with neither body size nor the number of clients holding a
buffer.

## Well-behaved clients work unhindered

Strictness is aimed at malformed or ambiguous traffic. A conforming
HTTP/1.1 or HTTP/2 client doing ordinary things (large uploads, keep-alive,
`100-continue`, WebSockets, redirects, compression) through an allowed rule
should notice nothing except the CA. A default that trips a conforming
client is a bug.
