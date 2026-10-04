# Principles and threat model

roxy is a security boundary for outbound HTTP. These principles decide
every behaviour described in the other pages; where a page says "fails
closed" or "deny wins", this is why.

## Threat model

**Attacker:** the client. It controls every byte it sends to roxy, may run
arbitrary code, and may have root inside its own container or VM.

**Trusted:** the host, roxy's binary and config, the secrets roxy holds, the
public CA trust store used to verify upstreams, and the upstreams the rules
allow. roxy does not treat upstream responses as adversarial. It applies the
size and time limits that protect its own resources, and re-frames responses
so the client sees one clean wire form.

**roxy prevents:**

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

**roxy does not try to prevent** timing or DNS side channels from the
workload (block DNS egress at the network layer; roxy resolves names
itself), compromise of an upstream the rules already allow, or compromise of
the host running roxy.

Containment comes from the network: the workload must have no route out
except through roxy ([deployment](/deploy/overview)).
roxy decides what passes through it; it cannot stop traffic that never
reaches it.

## Fail closed

Anything roxy cannot parse, verify or classify is dropped. An empty rule set
denies everything. A config that fails to compile is not loaded, and a
failed reload keeps the running policy. An addon that fails denies the flow.
A policy input that is unavailable (a full metric table, a list that failed
to load, a missing secret, a body too large to inspect) denies the flow
rather than making a predicate false. Nothing in roxy turns "could not
check" into "allowed". [Resource limits](/reference/limits) lists every case.

## Canonical re-serialisation

Requests are parsed into a strict internal model and re-emitted in one
unambiguous wire form; nothing the client sends reaches the upstream
byte-for-byte. Ambiguous input (both `Content-Length` and
`Transfer-Encoding`, duplicate lengths, bare LF, obs-fold, dot segments that
climb above the root, ...) is rejected rather than resolved. What the rules
match is exactly what is forwarded. This removes request smuggling,
header injection and path confusion as classes of attack
([HTTP](/reference/http)).

After a WebSocket upgrade the connection carries only that WebSocket, so
there is no later request to smuggle into. roxy splices its bytes unless a
rule reads messages; then every message is decoded strictly and re-encoded
in one form ([WebSockets](/policies/websockets#message-rules)).

## Deny always wins

A rule set is a list of allows and denies that restrict them. Any matching
deny wins over any matching allow, wherever it sits in the list, and
nothing can override a deny at any later point in an exchange. Rule order
orders effects, never decisions: a rule that reads a tag must follow every
rule that sets it, or the config is rejected. So adding a deny can only
narrow what
passes, and a reviewer can read each deny on its own
([rules](/policies/overview)).

## Never evict

Bounded tables (metric series, rule state, addon state) never evict to make
room. A flow that needs a new entry in a full table is denied instead.
Eviction would let a client reset its own counter by churning keys, so a
limit could be escaped by exceeding another one
([rules](/policies/rate-limits#metrics)).

## Audit backpressure

The flow log and traffic capture are an audit trail, and they never drop a
record. When a log falls behind or its disk fails, roxy holds traffic back
until it catches up: the wait propagates to the network, slowing clients
rather than losing records ([flow log](/operate/flow-log#writing)).

## The rules judge everything that leaves

The rules evaluate every request that leaves for the network. Addons sit
above the rules and can reshape traffic freely, but what they pass on is
re-validated as strictly as a client request and then judged by the rules as
if the client had sent it. Nothing configurable runs between the rules and
the network, and the address floor checks the IP actually dialled
([addons](/addons/overview)).

## Streams, not messages

An exchange is a request head, a request body stream, a response head and a
response body stream. Every stage works on those streams. A body is
buffered only when a rule or addon needs its content, and then only up to a
cap. Large uploads and long responses stream end to end, and memory use does
not grow with body size.

## Well-behaved clients work unhindered

Strictness is aimed at malformed or ambiguous traffic. A conforming
HTTP/1.1 or HTTP/2 client doing ordinary things (large uploads, keep-alive,
`100-continue`, WebSockets, redirects, compression) through an allowed rule
should notice nothing except the CA. A default that trips a conforming
client is a bug.
