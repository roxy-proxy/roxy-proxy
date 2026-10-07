# How roxy works

An exchange is one request and its response. Every exchange takes the same
path, whichever way roxy is deployed:

```
  client ──TCP──▶  listener: HTTP proxy (mode: http_proxy)
                     ▼
                   CONNECT: first bytes must be a TLS ClientHello
                     ▼      whose SNI matches the CONNECT host (the defaults:
                            http.allow_plain_in_connect, tls.require_sni_match)
                   TLS termination (leaf minted by roxy's CA), ALPN h1 | h2
                     ▼
                   strict parse → CanonicalRequest   ◀── or plain origin-form
                     ▼                                   requests (mode: http)
                     ▼
                   addons (in config order)
                     ▼
                   rules: the head decision (forward or deny)
                     ▼
                   upstream connector: own DNS, address floor, rustls, h1 | h2
                     ▼
                   watching rules (body bytes, response, byte metrics)
                     ▼
                   addons (in reverse order), then re-serialised to the client

                   flow log ◀── every stage emits events
```

## Decrypt and parse

A client connection is accepted by a listener. On an `http_proxy` listener
a CONNECT opens a tunnel; roxy checks that its first bytes are a TLS
ClientHello whose SNI names the CONNECT host, terminates TLS with a leaf
from its own CA, and reads HTTP/1.1 or HTTP/2 inside. On an `http`
listener TLS ends at the load balancer in front and roxy reads plain
origin-form requests ([HTTP](/reference/http)). Either way the connection
then carries a sequence of exchanges (HTTP/1.1 keep-alive) or concurrent
ones (HTTP/2 streams).

roxy parses each request head into one canonical form, which is what it
sends upstream. Ambiguous input is rejected, not resolved: request
smuggling and header injection do not reach the upstream, and what the
rules and addons see is exactly what is forwarded
([canonical request](/reference/http#canonical-request)). The body stays a
stream.

## Addons

Logic that needs to understand the traffic goes in an addon: an external
service that the traffic streams through, or a WASM component that runs
in process. An addon owns both streams of the exchanges it chooses and can
rewrite, withhold, answer or block. The stack runs outermost first, and
the last addon's `next` runs the rest of the core on what it passed on.
Whatever an addon passes on is judged by the rules as if the client had
sent it ([addon model](/design/addon-model)).

```yaml
addons:                                    # above the rules, outermost first
  - name: sentinel                         # a sidecar the exchange streams through
    kind: service
    when: host == "api.anthropic.com" and path starts_with "/v1/messages"
    endpoint: sidecar
    endpoints:
      sidecar: { url: "http://sentinel:9000/", private_ok: true }
    limits:
      first_byte_timeout: 120s             # how long it has to decide before roxy denies

  - name: audit-tap                        # sent a copy; can't change or delay traffic
    kind: service
    mode: observe
    when: method in [POST, PUT, PATCH, DELETE]
    sample: 0.1
    endpoint: tap
    endpoints:
      tap: { url: "https://audit.internal/roxy", private_ok: true }
```

## Rules

The rules are a list of allows plus the denies that restrict them, in one
YAML file. A matching deny always wins, and anything no rule allows is
denied. The forwarding decision is made at the request head; rules that
read the bodies or the response keep watching as they stream, and can
still stop the exchange. Metrics give rate limits and byte budgets
([policy evaluation](/design/policy-evaluation)).

```yaml
secrets:
  openai: { env: OPENAI_API_KEY }

rules:
  - id: github-reads
    when: host under "github.com" and method in [GET, HEAD]
    then: allow

  - id: openai
    when: host == "api.openai.com" and path starts_with "/v1/" and method == POST
    then:
      - set_header: { authorization: "Bearer ${secret:openai}" }   # the client never sees the key
      - allow

  - id: upload-cap                         # watches the body as it streams
    when: host == "api.openai.com" and body.bytes > 10mb
    then: { deny: { status: 413 } }
```

The request steps run in a fixed order: a bounded body buffer only when a
rule reads `body.text`, then the head decision and its effects. A step
returns a verdict, and the only verdict that leads to the upstream is
`Continue`; every error maps to a deny or a close. The steps are not an
extension point: extensions are addons, above them.

## Connect

The upstream connector resolves the host itself, checks every candidate IP
against the address floor, and connects. A name that resolves somewhere
private is refused, and so is a redirect target or addon endpoint that
does ([upstream](/reference/upstream),
[address floor](/reference/address-lists#address-floor)).

## Respond

When the response head arrives, the response steps run: a bounded buffer
of the response body only when a rule reads `response.body.text`, then the
watching rules, which may still stop the exchange or change the head. For
the rest of the exchange the watcher re-checks the watching rules as body
bytes stream, records byte metrics, and holds each chunk until the flow
log is ready. The response is re-framed for the client and passes back up
the addon stack.

## Log

Every stage writes to the flow log: one JSON line per exchange, naming the
rule that decided, the addons that ran and what changed. The log never
drops a record; when it falls behind, traffic waits
([flow log](/reference/flow-log)).

## Policy snapshots

The compiled policy (rules, metrics, addons, address lists) is an immutable
snapshot swapped atomically on reload. An exchange runs to the end on the
snapshot it started with.

## Node mode

With `--control-plane` the binary has no config file. It opens bootstrap
listeners that deny everything, enrols with the control plane (or loads
the certificate it stored last time) and polls for a lease: a rendered
`roxy.yaml`, the secret values it names and how long it is good for. The
first lease replaces the bootstrap listeners; later ones swap the policy
snapshot, the secret map or only `valid_until`, as a reload would. Every
flow event also goes into an in-memory spool and is shipped to the control
plane in batches until acknowledged ([node mode](/guides/node-mode),
[node protocol](/reference/node-protocol)).
