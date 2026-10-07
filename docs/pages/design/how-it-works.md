# How roxy works

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

A client connection is accepted by a listener and, after CONNECT (on an
`http_proxy` listener) and TLS termination, or directly (an `http`
listener, [HTTP](/reference/http#http-listener)), carries a sequence of
exchanges (HTTP/1.1 keep-alive) or concurrent ones (HTTP/2 streams). Both fronts feed one transport-agnostic
exchange core (`roxy-proxy`'s `exchange` module):

1. The request head is parsed into the canonical model
   ([HTTP](/reference/http#canonical-request)). The body stays a stream.
2. The addon stack runs, outermost first ([addons](/design/addon-model)). The last
   addon's `next` runs the rest of the core on what it passed on.
3. The request steps run, in a fixed order: a bounded body buffer only
   when a rule reads `body.text`, then the head decision and its effects
   ([rules](/design/policy-evaluation)). A step cannot forward anything itself;
   it returns a verdict, and the only verdict that leads to the upstream is
   `Continue`. Every error maps to a deny or a close. These steps are not
   an extension point: extensions are addons, above them.
4. The upstream connector resolves the host, checks every candidate IP
   against the address floor, and connects ([upstream](/reference/upstream)).
5. When the response head arrives, the response steps run: a bounded
   buffer of the response body only when a rule reads `response.body.text`,
   then the watching rules at the response head, which may still stop the
   exchange or change the head. For the rest of the exchange the watcher
   re-checks the watching rules as body bytes stream, records byte metrics,
   and holds each chunk until the flow log is ready
   ([audit backpressure](/reference/flow-log#writing)).
6. The response is re-framed for the client and passes back up the addon
   stack.

The compiled policy (rules, metrics, addons, address lists) is an immutable
snapshot swapped atomically on reload. An exchange runs to the end on the
snapshot it started with.

