# Gateway

An `http` listener lets roxy stand in for an origin: clients send ordinary
requests to a name that resolves to roxy, and per-host rules decide where
each one goes and what to add. The usual shape is an LLM gateway, where
clients hold placeholder keys and roxy injects the real ones.

```
  client ──https──▶ load balancer (TLS termination) ──http──▶ roxy (mode: http) ──https──▶ provider
```

```yaml
version: 1

listeners:
  - name: gateway
    mode: http
    bind: 0.0.0.0:8080

secrets:
  anthropic: { env: ANTHROPIC_API_KEY }

rules:
  - id: anthropic
    when: listener.name == "gateway" and host == "anthropic.gw.example.com" and path starts_with "/v1/"
    then:
      - redirect: { host: api.anthropic.com, port: 443, scheme: https, rewrite_host: true }
      - set_header: { x-api-key: "${secret:anthropic}" }
      - allow
```

`*.gw.example.com` points at the load balancer, which terminates TLS and
forwards plain HTTP to roxy. roxy sees each request with scheme `http` and
the `Host` the client sent; the `redirect` sets `https` and the provider's
host on the way out, and `set_header` replaces whatever key the client sent.
A request to a host or path no rule matches is denied, as everywhere.

What to know before relying on it:

- **This is not containment.** The listener serves whoever reaches it, and
  the clients may have other routes out. Containing a workload is a network
  property ([containing a workload](/deploy/overview)); a gateway only
  governs the traffic sent to it.
- **Clients are not authenticated.** The listener adds no auth surface. If
  the gateway must know who is calling, put an authentication addon on it
  ([addons](/addons/overview)) or authenticate at the load balancer.
- **`client.ip` is the load balancer's address.** Rules and the flow log see
  the connection roxy accepted, not the original client.
- **TLS stays in front.** roxy does not terminate TLS on an `http`
  listener; a client that starts a handshake is closed
  (`tls_on_http_listener`). Keep the hop from the load balancer to roxy on a
  network you trust, since it carries the clients' requests in the clear.
