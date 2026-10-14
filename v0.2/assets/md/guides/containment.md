# Sandbox containment

An untrusted workload runs where its only route out is roxy. It points
`HTTP_PROXY` and `HTTPS_PROXY` at an `http_proxy` listener and trusts
roxy's CA. roxy decrypts each request, judges it, injects the credentials
the workload needs, and logs every decision. Containment comes from the
network: the proxy variables only tell a well-behaved client where roxy
is ([threat model](/design/threat-model#which-use-case-claims-what)).

<img src={containment} alt="A workload inside a sealed sandbox network whose only exit is roxy's proxy port 3128. Requests go from the workload to roxy and on to the allowed upstreams, api.anthropic.com and github.com, with the real key added; responses come back the same way. roxy holds the CA and the secrets, and the workload fetches roxy-ca.pem from port 3130. A direct route out of the sandbox is blocked at the boundary: direct TCP, UDP and DNS have no route." />

## The recipe

1. **Take away the workload's route out.** Put it in a network namespace,
   VM or container network whose only reachable host is roxy. Block
   everything else, including direct TCP, UDP and DNS, at the network layer.
   roxy resolves DNS itself, so the workload needs none.

2. **Give roxy a route out**, and the workload a route to roxy's proxy port
   (an `http_proxy` listener, 3128 in the examples). Keep the CA endpoint
   (3130) reachable from the workload only if it should fetch the CA
   itself.

   ```yaml
   listeners:
     - name: proxy
       mode: http_proxy             # the default
       bind: 0.0.0.0:3128
   ca_server:
     bind: 0.0.0.0:3130             # serves /roxy-ca.pem to the workload
   ```

3. **Point the workload at roxy and make it trust roxy's CA**
   ([CA distribution](/guides/ca-certificates#ca-distribution)):

   ```sh
   export HTTP_PROXY=http://<proxy> HTTPS_PROXY=http://<proxy>
   export http_proxy=$HTTP_PROXY https_proxy=$HTTPS_PROXY   # curl reads only the lower-case http_proxy
   export SSL_CERT_FILE=/path/roxy-ca.pem         # OpenSSL-based tools, Python ssl, Go
   export REQUESTS_CA_BUNDLE=/path/roxy-ca.pem    # Python requests
   export NODE_EXTRA_CA_CERTS=/path/roxy-ca.pem   # Node
   export CURL_CA_BUNDLE=/path/roxy-ca.pem        # curl
   ```

   Adding the certificate to the system trust store also works. Do not put
   external hosts in `NO_PROXY`.

4. **Decide what shuts the proxy for good.** A workload that probes roxy
   with malformed requests, or reaches for something a rule marks as
   beyond the pale, can be [quarantined](/guides/operations#quarantine):
   every exchange refused until an operator, or the control plane, lets it
   out. Set `quarantine_on` on the listener and use the `quarantine` action
   in the rules that should trip it, and run roxy with `--state-dir` so the
   quarantine survives a restart:

   ```yaml
   listeners:
     - name: proxy
       bind: 0.0.0.0:3128
       quarantine_on:
         parse_errors: { count: 20, window: 1m }
   rules:
     - id: exfil
       when: host == "api.anthropic.com" and body.text contains "BEGIN PRIVATE KEY"
       then: quarantine
   ```

## With Docker Compose

The workload sits only on an `internal: true` network, which has no route
out (Docker's embedded DNS still resolves service names on it); roxy alone
is on both it and a network with a route out:

```yaml
services:
  roxy:
    image: ghcr.io/roxy-proxy/roxy:latest
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    volumes: [./roxy.yaml:/etc/roxy/roxy.yaml:ro, roxy-ca:/var/lib/roxy/ca]
    networks: [sandbox, egress]
  agent:
    image: your-workload
    networks: [sandbox]              # no route out except through roxy
    environment:
      HTTPS_PROXY: http://roxy:3128
      https_proxy: http://roxy:3128
      NO_PROXY: roxy                 # roxy's CA endpoint, reached directly
      no_proxy: roxy
networks:
  sandbox:
    internal: true                   # no route out: the containment
  egress: {}
volumes:
  roxy-ca: {}
```

The workload fetches the CA from `http://roxy:3130/roxy-ca.pem`. A client
that ignores the proxy variables, or a library that opens its own sockets,
gets nowhere: there is no route out, whatever a name resolves to.

Other services on the Compose network resolve to private addresses, which
the address floor denies by default. A rule that lets the workload reach
one needs `private_ok: true` on its `allow`, for example
`then: { allow: { private_ok: true } }`
([address floor](/reference/address-lists#address-floor)); rules for
public upstreams need nothing.

## Why a proxy port

An `http_proxy` listener is the narrowest interface roxy can offer a
workload: HTTP/1.1 or HTTP/2 and nothing else, with CONNECT opening only a
tunnel roxy intercepts (raw TCP never passes), and every destination a name
roxy parses itself, judges in the rules, resolves and checks the IP of
([HTTP](/reference/http)). An `http` listener is for traffic sent to roxy
on purpose ([HTTP gateway](/guides/gateway)), not for containing a
workload.
