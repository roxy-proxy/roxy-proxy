# Containing a workload

roxy is an explicit proxy, not a transparent gateway. A client's
`HTTPS_PROXY` only tells well-behaved clients where roxy is. What contains
a workload is the network: it must have no route out except through roxy.
The same recipe applies anywhere:

1. **Take away the workload's route out.** Put it in a network namespace,
   VM or container network whose only reachable host is roxy. Block
   everything else, including direct TCP, UDP and DNS, at the network layer.
   roxy resolves DNS itself, so the workload needs none.
2. **Give roxy a route out**, and the workload a route to roxy's proxy port
   (3128 in the examples). Keep the CA endpoint (3130) reachable from the
   workload only if it should fetch the CA itself.
3. **Point the workload at roxy and make it trust roxy's CA**
   ([CA distribution](/operate/ca-certificates#ca-distribution)):

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

With Docker Compose, the workload sits only on an `internal: true` network,
which has no route out and no outside DNS, and roxy is the only container on
both that network and one with a route out:

```yaml
services:
  roxy:
    image: ghcr.io/roxy-proxy/roxy:edge
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

The workload fetches the CA from `http://roxy:3130/roxy-ca.pem` (with
`ca_server.bind: 0.0.0.0:3130`). A client that ignores the proxy variables,
or a library that opens its own sockets, gets nowhere: direct connections
and DNS lookups fail.

## Why an explicit proxy

The explicit proxy keeps the interface roxy exposes to clients as narrow
as it can be while still being useful:

- **One protocol, parsed strictly.** A client can speak HTTP/1.1 or HTTP/2
  to roxy, and nothing else. CONNECT only opens a tunnel that roxy
  intercepts as TLS (or, if allowed, plain HTTP); raw TCP never passes. A
  TCP gateway forwards every protocol, so it either relays bytes it cannot
  judge or has to understand all of them.
- **Destinations are names, not addresses.** Each request names its
  destination in a form roxy parses itself: the absolute URI, the CONNECT
  authority, and an SNI that must match it. The rules judge that name; roxy
  resolves it and checks the IP it actually dials. There is no
  original-destination address to spoof or race.
- **Nothing is implicit.** A client that bypasses the proxy reaches nothing,
  because the network allows nothing else, and everything that does reach
  roxy is decided by a rule.

## DNS steering

For workloads that ignore proxy settings, roxy can be the workload's DNS
server and accept connections addressed to the origins themselves
([DNS steering](/deploy/dns-steering)). The containment recipe is the same: the network
is what holds the workload, and roxy is its only way out. The steps
change:

1. **Give roxy a fixed address on the workload's network**, and point the
   workload's resolver at it (Docker `dns:`, Kubernetes `dnsConfig`, or
   `/etc/resolv.conf`).
2. **Run direct listeners on the ports the workload uses** (usually 443 and
   80) and the DNS listener on 53, with `dns.answer` set to roxy's address
   on that network.
3. **Keep roxy's own resolver separate.** `upstream.dns` must reach a real
   resolver, never roxy's DNS listener; otherwise every name resolves to
   roxy.
4. **Make the workload trust roxy's CA** ([CA distribution](/operate/ca-certificates#ca-distribution)).
   No proxy variables are needed. `http://roxy.internal/roxy-ca.pem` works
   from inside, because roxy's DNS sends that name to the direct listener
   on port 80.

With Docker Compose:

```yaml
services:
  roxy:
    image: ghcr.io/roxy-proxy/roxy:edge
    volumes: [./roxy.yaml:/etc/roxy/roxy.yaml:ro, roxy-ca:/var/lib/roxy/ca]
    networks:
      sandbox: { ipv4_address: 172.30.0.2 }
      egress: {}
  agent:
    image: curlimages/curl
    dns: [172.30.0.2]
    networks: [sandbox]
networks:
  sandbox:
    internal: true
    # Other containers get addresses from ip_range, so roxy's is never taken.
    ipam: { config: [{ subnet: 172.30.0.0/24, ip_range: 172.30.0.128/25 }] }
  egress: {}
volumes:
  roxy-ca: {}
```

```yaml
# roxy.yaml, in part
listeners:
  - { name: https, mode: direct, bind: 0.0.0.0:443 }
  - { name: http,  mode: direct, bind: 0.0.0.0:80 }
dns:
  bind: 0.0.0.0:53
  answer: { ipv4: 172.30.0.2 }
```

Docker lets unprivileged processes bind low ports inside a container
(`net.ipv4.ip_unprivileged_port_start=0`), so the image binds 53, 80 and
443 as UID 65532 with no capabilities. Elsewhere, bind high ports and
redirect to them, setting each direct listener's `target_port` to the port
clients connect to.
