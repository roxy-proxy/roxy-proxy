# Containing a workload

roxy is an explicit proxy, not a transparent gateway. A client's
`HTTPS_PROXY` only tells well-behaved clients where roxy is. What contains
a workload is the network: it must have no route out except through roxy.
[`examples/compose`](https://github.com/roxy-proxy/roxy-proxy/blob/main/examples/compose) does this with Docker networks;
the same recipe applies anywhere:

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
