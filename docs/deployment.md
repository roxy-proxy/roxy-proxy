# Deployment

## Containing a workload

roxy is an explicit proxy, not a transparent gateway. A client's
`HTTPS_PROXY` only tells well-behaved clients where roxy is. What contains
a workload is the network: it must have no route out except through roxy.
[`examples/compose`](../examples/compose) does this with Docker networks;
the same recipe applies anywhere:

1. **Take away the workload's route out.** Put it in a network namespace,
   VM or container network whose only reachable host is roxy. Block
   everything else, including direct TCP, UDP and DNS, at the network layer.
   roxy resolves DNS itself, so the workload needs none.
2. **Give roxy a route out**, and the workload a route to roxy's proxy port
   (3128 in the examples). Keep the CA endpoint (3130) reachable from the
   workload only if it should fetch the CA itself.
3. **Point the workload at roxy and make it trust roxy's CA**
   ([CA distribution](tls.md#ca-distribution)):

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

### Why an explicit proxy

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

## Container image

`ghcr.io/roxy-proxy/roxy` is built from the `Dockerfile` for `linux/amd64`
and `linux/arm64`. Tags: `edge` (every push to `main`), and `vX.Y.Z`, `X.Y`
and `latest` for releases ([RELEASING.md](../RELEASING.md)).

- A static musl binary on `gcr.io/distroless/static-debian12:nonroot`. No
  shell, no package manager.
- Runs as UID/GID `65532` and works with a read-only root filesystem, no
  capabilities and `no-new-privileges`. The CA directory is the only path
  it needs to write.
- Upstream TLS trusts the embedded Mozilla roots plus
  `tls.upstream.extra_roots`, so the image ships no CA bundle.
- Published images carry an SBOM and SLSA provenance and are signed with
  cosign (keyless). Every build is scanned with Trivy.

```sh
docker run -d --name roxy \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  -v roxy-ca:/var/lib/roxy/ca \
  -v ./roxy.yaml:/etc/roxy/roxy.yaml:ro \
  -p 3128:3128 -p 3130:3130 \
  ghcr.io/roxy-proxy/roxy:edge
```

| path | what |
|---|---|
| `/etc/roxy/roxy.yaml` | The config. The default is [`examples/docker/roxy.yaml`](../examples/docker/roxy.yaml); mount your own read-only. |
| `/var/lib/roxy/ca` | Volume: the CA key and certificate, generated on first start. **Keep it**: a new CA means every client must re-trust it. Owned by 65532, mode 0700. |
| `/var/log/roxy` | Volume, for a config that sets `log.flow.path` (for example `/var/log/roxy/flow.jsonl`). The default config logs flows to stdout. |
| `capture_dir` | [Capture](flow-log.md#capture) is off by default. If you set `capture_dir`, mount a volume there; the root filesystem is read-only. |

Ports: `3128` is the proxy listener and `3130` is `ca_server`
(`/roxy-ca.pem`, `/healthz`). The image's `HEALTHCHECK` runs `roxy health`,
a small built-in HTTP probe (there is no curl), against
`http://127.0.0.1:3130/healthz`. A config that moves or removes `ca_server`
needs `--health-cmd` or `--no-healthcheck`. Other subcommands run the same
way:

```sh
docker run --rm -v ./roxy.yaml:/etc/roxy/roxy.yaml:ro ghcr.io/roxy-proxy/roxy:edge \
  check --config /etc/roxy/roxy.yaml
docker run --rm -v roxy-ca:/var/lib/roxy/ca ghcr.io/roxy-proxy/roxy:edge \
  ca export --config /etc/roxy/roxy.yaml > roxy-ca.pem
```

Verify a published image's signature:

```sh
cosign verify ghcr.io/roxy-proxy/roxy:edge \
  --certificate-identity-regexp '^https://github.com/roxy-proxy/roxy-proxy/\.github/workflows/image\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Running without Docker

```sh
cargo build --release
B=./target/release/roxy

$B check --config examples/minimal.yaml      # validate; exits 1 with diagnostics
$B run   --config examples/minimal.yaml      # start; edits to the file hot-reload
```

`examples/minimal.yaml` allows `GET`/`HEAD` to `example.com` and denies
everything else. Set `tls.ca_dir` to a writable directory first. Each GitHub
release carries prebuilt binaries (static musl builds for Linux).

## Operations

- **Reload:** edit the config, list files or addon files, or send
  `SIGHUP`. A bad config is rejected and the running one stays
  ([reload](rules.md#reload)). Listener, TLS and capture settings need a
  restart.
- **Logs:** the flow log goes to stdout or `log.flow.path`; roxy's own logs
  go to stderr (`--log-format json|pretty`, `--log-level` or `RUST_LOG`).
  `SIGHUP` also reopens log files.
- **Shutdown:** `SIGTERM` drains for up to 10 seconds
  ([limits](limits.md#connections)).
