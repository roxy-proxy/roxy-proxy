# Run roxy

## Container image

`ghcr.io/roxy-proxy/roxy` is published for `linux/amd64` and
`linux/arm64`.

| tag | what |
|---|---|
| `latest` | The newest release. |
| `vX.Y.Z` | That release. Pin this for a reproducible deployment. |
| `X.Y` | The newest patch release of that minor version. |
| `edge` | Every push to `main`. May break. On Kubernetes, use `imagePullPolicy: Always` to track it. |

The image is a static binary on a distroless base, with no shell. It runs
as UID/GID `65532` and works with a read-only root filesystem, no
capabilities and `no-new-privileges`. Images are signed with cosign and
carry an SBOM and build provenance.

```sh
docker run -d --name roxy \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  -v roxy-ca:/var/lib/roxy/ca \
  -v ./roxy.yaml:/etc/roxy/roxy.yaml:ro \
  -p 3128:3128 -p 3130:3130 \
  ghcr.io/roxy-proxy/roxy:latest
```

| path | what |
|---|---|
| `/etc/roxy/roxy.yaml` | The config. Mount your own read-only; the default is [`docker/roxy.yaml`](https://github.com/roxy-proxy/roxy-proxy/blob/main/docker/roxy.yaml). |
| `/var/lib/roxy/ca` | The CA, generated on first start. **Keep this volume**: a new CA means every client must trust it again. |
| `/var/log/roxy` | For a config that writes the flow log to a file. By default it goes to stdout. |

With the default config, port `3128` is the proxy and `3130` serves the CA
and the health checks. The image's `HEALTHCHECK` runs `roxy health`
against `/healthz`. Use `roxy health --ready` for readiness checks
([health](/guides/operations#health)). A config that moves `ca_server`
needs its own `--health-cmd`.

Other commands run the same way:

```sh
docker run --rm -v ./roxy.yaml:/etc/roxy/roxy.yaml:ro ghcr.io/roxy-proxy/roxy:latest \
  check --config /etc/roxy/roxy.yaml
docker run --rm -v roxy-ca:/var/lib/roxy/ca ghcr.io/roxy-proxy/roxy:latest \
  ca export --config /etc/roxy/roxy.yaml > roxy-ca.pem
```

To verify an image's signature:

```sh
cosign verify ghcr.io/roxy-proxy/roxy:latest \
  --certificate-identity-regexp '^https://github.com/roxy-proxy/roxy-proxy/\.github/workflows/image\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Without the image

Each GitHub release has prebuilt Linux binaries. To build one:

```sh
cargo build --release
B=./target/release/roxy

$B check --config roxy.yaml      # validate; exits 1 with diagnostics
$B run   --config roxy.yaml      # start; edits to the file reload
```

A minimal `roxy.yaml`, which allows `GET` and `HEAD` to `example.com` and
denies everything else:

```yaml
version: 1
listeners:
  - name: proxy
    bind: 127.0.0.1:3128
tls:
  ca_dir: ./ca                 # writable; the CA is generated here
rules:
  - id: example
    when: host == "example.com" and method in [GET, HEAD]
    then: allow
```

`run --state-dir DIR` keeps state that must survive a restart. A config
that can [quarantine](/guides/operations#quarantine) roxy requires it.
