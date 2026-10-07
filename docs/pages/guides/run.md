# Container image

`ghcr.io/roxy-proxy/roxy` is built from the `Dockerfile` for `linux/amd64`
and `linux/arm64`. Tags: `edge` (every push to `main`), and `vX.Y.Z`, `X.Y`
and `latest` for releases ([RELEASING.md](https://github.com/roxy-proxy/roxy-proxy/blob/main/RELEASING.md)).

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
| `/etc/roxy/roxy.yaml` | The config. The default is [`docker/roxy.yaml`](https://github.com/roxy-proxy/roxy-proxy/blob/main/docker/roxy.yaml); mount your own read-only. |
| `/var/lib/roxy/ca` | Volume: the CA key and certificate, generated on first start. **Keep it**: a new CA means every client must re-trust it. Owned by 65532, mode 0700. |
| `/var/log/roxy` | Volume, for a config that sets `log.flow.path` (for example `/var/log/roxy/flow.jsonl`). The default config logs flows to stdout. |
| `capture_dir` | [Capture](/reference/flow-log#capture) is off by default. If you set `capture_dir`, mount a volume there; the root filesystem is read-only. |

Ports, with the default config: `3128` is the proxy listener and `3130` is `ca_server`
(`/roxy-ca.pem`, `/healthz`, `/readyz`). The image's `HEALTHCHECK` runs
`roxy health`, a small built-in HTTP probe (there is no curl), against
`http://127.0.0.1:3130/healthz`. That is liveness: the process is up. Use
`roxy health --ready` (`/readyz`) where a check should mean "a policy is in
force", such as a compose `depends_on` or a Kubernetes readiness probe
([health](/guides/operations#health)). A config that moves or removes
`ca_server` needs `--health-cmd` or `--no-healthcheck`. Other subcommands
run the same way:

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
