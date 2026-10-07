# Managing the CA

On a proxy port roxy terminates every TLS tunnel with a leaf certificate
minted by its CA. roxy generates that CA, or uses one you provide, and
clients must trust it. The certificates roxy mints and the handshake it
offers are in [TLS](/reference/tls).

```yaml
ca_server:
  bind: 0.0.0.0:3130           # plain HTTP: /roxy-ca.pem, /healthz and /readyz; absent = off

tls:
  ca_dir: /var/lib/roxy/ca     # roxy-ca.pem + roxy-ca.key, generated if absent
  # ca_cert: /etc/roxy/ca/tls.crt  # a provided CA instead; set both or neither
  # ca_key: /etc/roxy/ca/tls.key
  require_sni_match: true
  leaf_cache_size: 10000
```

## Generated CA

On first `roxy run` (or `roxy ca init`) roxy generates an ECDSA P-256 CA:
10-year validity, `CA:TRUE, pathlen:0`, key usage `keyCertSign, cRLSign`.
It is written to `tls.ca_dir` as `roxy-ca.pem` (mode 0644) and
`roxy-ca.key` (mode 0600). An existing pair is reused. A corrupt pair is a fatal startup
error, never silently regenerated, since a new CA breaks the trust every
client already has; `roxy ca init --force` replaces it deliberately.

To use an existing CA in `ca_dir`, put its certificate and key there as
`roxy-ca.pem` and `roxy-ca.key`. The startup checks below apply.

## Provided CA

Set `tls.ca_cert` and `tls.ca_key` to use a CA you already have, such as a
sub-CA issued by your organisation's root or a Kubernetes `tls` secret
mounted read-only. Setting only one is a config error. `ca_dir` is then not
used.

- `ca_cert` is PEM. The first certificate is the CA that signs leaves.
  Any further certificates are its intermediates, in order up to but not
  including the root. roxy sends them after the CA in every handshake, so
  clients that trust only the root can build the chain.
- `ca_key` is the CA's private key as unencrypted PKCS#8 PEM
  (`BEGIN PRIVATE KEY`). ECDSA P-256 and P-384, Ed25519 and RSA keys work.
  Convert a SEC1 or PKCS#1 key with
  `openssl pkcs8 -topk8 -nocrypt -in ca.key -out ca-pkcs8.key`.

A provided CA is never generated or replaced. A missing or unusable file
is a fatal startup error, and `roxy ca init` refuses to run.

## Startup checks

Every CA, provided or generated, is checked at startup, and by `roxy
check`, which loads it the same way. It must be a CA certificate
(`CA:TRUE`), allow `keyCertSign` if it has a key usage extension, be within
its validity period, and match its key. Each intermediate must be a CA
within its validity period whose key signed the certificate before it. Any
failure stops roxy.

Two conditions are warnings, not errors; startup logs them and `check`
prints them as `warning:` lines:

- The key file is readable by its group or by others. Make it mode 0600.
- The CA expires within seven days. Leaves normally last seven days; one
  minted now ends when the CA does, and once the CA has expired roxy
  mints nothing and every TLS handshake fails (`leaf_mint_failed`).
  Replace the CA before then; a restart after expiry refuses to start.

## CA distribution

The CA certificate, never the key, is available three ways. For a
provided CA this is the signing CA alone, without intermediates; clients
that already trust your organisation's root need nothing from roxy.

```sh
roxy ca export --config roxy.yaml > roxy-ca.pem                   # at image build time (--der for DER)
curl -s http://<ca_server.bind>/roxy-ca.pem > roxy-ca.pem         # from the CA server
curl -s -x http://<proxy> http://roxy.internal/roxy-ca.pem        # through the proxy itself
```

The `ca_server` listener is separate from the proxy port so it can be
firewalled differently. It also serves the `/healthz` and `/readyz` probes
([health](/guides/operations#health)).
