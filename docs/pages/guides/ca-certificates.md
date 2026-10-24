# Managing the CA

On a proxy listener roxy terminates every TLS connection with a
certificate signed by its own CA, so clients must trust that CA. roxy
generates the CA, or uses one you provide. The certificates it signs are
described in [TLS](/reference/tls).

```yaml
ca_server:
  bind: 0.0.0.0:3130           # serves /roxy-ca.pem and the health checks; absent = off

tls:
  ca_dir: /var/lib/roxy/ca     # roxy-ca.pem + roxy-ca.key, generated if absent
  # ca_cert: /etc/roxy/ca/tls.crt  # a CA you provide instead; set both or neither
  # ca_key: /etc/roxy/ca/tls.key
  require_sni_match: true
  leaf_cache_size: 10000       # at least 1
```

## Generated CA

On first `roxy run`, or `roxy ca init`, roxy generates an ECDSA P-256 CA
valid for 10 years. It writes `roxy-ca.pem` and `roxy-ca.key` (mode 0600)
to `tls.ca_dir`, and reuses them on later starts. A corrupt pair stops
roxy rather than being replaced, since a new CA breaks every client's
trust. `roxy ca init --force` replaces it on purpose.

## Provided CA

Set `tls.ca_cert` and `tls.ca_key` to use a CA you already have, such as
a sub-CA of your organisation's root or a Kubernetes `tls` secret.

- `ca_cert` is PEM. The first certificate is the CA. Any further
  certificates are its intermediates, in order, without the root. roxy
  sends them to clients so that clients trusting only the root can build
  the chain.
- `ca_key` is the CA's private key as unencrypted PKCS#8 PEM
  (`BEGIN PRIVATE KEY`). roxy is tested with ECDSA P-256 keys. To convert
  another key format:
  `openssl pkcs8 -topk8 -nocrypt -in ca.key -out ca-pkcs8.key`.

roxy never generates or replaces a provided CA.

## Startup checks

At startup, and in `roxy check`, roxy checks that the CA is a valid CA
certificate within its validity period and matches its key. Any failure
stops roxy. It warns when the key file is readable by other users, and
when the CA expires within seven days. Once the CA has expired, every TLS
handshake fails.

## CA distribution

The CA certificate, never the key, can be fetched three ways. For a
provided CA this is the CA alone, without intermediates.

```sh
roxy ca export --config roxy.yaml > roxy-ca.pem                   # at image build time (--der for DER)
curl -s http://<ca_server.bind>/roxy-ca.pem > roxy-ca.pem         # from the CA server
curl -s -x http://<proxy> http://roxy.internal/roxy-ca.pem        # through the proxy itself
```

The `ca_server` listener is separate from the proxy port so it can be
firewalled separately.
