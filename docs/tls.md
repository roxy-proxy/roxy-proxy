# TLS and the CA

roxy terminates every TLS tunnel with a leaf certificate minted by its
CA, so it can inspect all HTTPS. roxy generates that CA, or uses one you
provide. Clients must trust that CA. This lives in
`roxy-tls`.

```yaml
ca_server:
  bind: 0.0.0.0:3130           # plain HTTP: /roxy-ca.pem and /healthz; absent = off

tls:
  ca_dir: /var/lib/roxy/ca     # roxy-ca.pem + roxy-ca.key, generated if absent
  # ca_cert: /etc/roxy/ca/tls.crt  # a provided CA instead; set both or neither
  # ca_key: /etc/roxy/ca/tls.key
  require_sni_match: true
  leaf_cache_size: 10000
```

## CA

On first `roxy run` (or `roxy ca init`) roxy generates an ECDSA P-256 CA:
10-year validity, `CA:TRUE, pathlen:0`, key usage `keyCertSign, cRLSign`.
It is written to `tls.ca_dir` as `roxy-ca.pem` and `roxy-ca.key`
(mode 0600). An existing pair is reused. A corrupt pair is a fatal startup
error, never silently regenerated, because a new CA breaks the trust every
client already has. `roxy ca init --force` replaces it deliberately.

To use an existing CA in `ca_dir`, put its certificate and key there as
`roxy-ca.pem` and `roxy-ca.key`. The checks below apply.

## Provided CA

Set `tls.ca_cert` and `tls.ca_key` to use a CA you already have, for
example a sub-CA issued by your organisation's root or a Kubernetes `tls`
secret mounted read-only. The two keys go together; setting only one is a
config error. `ca_dir` is then not used.

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

Every CA, provided or generated, is checked at startup. It must be a CA
certificate (`CA:TRUE`), allow `keyCertSign` if it has a key usage
extension, be within its validity period, and match its key. Each
intermediate must be the issuer of the certificate before it. Any failure
stops roxy rather than failing every handshake later.

## Leaf certificates

Minted on demand per host: a DNS SAN, or an IP SAN for IP targets; ECDSA
P-256; 7-day validity; signed by the CA. All leaves share one key pair (the
CA key is what matters). They are cached in an LRU of
`tls.leaf_cache_size` entries, and minted on the blocking pool.

## Client-facing TLS

The server certificate is picked by SNI. A client that sends no SNI gets
the CONNECT host as the fallback name; an SNI that is present but invalid
fails the handshake rather than using the fallback. ALPN offers `h2` (with
`http.enable_h2`) and `http/1.1`. TLS 1.2 and 1.3. Session resumption is
off (no session storage, no TLS 1.3 tickets): clients behind roxy are
usually short-lived, and resumption state would be one more thing to bound.

## CA distribution

The CA certificate, never the key, is available three ways. For a
provided CA this is the signing CA alone, without intermediates. Clients
that already trust your organisation's root need nothing from roxy.

```sh
roxy ca export --config roxy.yaml > roxy-ca.pem                   # at image build time (--der for DER)
curl -s http://<ca_server.bind>/roxy-ca.pem > roxy-ca.pem         # from the CA server
curl -s -x http://<proxy> http://roxy.internal/roxy-ca.pem        # through the proxy itself
```

The `ca_server` listener is separate from the proxy port so it can be
firewalled differently. It also serves `/healthz` for container health
checks.

## ClientHello sniffing

After a CONNECT, roxy reads just enough of the first TLS record to confirm
the tunnel carries TLS and to extract the SNI and ALPN, with a hard cap
(16 KiB) and a timeout. The whole handshake message must be present and
well-formed before it is parsed. A ClientHello split across several TLS
records, or a malformed or hostile `server_name` (non-ASCII, control
characters, NUL, trailing dot, duplicate entries), counts as not TLS and the
connection is closed; no real client sends either.
