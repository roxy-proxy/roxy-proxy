# TLS

How roxy speaks TLS to clients on a proxy listener. Setting up the CA is
in [managing the CA](/guides/ca-certificates).

## Leaf certificates

roxy creates a certificate for each host the first time a client
connects to it, signed by its CA. Certificates are ECDSA P-256 and valid
for seven days, or until the CA expires if that is sooner. roxy keeps up
to `tls.leaf_cache_size` of them.

## Client-facing TLS

- roxy picks the certificate by SNI, or by the CONNECT host if the client
  sends no SNI. An invalid SNI fails the handshake.
- Host names are compared in lower case without a trailing dot, so
  `CONNECT Example.COM.:443` with SNI `example.com` is one host.
- roxy offers HTTP/2 (with `http.enable_h2`) and HTTP/1.1.
- TLS 1.2 and 1.3 are supported. Sessions are not resumed.
- The handshake must finish within `limits.header_timeout`.

## ClientHello sniffing

After a CONNECT, roxy reads the first TLS message to confirm that the
tunnel carries TLS and to find the SNI. A ClientHello that is malformed,
over 16 KiB, or split across several TLS records is treated as not TLS,
and the connection is closed.
