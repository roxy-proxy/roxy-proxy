# TLS

How roxy speaks TLS to clients: the leaves it mints, the handshake it
offers, and how it checks a tunnel's first bytes. The CA itself is in
[managing the CA](/guides/ca-certificates).

## Leaf certificates

Minted on demand per host: a DNS SAN, or an IP SAN for IP targets; ECDSA
P-256; 7-day validity, or until the CA expires if sooner; signed by the CA.
All leaves share one key pair. They are cached in an LRU of
`tls.leaf_cache_size` entries, and minted on the blocking pool for the name
the handshake will serve (the SNI, or the CONNECT host when the client
sends none).

## Client-facing TLS

- The server certificate is picked by SNI. No SNI gets the CONNECT host as
  the fallback name; an SNI that is present but invalid fails the
  handshake. An SNI is valid when it would be valid as a request host:
  ASCII A-labels, IPv6 in brackets, and a name whose last label is numeric
  or `0x`-hex only as a dotted-quad IPv4 address.
- Hosts are canonicalised the same way everywhere (lower-cased, one
  trailing dot removed), and that form is the leaf cache key: `CONNECT
  Example.COM.:443` with SNI `example.com` names one host and gets one
  leaf.
- ALPN offers `h2` (with `http.enable_h2`) and `http/1.1`.
- TLS 1.2 and 1.3. Session resumption is off: no session storage, no
  TLS 1.3 tickets.

## ClientHello sniffing

After a CONNECT, roxy reads just enough of the first TLS record to confirm
the tunnel carries TLS and to extract the SNI and ALPN, with a hard cap
(16 KiB) and a timeout. The whole handshake message must be present and
well-formed before it is parsed. A ClientHello split across several TLS
records, or a malformed or hostile `server_name` (non-ASCII, control
characters, NUL, trailing dot, duplicate entries), counts as not TLS and
the connection is closed.
