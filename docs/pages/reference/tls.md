# TLS

How roxy speaks TLS to clients: the certificates it mints, the handshake
it offers, and how it checks a tunnel's first bytes. For the CA itself and
how clients come to trust it, see [managing the CA](/operate/ca-certificates).

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

## ClientHello sniffing

After a CONNECT, roxy reads just enough of the first TLS record to confirm
the tunnel carries TLS and to extract the SNI and ALPN, with a hard cap
(16 KiB) and a timeout. The whole handshake message must be present and
well-formed before it is parsed. A ClientHello split across several TLS
records, or a malformed or hostile `server_name` (non-ASCII, control
characters, NUL, trailing dot, duplicate entries), counts as not TLS and the
connection is closed; no real client sends either.
