//! The connection state machines: the explicit proxy
//! (proxy-port requests, CONNECT → sniff → TLS
//! termination or plaintext tunnel), direct listeners
//! (sniff → TLS termination by SNI, or
//! plaintext by `Host`), and the request loop inside a tunnel.

use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use http::StatusCode;
use roxy_http::h1::{Incoming, Role, ServerConn};
use roxy_http::{
    Authority, Body, CanonicalRequest, CanonicalResponse, Host, HttpFlags, Limits, Method, Reason,
    Scheme,
};
use roxy_tls::{ClientHelloInfo, MAX_HELLO_BYTES, Sniff, looks_like_http, sniff};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio_rustls::TlsAcceptor;

use crate::exchange::{self, respond};
use crate::flowlog::TlsInfo;
use crate::io::{BoxIo, ClientIo, Rewind};
use crate::listener::ClientConn;
use crate::pipeline::emit_connect_event;
use crate::server::Shared;
use crate::view::host_text;

/// The magic host served by the proxy itself.
pub const INTERNAL_HOST: &str = "roxy.internal";

/// The limits and flags that shape the client-facing codec, and which
/// codec a tunnel gets, fixed for a connection when it is accepted. A
/// reload changes them for new connections only; what is decided per
/// exchange (the policy, the upstream side, inspection caps) comes from
/// the exchange's snapshot.
#[derive(Clone)]
pub(crate) struct ConnLimits {
    pub limits: Arc<Limits>,
    pub flags: Arc<HttpFlags>,
    pub allow_plain_in_connect: bool,
}

impl ConnLimits {
    fn current(shared: &Shared) -> Self {
        let snap = shared.snapshot();
        Self {
            limits: snap.limits.clone(),
            flags: snap.flags.clone(),
            allow_plain_in_connect: snap.http.allow_plain_in_connect,
        }
    }

    fn codec(&self, io: ClientIo, buffered: BytesMut, role: Role) -> ServerConn<ClientIo> {
        ServerConn::with_buffered(io, buffered, role, self.limits.clone(), self.flags.clone())
    }
}

pub(crate) async fn serve_explicit(stream: BoxIo, client: ClientConn, shared: Arc<Shared>) {
    let cl = ConnLimits::current(&shared);
    let conn = cl.codec(ClientIo(stream), BytesMut::new(), Role::ProxyPort);
    Box::pin(proxy_port_loop(conn, client, shared, cl)).await;
}

fn is_internal(req: &CanonicalRequest) -> bool {
    matches!(&req.authority.host, Host::Dns(h) if h == INTERNAL_HOST)
}

/// `http://roxy.internal/roxy-ca.pem`. Anything else there is 404.
fn internal_response(req: &CanonicalRequest, shared: &Shared) -> CanonicalResponse {
    let get = matches!(req.method, Method::Get | Method::Head);
    let mut res;
    if get && req.path.as_str() == "/roxy-ca.pem" {
        res = CanonicalResponse::new(StatusCode::OK);
        let _ = res
            .headers
            .insert("content-type", crate::ca_server::PEM_CONTENT_TYPE);
        res.body = Body::from_bytes(Bytes::from(shared.ca.cert_pem()));
    } else {
        res = CanonicalResponse::new(StatusCode::NOT_FOUND);
        let _ = res.headers.insert("content-type", "application/json");
        res.body = Body::from_bytes(Bytes::from_static(b"{\"error\":\"not found\"}"));
    }
    res
}

async fn proxy_port_loop(
    mut conn: ServerConn<ClientIo>,
    client: ClientConn,
    shared: Arc<Shared>,
    cl: ConnLimits,
) {
    loop {
        let next = tokio::select! {
            r = conn.next_request() => r,
            () = shared.stop.cancelled() => return,
        };
        let incoming = match next {
            Ok(None) => return,
            Ok(Some(i)) => i,
            Err(e) => {
                exchange::close_on_parse_error(conn, None, &client, &shared, &e).await;
                return;
            }
        };
        match incoming {
            Incoming::Connect { authority, .. } => {
                Box::pin(handle_connect(conn, client, authority, shared, cl)).await;
                return;
            }
            Incoming::OriginFormOnProxyPort(req) => {
                if !is_internal(&req) {
                    let e = roxy_http::ParseError::new(
                        Reason::TargetFormMismatch,
                        "origin-form request on the proxy port",
                    );
                    exchange::close_on_parse_error(conn, None, &client, &shared, &e).await;
                    return;
                }
                let res = internal_response(&req, &shared);
                drop(req);
                match respond(conn, res).await {
                    Some(c) => conn = c,
                    None => return,
                }
            }
            Incoming::Request(req) => {
                if is_internal(&req) {
                    let res = internal_response(&req, &shared);
                    drop(req);
                    match respond(conn, res).await {
                        Some(c) => conn = c,
                        None => return,
                    }
                    continue;
                }
                match exchange::run(conn, req, client.clone(), None, &shared).await {
                    Some(c) => conn = c,
                    None => return,
                }
            }
        }
    }
}

async fn handle_connect(
    conn: ServerConn<ClientIo>,
    client: ClientConn,
    authority: Authority,
    shared: Arc<Shared>,
    cl: ConnLimits,
) {
    // No connect-time rules: a CONNECT is accepted for inspection; every
    // decision is made on the requests inside the tunnel.
    emit_connect_event(&shared, &client, &authority, false);

    let (io, buf) = match conn.accept_connect().await {
        Ok(x) => x,
        Err(e) => {
            shared.emit_parse_reason(&client, None, "connect_write_failed", Some(&e.to_string()));
            return;
        }
    };

    // Classify the first bytes: TLS, plaintext HTTP, or close.
    let timeout = cl.limits.header_timeout;
    let Some((io, buf, sniffed)) = classify(io, buf, timeout, &client, &shared).await else {
        return;
    };
    match sniffed {
        FirstBytes::Tls(hello) => {
            let mut sni_host = None;
            if let Some(sni) = &hello.sni {
                // Both sides of the comparison are canonical `Host`s, so case
                // and a trailing dot on either never count as a mismatch.
                let Ok(host) = roxy_http::url::parse_host(sni.as_bytes()) else {
                    shared.emit_parse_reason(&client, None, "bad_sni", Some(sni));
                    return;
                };
                if host != authority.host {
                    if shared.require_sni_match {
                        let connect_host = host_text(&authority.host);
                        shared.emit_parse_reason(
                            &client,
                            None,
                            "sni_mismatch",
                            Some(&format!("SNI {sni:?} != CONNECT host {connect_host:?}")),
                        );
                        return;
                    }
                    // The leaf will be for the SNI, not the CONNECT host.
                    sni_host = Some(host);
                }
            }
            Box::pin(terminate_tls(
                io,
                buf.freeze(),
                client,
                authority,
                sni_host,
                shared,
                cl,
            ))
            .await;
        }
        FirstBytes::Http if cl.allow_plain_in_connect => {
            let role = Role::Tunnel {
                authority,
                scheme: Scheme::Http,
            };
            let conn = cl.codec(io, buf, role);
            tunnel_loop(conn, client, None, shared).await;
        }
        FirstBytes::Http | FirstBytes::Other => {
            shared.emit_parse_reason(&client, None, "non_http_in_connect", None);
        }
    }
}

/// What the first bytes of a tunnel or direct connection are.
enum FirstBytes {
    /// A TLS `ClientHello`.
    Tls(ClientHelloInfo),
    /// The start of an HTTP/1 request line (a whole method and its space).
    Http,
    /// Anything else.
    Other,
}

/// Reads until the first bytes are classified: a whole `ClientHello`, a
/// whole request method and the space after it, or plainly neither. A
/// request line that arrives in pieces is not refused for it. `None` when
/// the client went away or took longer than `timeout` (logged).
async fn classify<IO: AsyncRead + Unpin>(
    mut io: IO,
    mut buf: BytesMut,
    timeout: std::time::Duration,
    client: &ClientConn,
    shared: &Shared,
) -> Option<(IO, BytesMut, FirstBytes)> {
    // A method is upper-case letters; `looks_like_http` reads at most 16.
    let method_pending = |b: &[u8]| b.len() < 16 && b.iter().all(u8::is_ascii_uppercase);
    let classified = tokio::time::timeout(timeout, async {
        loop {
            if !buf.is_empty() {
                match sniff(&buf) {
                    Sniff::Tls(hello) => return Some(FirstBytes::Tls(hello)),
                    Sniff::NotTls if !method_pending(&buf) => {
                        return Some(if looks_like_http(&buf) {
                            FirstBytes::Http
                        } else {
                            FirstBytes::Other
                        });
                    }
                    Sniff::NotTls | Sniff::NeedMore => {}
                }
            }
            if buf.len() >= MAX_HELLO_BYTES + 5 {
                return Some(FirstBytes::Other);
            }
            buf.reserve(4096);
            match io.read_buf(&mut buf).await {
                Ok(0) | Err(_) => return None,
                Ok(_) => {}
            }
        }
    })
    .await;
    match classified {
        Ok(Some(c)) => Some((io, buf, c)),
        Ok(None) => None,
        Err(_) => {
            shared.emit_parse_reason(client, None, "tunnel_timeout", None);
            None
        }
    }
}

/// A direct listener's connection: the
/// client believes it is talking to the origin on `port`. TLS is
/// terminated for the SNI, plaintext is parsed with `Host` as the
/// authority, anything else is closed.
pub(crate) async fn serve_direct(
    stream: BoxIo,
    client: ClientConn,
    port: u16,
    shared: Arc<Shared>,
) {
    let cl = ConnLimits::current(&shared);
    let timeout = cl.limits.header_timeout;
    let Some((io, buf, sniffed)) =
        classify(stream, BytesMut::new(), timeout, &client, &shared).await
    else {
        return;
    };
    match sniffed {
        FirstBytes::Tls(hello) => {
            let Some(sni) = hello.sni else {
                shared.emit_parse_reason(&client, None, "no_sni", None);
                return;
            };
            // The SNI names the host; the port is the one the client
            // connected to.
            let Ok(host) = roxy_http::url::parse_host(sni.as_bytes()) else {
                shared.emit_parse_reason(&client, None, "bad_sni", Some(&sni));
                return;
            };
            let authority = Authority { host, port };
            Box::pin(terminate_tls(
                ClientIo(io),
                buf.freeze(),
                client,
                authority,
                None,
                shared,
                cl,
            ))
            .await;
        }
        FirstBytes::Other => {
            shared.emit_parse_reason(&client, None, "non_http_on_direct", None);
        }
        FirstBytes::Http => {
            let conn = cl.codec(ClientIo(io), buf, Role::Direct { port });
            tunnel_loop(conn, client, None, shared).await;
        }
    }
}

/// `sni_host` is an SNI that differs from the authority's host and is
/// allowed to (`require_sni_match: false`); the leaf served is for it.
async fn terminate_tls(
    io: ClientIo,
    hello: Bytes,
    client: ClientConn,
    authority: Authority,
    sni_host: Option<Host>,
    shared: Arc<Shared>,
    cl: ConnLimits,
) {
    let host = host_text(&authority.host);
    // Mint the leaf off the async workers (~1 ms on a miss), so the resolver
    // inside the handshake hits the cache; a leaf already cached needs no
    // hop.
    let warm_host = sni_host.unwrap_or_else(|| authority.host.clone());
    if !shared.minter.is_cached(&warm_host) {
        let minter = shared.minter.clone();
        let warmed = tokio::task::spawn_blocking(move || minter.certified_key(&warm_host)).await;
        if !matches!(warmed, Ok(Ok(_))) {
            shared.emit_parse_reason(&client, None, "leaf_mint_failed", Some(&host));
            return;
        }
    }
    let cfg = roxy_tls::server_config_for(
        shared.minter.clone(),
        authority.host.clone(),
        shared.enable_h2,
    );
    let accept = TlsAcceptor::from(cfg).accept(Rewind::new(io, hello));
    let tls = match tokio::time::timeout(cl.limits.header_timeout, accept).await {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            shared.emit_parse_reason(&client, None, "tls_handshake_failed", Some(&e.to_string()));
            return;
        }
        Err(_) => {
            shared.emit_parse_reason(&client, None, "tls_handshake_timeout", None);
            return;
        }
    };
    let info = {
        let (_, sc) = tls.get_ref();
        TlsInfo {
            sni: sc.server_name().map(str::to_owned),
            alpn: sc
                .alpn_protocol()
                .map(|p| String::from_utf8_lossy(p).into_owned()),
            version: sc.protocol_version().map(|v| tls_version(v).to_owned()),
        }
    };
    if info.alpn.as_deref() == Some("h2") {
        // Only offered with `http.enable_h2`.
        crate::h2conn::serve(tls, client, authority, info, shared, cl).await;
        return;
    }
    let role = Role::Tunnel {
        authority,
        scheme: Scheme::Https,
    };
    let conn = cl.codec(ClientIo::new(tls), BytesMut::new(), role);
    tunnel_loop(conn, client, Some(info), shared).await;
}

async fn tunnel_loop(
    mut conn: ServerConn<ClientIo>,
    client: ClientConn,
    tls: Option<TlsInfo>,
    shared: Arc<Shared>,
) {
    loop {
        let next = tokio::select! {
            r = conn.next_request() => r,
            () = shared.stop.cancelled() => return,
        };
        match next {
            Ok(None) => return,
            Err(e) => {
                exchange::close_on_parse_error(conn, None, &client, &shared, &e).await;
                return;
            }
            Ok(Some(Incoming::Request(req)))
                if is_internal(&req) && matches!(conn.role(), Role::Direct { .. }) =>
            {
                // A direct listener is reached through roxy's DNS, which
                // steers `roxy.internal` here too.
                let res = internal_response(&req, &shared);
                drop(req);
                match respond(conn, res).await {
                    Some(c) => conn = c,
                    None => return,
                }
            }
            Ok(Some(Incoming::Request(req))) => {
                match exchange::run(conn, req, client.clone(), tls.clone(), &shared).await {
                    Some(c) => conn = c,
                    None => return,
                }
            }
            Ok(Some(Incoming::Connect { .. } | Incoming::OriginFormOnProxyPort(_))) => {
                // The tunnel role never yields these; refuse defensively.
                let e = roxy_http::ParseError::new(
                    Reason::TargetFormMismatch,
                    "unexpected request form inside a tunnel",
                );
                exchange::close_on_parse_error(conn, None, &client, &shared, &e).await;
                return;
            }
        }
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "rustls::ProtocolVersion is non_exhaustive"
)]
fn tls_version(v: rustls::ProtocolVersion) -> &'static str {
    match v {
        rustls::ProtocolVersion::TLSv1_3 => "1.3",
        rustls::ProtocolVersion::TLSv1_2 => "1.2",
        _ => "other",
    }
}
