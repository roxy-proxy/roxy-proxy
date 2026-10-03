//! The explicit-proxy connection state machine (`DESIGN.md` §4.1):
//! proxy-port requests, CONNECT → sniff → TLS termination or plaintext
//! tunnel, and the request loop inside a tunnel.

use std::sync::Arc;

use bytes::Bytes;
use http::StatusCode;
use roxy_http::h1::{Incoming, Role, ServerConn};
use roxy_http::{
    Authority, Body, CanonicalRequest, CanonicalResponse, Host, Method, Reason, Scheme,
};
use roxy_tls::{MAX_HELLO_BYTES, Sniff, looks_like_http, sniff};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use crate::auth::{AuthCache, authenticate};
use crate::exchange::{self, ClientFraming, respond};
use crate::flowlog::TlsInfo;
use crate::io::{ConnIo, Rewind};
use crate::listener::ClientConn;
use crate::pipeline::FlowCx;
use crate::server::Shared;
use crate::view::host_text;

/// The magic host served by the proxy itself (§9).
pub const INTERNAL_HOST: &str = "roxy.internal";

/// `407` header lines (the codec treats `proxy-authenticate` as reserved).
const PROXY_AUTHENTICATE: &[u8] = b"proxy-authenticate: Basic realm=\"roxy\"\r\n";

pub(crate) async fn serve_explicit(stream: TcpStream, client: ClientConn, shared: Arc<Shared>) {
    let snap = shared.snapshot();
    let handle = ConnIo::new(Box::new(stream));
    let conn = ServerConn::new(
        handle.clone(),
        Role::ProxyPort,
        snap.limits.clone(),
        snap.flags.clone(),
    );
    drop(snap);
    Box::pin(proxy_port_loop(conn, handle, client, shared)).await;
}

fn is_internal(req: &CanonicalRequest) -> bool {
    matches!(&req.authority.host, Host::Dns(h) if h == INTERNAL_HOST)
}

/// `http://roxy.internal/roxy-ca.pem` (§9). Anything else there is 404.
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

/// Proxy auth for one request or CONNECT. `Ok(user)` (None when the
/// listener has no auth), `Err(())` → 407.
async fn check_auth(
    client: &ClientConn,
    shared: &Shared,
    header: Option<&http::HeaderValue>,
    cache: &mut AuthCache,
) -> Result<Option<String>, ()> {
    if !client.listener.auth_required {
        return Ok(None);
    }
    let snap = shared.snapshot();
    let Some(db) = snap.users.get(&client.listener.name) else {
        // Auth required but no user database: nobody gets in.
        return Err(());
    };
    authenticate(db, header, cache).await.map(Some).ok_or(())
}

fn auth_required_response() -> CanonicalResponse {
    let mut res = CanonicalResponse::new(StatusCode::PROXY_AUTHENTICATION_REQUIRED);
    let _ = res.headers.insert("content-type", "application/json");
    res.body = Body::from_bytes(Bytes::from_static(
        b"{\"error\":\"proxy authentication required\"}",
    ));
    res
}

#[allow(clippy::too_many_lines)]
async fn proxy_port_loop(
    mut conn: ServerConn<ConnIo>,
    handle: ConnIo,
    client: ClientConn,
    shared: Arc<Shared>,
) {
    let mut auth_cache = AuthCache::default();
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
            Incoming::Connect {
                authority, meta, ..
            } => {
                let framing = ClientFraming { close: meta.close };
                let Ok(user) = check_auth(
                    &client,
                    &shared,
                    meta.proxy_authorization.as_ref(),
                    &mut auth_cache,
                )
                .await
                else {
                    {
                        respond(
                            conn,
                            &handle,
                            auth_required_response(),
                            true,
                            framing,
                            PROXY_AUTHENTICATE,
                        )
                        .await;
                        return;
                    }
                };
                Box::pin(handle_connect(
                    conn,
                    handle,
                    client.with_user(user),
                    authority,
                    shared,
                ))
                .await;
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
                let framing = ClientFraming {
                    close: req.meta.close,
                };
                let res = internal_response(&req, &shared);
                drop(req);
                match respond(conn, &handle, res, false, framing, b"").await {
                    Some(c) => conn = c,
                    None => return,
                }
            }
            Incoming::Request(req) => {
                let framing = ClientFraming {
                    close: req.meta.close,
                };
                if is_internal(&req) {
                    let res = internal_response(&req, &shared);
                    drop(req);
                    match respond(conn, &handle, res, false, framing, b"").await {
                        Some(c) => conn = c,
                        None => return,
                    }
                    continue;
                }
                let Ok(user) = check_auth(
                    &client,
                    &shared,
                    req.meta.proxy_authorization.as_ref(),
                    &mut auth_cache,
                )
                .await
                else {
                    {
                        drop(req);
                        respond(
                            conn,
                            &handle,
                            auth_required_response(),
                            true,
                            framing,
                            PROXY_AUTHENTICATE,
                        )
                        .await;
                        return;
                    }
                };
                match exchange::run(conn, &handle, req, client.with_user(user), None, &shared).await
                {
                    Some(c) => conn = c,
                    None => return,
                }
            }
        }
    }
}

/// Lower-case, without a trailing dot.
fn norm_name(s: &str) -> String {
    s.trim_end_matches('.').to_ascii_lowercase()
}

#[allow(clippy::too_many_lines)]
async fn handle_connect(
    conn: ServerConn<ConnIo>,
    handle: ConnIo,
    client: ClientConn,
    authority: Authority,
    shared: Arc<Shared>,
) {
    // A flow context carries the log helpers; there is no request yet.
    let snap = shared.snapshot();
    let placeholder = CanonicalRequest {
        method: Method::Connect,
        scheme: Scheme::Https,
        authority: authority.clone(),
        path: roxy_http::Path::root(),
        query: None,
        headers: roxy_http::Headers::new(),
        body: Body::empty(),
        meta: roxy_http::RequestMeta::new(
            roxy_http::Version::H1_1,
            roxy_http::TargetForm::Authority,
        ),
    };
    let mut cx = FlowCx::new(
        shared.clone(),
        snap.clone(),
        client.clone(),
        None,
        &placeholder,
    );
    cx.facts.request = None;
    // No connect-time rules (§4.3): a CONNECT that passed proxy auth is
    // accepted for inspection; every decision is made on the requests
    // inside the tunnel.
    cx.emit_connect_event(&authority, false);
    let limits = snap.limits.clone();
    let flags = snap.flags.clone();
    drop(snap);

    let Ok((io, mut buf)) = conn.accept_connect().await else {
        return;
    };
    drop(handle);

    // Classify the first bytes (§4.1): TLS, plaintext HTTP, or close.
    let classified = tokio::time::timeout(limits.header_timeout, async {
        let mut io = io;
        loop {
            if !buf.is_empty() {
                match sniff(&buf) {
                    Sniff::NeedMore => {}
                    other => return (io, Some(other)),
                }
            }
            if buf.len() >= MAX_HELLO_BYTES + 5 {
                return (io, Some(Sniff::NotTls));
            }
            buf.reserve(4096);
            match io.read_buf(&mut buf).await {
                Ok(0) | Err(_) => return (io, None),
                Ok(_) => {}
            }
        }
    })
    .await;
    let (io, sniffed) = match classified {
        Ok((io, Some(s))) => (io, s),
        Ok((_, None)) => return,
        Err(_) => {
            shared.emit_parse_reason(&client, None, "tunnel_timeout", None);
            return;
        }
    };
    match sniffed {
        Sniff::Tls(hello) => {
            let connect_host = host_text(&authority.host);
            if let Some(sni) = &hello.sni
                && shared.require_sni_match
                && norm_name(sni) != norm_name(&connect_host)
            {
                shared.emit_parse_reason(
                    &client,
                    None,
                    "sni_mismatch",
                    Some(&format!("SNI {sni:?} != CONNECT host {connect_host:?}")),
                );
                return;
            }
            Box::pin(terminate_tls(io, buf.freeze(), client, authority, shared)).await;
        }
        Sniff::NotTls | Sniff::NeedMore => {
            if flags.allow_plain_in_connect && looks_like_http(&buf) {
                let snap = shared.snapshot();
                let handle = ConnIo::new(Box::new(io));
                let conn = ServerConn::with_buffered(
                    handle.clone(),
                    buf,
                    Role::Tunnel {
                        authority,
                        scheme: Scheme::Http,
                    },
                    snap.limits.clone(),
                    snap.flags.clone(),
                );
                drop(snap);
                tunnel_loop(conn, handle, client, None, shared).await;
            } else {
                shared.emit_parse_reason(&client, None, "non_http_in_connect", None);
            }
        }
    }
}

async fn terminate_tls(
    io: ConnIo,
    hello: Bytes,
    client: ClientConn,
    authority: Authority,
    shared: Arc<Shared>,
) {
    let host = host_text(&authority.host);
    let Ok(name) = roxy_tls::server_name_for_host(&host) else {
        shared.emit_parse_reason(&client, None, "bad_connect_host", Some(&host));
        return;
    };
    // Mint (or warm) the leaf off the async workers (~1 ms on a miss).
    let minter = shared.minter.clone();
    let warm_name = name.clone();
    let warmed = tokio::task::spawn_blocking(move || minter.certified_key(&warm_name)).await;
    if !matches!(warmed, Ok(Ok(_))) {
        shared.emit_parse_reason(&client, None, "leaf_mint_failed", Some(&host));
        return;
    }
    let cfg = roxy_tls::server_config_for(shared.minter.clone(), name, shared.enable_h2);
    let limits = shared.snapshot().limits.clone();
    let accept = TlsAcceptor::from(cfg).accept(Rewind::new(io, hello));
    let tls = match tokio::time::timeout(limits.header_timeout, accept).await {
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
            version: sc.protocol_version().map(|v| {
                match v {
                    rustls::ProtocolVersion::TLSv1_3 => "1.3",
                    rustls::ProtocolVersion::TLSv1_2 => "1.2",
                    _ => "other",
                }
                .to_owned()
            }),
        }
    };
    if info.alpn.as_deref() == Some("h2") {
        // Only offered with `http.enable_h2`.
        crate::h2conn::serve(tls, client, authority, info, shared).await;
        return;
    }
    let snap = shared.snapshot();
    let handle = ConnIo::new(Box::new(tls));
    let conn = ServerConn::new(
        handle.clone(),
        Role::Tunnel {
            authority,
            scheme: Scheme::Https,
        },
        snap.limits.clone(),
        snap.flags.clone(),
    );
    drop(snap);
    tunnel_loop(conn, handle, client, Some(info), shared).await;
}

async fn tunnel_loop(
    mut conn: ServerConn<ConnIo>,
    handle: ConnIo,
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
            Ok(Some(Incoming::Request(req))) => {
                match exchange::run(conn, &handle, req, client.clone(), tls.clone(), &shared).await
                {
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
