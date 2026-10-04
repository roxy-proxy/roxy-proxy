//! The plain-HTTP CA endpoint (`ca_server.bind`): `GET
//! /roxy-ca.pem` and `GET /healthz`. Kept off the proxy port so it can be
//! firewalled differently.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;

use crate::server::{Shared, conn_slot};

/// `content-type` of the CA certificate.
pub const PEM_CONTENT_TYPE: &str = "application/x-pem-file";

fn reply(status: StatusCode, ctype: &str, body: impl Into<Bytes>) -> Response<Full<Bytes>> {
    let mut res = Response::new(Full::new(body.into()));
    *res.status_mut() = status;
    if let Ok(v) = http::HeaderValue::from_str(ctype) {
        res.headers_mut().insert(http::header::CONTENT_TYPE, v);
    }
    res
}

fn route(req: &Request<Incoming>, shared: &Shared) -> Response<Full<Bytes>> {
    let get = req.method() == Method::GET || req.method() == Method::HEAD;
    match (get, req.uri().path()) {
        (true, "/roxy-ca.pem") => reply(StatusCode::OK, PEM_CONTENT_TYPE, shared.ca.cert_pem()),
        (true, "/healthz") => reply(StatusCode::OK, "text/plain", "ok"),
        _ => reply(StatusCode::NOT_FOUND, "text/plain", "not found"),
    }
}

pub(crate) async fn serve(tcp: TcpListener, shared: Arc<Shared>) {
    loop {
        let accepted = tokio::select! {
            r = tcp.accept() => r,
            () = shared.stop.cancelled() => return,
        };
        let Ok((stream, peer)) = accepted else {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        let Some(slot) = conn_slot(&shared, peer.ip()) else {
            drop(stream);
            continue;
        };
        let s = shared.clone();
        let header_timeout = shared.snapshot().limits.header_timeout;
        shared.spawn_conn(slot, async move {
            let svc = service_fn(move |req: Request<Incoming>| {
                let res = route(&req, &s);
                async move { Ok::<_, Infallible>(res) }
            });
            let conn = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(header_timeout)
                .keep_alive(false)
                .serve_connection(TokioIo::new(stream), svc);
            if let Err(e) = conn.await {
                tracing::debug!(error = %e, "ca_server connection error");
            }
        });
    }
}
