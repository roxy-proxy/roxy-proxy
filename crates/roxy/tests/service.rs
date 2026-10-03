//! End-to-end tests of service layers (DESIGN.md §11.6): `roxy run` with a
//! `kind: service` addon streaming exchanges through an in-test service.
//! The service's behaviour is picked by its URL path.

mod support;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::Value;
use support::{Harness, Opts, fnv};
use tokio::net::TcpListener;

const ALLOW_UPSTREAM: &str = r#"
  - id: upstream
    when: host == "upstream.test"
    then: { allow: { private_ok: true } }
"#;

#[derive(Default)]
struct SvcState {
    /// `roxy-flow-*` headers of every call, with its direction.
    calls: Mutex<Vec<Vec<(String, String)>>>,
}

type Out = BoxBody<Bytes, std::io::Error>;

fn reply(status: StatusCode, ct: &str, body: impl Into<Bytes>) -> Response<Out> {
    let mut r = Response::new(
        Full::new(body.into())
            .map_err(|never: Infallible| match never {})
            .boxed(),
    );
    *r.status_mut() = status;
    r.headers_mut()
        .insert(http::header::CONTENT_TYPE, ct.parse().unwrap());
    r
}

fn message(body: impl Into<Bytes>) -> Response<Out> {
    reply(StatusCode::OK, "message/http", body)
}

async fn whole(body: Incoming) -> Vec<u8> {
    body.collect().await.unwrap().to_bytes().to_vec()
}

fn replace(hay: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < hay.len() {
        if hay[i..].starts_with(from) {
            out.extend_from_slice(to);
            i += from.len();
        } else {
            out.push(hay[i]);
            i += 1;
        }
    }
    out
}

#[allow(clippy::too_many_lines)] // one arm per behaviour, read as a table
async fn svc(req: Request<Incoming>, st: Arc<SvcState>) -> Result<Response<Out>, Infallible> {
    let (parts, body) = req.into_parts();
    let flow: Vec<(String, String)> = parts
        .headers
        .iter()
        .filter(|(n, _)| n.as_str().starts_with("roxy-flow-") || n.as_str() == "x-svc-key")
        .map(|(n, v)| (n.to_string(), v.to_str().unwrap_or("").to_owned()))
        .collect();
    st.calls.lock().unwrap().push(flow);
    assert_eq!(parts.headers["content-type"], "message/http");
    let dir = parts.headers["roxy-flow-direction"]
        .to_str()
        .unwrap()
        .to_owned();
    let request = dir == "request";
    Ok(match parts.uri.path() {
        // Streams the message straight back as it arrives.
        "/echo" => {
            let s = body.into_data_stream().map(|r| {
                r.map(Frame::data)
                    .map_err(|e| std::io::Error::other(e.to_string()))
            });
            let mut r = Response::new(BodyExt::boxed(StreamBody::new(s)));
            r.headers_mut()
                .insert(http::header::CONTENT_TYPE, "message/http".parse().unwrap());
            r
        }
        // Rewrites the request path; upper-cases the response body.
        "/rewrite" => {
            let m = whole(body).await;
            if request {
                message(replace(&m, b"/fine", b"/rewritten"))
            } else {
                let at = m.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
                let mut out = m[..at].to_vec();
                out.extend(m[at..].to_ascii_uppercase());
                message(out)
            }
        }
        "/deny" => {
            drop(whole(body).await);
            reply(
                StatusCode::OK,
                "application/roxy-decision+json",
                r#"{"deny": {"status": 451, "message": "the service said no"}}"#,
            )
        }
        "/deny-response" if request => message(whole(body).await),
        "/deny-response" => {
            drop(whole(body).await);
            reply(
                StatusCode::OK,
                "application/roxy-decision+json",
                r#"{"deny": {"message": "not this answer"}}"#,
            )
        }
        "/respond" => {
            drop(whole(body).await);
            reply(
                StatusCode::OK,
                "application/roxy-decision+json; charset=utf-8",
                r#"{"respond": {"status": 200, "headers": {"x-from": "service"}, "body": "made up"}}"#,
            )
        }
        "/status" => reply(StatusCode::INTERNAL_SERVER_ERROR, "text/plain", "broken"),
        "/wrong-type" => reply(StatusCode::OK, "text/plain", "hello"),
        "/garbage" => message("this is not an HTTP message"),
        "/smuggle" => {
            drop(whole(body).await);
            message(
                "POST http://upstream.test/ HTTP/1.1\r\nhost: upstream.test\r\n\
                 content-length: 3\r\ntransfer-encoding: chunked\r\n\r\nabc",
            )
        }
        "/bad-decision" => reply(
            StatusCode::OK,
            "application/roxy-decision+json",
            r#"{"allow": true}"#,
        ),
        "/slow" => {
            tokio::time::sleep(Duration::from_secs(5)).await;
            message(whole(body).await)
        }
        // Promises a body, sends part of it, then breaks the stream.
        "/drop" => {
            let m = whole(body).await;
            let at = m.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
            let head = String::from_utf8_lossy(&m[..at]).to_string();
            let head = if head.contains("content-length") {
                head
            } else {
                head.replacen("\r\n\r\n", "\r\ncontent-length: 1000\r\n\r\n", 1)
            };
            let head = Bytes::from(head);
            // The error comes after the head is on the wire.
            let s = futures_util::stream::iter(vec![
                Ok(Frame::data(head)),
                Ok(Frame::data(Bytes::from_static(b"partial"))),
            ])
            .chain(futures_util::stream::once(async {
                tokio::time::sleep(Duration::from_millis(200)).await;
                Err(std::io::Error::other("service crashed"))
            }));
            let mut r = Response::new(BodyExt::boxed(StreamBody::new(s)));
            r.headers_mut()
                .insert(http::header::CONTENT_TYPE, "message/http".parse().unwrap());
            r
        }
        p => panic!("unknown service path {p}"),
    })
}

use futures_util::StreamExt as _;

async fn start_service() -> (SocketAddr, Arc<SvcState>) {
    let st = Arc::new(SvcState::default());
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let s = st.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = l.accept().await else {
                return;
            };
            let s = s.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req| svc(req, s.clone()));
                let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tcp), svc)
                    .await;
            });
        }
    });
    (addr, st)
}

/// roxy with one service layer `s` at `path` on the in-test service.
async fn start(path: &str, extra: &str, rules: &str) -> (Harness, Arc<SvcState>) {
    let (addr, st) = start_service().await;
    let addons = format!(
        "addons:\n  - name: s\n    kind: service\n    endpoint: svc\n    endpoints:\n      \
         svc:\n        url: http://{addr}{path}\n        private_ok: true\n        \
         headers: {{ x-svc-key: \"${{secret:token}}\" }}\n{extra}"
    );
    let extra = addons;
    let h = Harness::start_with(Opts {
        rules,
        extra: &extra,
        ..Opts::default()
    })
    .await;
    (h, st)
}

fn json(b: &[u8]) -> Value {
    serde_json::from_slice(b)
        .unwrap_or_else(|e| panic!("not JSON ({e}): {}", String::from_utf8_lossy(b)))
}

#[tokio::test(flavor = "multi_thread")]
async fn pass_through_is_byte_identical() {
    let (h, st) = start("/echo", "", ALLOW_UPSTREAM).await;
    // Large enough to need several frames each way, streamed.
    let body: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let res = h
        .client()
        .post(h.https_url("/echo-me?q=1"))
        .header("x-thing", "kept")
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let v = json(&res.bytes().await.unwrap());
    assert_eq!(v["path"], "/echo-me?q=1");
    assert_eq!(v["body_len"], 300_000);
    assert_eq!(v["body_hash"], fnv(&body));
    assert_eq!(v["headers"]["x-thing"], "kept");

    // Both directions went through the service, with the flow metadata
    // and the endpoint's credential.
    let calls = st.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 2, "{calls:?}");
    let get = |c: &Vec<(String, String)>, n: &str| {
        c.iter()
            .find(|(k, _)| k == n)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    assert_eq!(get(&calls[0], "roxy-flow-direction"), "request");
    assert_eq!(get(&calls[1], "roxy-flow-direction"), "response");
    assert_eq!(get(&calls[0], "roxy-flow-layer"), "s");
    assert_eq!(get(&calls[0], "roxy-flow-client-ip"), "127.0.0.1");
    assert_eq!(get(&calls[0], "x-svc-key"), support::SECRET);
    let ev = h.wait_events("request", 1).await;
    assert_eq!(
        get(&calls[0], "roxy-flow-id"),
        ev[0]["flow"].as_str().unwrap()
    );
    assert_eq!(ev[0]["decision"], "allow");
    assert_eq!(ev[0]["addons"], serde_json::json!(["s"]));
    let calls = h.wait_events("endpoint_call", 2).await;
    assert_eq!(calls[0]["endpoint"], "svc");
    assert_eq!(calls[0]["status"], 200);
    h.stop().await;
}

/// What the service passes on is judged by the rules (invariant 1), and
/// its rewrite of the response reaches the client.
#[tokio::test(flavor = "multi_thread")]
async fn a_rewrite_is_applied_and_judged_by_the_rules() {
    let rules = r#"
  - id: no-rewritten
    when: path starts_with "/rewritten-secret"
    then: { deny: { status: 403 } }
  - id: upstream
    when: host == "upstream.test"
    then: { allow: { private_ok: true } }
"#;
    let (h, _) = start("/rewrite", "", rules).await;
    let res = h
        .client()
        .post(h.https_url("/fine-path"))
        .body("x")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body = res.text().await.unwrap();
    // The upstream saw the rewritten path; the service upper-cased the
    // response body on the way back.
    assert!(body.contains("\"PATH\":\"/REWRITTEN-PATH\""), "{body}");

    let res = h
        .client()
        .post(h.https_url("/fine-secret"))
        .body("x")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
    let ev = h.wait_events("request", 2).await;
    assert_eq!(ev[1]["terminal_rule"], "no-rewritten");
    assert_eq!(h.upstream.seen().len(), 1);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_deny_decision_is_honoured() {
    let (h, _) = start("/deny", "", ALLOW_UPSTREAM).await;
    let res = h
        .client()
        .post(h.https_url("/x"))
        .body("x")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 451);
    assert_eq!(res.text().await.unwrap(), "the service said no\n");
    assert!(h.upstream.seen().is_empty());
    let ev = h.wait_events("request", 1).await;
    assert_eq!(ev[0]["decision"], "deny");
    assert_eq!(ev[0]["terminal_rule"], "layer:s");
    assert!(
        ev[0]["tags"].as_array().unwrap().contains(&"s:deny".into()),
        "{}",
        ev[0]
    );
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn decisions_on_the_response_and_respond() {
    let (h, _) = start("/deny-response", "", ALLOW_UPSTREAM).await;
    let res = h.client().get(h.https_url("/x")).send().await.unwrap();
    assert_eq!(res.status(), 403);
    assert_eq!(res.text().await.unwrap(), "not this answer\n");
    // The request did reach the upstream; its answer was replaced.
    assert_eq!(h.upstream.seen().len(), 1);
    h.stop().await;

    let (h, _) = start("/respond", "", ALLOW_UPSTREAM).await;
    let res = h.client().get(h.https_url("/x")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.headers()["x-from"], "service");
    assert_eq!(res.text().await.unwrap(), "made up");
    assert!(h.upstream.seen().is_empty());
    h.stop().await;
}

/// Fail closed: every way a service can fail before the head denies the
/// exchange with `layer:<name>` and logs why.
#[tokio::test(flavor = "multi_thread")]
async fn failures_fail_closed() {
    for (path, kind) in [
        ("/status", "service:status"),
        ("/wrong-type", "service:content_type"),
        ("/garbage", "service:invalid_message"),
        ("/smuggle", "service:invalid_message"),
        ("/bad-decision", "service:invalid_decision"),
        ("/slow", "service:timeout"),
    ] {
        let (h, _) = start(
            path,
            "    limits: { first_byte_timeout: 500ms }\n",
            ALLOW_UPSTREAM,
        )
        .await;
        let res = h
            .client()
            .post(h.https_url("/x"))
            .body("x")
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 503, "{path}");
        assert_eq!(res.headers()["x-roxy-rule"], "layer:s", "{path}");
        assert!(h.upstream.seen().is_empty(), "{path}");
        let ev = h.wait_events("layer_error", 1).await;
        assert_eq!(ev[0]["kind"], kind, "{path}: {}", ev[0]);
        assert_eq!(ev[0]["layer"], "s");
        assert_eq!(ev[0]["mode"], "enforce");
        h.stop().await;
    }
}

/// A stream that breaks after the head never reaches the upstream as a
/// complete request.
#[tokio::test(flavor = "multi_thread")]
async fn a_dropped_stream_fails_closed() {
    let (h, _) = start("/drop", "", ALLOW_UPSTREAM).await;
    let res = h
        .client()
        .post(h.https_url("/x"))
        .body("hello")
        .send()
        .await
        .unwrap();
    assert!(res.status().is_server_error(), "{}", res.status());
    // The upstream either saw nothing or an incomplete body, never 1000
    // bytes.
    assert!(h.upstream.seen().iter().all(|s| s.body_len < 1000));
    let ev = h.wait_events("layer_error", 1).await;
    assert_eq!(ev[0]["kind"], "service:stream", "{}", ev[0]);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn observe_mode_cannot_block() {
    for path in ["/deny", "/status", "/garbage"] {
        let (h, st) = start(path, "    mode: observe\n", ALLOW_UPSTREAM).await;
        let res = h
            .client()
            .post(h.https_url("/x"))
            .body("x")
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200, "{path}");
        assert_eq!(h.upstream.seen().len(), 1, "{path}");
        if path != "/deny" {
            let ev = h.wait_events("layer_error", 1).await;
            assert_eq!(ev[0]["mode"], "observe", "{path}");
        }
        // The service saw the copy.
        assert!(!st.calls.lock().unwrap().is_empty(), "{path}");
        h.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn directions_limit_what_goes_through() {
    let (h, st) = start("/echo", "    directions: [response]\n", ALLOW_UPSTREAM).await;
    let res = h.client().get(h.https_url("/x")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    drop(res.bytes().await);
    let calls = st.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert!(
        calls[0].contains(&("roxy-flow-direction".into(), "response".into())),
        "{calls:?}"
    );
    h.stop().await;
}
