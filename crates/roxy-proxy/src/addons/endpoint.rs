//! Named endpoints: outbound calls an addon makes by name.
//!
//! roxy resolves the name to a URL, attaches the endpoint's headers
//! (credentials from secrets, never visible to the addon), applies the
//! timeout, and enforces the address floor and deny lists. The
//! call goes straight to the connector: it never passes through the layer
//! stack or the rules.

use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, HOST};
use http::{HeaderName, HeaderValue, Uri};
use roxy_http::upstream::from_upstream_response;
use roxy_http::{Authority, Body, Scheme};
use roxy_wasm::{EndpointError, LayerRequest, LayerResponse};

use super::{AddonSpec, EndpointPath, EndpointSpec, StackFlow};
use crate::body::{Collected, collect_prefix};
use crate::budget::{self, BufferLease};
use crate::flowlog::FlowEvent;
use crate::secrets::Secrets;
use crate::server::Shared;
use crate::upstream::{ConnectError, Protocols, classify};

/// Largest request body an endpoint call carries (it is buffered, charged
/// to the buffer budget, so the guest's body is read under the timeout and
/// the call is bounded).
const MAX_ENDPOINT_REQUEST_BYTES: u64 = 16 * 1024 * 1024;

/// Endpoint calls one exchange has in flight at once; the rest wait their
/// turn. With [`MAX_ENDPOINT_REQUEST_BYTES`] this bounds what a guest's
/// calls can have roxy hold for it.
pub(super) const MAX_ENDPOINT_CALLS_IN_FLIGHT: usize = 8;

/// Request fields the addon may not set on an endpoint call: hop-by-hop and
/// framing fields roxy owns.
const DROPPED: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
];

/// `value` with its `${secret:name}` references expanded by `secret`;
/// `None` if one is missing or the value does not parse (validation
/// refuses such a config, so this is a missing secret).
fn expand(value: &str, secret: impl Fn(&str) -> Option<String>) -> Option<String> {
    let parts = roxy_rules::parse_template(value).ok()?;
    roxy_rules::expand(&parts, secret)
}

/// `spec`'s headers with their secrets resolved from `secrets`, the
/// exchange's generation: every header of a call comes from one map, so a
/// swap landing between two of them cannot pair a key id with another
/// generation's key. `Err` names the header whose secret is not loaded or
/// whose value is not a header value.
pub(super) fn credentials(
    spec: &EndpointSpec,
    secrets: &Secrets,
) -> Result<Vec<(HeaderName, HeaderValue)>, String> {
    spec.headers
        .iter()
        .map(|(n, v)| {
            let v = expand(v, |name| secrets.get(name))
                .ok_or_else(|| format!("endpoint header {n}: secret not loaded"))?;
            let v = HeaderValue::from_str(&v).map_err(|_| format!("endpoint header {n}"))?;
            Ok((n.clone(), v))
        })
        .collect()
}

/// The URL for a call. `fixed`: the endpoint's URL as configured. `prefix`:
/// the endpoint's URL with the request's normalised path appended (a bare
/// `/` adds nothing) and the request's query after the endpoint's own.
///
/// A segment that starts with `..` is refused in either mode, whether or
/// not it would have climbed out: a layer that reflects text it inspected
/// into the path must not be able to express "up" at all, and the refusal
/// is the signal that it tried. The check is on the segment as an origin
/// reads it, so `..;params` and `%2e%2e` count. Under `prefix` an encoded
/// slash or backslash is refused too: roxy keeps it opaque, but an origin
/// that decodes before routing would read it as a separator, and `..`
/// beside it as a climb.
fn target(spec: &EndpointSpec, req: &Uri) -> Result<Uri, EndpointError> {
    let req_path = req.path();
    if req_path.split('/').any(climbs) {
        return Err(EndpointError::PathRefused(format!(
            "{req_path:?} has a segment that starts with `..`"
        )));
    }
    if spec.path == EndpointPath::Fixed {
        return Ok(spec.url.clone());
    }
    if has_encoded_separator(req_path) {
        return Err(EndpointError::PathRefused(format!(
            "{req_path:?} has a percent-encoded slash or backslash"
        )));
    }
    let normalised = roxy_http::url::normalize_path(req_path.as_bytes())
        .map_err(|e| EndpointError::PathRefused(e.to_string()))?;
    let base = spec.url.path().trim_end_matches('/');
    let path = match normalised.as_str() {
        "/" if !base.is_empty() => base.to_owned(),
        p => format!("{base}{p}"),
    };
    let req_query = match req.query() {
        Some(q) if !q.is_empty() => Some(
            roxy_http::url::normalize_query(q.as_bytes())
                .map_err(|e| EndpointError::PathRefused(e.to_string()))?,
        ),
        _ => None,
    };
    let query = match (spec.url.query(), req_query) {
        (None, None) => String::new(),
        (Some(q), None) => format!("?{q}"),
        (None, Some(q)) => format!("?{q}"),
        (Some(a), Some(b)) => format!("?{a}&{b}"),
    };
    let authority = spec.url.authority().map_or("", |a| a.as_str());
    let scheme = spec.url.scheme_str().unwrap_or("https");
    format!("{scheme}://{authority}{path}{query}")
        .parse()
        .map_err(|e| EndpointError::Failed(format!("endpoint URL: {e}")))
}

/// Whether a raw path segment reads as `..` to an origin: canonicalised
/// as a path of its own, it starts with two dots. Origins that strip
/// `;params` before routing (Java servlet containers) resolve `..;x` as
/// `..`, so the start of the segment is what counts, not the whole of it.
/// A segment the canonicaliser refuses (a bare `..` climbs above its own
/// root) is refused too.
fn climbs(segment: &str) -> bool {
    let alone = format!("/{segment}");
    match roxy_http::url::normalize_path(alone.as_bytes()) {
        Ok(p) => p
            .as_str()
            .strip_prefix('/')
            .is_none_or(|s| s.starts_with("..")),
        Err(_) => true,
    }
}

/// Whether a raw path carries `%2F` or `%5C` in either case.
fn has_encoded_separator(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("%2f") || lower.contains("%5c")
}

pub(super) fn authority_of(uri: &Uri) -> Result<(Scheme, Authority), String> {
    let scheme = match uri.scheme_str() {
        Some("http") => Scheme::Http,
        _ => Scheme::Https,
    };
    let raw = uri.authority().map_or("", |a| a.as_str());
    let authority = roxy_http::url::parse_authority(raw.as_bytes(), scheme.default_port())
        .map_err(|e| e.to_string())?;
    Ok((scheme, authority))
}

/// Calls endpoint `name` of `addon` for the flow `st`.
pub(crate) async fn call(
    st: &StackFlow,
    addon: &AddonSpec,
    name: &str,
    req: LayerRequest,
) -> Result<LayerResponse, EndpointError> {
    let Some(spec) = addon.endpoints.get(name) else {
        return Err(EndpointError::NotFound);
    };
    let started = Instant::now();
    let method = req.method().clone();
    let path = req
        .uri()
        .path_and_query()
        .map_or_else(|| "/".to_owned(), |p| p.as_str().to_owned());
    let result = attempt(st, spec, req).await;
    let (status, error) = match &result {
        Ok(r) => (Some(r.status().as_u16()), None),
        Err(e) => (None, Some(e.to_string())),
    };
    st.shared.sink.emit(&FlowEvent::EndpointCall {
        ts: chrono::Utc::now(),
        flow: st.flow.to_string(),
        conn: st.client.id.to_string(),
        layer: addon.name.clone(),
        endpoint: name.to_owned(),
        method: method.to_string(),
        path: st.secrets().redactor().redact_str(&path).into_owned(),
        status,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        error,
    });
    result
}

async fn attempt(
    st: &StackFlow,
    spec: &EndpointSpec,
    req: LayerRequest,
) -> Result<LayerResponse, EndpointError> {
    let fail = |e: String| EndpointError::Failed(e);
    let uri = target(spec, req.uri())?;
    let (scheme, authority) = authority_of(&uri).map_err(fail)?;
    let (parts, body) = req.into_parts();
    // The guest drives the body, so reading it is under the timeout like
    // the attempt itself; the permit holds the exchange's in-flight cap.
    let admitted = tokio::time::timeout(spec.timeout, async {
        let permit = st.endpoint_calls.acquire().await;
        (permit, collect_body(&st.shared, body).await)
    })
    .await;
    let Ok((permit, body)) = admitted else {
        return Err(EndpointError::Timeout);
    };
    let _permit = permit.map_err(|e| fail(format!("endpoint calls: {e}")))?;
    let (body, _lease) = body?;

    let mut headers = http::HeaderMap::new();
    for (n, v) in &parts.headers {
        if !DROPPED.contains(&n.as_str()) && !spec.headers.iter().any(|(h, _)| h == n) {
            headers.append(n.clone(), v.clone());
        }
    }
    for (n, v) in credentials(spec, st.secrets()).map_err(fail)? {
        headers.insert(n, v);
    }
    let host = HeaderValue::from_str(&authority.to_host_header(scheme))
        .map_err(|_| fail("endpoint host".into()))?;
    headers.insert(HOST, host);
    if !body.is_empty() || parts.method != http::Method::GET {
        headers.insert(CONTENT_LENGTH, HeaderValue::from(body.len()));
    }

    // The connector runs the address floor on the address it dials.
    let upstream = st.snap.upstream.clone();
    let mut r = http::Request::new(Body::from_bytes(body));
    *r.method_mut() = parts.method;
    *r.uri_mut() = uri;
    *r.headers_mut() = headers;
    let sent = tokio::time::timeout(
        spec.timeout,
        upstream.client(spec.private, Protocols::Any).request(r),
    )
    .await;
    match sent {
        Ok(Ok(res)) => {
            let res = from_upstream_response(res, &st.snap.limits);
            Ok(roxy_http::layer::to_layer_response(res))
        }
        Ok(Err(e)) => Err(match classify(&e) {
            Some(ce) => connect_error(&ce),
            None => EndpointError::Failed(crate::upstream::describe(&e)),
        }),
        Err(_) => Err(EndpointError::Timeout),
    }
}

/// Buffers the guest's request body whole, charged to the budget by the
/// returned lease for as long as the call needs it. Trailers are not sent
/// and not kept.
async fn collect_body(
    shared: &Arc<Shared>,
    mut body: Body,
) -> Result<(Bytes, BufferLease), EndpointError> {
    let exhausted = || EndpointError::Failed(format!("request body: {}", budget::EXHAUSTED));
    let Some(mut lease) = shared.reserve_buffer(0) else {
        return Err(exhausted());
    };
    let mut meter = |held: u64| shared.grow_buffer(&mut lease, held);
    match collect_prefix(&mut body, MAX_ENDPOINT_REQUEST_BYTES, &mut meter).await {
        Collected::Complete { data, .. } => {
            lease.shrink_to(data.len() as u64);
            Ok((data, lease))
        }
        Collected::TooLarge { .. } => Err(EndpointError::Failed(format!(
            "request body over {MAX_ENDPOINT_REQUEST_BYTES} bytes"
        ))),
        Collected::BudgetExhausted => Err(exhausted()),
        Collected::Failed(e) => Err(EndpointError::Failed(format!("request body: {e}"))),
    }
}

fn connect_error(e: &ConnectError) -> EndpointError {
    match e {
        ConnectError::Denied(_) => EndpointError::Denied,
        ConnectError::Timeout(_) => EndpointError::Timeout,
        other @ (ConnectError::Dns(_)
        | ConnectError::Connect(_)
        | ConnectError::Tls(_)
        | ConnectError::Target(_)) => EndpointError::Failed(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use std::time::Duration;

    use super::*;
    use crate::flowlog::Redactor;
    use crate::secrets::SecretStore;

    fn spec(url: &str, path: EndpointPath) -> EndpointSpec {
        EndpointSpec {
            url: url.parse().unwrap(),
            path,
            headers: Vec::new(),
            timeout: Duration::from_secs(1),
            private: crate::addr::PrivateAddrs::Deny,
        }
    }

    fn join(path: EndpointPath, base: &str, req: &str) -> Result<String, EndpointError> {
        target(&spec(base, path), &req.parse().unwrap()).map(|u| u.to_string())
    }

    #[test]
    fn prefix_joins_paths() {
        let t = |base, req| join(EndpointPath::Prefix, base, req).unwrap();
        assert_eq!(
            t("https://api.example.com/v1/messages", "/"),
            "https://api.example.com/v1/messages"
        );
        assert_eq!(
            t("https://api.example.com/v1/", "/score?q=1"),
            "https://api.example.com/v1/score?q=1"
        );
        assert_eq!(
            t("https://api.example.com", "/"),
            "https://api.example.com/"
        );
        assert_eq!(
            t("http://ti.internal:8443", "/x"),
            "http://ti.internal:8443/x"
        );
        // The endpoint's own query is kept, ahead of the request's.
        assert_eq!(
            t("https://api.example.com/v1?key=k", "/score?q=1"),
            "https://api.example.com/v1/score?key=k&q=1"
        );
        assert_eq!(
            t("https://api.example.com/v1?key=k", "/"),
            "https://api.example.com/v1?key=k"
        );
    }

    /// Dot segments that stay inside the prefix are resolved; encodings are
    /// canonicalised rather than passed through.
    #[test]
    fn prefix_normalises_the_request_path() {
        let t = |req| join(EndpointPath::Prefix, "https://api.example.com/v1", req).unwrap();
        assert_eq!(t("/a/./b"), "https://api.example.com/v1/a/b");
        assert_eq!(t("/a/"), "https://api.example.com/v1/a/");
        assert_eq!(t("/%7ex?q=%2f"), "https://api.example.com/v1/~x?q=%2F");
    }

    /// A segment starting with `..` is refused outright in both modes, even
    /// where it would not have left the prefix, in any percent-encoded
    /// spelling, and with anything after the dots (`..;x` is `..` to an
    /// origin that strips path parameters). Under `prefix` so is a
    /// percent-encoded slash or backslash, which an origin that decodes
    /// before routing would read as a separator.
    #[test]
    fn dot_dot_is_refused() {
        let refused = |mode, req: &str| {
            matches!(
                join(mode, "https://api.example.com/v1", req),
                Err(EndpointError::PathRefused(_))
            )
        };
        for mode in [EndpointPath::Fixed, EndpointPath::Prefix] {
            for req in [
                "/../admin",
                "/a/../admin",
                "/a/../../admin",
                "/%2e%2e/admin",
                "/.%2E/admin",
                "/a/..;x/admin",
                "/a/..;/admin",
                "/a/%2e%2e;x/admin",
                "/a/.%2E;jsessionid=1/admin",
                "/a/...",
                "/a/..x/admin",
            ] {
                assert!(refused(mode, req), "{mode:?} {req}");
            }
            // Dots that do not start a segment, and path parameters on an
            // ordinary segment, are not climbs.
            for req in ["/a/b..", "/a/.hidden", "/a;x/b", "/a/.;x/b"] {
                assert!(!refused(mode, req), "{mode:?} {req}");
            }
        }
        for req in [
            "/a%2F..%2Fadmin",
            "/a%2f..%2fadmin",
            "/a%5C..%5Cadmin",
            "/a%5c..%5cadmin",
            "/a%2Fb",
        ] {
            assert!(refused(EndpointPath::Prefix, req), "{req}");
            assert!(!refused(EndpointPath::Fixed, req), "{req}");
        }
    }

    /// `fixed` sends the configured URL whatever the request says.
    #[test]
    fn fixed_ignores_the_request_path() {
        let t = |req| {
            join(
                EndpointPath::Fixed,
                "https://api.example.com/v1/messages",
                req,
            )
            .unwrap()
        };
        for req in ["/", "/score?q=1", "/admin", "/?admin=1"] {
            assert_eq!(t(req), "https://api.example.com/v1/messages", "{req}");
        }
    }

    /// Every header of a call resolves from the generation the exchange
    /// loaded; a swap after that load, before or between the headers, is
    /// invisible to the call and only reaches the next exchange.
    #[test]
    fn credentials_come_from_one_generation() {
        let generation = |n: u8| {
            HashMap::from([
                ("akid".to_owned(), format!("AKID{n}")),
                ("sk".to_owned(), format!("SK{n}")),
            ])
        };
        let store = SecretStore::new(generation(1), Redactor::new());
        let mut spec = spec("https://api.example.com/v1", EndpointPath::Fixed);
        spec.headers = vec![
            ("x-key-id".parse().unwrap(), "${secret:akid}".to_owned()),
            (
                "authorization".parse().unwrap(),
                "Bearer ${secret:sk}".to_owned(),
            ),
        ];

        let exchange = store.load();
        store.swap(generation(2));
        let got = credentials(&spec, &exchange).unwrap();
        assert_eq!(got[0].1, "AKID1");
        assert_eq!(got[1].1, "Bearer SK1");

        let next = credentials(&spec, &store.load()).unwrap();
        assert_eq!(next[0].1, "AKID2");
        assert_eq!(next[1].1, "Bearer SK2");

        store.swap(HashMap::new());
        assert_eq!(
            credentials(&spec, &store.load()).unwrap_err(),
            "endpoint header x-key-id: secret not loaded"
        );
    }

    /// An endpoint call's body is charged to the budget while the call
    /// holds it and given back when the call is done; a body the budget
    /// cannot cover, or one declared over the cap, is refused before it is
    /// held.
    #[tokio::test]
    async fn request_bodies_are_charged_to_the_budget_while_the_call_holds_them() {
        use crate::testkit::Kit;
        let kit = Kit::builder()
            .limits(|l| l.max_buffered_bytes = 100)
            .start()
            .await;
        let shared = kit.server.shared().clone();
        let (data, lease) = collect_body(&shared, Body::from_bytes(vec![7u8; 60]))
            .await
            .unwrap();
        assert_eq!(data.len(), 60);
        assert_eq!(shared.buffered(), 60);

        let (mut tx, body) = Body::channel(u64::MAX, None);
        tx.send_data(Bytes::from(vec![7u8; 50])).await.unwrap();
        let err = collect_body(&shared, body).await.unwrap_err();
        assert!(
            matches!(&err, EndpointError::Failed(m) if m.contains(budget::EXHAUSTED)),
            "{err:?}"
        );
        assert_eq!(shared.buffered(), 60);
        drop(lease);
        assert_eq!(shared.buffered(), 0);

        let (_tx, body) = Body::channel(u64::MAX, Some(MAX_ENDPOINT_REQUEST_BYTES + 1));
        let err = collect_body(&shared, body).await.unwrap_err();
        assert!(
            matches!(&err, EndpointError::Failed(m) if m.contains("over")),
            "{err:?}"
        );
        assert_eq!(shared.buffered(), 0);
    }

    #[test]
    fn expands_secrets() {
        let s = |name: &str| (name == "k").then(|| "sk-1".to_owned());
        assert_eq!(
            expand("Bearer ${secret:k}", s).as_deref(),
            Some("Bearer sk-1")
        );
        assert_eq!(expand("${secret:missing}", s), None);
        assert_eq!(expand("plain", s).as_deref(), Some("plain"));
    }
}
