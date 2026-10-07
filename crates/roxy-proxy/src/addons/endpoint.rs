//! Named endpoints: outbound calls an addon makes by name.
//!
//! roxy resolves the name to a URL, attaches the endpoint's headers
//! (credentials from secrets, never visible to the addon), applies the
//! timeout and retries, and enforces the address floor and deny lists. The
//! call goes straight to the connector: it never passes through the layer
//! stack or the rules.

use std::time::{Duration, Instant};

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, HOST};
use http::{HeaderName, HeaderValue, Uri};
use roxy_http::upstream::from_upstream_response;
use roxy_http::{Authority, Body, Scheme};
use roxy_wasm::{EndpointError, LayerRequest, LayerResponse};

use super::{AddonSpec, EndpointPath, EndpointSpec, StackFlow};
use crate::flowlog::FlowEvent;
use crate::secrets::Secrets;
use crate::upstream::{ConnectError, Protocols, classify};

/// Largest request body an endpoint call carries (it is buffered so a retry
/// can resend it).
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
    let result = attempt_all(st, spec, req).await;
    let (status, attempts, error) = match &result {
        Ok((r, n)) => (Some(r.status().as_u16()), *n, None),
        Err((e, n)) => (None, *n, Some(e.to_string())),
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
        attempts,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        error,
    });
    result.map(|(r, _)| r).map_err(|(e, _)| e)
}

async fn attempt_all(
    st: &StackFlow,
    spec: &EndpointSpec,
    req: LayerRequest,
) -> Result<(LayerResponse, u32), (EndpointError, u32)> {
    let fail = |e: String| (EndpointError::Failed(e), 0);
    let uri = target(spec, req.uri()).map_err(|e| (e, 0))?;
    let (scheme, authority) = authority_of(&uri).map_err(fail)?;
    let (parts, body) = req.into_parts();
    // The guest drives the body, so reading it is under the timeout like
    // the attempt itself; the permit holds the exchange's in-flight cap.
    let admitted = tokio::time::timeout(spec.timeout, async {
        let permit = st.endpoint_calls.acquire().await;
        (permit, body.collect_up_to(MAX_ENDPOINT_REQUEST_BYTES).await)
    })
    .await;
    let Ok((permit, body)) = admitted else {
        return Err((EndpointError::Timeout, 0));
    };
    let _permit = permit.map_err(|e| fail(format!("endpoint calls: {e}")))?;
    let body = body.map_err(|e| fail(format!("request body: {e}")))?.data;

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

    // The connector runs the address floor on the address it dials; a
    // denied one fails the first attempt.
    let upstream = st.snap.upstream.clone();
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        let last = attempt > spec.retries;
        let mut r = http::Request::new(Body::from_bytes(Bytes::clone(&body)));
        *r.method_mut() = parts.method.clone();
        *r.uri_mut() = uri.clone();
        *r.headers_mut() = headers.clone();
        let sent = tokio::time::timeout(
            spec.timeout,
            upstream.client(spec.private, Protocols::Any).request(r),
        )
        .await;
        let err = match sent {
            Ok(Ok(res)) => {
                let retryable = matches!(res.status().as_u16(), 502..=504);
                if retryable && !last {
                    EndpointError::Failed(format!("status {}", res.status()))
                } else {
                    let res = from_upstream_response(res, &st.snap.limits);
                    return Ok((roxy_http::layer::to_layer_response(res), attempt));
                }
            }
            Ok(Err(e)) => match classify(&e) {
                Some(ce @ ConnectError::Denied(_)) => return Err((connect_error(&ce), attempt)),
                Some(ce) => connect_error(&ce),
                None => EndpointError::Failed(crate::upstream::describe(&e)),
            },
            Err(_) => EndpointError::Timeout,
        };
        if last {
            return Err((err, attempt));
        }
        let backoff = Duration::from_millis(100) * 2u32.saturating_pow(attempt - 1);
        tokio::time::sleep(backoff.min(Duration::from_secs(2))).await;
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

/// POSTs `json` to endpoint `name` of `addon` (audit and terminate
/// notifications). Failures are logged.
pub(crate) async fn notify(st: &StackFlow, addon: &AddonSpec, name: &str, json: serde_json::Value) {
    let mut req = http::Request::new(Body::from_bytes(json.to_string()));
    *req.method_mut() = http::Method::POST;
    *req.uri_mut() = Uri::from_static("/");
    req.headers_mut().insert(
        HeaderName::from_static("content-type"),
        HeaderValue::from_static("application/json"),
    );
    match call(st, addon, name, req).await {
        Ok(res) if res.status().is_success() => {}
        Ok(res) => {
            tracing::warn!(layer = addon.name, endpoint = name, status = %res.status(), "notification refused");
        }
        Err(e) => {
            tracing::warn!(layer = addon.name, endpoint = name, error = %e, "notification failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::flowlog::Redactor;
    use crate::secrets::SecretStore;

    fn spec(url: &str, path: EndpointPath) -> EndpointSpec {
        EndpointSpec {
            url: url.parse().unwrap(),
            path,
            headers: Vec::new(),
            timeout: Duration::from_secs(1),
            retries: 0,
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
