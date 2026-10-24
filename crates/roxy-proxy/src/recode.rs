//! The one place a body's content coding is undone and redone. A body
//! that something must read as plain bytes (the addon layers, under
//! `http.decode_for_addons`, or the masking of secrets) is decoded once,
//! where it enters, and encoded again in the same codings where it leaves,
//! so the client and the origin get the coding they negotiated.
//!
//! A response is decoded in the core, after the response rules, and
//! encoded again at the client's end: as the core hands it on without a
//! stack, or at the stack's client edge. A request is decoded as it enters
//! the first layer that reads it and encoded again as it reaches the core.
//! A head that comes out carrying its own `content-encoding` was encoded by
//! a layer and is left as it is.

use std::sync::Arc;

use http::{HeaderMap, HeaderValue, StatusCode};
use roxy_http::coding::{self, Coding};
use roxy_http::{Body, CanonicalResponse, Headers};

use crate::pipeline::{FlowCx, Refusal, response_known_empty};
use crate::server::Shared;

/// Flow-log `reason` of a response that must be read as plain bytes but
/// cannot be decoded: a coding roxy does not decode, or a range of an
/// encoded body.
const UNDECODABLE: &str = "unsupported_content_encoding";

/// Where the core hands its response: to the client, or to the addon
/// stack, which encodes it again at its client edge.
#[derive(Debug, Default)]
pub(crate) enum Leg {
    #[default]
    Direct,
    Stack {
        /// A layer that ran reads the response body, with
        /// `http.decode_for_addons` on.
        decode: bool,
        /// What the core decoded the response from, for the client edge.
        codings: Vec<Coding>,
    },
}

/// Who needs the response's body as plain bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Need {
    /// Nothing: it passes as it came.
    None,
    /// The addon layers. A body they cannot have decoded is passed to them
    /// as it is, for a layer to judge.
    Layers,
    /// The masking of secrets, which must not pass a body it cannot read.
    Masking,
}

/// Decodes `res`'s body if `need` asks for it, dropping `content-encoding`,
/// and returns the codings to encode it in again on its way out (none when
/// it was not decoded).
pub(crate) fn response(
    cx: &FlowCx,
    res: &mut CanonicalResponse,
    need: Need,
) -> Result<Vec<Coding>, Refusal> {
    if need == Need::None || response_known_empty(cx, res) {
        return Ok(Vec::new());
    }
    let refuse = || match need {
        Need::Masking => Err(Refusal::fail_closed(UNDECODABLE)),
        Need::Layers | Need::None => Ok(Vec::new()),
    };
    let Ok(codings) = coding::content_codings(&res.headers) else {
        return refuse();
    };
    if codings.is_empty() {
        return Ok(codings);
    }
    // A range of an encoded body cannot be decoded on its own.
    if res.status == StatusCode::PARTIAL_CONTENT || res.headers.contains("content-range") {
        return refuse();
    }
    res.headers.remove("content-encoding");
    res.body = coding::decode_body(
        std::mem::take(&mut res.body),
        &codings,
        cx.snap.limits.max_response_body_bytes,
        cx.shared.window_meter(),
    );
    Ok(codings)
}

/// Decodes `body` for a layer, dropping `content-encoding` from `headers`;
/// the codings to encode it in again. A coding roxy cannot decode is left,
/// header and all, and gives none.
pub(crate) fn request(
    shared: &Arc<Shared>,
    headers: &mut Headers,
    body: &mut Body,
    limit: u64,
) -> Vec<Coding> {
    let Ok(codings) = coding::content_codings(headers) else {
        return Vec::new();
    };
    if codings.is_empty() {
        return codings;
    }
    headers.remove("content-encoding");
    *body = coding::decode_body(std::mem::take(body), &codings, limit, shared.window_meter());
    codings
}

/// Encodes `res`'s body in `codings` again, unless a layer gave it a
/// coding of its own.
pub(crate) fn encode_response(
    shared: &Arc<Shared>,
    res: &mut CanonicalResponse,
    codings: &[Coding],
) {
    if codings.is_empty() || res.headers.contains("content-encoding") {
        return;
    }
    res.headers
        .insert("content-encoding", &header(codings))
        .expect("coding tokens are a valid header value");
    res.body = coding::encode_body(
        std::mem::take(&mut res.body),
        codings,
        shared.window_meter(),
    );
}

/// Encodes a request's body in `codings` again, unless a layer gave it a
/// coding of its own.
pub(crate) fn encode_request(
    shared: &Arc<Shared>,
    headers: &mut HeaderMap,
    body: &mut Body,
    codings: &[Coding],
) {
    if codings.is_empty() || headers.contains_key(http::header::CONTENT_ENCODING) {
        return;
    }
    headers.insert(
        http::header::CONTENT_ENCODING,
        HeaderValue::from_str(&header(codings)).expect("coding tokens are a valid header value"),
    );
    *body = coding::encode_body(std::mem::take(body), codings, shared.window_meter());
}

/// The `content-encoding` value naming `codings`, in the order applied.
fn header(codings: &[Coding]) -> String {
    codings
        .iter()
        .map(|c| c.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http_body_util::BodyExt;

    use super::*;
    use crate::testkit::Kit;

    /// A head that comes out with a coding of its own was encoded by a
    /// layer: it is not encoded a second time.
    #[tokio::test]
    async fn a_layers_own_coding_is_left_alone() {
        let kit = Kit::builder().start().await;
        let shared = kit.server.shared();
        let mut res = CanonicalResponse::new(StatusCode::OK);
        res.headers.append("content-encoding", "br").unwrap();
        res.body = Body::from_bytes(Bytes::from_static(b"as the layer made it"));
        encode_response(shared, &mut res, &[Coding::Gzip]);
        assert_eq!(res.headers.get("content-encoding"), Some("br"));
        let body = std::mem::take(&mut res.body).collect().await.unwrap();
        assert_eq!(body.to_bytes(), "as the layer made it");

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_ENCODING,
            HeaderValue::from_static("br"),
        );
        let mut body = Body::from_bytes(Bytes::from_static(b"x"));
        encode_request(shared, &mut headers, &mut body, &[Coding::Gzip]);
        assert_eq!(headers[http::header::CONTENT_ENCODING], "br");
    }

    /// Stacked codings come back in the order they were applied.
    #[tokio::test]
    async fn stacked_codings_are_named_in_order() {
        let kit = Kit::builder().start().await;
        let shared = kit.server.shared();
        let mut res = CanonicalResponse::new(StatusCode::OK);
        res.body = Body::from_bytes(Bytes::from_static(b"plain"));
        let codings = [Coding::Gzip, Coding::Br];
        encode_response(shared, &mut res, &codings);
        assert_eq!(res.headers.get("content-encoding"), Some("gzip, br"));
        let body = std::mem::take(&mut res.body).collect().await.unwrap();
        let plain = coding::decode(&codings, &body.to_bytes(), 1 << 20, coding::unmetered());
        assert_eq!(plain.unwrap(), b"plain");
    }
}
