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

use crate::pipeline::{FlowCx, Refusal, known_empty, response_known_empty};
use crate::server::Shared;

/// Flow-log `reason` of a response that must be read as plain bytes but
/// is in a coding roxy does not decode.
const UNDECODABLE: &str = "unsupported_content_encoding";

/// Flow-log `reason` of a range (`206`) of a response that masking must
/// read whole.
const PARTIAL: &str = "partial_response";

/// Where the core hands its response: to the client, or to the addon
/// stack, which encodes it again at its client edge.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) enum Leg {
    #[default]
    Direct,
    Stack {
        /// A layer that ran reads the response body, with
        /// `http.decode_for_addons` on.
        decode: bool,
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
    /// The masking of secrets, which must not pass a body it cannot read
    /// whole.
    Masking,
}

/// The codings `res`'s body is to be decoded from for `need`: none when
/// nothing needs it plain or it cannot be decoded for the layers, and a
/// refusal when masking cannot read it whole.
pub(crate) fn response_codings(
    cx: &FlowCx,
    res: &CanonicalResponse,
    need: Need,
) -> Result<Vec<Coding>, Refusal> {
    if need == Need::None || response_known_empty(cx, res) {
        return Ok(Vec::new());
    }
    let partial =
        res.status == StatusCode::PARTIAL_CONTENT || res.headers.contains("content-range");
    // Masking finds whole occurrences only, and a range's bounds are the
    // client's to choose: ranges that each cut a secret would carry it out
    // in pieces. The request went without `range` for this, so a range
    // that still comes back is refused.
    if need == Need::Masking && partial {
        return Err(Refusal::fail_closed(PARTIAL));
    }
    match coding::content_codings(&res.headers) {
        // A range of an encoded body cannot be decoded on its own.
        Ok(codings) if !partial => Ok(codings),
        // Masking cannot pass a body it cannot read; a layer judges it.
        Err(_) if need == Need::Masking => Err(Refusal::fail_closed(UNDECODABLE)),
        Ok(_) | Err(_) => Ok(Vec::new()),
    }
}

/// Decodes `res`'s body from `codings`, dropping `content-encoding`, and
/// notes them in `decoded_from` for [`encode_response`].
pub(crate) fn decode_response(cx: &FlowCx, res: &mut CanonicalResponse, codings: Vec<Coding>) {
    if codings.is_empty() {
        return;
    }
    res.headers.remove("content-encoding");
    res.body = coding::decode_body(
        std::mem::take(&mut res.body),
        &codings,
        cx.snap.limits.max_response_body_bytes,
        cx.shared.window_meter(),
    );
    res.meta.decoded_from = codings;
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

/// Encodes `res`'s body again in the codings it was decoded from, unless
/// a layer gave it a coding of its own or left it no body.
pub(crate) fn encode_response(shared: &Arc<Shared>, res: &mut CanonicalResponse) {
    let codings = std::mem::take(&mut res.meta.decoded_from);
    if codings.is_empty()
        || res.headers.contains("content-encoding")
        || res.status_forbids_body()
        || known_empty(&res.body)
    {
        return;
    }
    res.headers
        .insert("content-encoding", &header(&codings))
        .expect("coding tokens are a valid header value");
    res.body = coding::encode_body(
        std::mem::take(&mut res.body),
        &codings,
        shared.window_meter(),
    );
}

/// Encodes a request's body in `codings` again, unless a layer gave it a
/// coding of its own or left it no body.
pub(crate) fn encode_request(
    shared: &Arc<Shared>,
    headers: &mut HeaderMap,
    body: &mut Body,
    codings: &[Coding],
) {
    if codings.is_empty()
        || headers.contains_key(http::header::CONTENT_ENCODING)
        || known_empty(body)
    {
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
        res.meta.decoded_from = vec![Coding::Gzip];
        encode_response(shared, &mut res);
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

    /// A layer that left the message no body gets no coding put back.
    #[tokio::test]
    async fn a_message_without_a_body_is_not_encoded() {
        let kit = Kit::builder().start().await;
        let shared = kit.server.shared();
        for status in [StatusCode::NO_CONTENT, StatusCode::OK] {
            let mut res = CanonicalResponse::new(status);
            res.meta.decoded_from = vec![Coding::Gzip];
            encode_response(shared, &mut res);
            assert!(!res.headers.contains("content-encoding"), "{status}");
        }
        let mut headers = HeaderMap::new();
        let mut body = Body::empty();
        encode_request(shared, &mut headers, &mut body, &[Coding::Gzip]);
        assert!(headers.is_empty());
    }

    /// Stacked codings come back in the order they were applied.
    #[tokio::test]
    async fn stacked_codings_are_named_in_order() {
        let kit = Kit::builder().start().await;
        let shared = kit.server.shared();
        let mut res = CanonicalResponse::new(StatusCode::OK);
        res.body = Body::from_bytes(Bytes::from_static(b"plain"));
        let codings = [Coding::Gzip, Coding::Br];
        res.meta.decoded_from = codings.to_vec();
        encode_response(shared, &mut res);
        assert_eq!(res.headers.get("content-encoding"), Some("gzip, br"));
        let body = std::mem::take(&mut res.body).collect().await.unwrap();
        let plain = coding::decode(&codings, &body.to_bytes(), 1 << 20, coding::unmetered());
        assert_eq!(plain.unwrap(), b"plain");
    }
}
