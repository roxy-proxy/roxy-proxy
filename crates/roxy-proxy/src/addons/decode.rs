//! Bodies as the layers see them: decoded by their `content-encoding`,
//! with the header dropped, so a layer reads what the client or the origin
//! meant rather than its compression. A coding roxy cannot decode is left
//! as it is, header and all, for a layer to judge. The decoder's windows
//! are charged to the buffer budget for as long as the body lives.

use std::sync::Arc;

use roxy_http::{Body, CanonicalResponse, Headers, coding};
use roxy_wasm::LayerRequest;

use crate::server::Shared;

/// Decodes a request on its way into a layer.
pub(super) fn request(req: &mut LayerRequest, limit: u64, shared: &Arc<Shared>) {
    let mut headers = Headers::from_header_map_lenient(req.headers());
    let mut body = std::mem::take(req.body_mut());
    decode(&mut headers, &mut body, limit, shared);
    if !headers.contains("content-encoding") {
        req.headers_mut().remove(http::header::CONTENT_ENCODING);
    }
    *req.body_mut() = body;
}

/// Decodes the core's response on its way up to the layers. A range of an
/// encoded body is not decodable on its own, so a `206` (or a response
/// with `content-range`) is left as the origin sent it.
pub(super) fn response(res: &mut CanonicalResponse, limit: u64, shared: &Arc<Shared>) {
    if res.status == http::StatusCode::PARTIAL_CONTENT || res.headers.contains("content-range") {
        return;
    }
    decode(&mut res.headers, &mut res.body, limit, shared);
}

fn decode(headers: &mut Headers, body: &mut Body, limit: u64, shared: &Arc<Shared>) {
    let Ok(codings) = coding::content_codings(headers) else {
        return;
    };
    if codings.is_empty() {
        return;
    }
    headers.remove("content-encoding");
    *body = coding::decode_body(
        std::mem::take(body),
        &codings,
        limit,
        shared.window_meter(),
    );
}
