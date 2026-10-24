//! Requests as the layers see them: decoded by their `content-encoding`,
//! with the header dropped, so a layer reads what the client meant rather
//! than its compression. The request is encoded again as it reaches the
//! core ([`crate::recode`]). A coding roxy cannot decode is left as it is,
//! header and all, for a layer to judge. The decoder's windows are charged
//! to the buffer budget for as long as the body lives, and a body the
//! budget cannot cover fails as the budget's, not the reader's.
//!
//! The response is decoded for the layers in the core, with the masking of
//! secrets, and encoded again at the client edge.

use std::sync::Arc;

use roxy_http::Headers;
use roxy_wasm::LayerRequest;

use super::attribution::{Side, attributed};
use super::{StackFlow, lock};

/// Decodes a request on its way into a layer.
pub(super) fn request(st: &Arc<StackFlow>, req: &mut LayerRequest, limit: u64) {
    let mut headers = Headers::from_header_map_lenient(req.headers());
    let mut body = std::mem::take(req.body_mut());
    let codings = crate::recode::request(&st.shared, &mut headers, &mut body, limit);
    if codings.is_empty() {
        *req.body_mut() = body;
        return;
    }
    req.headers_mut().remove(http::header::CONTENT_ENCODING);
    *req.body_mut() = attributed(st, Side::Client, body);
    *lock(&st.request_codings) = codings;
}
