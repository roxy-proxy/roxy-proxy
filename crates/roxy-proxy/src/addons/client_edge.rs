//! The client edge: the stage at the client's end of the chain. It puts
//! the client's request on the first request lane, waits for the head on
//! the first response lane, and returns an [`Outcome`] to the HTTP/1.1
//! connection handler or HTTP/2 stream handler, which writes the response.

use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use http::StatusCode;
use http_body::{Body as HttpBody, Frame, SizeHint};
use roxy_http::layer::to_layer_request;
use roxy_http::upstream::from_upstream_response;
use roxy_http::{Body, BodyError, BodySender, CanonicalRequest, CanonicalResponse};
use roxy_wasm::LayerError;

use super::attribution::{Driven, Fault, Side, attributed};
use super::chain::{Chain, Head, Headless, Recorder};
use super::{BoxFuture, CLIENT_GONE, ENDED, Reclaim, StackError, StackFlow, core_edge, layer, ws};
use crate::exchange::{ClientTransport, Outcome, bad_upgrade_refusal, refusal_response};
use crate::flowlog::FlowSink;
use crate::pipeline::{Decider, FlowCx, Refusal, RefusalKind};

/// What the client edge found on the first response lane.
pub(super) type Arrival = Result<(Head, Body), Headless>;

/// The chain's view of the flow's record.
struct Record(Weak<StackFlow>);

impl Recorder for Record {
    fn fault(&self, layer: usize, err: StackError) {
        if let Some(st) = self.0.upgrade() {
            st.fail(&st.snap.addons[layer].name, err);
        }
    }

    fn failure_response(&self, _layer: usize) -> BoxFuture<Option<(http::response::Parts, Body)>> {
        let st = self.0.upgrade();
        Box::pin(async move {
            let res = failure_response(&st?).await?;
            let (parts, body) = roxy_http::layer::to_layer_response(res).into_parts();
            Some((parts, body))
        })
    }

    fn aborted(&self) {
        if let Some(st) = self.0.upgrade() {
            st.attribution.aborted();
        }
    }

    fn client_gone(&self) {
        if let Some(st) = self.0.upgrade() {
            st.attribution.client_gone();
        }
    }
}

/// A chain for `st`, its ends in hand, for tests that drive the stack's
/// parts directly.
#[cfg(test)]
pub(super) fn test_chain(
    st: &Arc<StackFlow>,
) -> (
    Arc<Chain>,
    super::chain::EdgeIo,
    Vec<super::chain::LayerIo>,
    super::chain::CoreIo,
) {
    Chain::new(st.snap.addons.len(), Record(Arc::downgrade(st)))
}

/// Runs the exchange through the addon stack. The flow context is parked
/// in the stack while the layers run, lent to the core if a request
/// reaches it, and comes back to the transport through the [`Reclaim`].
pub(crate) async fn run<F: ClientTransport>(
    transport: &mut F,
    cx: FlowCx,
    mut req: CanonicalRequest,
) -> (Reclaim, Outcome) {
    let st = Arc::new(StackFlow::new(&cx, &req));
    let (chain, edge, layers, core) = Chain::new(st.snap.addons.len(), Record(Arc::downgrade(&st)));
    assert!(st.chain.set(chain).is_ok(), "the chain is built once");
    // A WebSocket is a long-lived exchange: once upgraded, the client's
    // bytes are the request body and the upstream's the response body.
    let client_tx = if st.is_upgrade() {
        // The swap below would hide a body from `validate_upgrade_request`.
        if req.body.known_length() != Some(0) {
            let refusal = bad_upgrade_refusal(roxy_http::Reason::WsBadHandshake);
            return (Reclaim::now(cx), Outcome::Refuse(refusal));
        }
        let (tx, body) = Body::channel(u64::MAX, None);
        req.body = body;
        Some(tx)
    } else {
        None
    };
    req.body = attributed(&st, Side::Client, std::mem::take(&mut req.body));
    st.loan.park(cx);
    // Held from here: a transport that gives the exchange up mid-run (its task
    // aborted with the connection) tears the stack down with it.
    let reclaim = Reclaim::stack(st.clone());
    st.chain().spawn(core_edge::run(st.clone(), core));
    for (index, io) in layers.into_iter().enumerate() {
        st.chain().spawn(layer::run(st.clone(), index, io));
    }
    let (parts, body) = to_layer_request(req).into_parts();
    edge.req_out.whole(Head::Request(parts), body);
    let mut res_in = edge.res_in;
    // On task cancellation, publish the cause before dropping the lane.
    let guard = reclaim.cancellation_guard();
    let driven = transport
        .drive(Driven::new(st.clone(), async { res_in.head().await }))
        .await;
    let outcome = stack_outcome(&st, driven, client_tx);
    match &outcome {
        Outcome::Respond(_) | Outcome::LayeredUpgrade { .. } => {}
        Outcome::Upgrade { .. } => unreachable!("the client edge does not own upstream sockets"),
        Outcome::Close(roxy_http::DriveError::Client(_)) => st.tear_down(CLIENT_GONE),
        Outcome::Close(_) | Outcome::Refuse(_) => st.tear_down(ENDED),
    }
    if let Some(guard) = guard {
        guard.complete();
    }
    (reclaim, outcome)
}

/// What the stack's answer means for the client. `client_tx` feeds the
/// client's bytes into the stack after a `101`.
pub(super) fn stack_outcome(
    st: &Arc<StackFlow>,
    driven: Result<Arrival, roxy_http::DriveError>,
    client_tx: Option<BodySender>,
) -> Outcome {
    let (head, body) = match driven {
        Err(e) => return Outcome::Close(e),
        Ok(Err(_)) => return refuse(st),
        Ok(Ok(arrived)) => arrived,
    };
    let Head::Response(parts) = head else {
        unreachable!("a response lane carries responses")
    };
    let mut resp = http::Response::from_parts(parts, body);
    // A layer's answer is a final response a client can be given; the
    // one `1xx` with a meaning here is the `101` of a relayed upgrade,
    // judged below.
    let status = resp.status().as_u16();
    if status != 101 && !(200..=599).contains(&status) {
        let err = LayerError::InvalidResponse(format!("{status} is not a final response"));
        st.fail(st.response_producer(), err);
        return refuse(st);
    }
    // Attribution was captured when the layer published its response head.
    // A later upstream outcome does not change it. A generated failure
    // response retains the fault recorded for the layer.
    let answered = st.answered_by().filter(|&i| st.failed_layer() != Some(i));
    let _ = st.client_answer.set(answered);
    // A `101`'s body is the upgraded stream for the client, not an HTTP
    // body: keep it out of the response model.
    let upgraded_body =
        (resp.status() == StatusCode::SWITCHING_PROTOCOLS).then(|| std::mem::take(resp.body_mut()));
    let mut res = from_upstream_response(resp, &st.snap.limits);
    if answered.is_none() {
        // The core's response, decoded there: encoded again for the client.
        let codings = std::mem::take(&mut *super::lock(&st.response_codings));
        crate::recode::encode_response(&st.shared, &mut res, &codings);
    }
    res.body = gated(std::mem::take(&mut res.body), st.shared.sink.clone());
    if st.close.load(Ordering::Relaxed) {
        res.meta.close = true;
    }
    let upgrade = st.take_upgrade();
    if res.status == StatusCode::SWITCHING_PROTOCOLS {
        if let (Some(upgrade), Some(client_tx)) = (upgrade, client_tx) {
            // A layer cannot express `upgrade: websocket` (hop-by-hop); the
            // core relayed a real upgrade, so restore it.
            res.meta.upgrade = Some("websocket".to_owned());
            let checked =
                roxy_http::ws::validate_upgrade_response(&res, &upgrade.key).and_then(|()| {
                    if ws::ws_without_extensions(&st.snap, st.reads_bytes()) {
                        roxy_http::ws::validate_no_extensions(&res)
                    } else {
                        Ok(())
                    }
                });
            if let Err(e) = checked {
                st.fail(
                    st.response_producer(),
                    LayerError::InvalidResponse(e.to_string()),
                );
                return refuse(st);
            }
            let to_client = upgraded_body.unwrap_or_default();
            let client = ws::WsClient::new(
                client_tx,
                to_client,
                st.shared.sink.clone(),
                upgrade.start,
                st.chain().clone(),
            );
            // A failure from here on cuts the body (the codec then breaks
            // the connection) and is logged as it is recorded.
            st.attribution.head_out();
            return Outcome::LayeredUpgrade { res, client };
        }
        let err = LayerError::InvalidResponse("101 without an upgrade to relay".into());
        st.fail(st.response_producer(), err);
        return refuse(st);
    }
    if upgrade.is_some() {
        // The upstream switched protocols but the stack answered otherwise:
        // no body can carry the relay, so close it and fail closed.
        let err = LayerError::InvalidResponse(format!("{} over a relayed upgrade", res.status));
        st.fail(st.response_producer(), err);
        return refuse(st);
    }
    st.attribution.head_out();
    Outcome::Respond(res)
}

/// The exchange's refusal before the response head, from the fault
/// recorded: a layer's failure is logged and refused as its own; a request
/// body that failed on its way in closes the connection as it would
/// without a stack; the others are the refusals the core would give.
fn refuse(st: &Arc<StackFlow>) -> Outcome {
    let refusal = refusal_for_fault(st);
    st.tear_down(ENDED);
    match refusal {
        Ok(refusal) => Outcome::Refuse(refusal),
        Err(e) => Outcome::Close(e.into()),
    }
}

/// The HTTP error response for the recorded fault, or the client's parse error
/// when the fault is the client's.
pub(super) fn refusal_for_fault(st: &Arc<StackFlow>) -> Result<Refusal, roxy_http::ParseError> {
    let fault = st.attribution.fault().unwrap_or_else(|| {
        // Every path that fails a layer records it, so this is a layer
        // that returned an error without saying why.
        let name = st.blamed();
        st.fail(&name, LayerError::NoResponse);
        Fault::Layer {
            name,
            err: LayerError::NoResponse.into(),
        }
    });
    match &fault {
        Fault::Layer { name, .. } => {
            st.attribution.log();
            Ok(layer_refusal(name))
        }
        Fault::Client(e) => Err(e.clone()),
        Fault::UpstreamBody => Ok(Refusal::upstream(StatusCode::BAD_GATEWAY, fault.reason())),
        Fault::Budget => Ok(Refusal::fail_closed(fault.reason())),
    }
}

/// 503 `layer:<name>`, `layer_error`; closes.
fn layer_refusal(layer: &str) -> Refusal {
    Refusal {
        kind: RefusalKind::Deny,
        status: StatusCode::SERVICE_UNAVAILABLE,
        message: "request blocked: an addon failed".to_owned(),
        rule: Some(Decider::Layer(layer.to_owned())),
        close: true,
        reason: Some("layer_error".to_owned()),
    }
}

/// Generate the HTTP error response on a failed layer's response lane,
/// recorded on the flow as the refusal the transport would have written.
/// `None` when the fault is the client's (the exchange is closing, and no
/// layer answers it), or the record has already left the stack.
async fn failure_response(st: &Arc<StackFlow>) -> Option<CanonicalResponse> {
    let refusal = refusal_for_fault(st).ok()?;
    if refusal.close {
        st.close.store(true, Ordering::Relaxed);
    }
    // Wait for the cancelled core stage to return the context before
    // recording the refusal.
    let mut cx = st.loan.returned().await?;
    if cx.in_flight.is_some() {
        cx.record_refusal_sample(&refusal);
    }
    let res = refusal_response(&mut cx, &refusal);
    st.loan.give_back(cx);
    Some(res)
}

/// A layer's response body to the client, sent only while the flow log
/// keeps up (audit backpressure).
pub(super) fn gated(body: Body, sink: Arc<dyn FlowSink>) -> Body {
    let known = body.known_length();
    Body::wrap_native(Gated { inner: body, sink }, u64::MAX, known)
}

struct Gated {
    inner: Body,
    sink: Arc<dyn FlowSink>,
}

impl HttpBody for Gated {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        ready!(self.sink.poll_ready(cx));
        Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
