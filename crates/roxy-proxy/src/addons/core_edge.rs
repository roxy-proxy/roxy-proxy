//! The core stage is the upstream end of the chain. It validates the
//! forwarded request, evaluates admission and in-flight rules, applies the
//! address floor through the connector, and owns upstream processing until
//! completion. That includes upload accounting and the WebSocket relay.
//! Its response lane carries an upstream response or a local refusal.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use roxy_http::layer::to_layer_response;
use roxy_http::{Body, CanonicalRequest};
use roxy_wasm::{LayerError, LayerRequest};

use super::attribution::{Side, attributed};
use super::chain::{CoreIo, Head, Headless, LaneState, LaneTx};
use super::client_edge::refusal_for_fault;
use super::{StackFlow, decode, ws};
use crate::body::{Collected, collect_prefix};
use crate::exchange::{ClientTransport, Outcome, refusal_response};
use crate::pipeline::{BodyIo, CollectFuture, Refusal};

/// Runs the core stage on its lanes.
pub(super) async fn run(st: Arc<StackFlow>, io: CoreIo) {
    let CoreIo {
        mut req_in,
        res_out,
        stage,
    } = io;
    let torn_down = stage.torn_down();
    let forward = req_in.id();
    let arrived = tokio::select! {
        biased;
        () = torn_down.cancelled() => return,
        arrived = req_in.head() => arrived,
    };
    let req = match arrived {
        Ok((Head::Request(parts), body)) => http::Request::from_parts(parts, body),
        Ok((Head::Response(_), _)) => unreachable!("a request lane carries requests"),
        // Nothing was forwarded: nothing answers.
        Err(Headless::Ended) => return res_out.end_headless(),
        Err(Headless::Cut(why)) => return res_out.cut_headless(why),
    };
    let Some((creq, stream)) = admit(&st, req) else {
        return;
    };
    let Some(mut lease) = st.lease() else {
        // The context is lent once per exchange, and the chain carries one
        // request lane into the core.
        return res_out.cut_headless("the flow already reached the core");
    };
    let cx = lease.cx();
    cx.layer_reads_bytes = st.reads_bytes();
    cx.facts.request = Some(crate::pipeline::request_facts(&creq));
    st.set_facts(&cx.facts);
    let mut transport = LaneTransport;
    let outcome = tokio::select! {
        biased;
        () = torn_down.cancelled() => None,
        o = crate::exchange::core(&mut transport, cx, creq) => Some(o),
    };
    let Some(outcome) = outcome else {
        if lease.cx().record.decision.is_some() {
            st.chain().upstream_abandoned();
        }
        return;
    };
    let cx = lease.cx();
    st.set_facts(&cx.facts);
    let snap = st.snap.clone();
    match outcome {
        Outcome::Respond(mut res) => {
            res.body = attributed(&st, Side::Upstream, std::mem::take(&mut res.body));
            // A response body no layer reads passes through unchanged.
            if snap.http.decode_for_addons && st.body_subscribed(crate::in_flight::Dir::Response) {
                decode::response(&st, &mut res, snap.limits.max_response_body_bytes);
            }
            answer(res_out, res);
            if let Some(delivery) = lease.cx().request_delivery.take() {
                tokio::select! {
                    biased;
                    () = torn_down.cancelled() => st.chain().upstream_abandoned(),
                    complete = delivery.wait() => {
                        if !complete {
                            lease.cx().completion.upload_timed_out = true;
                        }
                    }
                }
            }
        }
        Outcome::Refuse(refusal) => {
            let res = refusal_response(cx, &refusal);
            drop(lease);
            refuse(&st, res_out, &refusal, res);
        }
        // A recorded body fault determines the refusal. A layer's
        // deliberate lane cut has no fault and cuts the response too.
        Outcome::Close(_) => {
            drop(lease);
            if let LaneState::Cut(why) = st.chain().state(forward)
                && st.attribution.fault().is_none()
            {
                res_out.cut_headless(why);
            } else {
                refused(&st, res_out).await;
            }
        }
        Outcome::Upgrade { res, upstream, key } => {
            relay_upgrade(
                &st,
                &stage,
                lease,
                res_out,
                stream.unwrap_or_default(),
                (res, upstream, key),
            )
            .await;
        }
        Outcome::LayeredUpgrade { .. } => {
            unreachable!("the core returns an upstream upgrade, never client plumbing")
        }
    }
}

/// The core retains the context and both relay endpoints until the
/// WebSocket closes. The client edge only confirms its handshake.
async fn relay_upgrade(
    st: &StackFlow,
    stage: &super::chain::StageHandle,
    mut lease: super::reclaim::Lease,
    res_out: LaneTx,
    stream: Body,
    (mut res, upstream, key): (
        roxy_http::CanonicalResponse,
        hyper::upgrade::Upgraded,
        roxy_http::ws::WsKey,
    ),
) {
    let torn_down = stage.torn_down();
    if let Err(refusal) = crate::exchange::prepare_websocket(lease.cx(), &res, &key) {
        crate::exchange::close_upstream_ws(upstream).await;
        let res = refusal_response(lease.cx(), &refusal);
        drop(stream);
        drop(lease);
        refuse(st, res_out, &refusal, res);
        return;
    }
    let relay_io = ws::relay_io(st, stream, &mut res);
    let (start, started) = tokio::sync::oneshot::channel();
    if st.offer_upgrade(ws::Upgrade { key, start }).is_err() {
        stage.cancel(super::ENDED);
        crate::exchange::close_upstream_ws(upstream).await;
        return;
    }
    answer(res_out, res);
    let client = tokio::select! {
        biased;
        () = torn_down.cancelled() => None,
        client = started => client.ok(),
    };
    let Some(client) = client else {
        stage.cancel(super::ENDED);
        crate::exchange::close_upstream_ws(upstream).await;
        return;
    };
    crate::exchange::relay_websocket(lease.cx(), relay_io, upstream, Vec::new(), &torn_down).await;
    // Let a close frame traverse the response lanes before cancelling
    // layers that keep their bodies open after the relay ends.
    if let Some(error) = client.close(crate::exchange::CLOSE_TIMEOUT).await {
        lease.cx().completion.drained(&error);
    }
    st.tear_down(super::ENDED);
}

/// The request the last layer passed on, re-validated as a client's would
/// be, and the stream after its head on an upgrade. `None` when it does
/// not validate: the fault of the nearest enforcing layer that ran.
pub(super) fn admit(
    st: &Arc<StackFlow>,
    req: LayerRequest,
) -> Option<(CanonicalRequest, Option<Body>)> {
    let (req, stream) = ws::split_upgrade_stream(st, req);
    match st.validate_request(st.snap.addons.len(), req) {
        Ok(creq) => Some((creq, stream)),
        Err(e) => {
            let last = st.snap.addons.len() - 1;
            let layer = st.passed_on_by(last + 1).unwrap_or(last);
            st.layer_failed(layer, LayerError::InvalidRequest(e.to_string()));
            None
        }
    }
}

fn answer(res_out: LaneTx, res: roxy_http::CanonicalResponse) {
    let (parts, body) = to_layer_response(res).into_parts();
    res_out.whole(Head::Response(parts), body);
}

fn refuse(st: &StackFlow, res_out: LaneTx, refusal: &Refusal, res: roxy_http::CanonicalResponse) {
    if refusal.close {
        st.close.store(true, Ordering::Relaxed);
    }
    answer(res_out, res);
}

/// Return an HTTP error response for the recorded failure. A broken client
/// request closes the exchange without an answer.
async fn refused(st: &Arc<StackFlow>, res_out: LaneTx) {
    let refusal = match refusal_for_fault(st) {
        Ok(refusal) => refusal,
        Err(e) => return res_out.cut_headless(e.to_string()),
    };
    let Some(mut cx) = st.loan.returned().await else {
        return res_out.cut_headless("the record has left the stack");
    };
    if cx.in_flight.is_some() {
        cx.record_refusal_sample(&refusal);
    }
    let res = refusal_response(&mut cx, &refusal);
    st.loan.give_back(cx);
    refuse(st, res_out, &refusal, res);
}

/// The client-side view the core needs when the "client" is the last
/// layer: its body is a stream from the lane, with no codec to service.
struct LaneTransport;

impl BodyIo for LaneTransport {
    fn collect<'a>(
        &'a mut self,
        body: &'a mut Body,
        cap: u64,
        meter: &'a mut (dyn FnMut(u64) -> bool + Send),
        idle: Option<Duration>,
    ) -> CollectFuture<'a, Result<Collected, roxy_http::DriveError>> {
        Box::pin(async move { Ok(collect_prefix(body, cap, meter, idle).await) })
    }
}

impl ClientTransport for LaneTransport {
    #[allow(clippy::manual_async_fn)] // the trait spells out the `Send` bound
    fn drive<Fut>(
        &mut self,
        fut: Fut,
    ) -> impl Future<Output = Result<Fut::Output, roxy_http::DriveError>> + Send
    where
        Fut: Future + Send,
        Fut::Output: Send,
    {
        async move { Ok(fut.await) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxy_http::layer::from_layer_request;

    #[tokio::test]
    async fn cancelling_upload_after_response_head_records_abandonment() {
        for (client_gone, earlier_reason, expected) in [
            (false, None, "upstream_aborted"),
            (true, None, "client_gone"),
            (true, Some("policy_failure"), "policy_failure"),
        ] {
            let kit = crate::testkit::Kit::builder()
                .addon(crate::testkit::AddonDef::test_layer("a"))
                .start()
                .await;
            let (st, mut cx, mut ends) = crate::addons::test_flow(&kit);
            cx.record.reason = earlier_reason.map(str::to_owned);
            let mut layer = ends.layers.pop().unwrap();
            layer.stage.enforcing();
            st.loan.park(cx);
            let core = st.chain().spawn(run(st.clone(), ends.core));
            let (_upload, body) = Body::channel(u64::MAX, None);
            let (parts, body) = http::Request::post("http://up.test/early-drip?n=100&ms=50")
                .body(body)
                .unwrap()
                .into_parts();
            layer.req_out.whole(Head::Request(parts), body);
            let (_, response_body) = layer.res_in.head().await.unwrap();
            drop(response_body);
            core.await.unwrap();
            // Abandonment happened first while the layer was still alive.
            // A subsequent transport cancellation is stronger evidence.
            if client_gone {
                st.tear_down(crate::addons::CLIENT_GONE);
            }
            let mut cx = st.loan.returned().await.unwrap();
            st.fold_into(&mut cx);
            assert_eq!(cx.record.reason.as_deref(), Some(expected));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_upload_deadline_runs_before_response_writing_or_reclamation() {
        let kit = crate::testkit::Kit::builder()
            .limits(|l| l.body_idle_timeout = Duration::from_millis(100))
            .start()
            .await;
        let (st, mut cx, _ends) = crate::addons::test_flow(&kit);
        let (mut upload, body) = Body::channel(u64::MAX, None);
        let req = http::Request::post("https://up.test/early-drip?n=100&ms=50")
            .body(body)
            .unwrap();
        let req = from_layer_request(req, st.client_meta.clone(), &cx.snap.limits, &cx.snap.flags)
            .unwrap();
        let outcome = crate::exchange::core(&mut LaneTransport, &mut cx, req).await;
        assert!(matches!(outcome, Outcome::Respond(_)));
        tokio::time::sleep(Duration::from_millis(201)).await;
        assert!(
            upload
                .send_data(bytes::Bytes::from_static(b"too late"))
                .await
                .is_err(),
            "the upload is released while the response is still unwritten"
        );
        assert!(!cx.request_delivery.as_ref().unwrap().wait().await);
        drop(outcome);
        let cx = crate::addons::Reclaim::now(cx).take().await;
        assert_eq!(
            cx.completion.reason(None).as_deref(),
            Some("upstream_body_timeout")
        );
    }
}
