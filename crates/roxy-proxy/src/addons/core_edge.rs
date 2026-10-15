//! The core edge: the stage at the upstream end of the chain. It takes
//! what the last layer passed on from the last request lane, re-validates
//! it exactly as strictly as a client request, runs the exchange core
//! (rules, address floor, connector, WebSocket relay) on it with the flow's
//! own [`FlowCx`], and puts what came of it on the last response lane: the
//! upstream's response, the rules' refusal, or the refusal a failure on
//! the way earns.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use roxy_http::layer::{from_layer_request, to_layer_response};
use roxy_http::{Body, CanonicalRequest};
use roxy_wasm::{LayerError, LayerRequest};

use super::attribution::{Side, attributed};
use super::chain::{CoreIo, Head, Headless, LaneTx};
use super::client_edge::refusal_for_fault;
use super::{StackFlow, decode, ws};
use crate::body::{Collected, collect_prefix};
use crate::exchange::{Front, Outcome, refusal_response};
use crate::pipeline::{BodyIo, CollectFuture, Refusal};

/// Runs the core edge on its lanes.
pub(super) async fn run(st: Arc<StackFlow>, io: CoreIo) {
    let CoreIo {
        mut req_in,
        res_out,
        stage,
    } = io;
    let torn_down = stage.torn_down();
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
        return refused(&st, res_out).await;
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
    let mut front = Detached;
    let outcome = tokio::select! {
        biased;
        () = torn_down.cancelled() => None,
        o = crate::exchange::core(&mut front, cx, creq) => Some(o),
    };
    let Some(outcome) = outcome else {
        // The lease records the abandonment as it goes back; the lanes are
        // cut by the teardown.
        return;
    };
    lease.done = true;
    let cx = lease.cx();
    st.set_facts(&cx.facts);
    let snap = st.snap.clone();
    match outcome {
        Outcome::Respond(mut res) => {
            res.body = attributed(&st, Side::Upstream, std::mem::take(&mut res.body));
            // A response body no layer reads goes up as the origin sent it.
            if snap.http.decode_for_addons && st.body_subscribed(crate::in_flight::Dir::Response) {
                decode::response(&st, &mut res, snap.limits.max_response_body_bytes);
            }
            drop(lease);
            answer(res_out, res);
        }
        Outcome::Refuse(refusal) => {
            let res = refusal_response(cx, &refusal);
            drop(lease);
            refuse(&st, res_out, &refusal, res);
        }
        // The request body failed on its way in, recorded where it entered
        // the stack (the client's) or by the layer that produced it; the
        // refusal that earns, if one does, is the answer.
        Outcome::Close(_) => {
            drop(lease);
            refused(&st, res_out).await;
        }
        Outcome::Upgrade {
            mut res,
            upstream,
            key,
        } => {
            st.relayed(ws::Relay::new(
                upstream,
                key,
                stream.unwrap_or_default(),
                &mut res,
            ));
            let settled = st.chain().settled(res_out.id());
            answer(res_out, res);
            drop(lease);
            // The relay waits for the stack to carry the `101` down; a lane
            // that ends without that happening leaves it to close here.
            settled.await;
            if let Some(relay) = st.take_relay() {
                tokio::spawn(crate::exchange::close_upstream_ws(relay.upstream));
            }
        }
    }
}

/// The request the last layer passed on, re-validated as a client's would
/// be, and the stream after its head on an upgrade. `None` when it does
/// not validate: the fault of the nearest enforcing layer that ran.
pub(super) fn admit(st: &StackFlow, req: LayerRequest) -> Option<(CanonicalRequest, Option<Body>)> {
    let snap = &st.snap;
    let last = snap.addons.len() - 1;
    let layer = &snap.addons[st.passed_on_by(last + 1).unwrap_or(last)].name;
    let (req, stream) = ws::split_upgrade_stream(st, req);
    match from_layer_request(req, st.client_meta.clone(), &snap.limits, &snap.flags) {
        Ok(creq) => Some((creq, stream)),
        Err(e) => {
            st.fail(layer, LayerError::InvalidRequest(e.to_string()));
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

/// Answers with the refusal the fault recorded earns, recorded on the flow
/// as the front would have; a fault that is the client's own gets no
/// answer, the lane is cut.
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
struct Detached;

impl BodyIo for Detached {
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

impl Front for Detached {
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
