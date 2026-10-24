//! A layer's stage: runs one layer on its lanes. The request arrives on
//! the lane downstream of the layer; what the layer forwards goes on the
//! lane upstream of it, what comes back there is its `next`'s response,
//! and what it answers goes on the response lane downstream. A layer that
//! does not run on the exchange (its `when` or `sample` skipped it, or
//! nothing reached it) passes each lane through as it found it.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use roxy_wasm::{LayerError, LayerRequest, LayerResponse};

use super::chain::{Head, Headless, LaneRx, LaneTx, LayerIo, StageHandle};
use super::{
    AddonImpl, AddonMode, StackError, StackFlow, decode, lock, select, service, subscribe, tee,
};

/// A layer's ends of the hop upstream of it: where its forward goes, and
/// where the response to it comes back.
pub(super) struct Forward {
    req_out: LaneTx,
    res_in: LaneRx,
}

/// How running the layer ended.
enum Entered {
    /// The layer ran to the end of its handler; whatever it answered went
    /// on its lane as it answered.
    Done,
    /// The layer did not run: what came back from upstream, passed on.
    Through(Result<LayerResponse, Headless>),
    /// A service layer: it runs its own stage on the lanes, torn down by
    /// the chain rather than by this task.
    Service(service::ServiceSpec, LayerRequest),
    Fault(StackError),
}

/// Runs layer `index` on its lanes.
pub(super) async fn run(st: Arc<StackFlow>, index: usize, io: LayerIo) {
    let LayerIo {
        mut req_in,
        res_in,
        req_out,
        res_out,
        stage,
    } = io;
    *lock(&st.layers[index].forward) = Some(Forward { req_out, res_in });
    // The layer's answer goes on the lane where the layer gives it (a
    // guest's `respond`, a service's `response` message); the stage keeps
    // the lane until then.
    let res_out = Arc::new(Mutex::new(Some(res_out)));
    let torn_down = stage.torn_down();
    let arrived = tokio::select! {
        biased;
        () = torn_down.cancelled() => None,
        arrived = req_in.head() => Some(arrived),
    };
    let entered = match arrived {
        None => None,
        Some(Ok((Head::Request(parts), body))) => {
            let req = http::Request::from_parts(parts, body);
            tokio::select! {
                biased;
                () = torn_down.cancelled() => None,
                entered = enter(&st, index, &stage, req, &res_out) => Some(entered),
            }
        }
        Some(Ok((Head::Response(_), _))) => unreachable!("a request lane carries requests"),
        // Nothing reached the layer: nothing leaves it, and what comes
        // back from upstream for that nothing is passed on.
        Some(Err(headless)) => Some(Entered::Through(
            forward_lanes(&st, index, Err(headless), false).await,
        )),
    };
    match entered {
        // Torn down (the chain has cut the layer's lanes), or the layer ran
        // to the end of its handler with its answer on its lane.
        None | Some(Entered::Done) => {}
        Some(Entered::Service(svc, req)) => {
            let forward = lock(&st.layers[index].forward).take();
            let answer = lock(&res_out).take();
            let (Some(Forward { req_out, res_in }), Some(answer)) = (forward, answer) else {
                unreachable!("a layer's lanes are taken once")
            };
            let ends = service::Ends {
                res_in,
                forward: req_out,
                answer,
            };
            service::run(&st, index, &svc, req, ends, &stage).await;
        }
        Some(Entered::Through(through)) => {
            if let Some(res_out) = lock(&res_out).take() {
                match through {
                    Ok(res) => {
                        let (parts, body) = res.into_parts();
                        res_out.whole(Head::Response(parts), body);
                    }
                    Err(Headless::Ended) => res_out.end_headless(),
                    Err(Headless::Cut(why)) => res_out.cut_headless(why),
                }
            }
        }
        Some(Entered::Fault(e)) => stage.fail(e),
    }
    // Done: a forward the layer never made is no forward, and an answer it
    // never gave is none.
    let forward = lock(&st.layers[index].forward).take();
    drop(forward);
    let answer = lock(&res_out).take();
    drop(answer);
}

/// Runs layer `index` on `req`.
async fn enter(
    st: &Arc<StackFlow>,
    index: usize,
    stage: &StageHandle,
    req: LayerRequest,
    answer: &Arc<Mutex<Option<LaneTx>>>,
) -> Entered {
    let addon = st.snap.addons[index].clone();
    let req = match select::selects(st, index, &addon, req) {
        Ok((true, req)) => req,
        // Skipped: as if the layer passed both directions on unchanged.
        Ok((false, req)) => {
            return Entered::Through(forward_lanes(st, index, Ok(req), false).await);
        }
        Err(e) => return Entered::Fault(e),
    };
    st.layers[index].ran.store(true, Ordering::SeqCst);
    let mut req = req;
    // Layers see bodies decoded, from the first layer subscribed to the
    // body; a body no layer reads is left as the client sent it.
    if st.snap.http.decode_for_addons
        && addon.subscribe.request == subscribe::Part::Full
        && !st.request_decoded.swap(true, Ordering::SeqCst)
    {
        decode::request(st, &mut req, st.snap.limits.max_request_body_bytes);
    }
    if addon.mode == AddonMode::Observe {
        return Entered::Through(tee::observe(st.clone(), index, req).await);
    }
    stage.enforcing();
    match &addon.kind {
        AddonImpl::Wasm(layer) => {
            let mut req = req;
            let host = super::host::StackHost {
                st: st.clone(),
                index,
                observer: None,
                call: None,
                answer: answer.clone(),
                bypassed: subscribe::Bypassed::default(),
            };
            // A head-only layer gets the head with an empty body; the body
            // stays here, to go on with the head the layer passes on.
            if addon.subscribe.request == subscribe::Part::Head {
                host.bypassed.hold_request(&mut req);
            }
            // The answer goes on its lane as the guest gives it; this
            // returns once the handler has returned.
            match layer.handle(Arc::new(host), req).await {
                Ok(()) => Entered::Done,
                // Recorded as it happened, through the host; an error
                // from before the exchange had a host (no instance,
                // say) is not.
                Err(e) => Entered::Fault(e.into()),
            }
        }
        AddonImpl::Service(svc) => Entered::Service(svc.clone(), req),
    }
}

/// What layer `index`'s `next` reaches, on its lanes: the request goes
/// upstream, and what comes back is the response, whoever produced it: the
/// upstream's, the rules' refusal, or the refusal a failure upstream
/// produces, carried to the layers downstream as they would receive
/// any response. A lane that ends without a head is the one case nothing
/// answers: the forward was cut, the client's own request failed, or a
/// stage was torn down. `Err` forwards nothing: the lane upstream is ended
/// as it was found. `own` says the request's body is the layer's own
/// making (a guest's stream), so an error in it is the layer's cut rather
/// than one it passed through.
pub(super) async fn forward_lanes(
    st: &Arc<StackFlow>,
    index: usize,
    req: Result<LayerRequest, Headless>,
    own: bool,
) -> Result<LayerResponse, Headless> {
    let Some(Forward {
        req_out,
        mut res_in,
    }) = lock(&st.layers[index].forward).take()
    else {
        st.fail(&st.snap.addons[index].name, LayerError::NextCalledTwice);
        return Err(Headless::Cut("next called twice".to_owned()));
    };
    match req {
        Ok(req) if own => {
            let (parts, body) = req.into_parts();
            req_out.produced(Head::Request(parts), body);
        }
        Ok(req) => {
            let (parts, body) = req.into_parts();
            req_out.whole(Head::Request(parts), body);
        }
        Err(Headless::Ended) => req_out.end_headless(),
        Err(Headless::Cut(why)) => req_out.cut_headless(why),
    }
    let (head, body) = res_in.head().await?;
    let Head::Response(parts) = head else {
        unreachable!("a response lane carries responses")
    };
    Ok(http::Response::from_parts(parts, body))
}
