//! A layer's stage: runs one layer on its lanes. The request arrives on
//! the lane downstream of the layer; what the layer forwards goes on the
//! lane upstream of it, what comes back there is its `next`'s response,
//! and what it answers goes on the response lane downstream. A layer that
//! does not run on the exchange (its `when` or `sample` skipped it, or
//! nothing reached it) passes each lane through as it found it.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use roxy_wasm::{HostError, LayerError, LayerRequest, LayerResponse};

use super::chain::{Head, Headless, LaneRx, LaneTx, LayerIo, StageHandle};
use super::{
    AddonImpl, AddonMode, BoxFuture, ENDED, StackError, StackFlow, decode, lock, select, service,
    subscribe, tee,
};

/// A layer's ends of the hop upstream of it: where its forward goes, and
/// where the response to it comes back.
pub(super) struct Forward {
    req_out: LaneTx,
    res_in: LaneRx,
}

/// How running the layer ended.
enum Entered {
    /// The layer answered: `res` is still to go on its lane, or it went
    /// there as the layer answered. `done` resolves when the layer has
    /// finished with the exchange, with its failure if it failed after
    /// answering.
    Answered {
        res: Option<LayerResponse>,
        done: BoxFuture<Result<(), StackError>>,
    },
    /// The layer did not run: what came back from upstream, passed on.
    Through(Result<LayerResponse, Headless>),
    Fault(StackError),
    /// Roxy gave the layer up before it answered: nothing of the layer's
    /// failed.
    Abandoned,
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
    // A service's answer goes on the lane where its head is parsed; the
    // stage keeps the lane until then, or for an answer of its own.
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
            below_lanes(&st, index, Err(headless)).await,
        )),
    };
    match entered {
        // Torn down: the chain has cut the layer's lanes.
        None => {}
        Some(Entered::Answered { res, done }) => {
            if let (Some(res), Some(res_out)) = (res, lock(&res_out).take()) {
                let (parts, body) = res.into_parts();
                res_out.whole(Head::Response(parts), body);
            }
            let finished = tokio::select! {
                biased;
                () = torn_down.cancelled() => Ok(()),
                r = done => r,
            };
            if let Err(e) = finished {
                stage.fail(e);
            }
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
        Some(Entered::Abandoned) => stage.gone(ENDED),
    }
    // Done: nothing of the layer's takes a body parked for it, a forward
    // it never made is no forward, and an answer it never gave is none.
    subscribe::release(&st, index);
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
    res_out: &Arc<Mutex<Option<LaneTx>>>,
) -> Entered {
    let addon = st.snap.addons[index].clone();
    let req = match select::selects(st, index, &addon, req) {
        Ok((true, req)) => req,
        // Skipped: as if the layer passed both directions on unchanged.
        Ok((false, req)) => return Entered::Through(below_lanes(st, index, Ok(req)).await),
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
    let req = subscribe::detach_request(st, index, req);
    let (res, done): (Option<LayerResponse>, BoxFuture<Result<(), StackError>>) = match &addon.kind
    {
        AddonImpl::Wasm(layer) => {
            let h = Arc::new(super::host::StackHost {
                st: st.clone(),
                index,
                observer: None,
                call: None,
            });
            match layer.handle(h, req).await {
                Ok(mut res) => {
                    // The guest runs on after answering, and may still
                    // forward, until its handler returns: kept running
                    // whether or not the front writes its body, and
                    // cancelled with the stage.
                    let running = res.extensions_mut().remove::<roxy_wasm::Running>();
                    let outcome = res.extensions().get::<roxy_wasm::LayerOutcome>().cloned();
                    let done = Box::pin(async move {
                        let r = match outcome {
                            Some(outcome) => outcome.wait().await.map_err(StackError::from),
                            None => Ok(()),
                        };
                        drop(running);
                        r
                    });
                    (Some(subscribe::reattach_response(st, index, res)), done)
                }
                // Recorded as it happened, through the host; an error
                // from before the exchange had a host (no instance,
                // say) is not.
                Err(e) => return Entered::Fault(e.into()),
            }
        }
        AddonImpl::Service(svc) => {
            match service::handle(st, index, svc, req, res_out.clone()).await {
                Ok(attended) => (
                    None,
                    Box::pin(async move {
                        let _ = attended.await;
                        Ok(())
                    }),
                ),
                Err(service::Unanswered::Service(e)) => {
                    return Entered::Fault(StackError::Service(e));
                }
                Err(service::Unanswered::Abandoned(_)) => return Entered::Abandoned,
            }
        }
    };
    Entered::Answered { res, done }
}

/// What layer `index`'s `next` reaches, on its lanes: the request goes
/// upstream, and what comes back is the response, whoever produced it: the
/// upstream's, the rules' refusal, or the refusal a failure upstream
/// earns, put on the lane for the layers downstream to see as they would
/// any response. A lane that ends without a head is the one case nothing
/// answers: the client's own failure, or a stage torn down.
pub(crate) fn below(
    st: Arc<StackFlow>,
    index: usize,
    req: LayerRequest,
) -> BoxFuture<Result<LayerResponse, HostError>> {
    Box::pin(async move {
        below_lanes(&st, index, Ok(req))
            .await
            .map_err(|e| HostError::new(e.to_string()))
    })
}

/// [`below`], with the lane's own account of a response that never came.
/// `Err` forwards nothing: the lane upstream is ended as it was found.
pub(super) async fn below_lanes(
    st: &Arc<StackFlow>,
    index: usize,
    req: Result<LayerRequest, Headless>,
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
        Ok(req) => {
            let req = subscribe::reattach_request(st, index, req);
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
    let res = http::Response::from_parts(parts, body);
    // A skipped layer, or an observer, passes the response on whole; an
    // enforce layer subscribed to the head gets only that.
    Ok(if st.enforced(index) {
        subscribe::detach_response(st, index, res)
    } else {
        res
    })
}
