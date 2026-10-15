//! The [`LayerHost`] each layer of an exchange talks to.

use std::sync::Arc;
use std::time::Duration;

use roxy_wasm::{
    EndpointError, EndpointPermit, FlowInfo, GuestBody, HostError, LayerError, LayerHost,
    LayerRequest, LayerResponse, LogLevel, Principal, TagError, async_trait,
};

use std::sync::Mutex;

use roxy_http::Body;

use super::chain::{Head, Headless, LaneTx};
use super::{AddonMode, AddonSpec, Part, StackFlow, endpoint, lock, subscribe};
use crate::flowlog::{FlowEvent, sink_ready};
use crate::in_flight::Dir;
use crate::view::ProxyView;

/// Longest key and value a layer may write to the state store. The store
/// is the rules' own and outlives the exchange; a rule's keys and values
/// come from config, a guest's from anywhere.
pub(crate) const MAX_STATE_KEY_BYTES: usize = 1024;
pub(crate) const MAX_STATE_VALUE_BYTES: usize = 64 * 1024;

/// Why a `state-put` is refused for what the guest passed, if it is. This
/// is the guest's own error to handle; what the store does with an
/// admissible write is the host's.
fn state_write_refusal(key: &str, value: &str) -> Option<String> {
    if key.len() > MAX_STATE_KEY_BYTES {
        return Some(format!(
            "key is {} bytes; the limit is {MAX_STATE_KEY_BYTES}",
            key.len()
        ));
    }
    if value.len() > MAX_STATE_VALUE_BYTES {
        return Some(format!(
            "value is {} bytes; the limit is {MAX_STATE_VALUE_BYTES}",
            value.len()
        ));
    }
    None
}

/// Layer `index` of an exchange's stack.
pub(crate) struct StackHost {
    pub(crate) st: Arc<StackFlow>,
    pub(crate) index: usize,
    /// A WASM observer's copy of the real response, for its `next`. What
    /// an observer may do goes by the layer's mode (`observing`), which a
    /// service observer has without a copy: its `next` is its own stream.
    pub(crate) observer: Option<super::tee::ObserverNext>,
    /// A service layer's id for the call being run, carried into roxy's
    /// record of it (`call`) so the two can be matched. A WASM layer's
    /// imports have none.
    pub(crate) call: Option<u64>,
    /// Where an enforcing WASM layer's answer goes, until it answers.
    /// Shared with the layer's stage, which keeps the lane if the layer
    /// never answers: the lane's end is then the stage's to decide, after
    /// the layer's own failure is recorded.
    pub(crate) answer: Arc<Mutex<Option<LaneTx>>>,
    /// The bodies a head-only layer does not see, to go on with the heads
    /// it passes on: the request body, and the response body from upstream
    /// with its status.
    pub(crate) held_request: Mutex<Option<Body>>,
    pub(crate) held_response: Mutex<Option<(http::StatusCode, Body)>>,
}

impl StackHost {
    /// A host for a layer that answers nowhere: an observer, or a service
    /// stream's host calls.
    pub(crate) fn silent(
        st: Arc<StackFlow>,
        index: usize,
        observer: Option<super::tee::ObserverNext>,
        call: Option<u64>,
    ) -> Self {
        Self {
            st,
            index,
            observer,
            call,
            answer: Arc::default(),
            held_request: Mutex::new(None),
            held_response: Mutex::new(None),
        }
    }
}

impl StackHost {
    fn addon(&self) -> &Arc<AddonSpec> {
        &self.st.snap.addons[self.index]
    }

    /// Whether the layer observes: it may read, but nothing it does may
    /// steer traffic.
    fn observing(&self) -> bool {
        self.addon().mode == AddonMode::Observe
    }
}

#[async_trait]
impl LayerHost for StackHost {
    async fn next(&self, req: LayerRequest) -> Result<Option<LayerResponse>, HostError> {
        if self.observing() {
            // An observer's request goes nowhere; it gets the real response.
            drop(req);
            return match &self.observer {
                Some(obs) => obs.response().await.map(Some),
                None => Err(HostError::new("an observing service has no `next`")),
            };
        }
        let subscribe = self.addon().subscribe;
        // A head-only layer passes the head on; the body it did not see
        // goes on with it, framed as it came.
        let held = lock(&self.held_request).take();
        let req = match held {
            Some(held) => {
                let mut req = req;
                req.extensions_mut().remove::<GuestBody>();
                req.map(|own| subscribe::splice(&self.st, self.index, Dir::Request, own, held))
            }
            None => req,
        };
        let own = req.extensions().get::<GuestBody>().is_some();
        match super::layer::forward_lanes(&self.st, self.index, Ok(req), own).await {
            Ok(mut res) => {
                if subscribe.response == Part::Head {
                    let body = std::mem::take(res.body_mut());
                    subscribe::head_only(res.headers_mut());
                    *lock(&self.held_response) = Some((res.status(), body));
                }
                Ok(Some(res))
            }
            // Nothing came back: the forward was cut, or nothing answered.
            Err(Headless::Ended | Headless::Cut(_)) => Ok(None),
        }
    }

    fn respond(&self, res: LayerResponse) {
        let Some(answer) = lock(&self.answer).take() else {
            // An observer's answer goes nowhere; read to its end so the
            // layer's own failures surface.
            tokio::spawn(super::tee::discard(res.into_body()));
            return;
        };
        // A head-only layer passing the response from upstream on (the
        // same status) gets its body back; any other status is an answer
        // of the layer's own, whole.
        let held = lock(&self.held_response).take();
        let res = match held {
            Some((status, body)) if status == res.status() => {
                let mut res = res;
                res.extensions_mut().remove::<GuestBody>();
                res.map(|own| subscribe::splice(&self.st, self.index, Dir::Response, own, body))
            }
            _ => res,
        };
        let own = res.extensions().get::<GuestBody>().is_some();
        let (parts, body) = res.into_parts();
        if own {
            answer.produced(Head::Response(parts), body);
        } else {
            answer.whole(Head::Response(parts), body);
        }
    }

    async fn endpoint_permit(&self) -> Result<EndpointPermit, EndpointError> {
        self.st
            .endpoint_calls
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| EndpointError::Failed(format!("endpoint calls: {e}")))
    }

    async fn endpoint_call(
        &self,
        name: &str,
        req: LayerRequest,
    ) -> Result<LayerResponse, EndpointError> {
        endpoint::call(&self.st, self.addon(), name, req).await
    }

    fn flow_info(&self) -> FlowInfo {
        let st = &self.st;
        FlowInfo {
            flow_id: st.flow.to_string(),
            conn_id: st.client.id.to_string(),
            principal: Principal {
                client_ip: st.client_ip,
                listener: st.client.listener.name.clone(),
                tls_sni: st.tls.as_ref().and_then(|t| t.sni.clone()),
            },
            tags: st.tags(),
        }
    }

    fn add_tag(&self, tag: String) -> Result<(), TagError> {
        if self.observing() {
            // A tag steers the `when` of every layer upstream, so it is an
            // effect on traffic, which an observer must not have.
            let layer = &self.addon().name;
            let flow = self.st.flow.to_string();
            let call = self.call;
            tracing::warn!(
                layer,
                flow,
                call,
                tag,
                "observer called `flow.add-tag`: refused"
            );
            return Err(HostError::new(
                "layer called `flow.add-tag` in observe mode: an observer cannot tag",
            )
            .into());
        }
        self.st.add_tag(tag)
    }

    fn log(&self, level: LogLevel, msg: &str) {
        let layer = &self.addon().name;
        let flow = self.st.flow.to_string();
        let call = self.call;
        match level {
            LogLevel::Trace => tracing::trace!(layer, flow, call, "{msg}"),
            LogLevel::Debug => tracing::debug!(layer, flow, call, "{msg}"),
            LogLevel::Info => tracing::info!(layer, flow, call, "{msg}"),
            LogLevel::Warn => tracing::warn!(layer, flow, call, "{msg}"),
            LogLevel::Error => tracing::error!(layer, flow, call, "{msg}"),
        }
    }

    async fn record(&self, kind: String, json: String) -> Result<(), HostError> {
        let data: serde_json::Value = serde_json::from_str(&json)
            .map_err(|e| HostError::new(format!("record {kind:?}: not JSON: {e}")))?;
        let addon = self.addon().clone();
        // Never dropped: wait for the flow log like any other audit record.
        sink_ready(&*self.st.shared.sink).await;
        // `kind` is the guest's string too: both go through this exchange's
        // redactor before reaching the flow log.
        let redactor = self.st.secrets().redactor();
        let kind = redactor.redact_str(&kind).into_owned();
        let data = redactor.redact_json(data);
        self.st.shared.sink.emit(&FlowEvent::LayerRecord {
            ts: chrono::Utc::now(),
            flow: self.st.flow.to_string(),
            conn: self.st.client.id.to_string(),
            layer: addon.name.clone(),
            call: self.call,
            kind,
            data,
        });
        Ok(())
    }

    async fn state_get(&self, key: String) -> Result<Option<String>, HostError> {
        Ok(self.st.shared.state.get(&key))
    }

    async fn state_put(
        &self,
        key: String,
        value: String,
        ttl_ms: Option<u64>,
    ) -> Result<Result<(), String>, HostError> {
        if self.observing() {
            // The store steers the rules of every flow, so a write is an
            // effect on traffic, which an observer must not have.
            let layer = &self.addon().name;
            let flow = self.st.flow.to_string();
            let call = self.call;
            tracing::warn!(
                layer,
                flow,
                call,
                key,
                "observer called `flow.state-put`: refused"
            );
            return Err(HostError::new(
                "layer called `flow.state-put` in observe mode: an observer cannot write state",
            ));
        }
        if let Some(why) = state_write_refusal(&key, &value) {
            return Ok(Err(why));
        }
        // A full store denies a rule's `set_state`; a layer's write is no
        // different, and the guest must not be able to shrug it off.
        self.st
            .shared
            .state
            .set(&key, &value, ttl_ms.map(Duration::from_millis))
            .map_err(|e| HostError::new(e.to_string()))?;
        Ok(Ok(()))
    }

    async fn metric_get(&self, id: String, key: Vec<String>) -> Result<Option<i64>, HostError> {
        if !key.is_empty() {
            return Err(HostError::new(
                "metric-get reads this flow's own key: pass an empty key list",
            ));
        }
        let shared = &self.st.shared;
        let facts = self.st.facts();
        let view = ProxyView::new(
            &facts,
            &*shared.metrics,
            &*shared.state,
            &self.st.snap.address_lists,
        );
        shared
            .metrics
            .get(&id, &view)
            .map_err(|e| HostError::new(format!("metric {id}: {e}")))
    }

    fn quarantine(&self) -> Result<(), HostError> {
        let layer = &self.addon().name;
        let flow = self.st.flow.to_string();
        let call = self.call;
        if self.observing() {
            tracing::warn!(
                layer,
                flow,
                call,
                "observer called `flow.quarantine`: refused"
            );
            return Err(HostError::new(
                "layer called `flow.quarantine` in observe mode: an observer cannot quarantine",
            ));
        }
        self.st
            .shared
            .trip_quarantine(crate::quarantine::QuarantineCause::Layer {
                layer: layer.clone(),
                flow,
                call,
            });
        Ok(())
    }

    fn failed(&self, err: &LayerError) {
        // An observer's failure is its own, logged by the task that runs
        // it; it is never the exchange's.
        if !self.observing() {
            self.st.fail(&self.addon().name, err.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_writes_are_capped_at_the_byte() {
        let k = |n| "k".repeat(n);
        let v = |n| "v".repeat(n);
        assert_eq!(state_write_refusal(&k(MAX_STATE_KEY_BYTES), ""), None);
        assert!(state_write_refusal(&k(MAX_STATE_KEY_BYTES + 1), "").is_some());
        assert_eq!(state_write_refusal("k", &v(MAX_STATE_VALUE_BYTES)), None);
        assert!(state_write_refusal("k", &v(MAX_STATE_VALUE_BYTES + 1)).is_some());
    }
}
