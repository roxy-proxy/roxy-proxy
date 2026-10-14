//! The [`LayerHost`] each layer of an exchange talks to.

use std::sync::Arc;
use std::time::Duration;

use roxy_wasm::{
    EndpointError, EndpointPermit, FlowInfo, HostError, LayerError, LayerHost, LayerRequest,
    LayerResponse, LogLevel, Principal, TagError, async_trait,
};

use super::{AddonMode, AddonSpec, StackFlow, endpoint};
use crate::flowlog::{FlowEvent, sink_ready};
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
    /// Observe mode: effects on the flow (`next`, `add-tag`) are not taken,
    /// and `next` returns the copy of the real response.
    pub(crate) observer: Option<super::tee::ObserverNext>,
    /// A service layer's id for the call being run, carried into roxy's
    /// record of it (`call`) so the two can be matched. A WASM layer's
    /// imports have none.
    pub(crate) call: Option<u64>,
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
    async fn next(&self, req: LayerRequest) -> Result<LayerResponse, HostError> {
        if let Some(obs) = &self.observer {
            // An observer's request goes nowhere; it gets the real response.
            drop(req);
            return obs.response().await;
        }
        super::below(self.st.clone(), self.index, req).await
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
            // A tag steers the `when` of every layer below, so it is an
            // effect on traffic, which an observer must not have.
            let layer = &self.addon().name;
            let flow = self.st.flow.to_string();
            tracing::warn!(layer, flow, tag, "observer called `flow.add-tag`: refused");
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
            tracing::warn!(
                layer,
                flow,
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

    fn failed(&self, err: &LayerError) {
        // An observer's failure is its own, logged by the task that runs
        // it; it is never the exchange's.
        if self.observer.is_none() {
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
