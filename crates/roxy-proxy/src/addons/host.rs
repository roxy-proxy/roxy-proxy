//! The [`LayerHost`] each layer of an exchange talks to.

use std::sync::Arc;
use std::time::Duration;

use roxy_wasm::{
    EndpointError, FlowInfo, HostError, LayerHost, LayerRequest, LayerResponse, LogLevel,
    Principal, TagError, async_trait,
};

use super::{AddonSpec, StackFlow, endpoint};
use crate::flowlog::{FlowEvent, sink_ready};
use crate::view::ProxyView;

/// Layer `index` of an exchange's stack.
pub(crate) struct StackHost {
    pub(crate) st: Arc<StackFlow>,
    pub(crate) index: usize,
    /// Observe mode: effects on the flow (`next`, `add-tag`) are not taken,
    /// and `next` returns the copy of the real response.
    pub(crate) observer: Option<super::tee::ObserverNext>,
}

impl StackHost {
    fn addon(&self) -> &Arc<AddonSpec> {
        &self.st.snap.addons[self.index]
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
                client_ip: st.client.peer.ip(),
                listener: st.client.listener.name.clone(),
                tls_sni: st.tls.as_ref().and_then(|t| t.sni.clone()),
            },
            tags: st.tags(),
        }
    }

    fn add_tag(&self, tag: String) -> Result<(), TagError> {
        if self.observer.is_some() {
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
        match level {
            LogLevel::Trace => tracing::trace!(layer, flow, "{msg}"),
            LogLevel::Debug => tracing::debug!(layer, flow, "{msg}"),
            LogLevel::Info => tracing::info!(layer, flow, "{msg}"),
            LogLevel::Warn => tracing::warn!(layer, flow, "{msg}"),
            LogLevel::Error => tracing::error!(layer, flow, "{msg}"),
        }
    }

    async fn record(&self, kind: String, json: String, audit: bool) -> Result<(), HostError> {
        let data: serde_json::Value = serde_json::from_str(&json)
            .map_err(|e| HostError::new(format!("record {kind:?}: not JSON: {e}")))?;
        let addon = self.addon().clone();
        // Never dropped: wait for the flow log like any other audit record.
        sink_ready(&*self.st.shared.sink).await;
        let data = self.st.secrets().redactor().redact_json(data);
        self.st.shared.sink.emit(&FlowEvent::LayerRecord {
            ts: chrono::Utc::now(),
            flow: self.st.flow.to_string(),
            conn: self.st.client.id.to_string(),
            layer: addon.name.clone(),
            kind: kind.clone(),
            data: data.clone(),
            audit,
        });
        if audit && let Some(name) = addon.audit_endpoint.clone() {
            let st = self.st.clone();
            let body = serde_json::json!({
                "flow": st.flow.to_string(),
                "layer": addon.name,
                "kind": kind,
                "data": data,
            });
            tokio::spawn(async move { endpoint::notify(&st, &addon, &name, body).await });
        }
        Ok(())
    }

    async fn state_get(&self, key: String) -> Result<Option<String>, HostError> {
        Ok(self.st.shared.layer_state.get(&self.addon().name, &key))
    }

    async fn state_put(
        &self,
        key: String,
        json: String,
        ttl_ms: Option<u64>,
    ) -> Result<Result<(), String>, HostError> {
        if serde_json::from_str::<serde_json::Value>(&json).is_err() {
            return Ok(Err("value is not JSON".to_owned()));
        }
        let addon = self.addon();
        Ok(self.st.shared.layer_state.put(
            &addon.name,
            &addon.state,
            &key,
            &json,
            ttl_ms.map(Duration::from_millis),
        ))
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
        match shared.metrics.get(&id, &view) {
            Ok(v) => Ok(Some(v)),
            Err(e) => Err(HostError::new(format!("metric {id}: {e}"))),
        }
    }
}
