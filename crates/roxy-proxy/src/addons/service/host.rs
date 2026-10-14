//! Host services for a service layer: the messages a service sends for
//! what a WASM layer reaches through its `flow` imports, answered by the
//! same [`StackHost`], so a call has one meaning, one set of refusals and
//! one flow-log kind whichever kind of layer makes it.

use std::sync::Arc;

use roxy_wasm::{Budget, Capability, LayerError, LayerHost, MAX_MESSAGE_BYTES, TagError};
use serde_json::Value;

use super::In;
use crate::addons::StackFlow;
use crate::addons::host::StackHost;

/// What a call gives back to the service: its value (`null` for a call
/// with none), or the refusal of what the service passed.
pub(super) type Reply = Result<Value, String>;

/// Runs `call`, the service's call `id`, for layer `index` of `st`. `Err`
/// fails the exchange, as the same failure would a WASM layer's.
pub(super) async fn call(
    st: &Arc<StackFlow>,
    index: usize,
    id: u64,
    call: In,
) -> Result<Reply, LayerError> {
    let host = StackHost {
        st: st.clone(),
        index,
        observer: None,
        call: Some(id),
    };
    let caps = st.snap.addons[index].capabilities;
    let require = |cap: Capability, import: &'static str| {
        if caps.contains(cap) {
            Ok(())
        } else {
            Err(LayerError::CapabilityDenied {
                capability: cap,
                import,
            })
        }
    };
    let message = |len: usize| {
        if len > MAX_MESSAGE_BYTES {
            Err(LayerError::BudgetExceeded(Budget::Message))
        } else {
            Ok(())
        }
    };
    match call {
        In::Log {
            level,
            message: msg,
            ..
        } => {
            require(Capability::Log, "flow.log")?;
            message(msg.len())?;
            host.log(level.into(), &msg);
            Ok(Ok(Value::Null))
        }
        In::Record { kind, data, .. } => {
            require(Capability::Record, "flow.record")?;
            let json = data.to_string();
            message(kind.len().saturating_add(json.len()))?;
            host.record(kind, json).await?;
            Ok(Ok(Value::Null))
        }
        In::AddTag { tag, .. } => {
            host.add_tag(tag).map_err(|e| match e {
                TagError::Full => LayerError::BudgetExceeded(Budget::Tags),
                TagError::Host(e) => LayerError::Host(e),
            })?;
            Ok(Ok(Value::Null))
        }
        In::StateGet { key, .. } => {
            require(Capability::State, "flow.state-get")?;
            let value = host.state_get(key).await?;
            Ok(Ok(value.map_or(Value::Null, Value::String)))
        }
        In::StatePut {
            key, value, ttl_ms, ..
        } => {
            require(Capability::State, "flow.state-put")?;
            let result = host.state_put(key, value, ttl_ms).await?;
            Ok(result.map(|()| Value::Null))
        }
        In::MetricGet { metric, .. } => {
            require(Capability::Metrics, "flow.metric-get")?;
            let value = host.metric_get(metric, Vec::new()).await?;
            Ok(Ok(value.map_or(Value::Null, Value::from)))
        }
        In::Request { .. }
        | In::RequestEnd
        | In::Response { .. }
        | In::ResponseEnd
        | In::Credit { .. }
        | In::Reset { .. } => Ok(Ok(Value::Null)),
    }
}
