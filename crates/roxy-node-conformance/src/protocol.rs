//! The wire types. Field names and shapes follow the schemas in
//! `spec/node-protocol/v1/`; the schemas are the source of truth and
//! [`crate::schema`] checks every body against them.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Body of `POST /roxy/v1/enrol` and `POST /roxy/v1/renew`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrolRequest {
    pub csr: String,
    pub roxy_version: String,
    pub protocol_version: u32,
    pub features: Vec<String>,
}

/// `200` body of enrol and renew.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrolResponse {
    pub node_id: String,
    pub certificate_chain: String,
    pub not_after: String,
    pub renew_after_seconds: u64,
}

/// Value of the `Roxy-Node-State` header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeState {
    pub lease_id: Option<String>,
    pub config_hash: Option<String>,
    pub secrets_hash: Option<String>,
    pub roxy_version: String,
    pub protocol_version: u32,
    pub features: Vec<String>,
    pub uptime_seconds: u64,
    pub policy_state: String,
    pub spooled_bytes: u64,
}

/// A secret value: UTF-8 text, or bytes as standard base64.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SecretValue {
    Text(String),
    Bytes { b64: String },
}

/// The lease's `flow` block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowSettings {
    pub ship: bool,
    pub batch_max_bytes: u64,
    pub batch_max_events: u64,
    pub flush_interval_seconds: u64,
    pub spool_high_water_bytes: u64,
    pub on_high_water: String,
}

/// `200` body of `GET /roxy/v1/lease`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    pub lease_id: String,
    pub issued_at: String,
    pub valid_for_seconds: u64,
    pub refresh_after_seconds: u64,
    pub config: String,
    pub config_hash: String,
    pub secrets: BTreeMap<String, SecretValue>,
    pub secrets_hash: String,
    pub state_epoch: String,
    pub flow: FlowSettings,
}

/// Body of `POST /roxy/v1/flows`. Events are flow-log records carrying a
/// `seq`; they are kept as JSON because the harness does not interpret them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowBatch {
    pub node_id: String,
    pub lease_id: String,
    pub seq_first: u64,
    pub events: Vec<serde_json::Value>,
}

/// `200` body of `POST /roxy/v1/flows`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct FlowAck {
    pub acked_through: u64,
}

/// Body of every non-`2xx`, non-`304` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing: Option<Vec<String>>,
}

impl ErrorBody {
    pub fn new(error: &str, message: impl Into<String>) -> Self {
        Self {
            error: error.to_owned(),
            message: message.into(),
            missing: None,
        }
    }
}
