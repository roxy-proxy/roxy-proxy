//! Wire types for `/roxy/v1/`: the request and response bodies of enrol,
//! renew, lease and flow upload.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The protocol version this client speaks.
pub const PROTOCOL_VERSION: u32 = 1;

/// Path prefix of every endpoint.
pub const PREFIX: &str = "/roxy/v1";

/// Body of every non-2xx response.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ErrorBody {
    /// A stable code.
    pub error: String,
    pub message: String,
    /// On 426: the protocol or roxy version the node lacks.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing: Vec<String>,
}

/// `POST /roxy/v1/enrol` and `POST /roxy/v1/renew` body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRequest {
    /// PEM `CERTIFICATE REQUEST`; the key never leaves the node.
    pub csr: String,
    pub roxy_version: String,
    pub protocol_version: u32,
}

/// Enrol and renew response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateResponse {
    pub node_id: String,
    /// PEM: the node certificate first, then any intermediates.
    pub certificate_chain: String,
    pub not_after: DateTime<Utc>,
    /// Seconds after receipt at which the node renews. Relative, so clock
    /// skew between node and server cannot move the renewal.
    pub renew_after_seconds: u64,
}

/// `POST /roxy/v1/lease` body: what the node is running.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeState {
    /// The lease the node holds; `null` before the first.
    pub lease_id: Option<String>,
    pub roxy_version: String,
    pub protocol_version: u32,
    pub uptime_seconds: u64,
    pub policy_state: PolicyState,
    /// Flow-log bytes accepted but not yet acknowledged.
    pub spooled_bytes: u64,
}

/// The node's view of its own policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyState {
    /// No lease has been applied: everything is denied.
    None,
    /// A lease is applied and inside `valid_until`.
    Loaded,
    /// The last lease ran out, or the node is revoked: everything is
    /// denied.
    Expired,
}

impl PolicyState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Loaded => "loaded",
            Self::Expired => "expired",
        }
    }
}

/// `POST /roxy/v1/lease` 200 body. Every poll carries the whole lease; the
/// node compares `config` and `secrets` with what it holds.
#[derive(Clone, Serialize, Deserialize)]
pub struct Lease {
    /// Opaque; changes whenever any other field does.
    pub lease_id: String,
    /// The node turns this into an absolute `valid_until` from its own
    /// receipt time.
    pub valid_for_seconds: u64,
    /// Poll hint, well inside `valid_for_seconds`.
    pub refresh_after_seconds: u64,
    /// The rendered, secret-free `roxy.yaml`.
    pub config: String,
    /// Each secret name the config declares with `lease: true`, to its
    /// value.
    #[serde(default)]
    pub secrets: BTreeMap<String, String>,
    /// Opaque. A change clears rule state and metric windows.
    pub state_epoch: String,
    pub flow: FlowSettings,
    /// Reserved for per-node interception CA issuance; carried, not read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interception_ca: Option<serde_json::Value>,
}

/// Never prints the secret values.
impl std::fmt::Debug for Lease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lease")
            .field("lease_id", &self.lease_id)
            .field("valid_for_seconds", &self.valid_for_seconds)
            .field("refresh_after_seconds", &self.refresh_after_seconds)
            .field("config_bytes", &self.config.len())
            .field("secrets", &self.secrets.len())
            .field("state_epoch", &self.state_epoch)
            .field("flow", &self.flow)
            .field("interception_ca", &self.interception_ca.is_some())
            .finish()
    }
}

/// The lease's flow-shipping settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowSettings {
    pub ship: bool,
    /// Largest batch, measured on the JSON before compression.
    pub batch_max_bytes: u64,
    pub flush_interval_seconds: u64,
    pub spool_high_water_bytes: u64,
    pub on_high_water: OnHighWater,
}

/// What the node does with traffic when the spool is at its high water.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnHighWater {
    /// Hold traffic (roxy's flow-log backpressure) until the spool drains.
    Hold,
    /// Keep traffic flowing and drop the oldest spooled events.
    Spool,
}

/// `POST /roxy/v1/flows` body. The node writes it straight from its
/// spooled JSON lines ([`encode_flow_batch`]); this is the parsed form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowBatch {
    pub node_id: String,
    pub lease_id: String,
    /// `seq` of the first event; the rest follow contiguously.
    pub seq_first: u64,
    /// Flow-log records, each with its `seq`.
    pub events: Vec<serde_json::Value>,
}

/// Serialises a flow batch from already-encoded JSON objects (one flow-log
/// record each, no trailing newline), without re-parsing them.
pub fn encode_flow_batch(
    node_id: &str,
    lease_id: &str,
    seq_first: u64,
    events: impl IntoIterator<Item = impl AsRef<[u8]>>,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"{\"node_id\":");
    out.extend_from_slice(
        serde_json::to_string(node_id)
            .unwrap_or_default()
            .as_bytes(),
    );
    out.extend_from_slice(b",\"lease_id\":");
    out.extend_from_slice(
        serde_json::to_string(lease_id)
            .unwrap_or_default()
            .as_bytes(),
    );
    out.extend_from_slice(format!(",\"seq_first\":{seq_first},\"events\":[").as_bytes());
    for (i, event) in events.into_iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        out.extend_from_slice(event.as_ref());
    }
    out.extend_from_slice(b"]}");
    out
}

/// `POST /roxy/v1/flows` 200 body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowAck {
    /// The highest `seq` the server has stored for this node.
    pub acked_through: u64,
}

/// `sha256:<hex>` of `bytes`: the fingerprint form roxy logs certificates
/// in.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut out = String::with_capacity(7 + 64);
    out.push_str("sha256:");
    for b in digest.as_ref() {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_fingerprint_form() {
        assert_eq!(
            sha256_hex(b"abc"),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn flow_batch_encoding_parses_back() {
        let bytes = encode_flow_batch("n\"1", "L", 7, [r#"{"a":1}"#, r#"{"b":"x"}"#]);
        let batch: FlowBatch = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(batch.node_id, "n\"1");
        assert_eq!(batch.seq_first, 7);
        assert_eq!(batch.events.len(), 2);
        assert_eq!(batch.events[1]["b"], "x");
        let empty: FlowBatch =
            serde_json::from_slice(&encode_flow_batch("n", "l", 0, Vec::<&[u8]>::new())).unwrap();
        assert_eq!(empty.events.len(), 0);
    }

    #[test]
    fn a_lease_never_debug_prints_its_secrets() {
        let lease: Lease = serde_json::from_str(
            r#"{"lease_id":"L","valid_for_seconds":1,"refresh_after_seconds":1,"config":"version: 1\n",
                "secrets":{"token":"hunter2"},"state_epoch":"e",
                "flow":{"ship":true,"batch_max_bytes":1,"flush_interval_seconds":1,"spool_high_water_bytes":1,"on_high_water":"hold"}}"#,
        )
        .unwrap();
        let text = format!("{lease:?}");
        assert!(!text.contains("hunter2"), "{text}");
        assert!(text.contains("lease_id: \"L\""));
        assert_eq!(lease.secrets["token"], "hunter2");
    }
}
