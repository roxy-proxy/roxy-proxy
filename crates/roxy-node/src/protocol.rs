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
pub struct EnrolRequest {
    pub roxy_version: String,
    pub protocol_version: u32,
}

/// Enrol and renew response.
#[derive(Clone, Serialize, Deserialize)]
pub struct EnrolResponse {
    pub node_id: String,
    /// The node token: opaque, 1 to 512 bytes of printable ASCII, sent as
    /// `Authorization: Bearer` on every later request.
    pub token: String,
    /// When the server stops accepting the token.
    pub not_after: DateTime<Utc>,
    /// Seconds after receipt at which the node renews. Relative, so clock
    /// skew between node and server cannot move the renewal.
    pub renew_after_seconds: u64,
}

/// Never prints the token.
impl std::fmt::Debug for EnrolResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrolResponse")
            .field("node_id", &self.node_id)
            .field("not_after", &self.not_after)
            .field("renew_after_seconds", &self.renew_after_seconds)
            .finish_non_exhaustive()
    }
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
    /// Events are being tagged with `seq` values past the persisted
    /// reservation, because a `flow.seq` write is failing or lagging: a
    /// restart now may reuse them, and the server's `(node_id, seq)`
    /// deduplication would drop the reused ones. Always sent; nodes that
    /// predate the field leave it out.
    #[serde(default)]
    pub seq_unreserved: bool,
    /// The quarantine in force, or `null`. Always sent; nodes that predate
    /// the field leave it out.
    #[serde(default)]
    pub quarantine: Option<QuarantineReport>,
}

/// A node's quarantine, as reported on every lease poll. The lease's
/// `quarantine.release` names `id` to lift it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineReport {
    /// Minted by the node per incident.
    pub id: String,
    pub since: DateTime<Utc>,
    /// What tripped it: `{"kind": "rule", ...}`, `{"kind": "threshold",
    /// ...}` or `{"kind": "layer", ...}`, as the proxy's `quarantined` flow
    /// event carries it.
    pub cause: serde_json::Value,
}

/// The lease's `quarantine` object.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseQuarantine {
    /// Incident ids the control plane has released. The node lifts its
    /// quarantine when the active id is among them; other ids are ignored.
    #[serde(default)]
    pub release: Vec<String>,
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
    /// Releases of the node's quarantine. Orthogonal to the policy: the
    /// rest of the lease applies whether or not the node is quarantined.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quarantine: Option<LeaseQuarantine>,
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
            .field("quarantine", &self.quarantine)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_node_state_without_seq_unreserved_parses_as_false() {
        let state: NodeState = serde_json::from_str(
            r#"{"lease_id":null,"roxy_version":"0.1.1","protocol_version":1,
                "uptime_seconds":0,"policy_state":"none","spooled_bytes":0}"#,
        )
        .unwrap();
        assert!(!state.seq_unreserved);
    }

    #[test]
    fn an_enrol_response_never_debug_prints_its_token() {
        let res: EnrolResponse = serde_json::from_str(
            r#"{"node_id":"n1","token":"hunter2","not_after":"2026-11-05T10:12:00Z","renew_after_seconds":1}"#,
        )
        .unwrap();
        let text = format!("{res:?}");
        assert!(!text.contains("hunter2"), "{text}");
        assert!(text.contains("node_id: \"n1\""));
        assert_eq!(res.token, "hunter2");
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
