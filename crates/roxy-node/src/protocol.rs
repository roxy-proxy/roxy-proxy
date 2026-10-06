//! Wire types for `/roxy/v1/`: the request and response bodies of enrol,
//! renew, lease and flow upload, and the headers the lease fetch reports
//! node state in.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The protocol version this client speaks.
pub const PROTOCOL_VERSION: &str = "1";

/// Path prefix of every endpoint.
pub const PREFIX: &str = "/roxy/v1";

/// Request headers a lease fetch reports node state in.
pub mod headers {
    pub const LEASE_ID: &str = "x-roxy-lease-id";
    pub const CONFIG_HASH: &str = "x-roxy-config-hash";
    pub const SECRETS_HASH: &str = "x-roxy-secrets-hash";
    pub const ROXY_VERSION: &str = "x-roxy-version";
    pub const PROTOCOL_VERSION: &str = "x-roxy-protocol-version";
    pub const FEATURES: &str = "x-roxy-features";
    pub const UPTIME: &str = "x-roxy-uptime-seconds";
    pub const POLICY_STATE: &str = "x-roxy-policy-state";
    pub const SPOOLED_BYTES: &str = "x-roxy-spooled-bytes";
}

/// `POST /roxy/v1/enrol` and `POST /roxy/v1/renew` body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRequest {
    /// PEM `CERTIFICATE REQUEST`; the key never leaves the node.
    pub csr: String,
    pub roxy_version: String,
    pub protocol_version: String,
    pub features: Vec<String>,
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

/// What the node is running, as reported with every lease fetch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeState {
    pub lease_id: Option<String>,
    pub config_hash: Option<String>,
    pub secrets_hash: Option<String>,
    pub roxy_version: String,
    pub features: Vec<String>,
    pub uptime_seconds: u64,
    pub policy_state: PolicyState,
    pub spooled_bytes: u64,
}

/// The node's view of its own policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyState {
    /// No lease has been applied: everything is denied.
    None,
    /// A lease is applied and inside `valid_until`.
    Loaded,
    /// The last lease ran out: everything is denied.
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

/// `GET /roxy/v1/lease` 200 body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    pub lease_id: String,
    pub issued_at: DateTime<Utc>,
    /// The node turns this into an absolute `valid_until` from its own
    /// receipt time.
    pub valid_for_seconds: u64,
    /// Poll hint, well inside `valid_for_seconds`.
    pub refresh_after_seconds: u64,
    /// The rendered, secret-free `roxy.yaml`.
    pub config: String,
    pub config_hash: String,
    #[serde(default)]
    pub secrets: BTreeMap<String, SecretValue>,
    pub secrets_hash: String,
    /// Opaque. A change clears rule state and metric windows.
    pub state_epoch: String,
    pub flow: FlowSettings,
    /// Reserved for per-node interception CA issuance; carried, not read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interception_ca: Option<serde_json::Value>,
}

/// A secret value: a UTF-8 string, or `{b64: ...}` for anything else.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SecretValue {
    Text(String),
    Encoded { b64: String },
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretValue([REDACTED])")
    }
}

impl SecretValue {
    /// The value as roxy's `${secret:name}` substitutes it. Base64 that
    /// does not decode, or decodes to non-UTF-8, is `None`: such a secret
    /// is left out of the map, so a rule that needs it fails closed.
    pub fn decode(&self) -> Option<String> {
        use base64::Engine as _;
        match self {
            Self::Text(s) => Some(s.clone()),
            Self::Encoded { b64 } => base64::engine::general_purpose::STANDARD
                .decode(b64)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok()),
        }
    }
}

/// The lease's flow-shipping settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowSettings {
    pub ship: bool,
    pub batch_max_bytes: u64,
    pub batch_max_events: u64,
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
    out.extend_from_slice(serde_json::to_string(node_id).unwrap_or_default().as_bytes());
    out.extend_from_slice(b",\"lease_id\":");
    out.extend_from_slice(serde_json::to_string(lease_id).unwrap_or_default().as_bytes());
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
    /// The highest `seq` stored with no gap before it.
    pub acked_through: u64,
}

/// `sha256:<hex>` of `bytes`, the form of `config_hash`.
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

impl Lease {
    /// Whether `config_hash` is the hash of `config`. The hash is what the
    /// node reports back and compares across refreshes, so a lease whose
    /// hash does not describe its config is refused rather than applied.
    pub fn config_hash_matches(&self) -> bool {
        self.config_hash == sha256_hex(self.config.as_bytes())
    }

    /// Secret values decoded, in name order. A value that does not decode
    /// is left out (and named), so the rule that reads it fails closed.
    pub fn decoded_secrets(&self) -> (BTreeMap<String, String>, Vec<String>) {
        let mut out = BTreeMap::new();
        let mut undecodable = Vec::new();
        for (name, value) in &self.secrets {
            match value.decode() {
                Some(v) => {
                    out.insert(name.clone(), v);
                }
                None => undecodable.push(name.clone()),
            }
        }
        (out, undecodable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_hash_is_sha256_of_the_config_text() {
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
        let empty: FlowBatch = serde_json::from_slice(&encode_flow_batch("n", "l", 0, Vec::<&[u8]>::new())).unwrap();
        assert!(empty.events.is_empty());
    }

    #[test]
    fn secret_values_decode_text_and_base64_only_when_utf8() {
        let text: SecretValue = serde_json::from_str("\"plain\"").unwrap();
        assert_eq!(text.decode().as_deref(), Some("plain"));
        let b64: SecretValue = serde_json::from_str("{\"b64\":\"aGVsbG8=\"}").unwrap();
        assert_eq!(b64.decode().as_deref(), Some("hello"));
        let bad: SecretValue = serde_json::from_str("{\"b64\":\"/w==\"}").unwrap();
        assert_eq!(bad.decode(), None, "0xff is not UTF-8");
        let junk: SecretValue = serde_json::from_str("{\"b64\":\"!!\"}").unwrap();
        assert_eq!(junk.decode(), None);
        assert_eq!(format!("{text:?}"), "SecretValue([REDACTED])");
    }
}
