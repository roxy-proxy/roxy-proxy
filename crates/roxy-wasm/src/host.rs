//! The interface the proxy implements for a layer.

use std::net::IpAddr;

use roxy_http::Body;

use crate::error::LayerError;

/// A request passing through a layer: the head as an [`http::Request`]
/// with an absolute URI (scheme and authority set), and a streaming
/// [`Body`].
///
/// Requests handed *to* a layer come from the proxy's canonical model.
/// Requests a layer passes *on* (`next`) are whatever the guest built; the
/// host must re-validate them through the canonical model exactly as if a
/// client had sent them (invariant 1) and fail the
/// exchange closed if they do not validate. roxy-wasm sets no `host`
/// header; the authority is in the URI.
pub type LayerRequest = http::Request<Body>;

/// A response passing through a layer, with a streaming [`Body`]. A
/// response a layer returns is whatever the guest built and must be
/// re-validated by the host the same way.
pub type LayerResponse = http::Response<Body>;

/// The client as roxy established it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// Client IP address.
    pub client_ip: IpAddr,
    /// Name of the listener the client connected to.
    pub listener: String,
    /// SNI of the client's TLS connection (intercepted CONNECT), if any.
    pub tls_sni: Option<String>,
}

/// The current flow (`flow.current`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowInfo {
    /// Flow id, as in the flow log.
    pub flow_id: String,
    /// Connection id, as in the flow log.
    pub conn_id: String,
    /// The client.
    pub principal: Principal,
    /// Tags added to the flow so far.
    pub tags: Vec<String>,
}

/// `flow.log` levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    /// Trace.
    Trace,
    /// Debug.
    Debug,
    /// Info.
    Info,
    /// Warn.
    Warn,
    /// Error.
    Error,
}

/// A host service failed in a way that must fail the exchange closed (a
/// policy input is unavailable, the request passed to `next` does not
/// validate, the flow log cannot accept a record, ...). The guest traps
/// and the exchange ends with [`crate::LayerError::Host`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct HostError(pub String);

impl HostError {
    /// A host error with a message.
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

/// Why `flow.add-tag` was refused. Either fails the exchange closed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TagError {
    /// The flow holds as many tags, or as many bytes of them, as the host
    /// allows.
    #[error("the flow is at its tag cap")]
    Full,
    /// The host refused the tag for another reason.
    #[error(transparent)]
    Host(#[from] HostError),
}

/// Why an endpoint call failed. Returned to the guest as a
/// `wasi:http/types.error-code`; the guest decides what to do (it is not
/// fatal to the exchange).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EndpointError {
    /// No endpoint with that name is configured for this layer.
    #[error("unknown endpoint")]
    NotFound,
    /// The endpoint's address is denied by the address floor or deny
    /// lists.
    #[error("endpoint address denied")]
    Denied,
    /// The request's path has a `..` segment, or does not normalise so
    /// cannot go under the endpoint's prefix.
    #[error("endpoint path refused: {0}")]
    PathRefused(String),
    /// The endpoint did not answer within its timeout.
    #[error("endpoint timed out")]
    Timeout,
    /// Connecting or talking to the endpoint failed.
    #[error("endpoint call failed: {0}")]
    Failed(String),
}

/// What the proxy provides to a layer during one exchange. One value per
/// exchange: [`crate::Layer::handle`] takes it with the request.
///
/// roxy-wasm enforces capabilities before calling any of these (a method
/// whose capability was not granted is never called), calls
/// [`LayerHost::next`] at most once per exchange, and drops a call's
/// future when the exchange fails or is cancelled. Calls have no deadline
/// of their own here: time below the layer is not the layer's.
#[async_trait::async_trait]
pub trait LayerHost: Send + Sync + 'static {
    /// Pass the request to the layers below this one. Called at most once
    /// per exchange.
    ///
    /// The host validates the request through the canonical model and
    /// runs it down the rest of the stack. Bodies stream in both
    /// directions: the request body is still being produced by the guest
    /// when this is called, and the response body is read by the guest as
    /// it arrives. A denial is a response, not an error. `Err` fails the
    /// exchange closed (for example, the request does not validate).
    async fn next(&self, req: LayerRequest) -> Result<LayerResponse, HostError>;

    /// Call the named endpoint (capability `endpoints`). The request's
    /// URI holds only the path and query the guest asked for; the host
    /// resolves `name` to its URL, attaches credentials and applies its
    /// policy. The call never passes through the layer stack.
    async fn endpoint_call(
        &self,
        name: &str,
        req: LayerRequest,
    ) -> Result<LayerResponse, EndpointError>;

    /// The current flow. Always available.
    fn flow_info(&self) -> FlowInfo;

    /// Add a tag to the flow's log record. Needs no capability, but only
    /// an enforcing layer may tag: `Err` from an observer fails its
    /// exchange closed, as a call without its capability would. The host
    /// caps a flow's tags, in number and in bytes; [`TagError::Full`] fails
    /// the exchange with [`crate::Budget::Tags`].
    fn add_tag(&self, tag: String) -> Result<(), TagError>;

    /// Write to the operational log (capability `log`).
    fn log(&self, level: LogLevel, msg: &str);

    /// Write a structured event to the flow log (capability `record`).
    /// `json` is what the guest passed; the host validates it. Must not
    /// drop the record: wait if the log is behind, or fail.
    async fn record(&self, kind: String, json: String, audit: bool) -> Result<(), HostError>;

    /// Read the layer's keyed store (capability `state`).
    async fn state_get(&self, key: String) -> Result<Option<String>, HostError>;

    /// Write the layer's keyed store (capability `state`). `Ok(Err(msg))`
    /// is a refusal the guest sees (store full, value too large); `Err`
    /// fails the exchange closed.
    async fn state_put(
        &self,
        key: String,
        json: String,
        ttl_ms: Option<u64>,
    ) -> Result<Result<(), String>, HostError>;

    /// Read a metric (capability `metrics`).
    async fn metric_get(&self, id: String, key: Vec<String>) -> Result<Option<i64>, HostError>;

    /// The exchange failed with `err`. Called once, before the failure can
    /// be seen anywhere else: before [`crate::Layer::handle`] returns it,
    /// before a body the layer produced ends on it, before the
    /// [`crate::LayerOutcome`] reports it. So a host that attributes
    /// failures has this one recorded by the time anything downstream fails
    /// on it. Must not call back into the layer.
    fn failed(&self, err: &LayerError);
}
