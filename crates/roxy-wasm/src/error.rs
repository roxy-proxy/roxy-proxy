//! Errors. Every [`LayerError`] fails the exchange closed (addon
//! invariant 3): the caller denies the flow, or closes the connection
//! if the response head is already out. Nothing here is ever a "pass".

use std::fmt;

use crate::config::Capability;
use crate::host::HostError;

/// A limit on a layer: one from [`crate::LayerLimits`], or a fixed cap on
/// what the host holds on a guest's behalf.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Budget {
    /// `max_memory`: linear memory would grow past the cap.
    Memory,
    /// `first_byte_timeout`: no response head in time.
    FirstByte,
    /// The flow holds as many tags, or as many bytes of them, as it may.
    Tags,
    /// A head the guest handed the host is over [`crate::MAX_FIELDS_BYTES`].
    Fields,
    /// A `flow.log` message or `flow.record` document is over
    /// [`crate::MAX_MESSAGE_BYTES`].
    Message,
    /// A whole body the guest handed the host (`body.bytes`) is over
    /// [`crate::MAX_BODY_BYTES`].
    Body,
}

impl Budget {
    /// The config key of the limit, or the fixed cap's name.
    pub fn name(self) -> &'static str {
        match self {
            Budget::Memory => "max_memory",
            Budget::FirstByte => "first_byte_timeout",
            Budget::Tags => "tags",
            Budget::Fields => "fields",
            Budget::Message => "message",
            Budget::Body => "body",
        }
    }
}

impl fmt::Display for Budget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Why a layer failed an exchange. Every variant fails the exchange closed
/// (`layer_error`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LayerError {
    /// The guest trapped (including `unreachable`, a Rust panic, stack
    /// exhaustion, or `exit`).
    #[error("layer trapped: {0}")]
    Trap(String),
    /// A budget was exceeded.
    #[error("layer exceeded its {0} budget")]
    BudgetExceeded(Budget),
    /// The guest called an import whose capability was not granted.
    #[error("layer called `{import}` without the `{capability}` capability")]
    CapabilityDenied {
        /// The missing capability.
        capability: Capability,
        /// The WIT function called.
        import: &'static str,
    },
    /// The guest called `chain.next` a second time in one exchange.
    #[error("layer called `next` twice in one exchange")]
    NextCalledTwice,
    /// The guest called an exchange-scoped import outside an exchange
    /// (during `init`).
    #[error("layer called `{0}` outside an exchange")]
    OutsideExchange(&'static str),
    /// The request the guest passed to `next` or an endpoint could not be
    /// used (bad method, scheme, authority, path or header; a body stream
    /// that is not the host's; a body left unfinished).
    #[error("layer passed an invalid request: {0}")]
    InvalidRequest(String),
    /// The guest's handler returned without answering.
    #[error("layer returned without a response")]
    NoResponse,
    /// The response the guest answered with could not be used (bad status
    /// or header; a second answer; a body left unfinished).
    #[error("layer answered with an invalid response: {0}")]
    InvalidResponse(String),
    /// A host service failed; failing closed.
    #[error("host service failed: {0}")]
    Host(#[from] HostError),
    /// `init` returned an error.
    #[error("layer init failed: {0}")]
    Init(String),
    /// A fresh instance could not be created.
    #[error("layer instantiation failed: {0}")]
    Instantiate(String),
    /// Every instance was busy for as long as the caller would wait
    /// ([`crate::SlotWait::Within`]).
    #[error("no layer instance free within the wait")]
    NoInstance,
    /// The exchange was abandoned by its caller (the request future or the
    /// response body was dropped before the layer finished).
    #[error("exchange cancelled")]
    Cancelled,
    /// The layer passed on bytes of a body it is not subscribed to (the
    /// direction named).
    #[error("layer passed on a {0} body it is not subscribed to")]
    Unsubscribed(&'static str),
}

impl LayerError {
    /// The budget this error reports, if any.
    pub fn budget(&self) -> Option<Budget> {
        if let LayerError::BudgetExceeded(b) = self {
            Some(*b)
        } else {
            None
        }
    }
}

/// Why a layer could not be loaded. A layer that fails to load fails the
/// config load; roxy keeps its old policy.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// The bytes are not a valid component, or compilation failed.
    #[error("layer `{layer}`: compile failed: {message}")]
    Compile {
        /// Layer name.
        layer: String,
        /// Compiler message.
        message: String,
    },
    /// The component imports something roxy does not provide (`wasi:http`,
    /// say), or its imports have the wrong types.
    #[error("layer `{layer}`: link failed: {message}")]
    Link {
        /// Layer name.
        layer: String,
        /// Linker message.
        message: String,
    },
    /// A required export is missing (`roxy:addon/handler`,
    /// `roxy:addon/init`).
    #[error("layer `{layer}`: missing export: {message}")]
    MissingExport {
        /// Layer name.
        layer: String,
        /// What is missing.
        message: String,
    },
    /// The first instance could not be created or its `init` failed.
    #[error("layer `{layer}`: {source}")]
    Start {
        /// Layer name.
        layer: String,
        /// The failure.
        source: LayerError,
    },
    /// The engine could not be created.
    #[error("wasm engine: {0}")]
    Engine(String),
    /// A limit is out of range.
    #[error("layer `{layer}`: {message}")]
    Limits {
        /// Layer name.
        layer: String,
        /// What is wrong.
        message: String,
    },
}
