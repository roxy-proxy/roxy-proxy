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
    /// A `fields` the guest built would grow past [`crate::MAX_FIELDS_BYTES`].
    Fields,
    /// A `flow.log` message or `flow.record` document is over
    /// [`crate::MAX_MESSAGE_BYTES`].
    Message,
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
    /// The request the guest passed to `next` could not be built (bad
    /// method, scheme, authority or path).
    #[error("layer passed an invalid request to `next`: {0}")]
    InvalidRequest(String),
    /// The guest's handler returned without setting a response.
    #[error("layer returned without a response")]
    NoResponse,
    /// The guest set an error instead of a response.
    #[error("layer answered with an error: {0}")]
    ErrorResponse(String),
    /// The response the guest set could not be used.
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
    /// The exchange was abandoned by its caller (the request future or the
    /// response body was dropped before the layer finished).
    #[error("exchange cancelled")]
    Cancelled,
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
    /// The component imports something roxy does not provide (for
    /// example `wasi:http/outgoing-handler`), or its imports have the
    /// wrong types.
    #[error("layer `{layer}`: link failed: {message}")]
    Link {
        /// Layer name.
        layer: String,
        /// Linker message.
        message: String,
    },
    /// A required export is missing (`wasi:http/incoming-handler`,
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
