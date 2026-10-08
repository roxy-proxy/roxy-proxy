//! The WASM layer host for roxy addons.
//!
//! Loads `roxy:addon` components (`wit/addon.wit`), runs them under strict
//! budgets, and drives one exchange at a time through a layer against a
//! [`LayerHost`] the proxy implements. Every failure is a [`LayerError`]
//! the caller turns into a fail-closed deny.

#[allow(unsafe_code, clippy::all, clippy::pedantic)]
mod bindings;
mod config;
mod error;
mod exchange;
mod head;
mod host;
mod runtime;
mod state;
mod streams;

pub use async_trait::async_trait;
pub use config::{Capabilities, Capability, LayerConfig, LayerLimits};
pub use error::{Budget, LayerError, LoadError};
pub use exchange::LayerOutcome;
pub use head::MAX_FIELDS_BYTES;
pub use host::{
    EndpointError, FlowInfo, HostError, LayerHost, LayerRequest, LayerResponse, LogLevel,
    Principal, TagError,
};
pub use runtime::{Layer, SlotWait, WasmRuntime};
pub use state::MAX_MESSAGE_BYTES;
