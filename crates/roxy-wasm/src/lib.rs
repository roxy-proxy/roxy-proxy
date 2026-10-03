//! The WASM layer host for roxy addons (DESIGN.md §11.1–§11.5).
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
mod host;
mod runtime;
mod state;

pub use async_trait::async_trait;
pub use config::{Capabilities, Capability, LayerConfig, LayerLimits};
pub use error::{Budget, LayerError, LoadError};
pub use exchange::LayerOutcome;
pub use host::{
    EndpointError, FlowInfo, HostError, LayerHost, LayerRequest, LayerResponse, LogLevel, Principal,
};
pub use runtime::{Layer, WasmRuntime};
