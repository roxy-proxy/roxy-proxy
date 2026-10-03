//! Runtime configuration handed to [`crate::Server::start`] by the binary.
//!
//! Split in two: [`RuntimeConfig`] is fixed for the life of the server
//! (listener binds, CA, client-facing TLS, caps, sinks), and
//! [`PolicyUpdate`] is everything a reload may change, swapped atomically
//! as one snapshot.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use roxy_http::{HttpFlags, Limits};
use roxy_rules::Policy;
use roxy_tls::{Ca, LeafMinter, UpstreamTlsOptions};

use crate::addrlist::AddressLists;
use crate::auth::UserDb;
use crate::flowlog::{FlowSink, Redactor};
use crate::sources::{MetricSource, StateSource};
use crate::upstream::UpstreamSettings;

/// One listener to bind.
#[derive(Debug, Clone)]
pub struct ListenerSpec {
    pub name: String,
    pub bind: SocketAddr,
    /// Require `Proxy-Authorization` (users: [`PolicyUpdate::users`]).
    pub auth_required: bool,
}

/// Fixed server configuration.
pub struct RuntimeConfig {
    pub listeners: Vec<ListenerSpec>,
    /// Plain-HTTP CA download + health endpoint.
    pub ca_server: Option<SocketAddr>,
    pub ca: Arc<Ca>,
    pub minter: Arc<LeafMinter>,
    /// `tls.require_sni_match`.
    pub require_sni_match: bool,
    /// `http.enable_h2`. Client-side h2 is not in this build: when set, a
    /// warning is logged and only `http/1.1` is offered.
    pub enable_h2: bool,
    /// `tls.upstream.*`.
    pub upstream_tls: UpstreamTlsOptions,
    /// `limits.max_connections`.
    pub max_connections: usize,
    /// `limits.max_connections_per_client`.
    pub max_connections_per_client: usize,
    /// `log.flow.connection_events`.
    pub connection_events: bool,
    pub sink: Arc<dyn FlowSink>,
    pub metrics: Arc<dyn MetricSource>,
    pub state: Arc<dyn StateSource>,
    /// The initial reloadable part.
    pub policy: PolicyUpdate,
}

/// The reloadable part of the configuration.
pub struct PolicyUpdate {
    pub policy: Policy,
    /// Resolved secret values by name, for `${secret:name}`.
    pub secrets: HashMap<String, String>,
    /// Scrubs secrets and sensitive headers from the flow log.
    pub redactor: Redactor,
    /// Proxy-auth users by listener name.
    pub users: HashMap<String, Arc<UserDb>>,
    pub limits: Limits,
    pub flags: HttpFlags,
    pub upstream: UpstreamSettings,
    /// Every `address_lists:` entry, loaded and compiled. A list that failed
    /// to load must never be represented here as empty: loading errors fail
    /// startup or the whole reload.
    pub address_lists: Arc<AddressLists>,
    /// `upstream.deny_lists`: names in `address_lists` applied as a hard
    /// floor in the connector. A name missing from `address_lists` fails
    /// the snapshot build (startup error / failed reload).
    pub deny_lists: Vec<String>,
}

impl std::fmt::Debug for PolicyUpdate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyUpdate")
            .field("secrets", &self.secrets.len())
            .field("users", &self.users.len())
            .field("limits", &self.limits)
            .field("flags", &self.flags)
            .field("upstream", &self.upstream)
            .field("address_lists", &self.address_lists.len())
            .field("deny_lists", &self.deny_lists)
            .finish_non_exhaustive()
    }
}
