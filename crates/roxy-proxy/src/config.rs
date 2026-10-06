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
use crate::flowlog::{FlowSink, Redactor};
use crate::sources::{MetricSource, StateSource};
use crate::upstream::UpstreamSettings;

/// One listener to bind.
#[derive(Debug, Clone)]
pub struct ListenerSpec {
    pub name: String,
    pub bind: SocketAddr,
    pub kind: ListenerKind,
}

/// What a listener serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerKind {
    /// The explicit proxy.
    Explicit,
    /// Connections addressed to the origin.
    Direct {
        /// The port clients connect to; `None` = the bound port.
        target_port: Option<u16>,
    },
}

/// Fixed server configuration.
pub struct RuntimeConfig {
    pub listeners: Vec<ListenerSpec>,
    /// Plain-HTTP CA download + health endpoint.
    pub ca_server: Option<SocketAddr>,
    /// The DNS listener (`dns:`).
    pub dns: Option<crate::dns_server::DnsServerSpec>,
    pub ca: Arc<Ca>,
    pub minter: Arc<LeafMinter>,
    /// `tls.upstream.*`.
    pub upstream_tls: UpstreamTlsOptions,
    /// `limits.max_connections`.
    pub max_connections: usize,
    /// `limits.max_connections_per_client`.
    pub max_connections_per_client: usize,
    /// `log.flow.connection_events`.
    pub connection_events: bool,
    /// `log.flow.ws_message_every`.
    pub ws_message_every: u64,
    pub sink: Arc<dyn FlowSink>,
    /// Body capture / traffic tee; `None` = capture disabled.
    pub capture: Option<Arc<crate::capture::CaptureLog>>,
    pub metrics: Arc<dyn MetricSource>,
    pub state: Arc<dyn StateSource>,
    /// The initial reloadable part.
    pub policy: PolicyUpdate,
}

/// What the proxy does with HTTP beyond parsing it: the `http.*` keys the
/// codec does not read, and the `tls.*` key that shapes a CONNECT tunnel.
/// A connection takes these when it is accepted and keeps them.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct HttpBehaviour {
    /// `tls.require_sni_match`: a tunnel's `ClientHello` must name the
    /// CONNECT host.
    pub require_sni_match: bool,
    /// `http.enable_h2`: offer ALPN `h2` (then `http/1.1`) in terminated
    /// tunnels; otherwise only `http/1.1`.
    pub enable_h2: bool,
    /// `http.allow_plain_in_connect`: serve plaintext HTTP inside a CONNECT
    /// tunnel instead of refusing it.
    pub allow_plain_in_connect: bool,
    /// `http.strip_accept_encoding`: remove `accept-encoding` from
    /// requests, so origins answer uncompressed.
    pub strip_accept_encoding: bool,
    /// `http.decode_for_addons`: decode bodies at the edge of the addon
    /// stack. Default true.
    pub decode_for_addons: bool,
}

impl Default for HttpBehaviour {
    fn default() -> Self {
        Self {
            require_sni_match: true,
            enable_h2: true,
            allow_plain_in_connect: false,
            strip_accept_encoding: false,
            decode_for_addons: true,
        }
    }
}

/// The reloadable part of the configuration.
pub struct PolicyUpdate {
    pub policy: Policy,
    /// Resolved secret values by name, for `${secret:name}`. Installed in
    /// the server's [`crate::secrets::SecretStore`], which a
    /// [`crate::ServerHandle::swap_secrets`] replaces without a reload.
    pub secrets: HashMap<String, String>,
    /// The header names never logged. The secret values are added when
    /// the store builds the redactor exchanges use.
    pub redactor: Redactor,
    pub limits: Limits,
    pub flags: HttpFlags,
    pub http: HttpBehaviour,
    pub upstream: UpstreamSettings,
    /// Every `address_lists:` entry, loaded and compiled. A list that failed
    /// to load must never be represented here as empty: loading errors fail
    /// startup or the whole reload.
    pub address_lists: Arc<AddressLists>,
    /// `upstream.deny_lists`: names in `address_lists` applied as a hard
    /// floor in the connector. A name missing from `address_lists` fails
    /// the snapshot build (startup error / failed reload).
    pub deny_lists: Vec<String>,
    /// The addon stack, outermost first. Swapped with the rest of
    /// the policy: new exchanges use the new stack, in-flight ones finish
    /// on theirs.
    pub addons: Vec<Arc<crate::addons::AddonSpec>>,
}

impl std::fmt::Debug for PolicyUpdate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyUpdate")
            .field("secrets", &self.secrets.len())
            .field("limits", &self.limits)
            .field("flags", &self.flags)
            .field("http", &self.http)
            .field("upstream", &self.upstream)
            .field("address_lists", &self.address_lists.len())
            .field("deny_lists", &self.deny_lists)
            .finish_non_exhaustive()
    }
}
