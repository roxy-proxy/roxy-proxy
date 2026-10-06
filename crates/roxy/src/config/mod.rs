//! roxy's YAML configuration.
//!
//! Parsing is strict: every struct denies unknown fields, so a typo is an
//! error rather than a silently ignored setting, and the named maps
//! (`secrets`, `static_hosts`, endpoint `headers`, addon `endpoints`) refuse
//! a repeated key. [`Config::validate`] adds the
//! cross-reference checks serde cannot express. Secrets are *not* resolved
//! here; see [`crate::secrets`]. Rule and metric types (and their compiler)
//! live in `roxy-rules` and are re-exported here.

mod convert;
mod units;
mod validate;

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context as _;
use bytesize::ByteSize;
use ipnet::IpNet;
use serde::Deserialize;

pub use roxy_rules::Diagnostic;
pub use roxy_rules::config::{
    Action, Expr, MetricConfig as Metric, MetricCount, RuleConfig as Rule, Then,
};
pub use units::Resolver;
pub use validate::Compiled;

/// The only supported config `version`.
pub const CONFIG_VERSION: u32 = 1;

/// Root of the configuration file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Schema version; must be [`CONFIG_VERSION`].
    pub version: u32,
    #[serde(default)]
    pub listeners: Vec<Listener>,
    /// Plain-HTTP endpoint serving the CA cert and health checks. Absent = off.
    #[serde(default)]
    pub ca_server: Option<CaServer>,
    /// DNS steering is gone. Parsed so a config that still sets it is
    /// refused with a diagnostic rather than an unknown-field error.
    #[serde(default)]
    pub dns: Option<serde_yaml_ng::Value>,
    #[serde(default)]
    pub tls: Tls,
    #[serde(default)]
    pub http: Http,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub upstream: Upstream,
    #[serde(default, deserialize_with = "units::unique_map")]
    pub secrets: BTreeMap<String, SecretSource>,
    /// Named IP address lists, referenced as `@name` in rules.
    #[serde(default)]
    pub address_lists: Vec<AddressList>,
    #[serde(default)]
    pub metrics: Vec<Metric>,
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub addons: Vec<Addon>,
    #[serde(default)]
    pub log: Log,
    /// Directory for `capture` action output. Absent = capture disabled.
    #[serde(default)]
    pub capture_dir: Option<PathBuf>,
}

// ----- listeners ------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listener {
    pub name: String,
    #[serde(default)]
    pub mode: ListenerMode,
    pub bind: SocketAddr,
    /// Proxy authentication is gone. Parsed so a config that still sets
    /// it is refused with a diagnostic rather than an unknown-field error.
    #[serde(default)]
    pub auth: Option<serde_yaml_ng::Value>,
    /// Transparent listeners only; rejected by `roxy check`.
    #[serde(default)]
    pub allow_passthrough: Option<bool>,
    /// Transparent listeners only; rejected by `roxy check`.
    #[serde(default)]
    pub upstream_target: Option<UpstreamTarget>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListenerMode {
    #[default]
    Explicit,
    /// Removed with DNS steering. Parsed so a config that still asks for
    /// it is refused with a diagnostic rather than a parse error.
    Direct,
    /// Parsed so the config shape is stable, but rejected by validation
    /// until transparent mode is built (issue #15).
    Transparent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamTarget {
    Resolve,
    OriginalDst,
    RequireMatch,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaServer {
    pub bind: SocketAddr,
}

// ----- tls ------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Tls {
    /// Where `roxy-ca.pem` / `roxy-ca.key` live; generated if absent.
    /// Unused when `ca_cert` and `ca_key` are set.
    pub ca_dir: PathBuf,
    /// A provided CA certificate (then any intermediates), PEM. Set together
    /// with `ca_key`; never generated.
    pub ca_cert: Option<PathBuf>,
    /// The provided CA's PKCS#8 PEM key.
    pub ca_key: Option<PathBuf>,
    pub require_sni_match: bool,
    /// Leaf certificate LRU size.
    pub leaf_cache_size: usize,
    pub upstream: TlsUpstream,
}

impl Tls {
    /// The provided CA's certificate and key paths, if both are set.
    ///
    /// Exactly one being set is an error rather than a fallback to
    /// `ca_dir`: that would quietly serve a different CA than the operator
    /// configured. `Config::validate` reports it too; this guards the CA
    /// commands, which skip validation.
    pub fn provided_ca(&self) -> anyhow::Result<Option<(&Path, &Path)>> {
        match (&self.ca_cert, &self.ca_key) {
            (Some(cert), Some(key)) => Ok(Some((cert, key))),
            (None, None) => Ok(None),
            _ => anyhow::bail!("tls.ca_cert and tls.ca_key must be set together"),
        }
    }
}

impl Default for Tls {
    fn default() -> Self {
        Self {
            ca_dir: PathBuf::from("/var/lib/roxy/ca"),
            ca_cert: None,
            ca_key: None,
            require_sni_match: true,
            leaf_cache_size: 10_000,
            upstream: TlsUpstream::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TlsUpstream {
    pub verify: UpstreamVerify,
    pub extra_roots: Vec<PathBuf>,
    pub min_version: TlsVersion,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
pub enum UpstreamVerify {
    /// Bundled webpki roots only.
    #[default]
    #[serde(rename = "strict")]
    Strict,
    /// Bundled webpki roots plus `extra_roots`.
    #[serde(rename = "strict+extra_roots")]
    StrictExtraRoots,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
pub enum TlsVersion {
    #[default]
    #[serde(rename = "1.2")]
    Tls12,
    #[serde(rename = "1.3")]
    Tls13,
}

// ----- http -----------------------------------------------------------------

/// Strictness knobs for client-side HTTP parsing. All default to the
/// strict setting (`enable_h2` defaults to true: it is a capability, and the
/// h2 path is as strict as h1), plus how roxy handles content codings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[allow(clippy::struct_excessive_bools)]
pub struct Http {
    pub allow_http10: bool,
    pub allow_trailers: bool,
    pub allow_chunk_extensions: bool,
    pub allow_plain_in_connect: bool,
    pub allow_obs_text: bool,
    pub allow_body_on_get: bool,
    /// Offer `h2` in client-facing ALPN. Default true.
    pub enable_h2: bool,
    /// Remove `accept-encoding` from requests.
    pub strip_accept_encoding: bool,
    /// Decode bodies for the addons.
    /// Default true.
    pub decode_for_addons: bool,
}

impl Default for Http {
    fn default() -> Self {
        Self {
            allow_http10: false,
            allow_trailers: false,
            allow_chunk_extensions: false,
            allow_plain_in_connect: false,
            allow_obs_text: false,
            allow_body_on_get: false,
            enable_h2: true,
            strip_accept_encoding: false,
            decode_for_addons: true,
        }
    }
}

// ----- limits ---------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    #[serde(deserialize_with = "units::size")]
    pub max_header_bytes: ByteSize,
    #[serde(deserialize_with = "units::size")]
    pub max_url_bytes: ByteSize,
    pub max_headers: usize,
    #[serde(deserialize_with = "units::size")]
    pub max_request_body_bytes: ByteSize,
    #[serde(deserialize_with = "units::size")]
    pub max_response_body_bytes: ByteSize,
    #[serde(deserialize_with = "units::size")]
    pub max_inspect_body_bytes: ByteSize,
    #[serde(deserialize_with = "units::size")]
    pub max_ws_message_bytes: ByteSize,
    #[serde(deserialize_with = "units::size")]
    pub max_capture_body_bytes: ByteSize,
    /// Bytes buffered per direction for an observe-mode addon's copy of a
    /// body; an observer further behind the real exchange than this has its
    /// copy cut.
    #[serde(deserialize_with = "units::size")]
    pub max_observer_lag_bytes: ByteSize,
    /// Process-wide budget for inspection buffers, WebSocket reassembly
    /// and observer copies together; an exchange that cannot reserve its
    /// cap fails closed (an observer copy is cut instead).
    #[serde(deserialize_with = "units::size")]
    pub max_buffered_bytes: ByteSize,
    #[serde(with = "humantime_serde")]
    pub header_timeout: Duration,
    /// Longest stall the client is allowed: sending its request body, or
    /// taking the response.
    #[serde(with = "humantime_serde")]
    pub body_idle_timeout: Duration,
    /// Longest gap between the upstream's response-body frames.
    #[serde(with = "humantime_serde")]
    pub response_body_idle_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub response_header_timeout: Duration,
    /// Keep-alive idle time between requests on a client connection; also
    /// the idle timeout of a relayed WebSocket.
    #[serde(with = "humantime_serde")]
    pub idle_timeout: Duration,
    /// Global cap on concurrent client connections.
    pub max_connections: usize,
    pub max_connections_per_client: usize,
    /// Client-side h2 (when it lands): concurrent streams per connection.
    pub h2_max_concurrent_streams: u32,
    /// Client-side h2: header list size cap per stream.
    #[serde(deserialize_with = "units::size")]
    pub h2_max_header_list_bytes: ByteSize,
    pub max_metric_keys: usize,
    /// Approximate byte budget across all metric series. A flow that
    /// would take the store past it is denied like a full key table; nothing
    /// is evicted.
    #[serde(deserialize_with = "units::size")]
    pub max_metric_bytes: ByteSize,
    /// Cap on live `set_state` entries; a new key when full denies the flow
    /// that tried (no eviction).
    pub max_state_entries: usize,
    /// Largest address list file roxy will load; a bigger file is a
    /// load error (startup fails / the reload fails).
    #[serde(deserialize_with = "units::size")]
    pub max_address_list_bytes: ByteSize,
}

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const GIB: u64 = 1024 * MIB;

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_header_bytes: ByteSize::b(64 * KIB),
            max_url_bytes: ByteSize::b(8 * KIB),
            max_headers: 100,
            max_request_body_bytes: ByteSize::b(GIB),
            max_response_body_bytes: ByteSize::b(GIB),
            max_inspect_body_bytes: ByteSize::b(MIB),
            max_ws_message_bytes: ByteSize::b(16 * MIB),
            max_capture_body_bytes: ByteSize::b(16 * MIB),
            max_observer_lag_bytes: ByteSize::b(16 * MIB),
            max_buffered_bytes: ByteSize::b(GIB),
            header_timeout: Duration::from_secs(10),
            body_idle_timeout: Duration::from_secs(30),
            response_body_idle_timeout: Duration::from_secs(300),
            response_header_timeout: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(300),
            max_connections: 10_000,
            max_connections_per_client: 256,
            h2_max_concurrent_streams: 100,
            h2_max_header_list_bytes: ByteSize::b(64 * KIB),
            max_metric_keys: 100_000,
            max_metric_bytes: ByteSize::b(roxy_rules::DEFAULT_MAX_METRIC_BYTES as u64),
            max_state_entries: 100_000,
            max_address_list_bytes: ByteSize::b(256 * MIB),
        }
    }
}

impl Limits {
    /// The metric store's bounds. `max_metric_bytes` is validated to fit a
    /// `usize`; should an unvalidated value not fit, it saturates (the
    /// budget is a cap, so this can only be reached by a value that is
    /// already past the validated ceiling).
    pub fn metric_limits(&self) -> roxy_rules::MetricLimits {
        roxy_rules::MetricLimits {
            max_keys: self.max_metric_keys,
            max_bytes: usize::try_from(self.max_metric_bytes.as_u64()).unwrap_or(usize::MAX),
        }
    }
}

// ----- upstream -------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Upstream {
    pub dns: Dns,
    /// Deny loopback, link-local, RFC 1918, ULA, multicast and unspecified
    /// destinations after resolution.
    pub deny_private_ranges: bool,
    pub deny_cidrs: Vec<IpNet>,
    pub allow_cidrs: Vec<IpNet>,
    /// Names of `address_lists` whose addresses are never valid upstream
    /// destinations, checked like `deny_cidrs`.
    pub deny_lists: Vec<String>,
    #[serde(with = "humantime_serde")]
    pub connect_timeout: Duration,
}

impl Default for Upstream {
    fn default() -> Self {
        Self {
            dns: Dns::default(),
            deny_private_ranges: true,
            deny_cidrs: Vec::new(),
            allow_cidrs: Vec::new(),
            deny_lists: Vec::new(),
            connect_timeout: Duration::from_secs(10),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Dns {
    pub resolver: Resolver,
    #[serde(with = "humantime_serde")]
    pub cache_ttl_cap: Duration,
    /// Fixed answers (`name: ip`) consulted before DNS. Intended for tests
    /// and air-gapped deployments; the answers are still subject to the
    /// address floor (`deny_private_ranges`, `deny_cidrs`).
    #[serde(deserialize_with = "units::unique_map")]
    pub static_hosts: BTreeMap<String, IpAddr>,
}

impl Default for Dns {
    fn default() -> Self {
        Self {
            resolver: Resolver::System,
            cache_ttl_cap: Duration::from_secs(60),
            static_hosts: BTreeMap::new(),
        }
    }
}

// ----- secrets --------------------------------------------------------------

/// Where a secret's value comes from. Resolved only at `run`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RawSecretSource")]
pub enum SecretSource {
    /// `{ env: NAME }`
    Env(String),
    /// `{ file: /path }`; one trailing newline is stripped.
    File(PathBuf),
}

/// YAML shape of [`SecretSource`]: a map with exactly one of `env` / `file`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSecretSource {
    env: Option<String>,
    file: Option<PathBuf>,
}

impl TryFrom<RawSecretSource> for SecretSource {
    type Error = &'static str;
    fn try_from(raw: RawSecretSource) -> Result<Self, Self::Error> {
        match (raw.env, raw.file) {
            (Some(env), None) => Ok(Self::Env(env)),
            (None, Some(file)) => Ok(Self::File(file)),
            _ => Err("a secret must have exactly one of `env` or `file`"),
        }
    }
}

// ----- address lists ----------------------------------------------------------

/// One entry of `address_lists:`: a named set of IPs / CIDRs.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RawAddressList")]
pub struct AddressList {
    pub name: String,
    pub source: AddressListSource,
}

/// Where an address list's entries come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressListSource {
    /// `file: PATH`: one entry per line, `#` comments (loaded by `check`, at
    /// startup and on every reload; the file is watched).
    File(PathBuf),
    /// `inline: [cidr-or-ip, ...]`, kept as text so `check` can report each
    /// bad entry by index.
    Inline(Vec<String>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAddressList {
    name: String,
    file: Option<PathBuf>,
    inline: Option<Vec<String>>,
}

impl TryFrom<RawAddressList> for AddressList {
    type Error = &'static str;
    fn try_from(raw: RawAddressList) -> Result<Self, Self::Error> {
        let source = match (raw.file, raw.inline) {
            (Some(f), None) => AddressListSource::File(f),
            (None, Some(v)) => AddressListSource::Inline(v),
            _ => return Err("an address list must have exactly one of `file` or `inline`"),
        };
        Ok(Self {
            name: raw.name,
            source,
        })
    }
}

// ----- addons ---------------------------------------------------------------

/// A host service an addon may use. Each gates imports that are
/// always linked: calling one without its capability fails the flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RawCapability")]
pub enum Capability {
    /// Named outbound calls (`endpoints:`).
    Endpoints,
    /// The addon's keyed store.
    State,
    /// Structured events in the flow log (and the audit endpoint).
    Record,
    /// Read-only metrics.
    Metrics,
    /// roxy's operational log.
    Log,
}

/// YAML names of [`Capability`], plus `secrets`, which gets a pointed
/// refusal rather than "unknown variant": endpoints attach credentials, so
/// an addon never needs to see a secret.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum RawCapability {
    Endpoints,
    State,
    Record,
    Metrics,
    Log,
    Secrets,
}

impl TryFrom<RawCapability> for Capability {
    type Error = &'static str;
    fn try_from(raw: RawCapability) -> Result<Self, Self::Error> {
        Ok(match raw {
            RawCapability::Endpoints => Self::Endpoints,
            RawCapability::State => Self::State,
            RawCapability::Record => Self::Record,
            RawCapability::Metrics => Self::Metrics,
            RawCapability::Log => Self::Log,
            RawCapability::Secrets => {
                return Err(
                    "the `secrets` capability is not provided: put credentials on an \
                            endpoint's `headers`, which roxy attaches without the addon seeing \
                            them",
                );
            }
        })
    }
}

/// A named outbound endpoint. The addon names it; roxy resolves the
/// URL, attaches the headers, applies the timeout and retries, and enforces
/// the address floor and deny lists. Endpoint calls never pass through the
/// layer stack or the rules.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    /// `http(s)://host[:port][/path]`: the whole target (`path: fixed`) or
    /// the prefix the addon's path goes under (`path: prefix`).
    pub url: String,
    /// What the addon's request path contributes (default `fixed`).
    #[serde(default)]
    pub path: EndpointPath,
    /// Headers roxy attaches (values may use `${secret:name}`). They replace
    /// any the addon set.
    #[serde(default, deserialize_with = "units::unique_map")]
    pub headers: BTreeMap<String, String>,
    /// Per attempt, until the response head (default 30s).
    #[serde(default, with = "humantime_serde")]
    pub timeout: Option<Duration>,
    /// Extra attempts after a connection failure or a 502/503/504 (default 0,
    /// at most 9).
    #[serde(default)]
    pub retries: u32,
    /// Allow private, loopback and link-local addresses (default false).
    #[serde(default)]
    pub private_ok: bool,
}

/// How an endpoint call's URL takes the addon's path and query. A `..`
/// segment is refused in either mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointPath {
    /// The configured URL is the whole target; the addon's path and query
    /// are ignored.
    #[default]
    Fixed,
    /// The addon's path and query are normalised and appended under the
    /// configured path.
    Prefix,
}

/// An addon's keyed store. Nothing is evicted: a write when full
/// fails and the addon decides.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AddonState {
    /// Most live entries (default 100 000).
    #[serde(deserialize_with = "units::opt_count")]
    pub max_entries: Option<u64>,
    /// Largest value (default 64 KiB).
    #[serde(deserialize_with = "units::opt_size")]
    pub max_value_bytes: Option<ByteSize>,
    /// TTL for writes that give none (default 6h).
    #[serde(with = "humantime_serde")]
    pub default_ttl: Option<Duration>,
}

/// How an addon is implemented.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddonKind {
    /// A WebAssembly component run in-process. Needs `path`.
    #[default]
    Wasm,
    /// An external service the exchange streams through over a WebSocket.
    /// Needs `endpoint`.
    Service,
}

/// Whether an addon's output takes effect.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddonMode {
    /// In the path; failures fail the flow closed. There is deliberately no
    /// way to let traffic through a failing enforcing addon.
    #[default]
    Enforce,
    /// Gets a copy (tee) of the streams; cannot change or delay traffic, so
    /// its failures are logged only.
    Observe,
}

/// Per-addon limits. They protect roxy and catch a broken addon; they
/// don't police how fast it is. Each has a default when absent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AddonLimits {
    /// Linear memory cap per instance (default 64 MiB).
    #[serde(deserialize_with = "units::opt_size")]
    pub max_memory: Option<ByteSize>,
    /// The addon must produce each response head (a service: each head)
    /// within this much of its own time; time below it doesn't count
    /// (default 30s).
    #[serde(with = "humantime_serde")]
    pub first_byte_timeout: Option<Duration>,
    /// A service addon's connections to its endpoint (default 4).
    #[serde(deserialize_with = "units::opt_count")]
    pub max_connections: Option<u64>,
    /// Streams (exchanges) on one service connection (default 100).
    #[serde(deserialize_with = "units::opt_count")]
    pub max_streams: Option<u64>,
    /// Replace a WASM instance after this many exchanges (default 10 000).
    #[serde(deserialize_with = "units::opt_count")]
    pub recycle_after_exchanges: Option<u64>,
    /// Replace a WASM instance whose memory passed this (default 48 MiB).
    #[serde(deserialize_with = "units::opt_size")]
    pub recycle_above_memory: Option<ByteSize>,
    /// Most instances alive at once, i.e. concurrent exchanges (default 1024).
    #[serde(deserialize_with = "units::opt_count")]
    pub max_instances: Option<u64>,
}

/// One `addons:` entry. There is no hook list: an addon has one
/// entry point (`handle`) and an optional `tunnel` export discovered at
/// load time.
///
/// Addons always sit above the built-in rules, in the order listed: the
/// first addon sees the request first and the response last.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Addon {
    pub name: String,
    #[serde(default)]
    pub kind: AddonKind,
    /// The component file (`kind: wasm`).
    #[serde(default)]
    pub path: Option<PathBuf>,
    /// The named endpoint the exchange streams through (`kind: service`).
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub mode: AddonMode,
    /// The layer runs only on requests this head condition matches, as
    /// they reach it; others go straight to the layer below.
    #[serde(default)]
    pub when: Option<roxy_rules::Expr>,
    /// `mode: observe` only: the share of matching exchanges the layer
    /// gets a copy of, in (0, 1].
    #[serde(default)]
    pub sample: Option<f64>,
    /// Opaque config passed to the addon as JSON.
    #[serde(default)]
    pub config: serde_yaml_ng::Value,
    #[serde(default)]
    pub capabilities: Vec<Capability>,
    #[serde(default)]
    pub limits: AddonLimits,
    /// Named endpoints this addon may call.
    #[serde(default, deserialize_with = "units::unique_map")]
    pub endpoints: BTreeMap<String, Endpoint>,
    /// The addon's keyed store.
    #[serde(default)]
    pub state: AddonState,
    /// An endpoint (of this addon) that also receives `record(.., audit:
    /// true)` events.
    #[serde(default)]
    pub audit_endpoint: Option<String>,
}

// ----- log ------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Log {
    pub flow: FlowLog,
    /// Body capture / traffic tee, written under `capture_dir`.
    pub capture: CaptureLog,
    /// Extra header names whose values are never logged, on top of the
    /// built-in list.
    pub redact_headers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FlowLog {
    /// JSONL output file; absent = stdout.
    pub path: Option<PathBuf>,
    /// Also log connection-level (`connect`) events.
    pub connection_events: bool,
    /// Log every Nth checked WebSocket message as a `ws_message` event; 0
    /// logs only denied ones.
    pub ws_message_every: u64,
    /// Unwritten log bytes at which traffic is held back.
    #[serde(deserialize_with = "units::size")]
    pub high_water: ByteSize,
    /// Rotate `path` once it reaches this size; absent = never rotate.
    #[serde(deserialize_with = "units::opt_size")]
    pub max_file_bytes: Option<ByteSize>,
    /// Keep at most this many rotated files; absent = keep all.
    pub max_files: Option<usize>,
    /// Gzip rotated files.
    pub compress: bool,
}

impl Default for FlowLog {
    fn default() -> Self {
        Self {
            path: None,
            connection_events: false,
            ws_message_every: 0,
            high_water: ByteSize::b(roxy_proxy::logging::DEFAULT_HIGH_WATER as u64),
            max_file_bytes: None,
            max_files: None,
            compress: false,
        }
    }
}

/// `log.capture`: how captured traffic is written. Which exchanges
/// are captured: those a rule's `capture` action selects, or every
/// forwarded exchange with `all: true`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CaptureLog {
    /// Capture every forwarded exchange, both directions.
    pub all: bool,
    /// Unwritten capture bytes at which traffic is held back.
    #[serde(deserialize_with = "units::size")]
    pub high_water: ByteSize,
    /// Rotate `capture.rxc` once it reaches this size; absent = never.
    #[serde(deserialize_with = "units::opt_size")]
    pub max_file_bytes: Option<ByteSize>,
    /// Keep at most this many rotated files; absent = keep all.
    pub max_files: Option<usize>,
    /// Gzip rotated files.
    pub compress: bool,
}

impl Default for CaptureLog {
    fn default() -> Self {
        Self {
            all: false,
            // Captured bodies are bulkier than events: a larger backlog
            // before traffic is held.
            high_water: ByteSize::b(64 << 20),
            max_file_bytes: None,
            max_files: None,
            compress: false,
        }
    }
}

impl Config {
    /// Whether anything captures: a `capture` action or `log.capture.all`.
    pub fn uses_capture(&self) -> bool {
        self.log.capture.all
            || self
                .rules
                .iter()
                .flat_map(|r| r.then.0.iter())
                .any(|a| matches!(a, Action::Capture(_)))
    }
}

// ----- loading --------------------------------------------------------------

impl Config {
    /// Parse a config from YAML text. Structural errors only; call
    /// [`Config::validate`] afterwards.
    pub fn from_yaml(text: &str) -> Result<Self, serde_yaml_ng::Error> {
        serde_yaml_ng::from_str(text)
    }

    /// Read and parse a config file.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Self::from_yaml(&text)
            .map_err(|e| anyhow::anyhow!(describe_parse_error(&text, &e)))
            .with_context(|| format!("parsing {}", path.display()))
    }
}

/// Render a structural parse error. Errors inside `rules[N]` get the rule's
/// id appended (`... (rule "github-reads")`), since the deserialiser only
/// knows the YAML path.
pub fn describe_parse_error(text: &str, err: &serde_yaml_ng::Error) -> String {
    let msg = err.to_string();
    let index = msg
        .strip_prefix("rules[")
        .and_then(|rest| rest.split_once(']'))
        .and_then(|(n, _)| n.parse::<usize>().ok());
    let id = index.and_then(|i| {
        let doc: serde_yaml_ng::Value = serde_yaml_ng::from_str(text).ok()?;
        Some(doc.get("rules")?.get(i)?.get("id")?.as_str()?.to_owned())
    });
    match id {
        Some(id) => format!("{msg} (rule {id:?})"),
        None => msg,
    }
}

#[cfg(test)]
mod tests;
