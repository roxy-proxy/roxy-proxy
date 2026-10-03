//! roxy's YAML configuration (`DESIGN.md` §6.1).
//!
//! Parsing is strict: every struct denies unknown fields, so a typo is an
//! error rather than a silently ignored setting. [`Config::validate`] adds the
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

pub use roxy_rules::config::{
    Action, Expr, MetricConfig as Metric, MetricCount, Phase, RuleConfig as Rule, Then,
};
pub use units::Resolver;
pub use validate::Diagnostic;

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
    #[serde(default)]
    pub tls: Tls,
    #[serde(default)]
    pub http: Http,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub upstream: Upstream,
    #[serde(default)]
    pub secrets: BTreeMap<String, SecretSource>,
    /// Named IP address lists, referenced as `@name` in rules (§7.1).
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
    /// Directory for `capture` action output (§10.2). Absent = capture disabled.
    #[serde(default)]
    pub capture_dir: Option<PathBuf>,
}

// ----- listeners ------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listener {
    pub name: String,
    #[serde(default)]
    pub mode: ListenerMode,
    pub bind: SocketAddr,
    #[serde(default)]
    pub auth: Option<ListenerAuth>,
    /// Transparent listeners only (deferred, §4.2).
    #[serde(default)]
    pub allow_passthrough: Option<bool>,
    /// Transparent listeners only (deferred, §4.2).
    #[serde(default)]
    pub upstream_target: Option<UpstreamTarget>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListenerMode {
    #[default]
    Explicit,
    /// Parsed so the config shape is stable, but rejected by validation
    /// until transparent mode is built (§4.2).
    Transparent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamTarget {
    Resolve,
    OriginalDst,
    RequireMatch,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerAuth {
    pub basic: BasicAuth,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BasicAuth {
    pub users_file: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaServer {
    pub bind: SocketAddr,
}

// ----- tls ------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Tls {
    /// Where `roxy-ca.pem` / `roxy-ca.key` live; generated if absent.
    pub ca_dir: PathBuf,
    pub require_sni_match: bool,
    /// Leaf certificate LRU size (§9).
    pub leaf_cache_size: usize,
    pub upstream: TlsUpstream,
}

impl Default for Tls {
    fn default() -> Self {
        Self {
            ca_dir: PathBuf::from("/var/lib/roxy/ca"),
            require_sni_match: true,
            leaf_cache_size: 10_000,
            upstream: TlsUpstream::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
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

/// Strictness knobs for client-side HTTP parsing (§5.3). All default to the
/// strict setting.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[allow(clippy::struct_excessive_bools)]
pub struct Http {
    pub allow_http10: bool,
    pub allow_trailers: bool,
    pub allow_chunk_extensions: bool,
    pub allow_plain_in_connect: bool,
    pub allow_obs_text: bool,
    pub allow_body_on_get: bool,
    /// Offer `h2` in client-facing ALPN. Defaults to false until the h2
    /// server path lands (M3, §5.1a).
    pub enable_h2: bool,
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
    #[serde(with = "humantime_serde")]
    pub header_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub body_idle_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub response_header_timeout: Duration,
    /// Keep-alive idle time between requests on a client connection; also
    /// the idle timeout of a relayed WebSocket.
    #[serde(with = "humantime_serde")]
    pub idle_timeout: Duration,
    /// Global cap on concurrent client connections (§12).
    pub max_connections: usize,
    pub max_connections_per_client: usize,
    /// Client-side h2 (when it lands): concurrent streams per connection.
    pub h2_max_concurrent_streams: u32,
    /// Client-side h2: header list size cap per stream.
    #[serde(deserialize_with = "units::size")]
    pub h2_max_header_list_bytes: ByteSize,
    pub max_metric_keys: usize,
    /// Cap on live `set_state` entries; a new key when full denies the flow
    /// that tried (§6.4, no eviction).
    pub max_state_entries: usize,
    /// Largest address list file roxy will load (§7.1); a bigger file is a
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
            header_timeout: Duration::from_secs(10),
            body_idle_timeout: Duration::from_secs(30),
            response_header_timeout: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(300),
            max_connections: 10_000,
            max_connections_per_client: 256,
            h2_max_concurrent_streams: 100,
            h2_max_header_list_bytes: ByteSize::b(64 * KIB),
            max_metric_keys: 100_000,
            max_state_entries: 100_000,
            max_address_list_bytes: ByteSize::b(256 * MIB),
        }
    }
}

// ----- upstream -------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Upstream {
    pub dns: Dns,
    /// Deny loopback, link-local, RFC 1918, ULA, multicast and unspecified
    /// destinations after resolution (§7).
    pub deny_private_ranges: bool,
    pub deny_cidrs: Vec<IpNet>,
    pub allow_cidrs: Vec<IpNet>,
    /// Names of `address_lists` whose addresses are never valid upstream
    /// destinations (§7.1), checked like `deny_cidrs`.
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

/// One entry of `address_lists:` (§7.1): a named set of IPs / CIDRs.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    State,
    Log,
    Secrets,
}

/// Where an addon runs (§11.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddonStage {
    /// Sees every canonical request, before the rules.
    #[default]
    BeforeRules,
    /// Invoked only by a rule's `call: <addon>`.
    InChain,
    /// Sees only requests the rules allowed.
    AfterRules,
}

/// Per-addon resource limits (§11.1, §11.3). Each defaults to the global
/// setting when absent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AddonLimits {
    /// Linear memory cap per instance (default 64 MiB).
    #[serde(deserialize_with = "units::opt_size")]
    pub max_memory: Option<ByteSize>,
    /// Most body bytes the addon may hold (default
    /// `limits.max_inspect_body_bytes`).
    #[serde(deserialize_with = "units::opt_size")]
    pub max_buffered_body_bytes: Option<ByteSize>,
    /// CPU time between host calls (default 50 ms).
    #[serde(with = "humantime_serde")]
    pub step_cpu: Option<Duration>,
    /// Fuel per I/O step (default 100 000 000).
    #[serde(deserialize_with = "units::opt_count")]
    pub fuel_per_step: Option<u64>,
}

/// What a failing addon (trap, timeout, cap exceeded, invalid mutation)
/// does to its flow. There is deliberately no `pass` (§11.1): an attacker
/// must not be able to switch inspection off by making the addon fail.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub enum OnError {
    /// Deny the flow (`addon_error`).
    #[default]
    Deny,
    /// Close the connection.
    Close,
}

impl TryFrom<String> for OnError {
    type Error = String;
    fn try_from(s: String) -> Result<Self, String> {
        match s.as_str() {
            "deny" => Ok(Self::Deny),
            "close" => Ok(Self::Close),
            other => Err(format!(
                "unknown on_error {other:?}: expected `deny` or `close` (there is deliberately \
                 no `pass`: a failing addon always fails its flow closed)"
            )),
        }
    }
}

/// One `addons:` entry (§11.1). There is no hook list: an addon has one
/// entry point (`handle`) and an optional `tunnel` export discovered at
/// load time.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Addon {
    pub name: String,
    pub path: PathBuf,
    #[serde(default)]
    pub stage: AddonStage,
    /// Opaque config passed to the addon as JSON.
    #[serde(default)]
    pub config: serde_yaml_ng::Value,
    #[serde(default)]
    pub capabilities: Vec<Capability>,
    #[serde(default)]
    pub limits: AddonLimits,
    #[serde(default)]
    pub on_error: OnError,
}

// ----- log ------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Log {
    pub flow: FlowLog,
    /// Extra header names whose values are never logged, on top of the
    /// built-in list.
    pub redact_headers: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FlowLog {
    /// JSONL output file; absent = stdout.
    pub path: Option<PathBuf>,
    /// Also log connection-level (`connect`) events.
    pub connection_events: bool,
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
