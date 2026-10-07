//! In-process test harness: a whole roxy [`Server`] with no bound
//! listeners, client connections over in-memory duplexes, and a scripted
//! upstream reached through the connector's test dial (after real DNS
//! overrides, the real address floor and real upstream TLS).
//!
//! ```text
//!   test client ──duplex──▶ conn::serve_http_proxy | conn::serve_http ─▶ … ─▶ Connector ──TestDial──▶ scripted upstream
//! ```
//!
//! * Names: `up.test` resolves to a public test address, `private.test` to a
//!   private one (denied by the floor unless `private_ok`), `mixed.test` to
//!   both, `down.test` to an address that refuses connections.
//! * The upstream answers by path (see [`upstream_answer`]) and records what
//!   reached it ([`Seen`]): the head, the body bytes, and whether the body
//!   completed or was cut.
//! * Flow events go to a [`MemorySink`]; [`MemorySink::wait_for`] waits on
//!   emits instead of polling.

#![allow(dead_code)]

#[cfg(test)]
mod addon_tests;
#[cfg(test)]
mod budget_tests;
#[cfg(test)]
mod ca_server_tests;
#[cfg(test)]
mod capture_tests;
#[cfg(test)]
mod coding_tests;
#[cfg(test)]
mod core_tests;
#[cfg(test)]
#[cfg(test)]
mod early_tests;
mod gate;
#[cfg(test)]
mod gateway_tests;
mod h2raw;
#[cfg(test)]
mod http_tests;
#[cfg(test)]
mod lease_tests;
#[cfg(test)]
mod rules_tests;
#[cfg(test)]
mod sign_tests;
mod upstream;
#[cfg(test)]
mod ws_tests;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use http_body_util::BodyExt as _;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use roxy_http::{Body, BodySender, HttpFlags, Limits};
use roxy_rules::{Policy, PolicyInput, RuleConfig};
use roxy_tls::{Ca, LeafMinter, UpstreamTlsOptions};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use ulid::Ulid;

#[allow(unused_imports)]
pub(crate) use gate::{GatedSink, LogGate};
#[allow(unused_imports)]
pub(crate) use h2raw::{H2_GOAWAY, H2_HEADERS, H2_RST_STREAM, h2_client, h2_get, h2_raw_request};
#[allow(unused_imports)]
pub(crate) use upstream::{Seen, Upstream};

use crate::Server;
use crate::addons::{AddonMode, AddonSpec, EndpointPath, EndpointSpec, StateLimits};
use crate::addr::PrivateAddrs;
use crate::addrlist::{AddressList, AddressLists};
use crate::config::{HttpBehaviour, PolicyUpdate, RuntimeConfig};
use crate::flowlog::{FlowSink, MemorySink, Redactor};
use crate::listener::{ClientConn, ListenerInfo, ListenerMode};
use crate::sources::{MetricSource, Sample, StateSource, UnavailableMetrics, UnavailableState};
use crate::upstream::{DnsSettings, TestDial, UpstreamSettings};

/// The scripted upstream's public address (`up.test`).
pub(crate) const UP_IP: &str = "93.184.215.14";
/// A private address (`private.test`): the floor denies it without
/// `private_ok`.
pub(crate) const PRIVATE_IP: &str = "10.0.0.5";
/// An address whose dial is refused (`down.test`).
pub(crate) const DOWN_IP: &str = "93.184.215.99";
/// An address that accepts and reads but never answers (`stall.test`).
pub(crate) const STALL_IP: &str = "93.184.215.77";

/// Allows everything to `up.test`.
pub(crate) const ALLOW_UP: &str = r#"
- id: up
  when: host == "up.test"
  then: allow
"#;

/// The roxy-wasm test layer (`crates/roxy-wasm/test-components`).
pub(crate) const TEST_LAYER: &[u8] =
    include_bytes!("../../../roxy-wasm/tests/fixtures/test_layer.wasm");

/// One addon of the stack under test.
#[derive(Clone)]
pub(crate) struct AddonDef {
    pub name: String,
    pub wasm: &'static [u8],
    pub mode: AddonMode,
    pub caps: Vec<roxy_wasm::Capability>,
    pub config: serde_json::Value,
    pub limits: roxy_wasm::LayerLimits,
    pub when: Option<String>,
    pub sample: Option<f64>,
    pub endpoints: HashMap<String, EndpointSpec>,
}

impl AddonDef {
    /// The test layer, named `name` (it reads `x-test-<name>` first).
    pub(crate) fn test_layer(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            wasm: TEST_LAYER,
            mode: AddonMode::Enforce,
            caps: Vec::new(),
            config: serde_json::json!({ "name": name }),
            limits: roxy_wasm::LayerLimits::default(),
            when: None,
            sample: None,
            endpoints: HashMap::new(),
        }
    }

    #[must_use]
    pub(crate) fn caps(mut self, caps: &[roxy_wasm::Capability]) -> Self {
        self.caps = caps.to_vec();
        self
    }

    #[must_use]
    pub(crate) fn limits(mut self, f: impl FnOnce(&mut roxy_wasm::LayerLimits)) -> Self {
        f(&mut self.limits);
        self
    }

    /// A named endpoint the layer may call; `headers` may use
    /// `${secret:name}`.
    #[must_use]
    pub(crate) fn endpoint(
        mut self,
        name: &str,
        url: &str,
        headers: &[(&str, &str)],
        private_ok: bool,
    ) -> Self {
        self.endpoints.insert(
            name.to_owned(),
            EndpointSpec {
                url: url.parse().unwrap(),
                path: EndpointPath::Fixed,
                headers: headers
                    .iter()
                    .map(|(n, v)| (n.parse().unwrap(), (*v).to_owned()))
                    .collect(),
                timeout: Duration::from_secs(5),
                retries: 0,
                private: PrivateAddrs::from_private_ok(private_ok),
            },
        );
        self
    }

    /// Sets how endpoint `name` takes the layer's path.
    #[must_use]
    pub(crate) fn endpoint_path(mut self, name: &str, path: EndpointPath) -> Self {
        self.endpoints.get_mut(name).expect("endpoint").path = path;
        self
    }

    /// Observe mode. The test layer is told not to tag the flows it passes
    /// on, since the host refuses an observer's tags.
    #[must_use]
    pub(crate) fn observe(mut self) -> Self {
        self.mode = AddonMode::Observe;
        self.config["tag"] = serde_json::Value::Bool(false);
        self
    }

    /// Runs only on requests `when` matches.
    #[must_use]
    pub(crate) fn when(mut self, when: &str) -> Self {
        self.when = Some(when.to_owned());
        self
    }

    /// Gets a copy of this share of exchanges (observe mode).
    #[must_use]
    pub(crate) fn sample(mut self, p: f64) -> Self {
        self.sample = Some(p);
        self
    }

    /// The loaded addon, for a stack handed to the server directly rather
    /// than through the builder (`when` is compiled against no rules).
    pub(crate) async fn spec(self) -> Arc<AddonSpec> {
        let none = std::collections::HashSet::new();
        let input = PolicyInput {
            rules: &[],
            metrics: &[],
            secret_names: &none,
            address_lists: &none,
        };
        let rt = roxy_wasm::WasmRuntime::new().unwrap();
        self.load(&rt, &input).await
    }

    async fn load(self, rt: &roxy_wasm::WasmRuntime, input: &PolicyInput<'_>) -> Arc<AddonSpec> {
        let when = self.when.as_deref().map(|w| {
            roxy_rules::Condition::compile(input, &format!("{}.when", self.name), w)
                .unwrap_or_else(|d| panic!("when: {d:?}"))
        });
        let layer = roxy_wasm::Layer::load(
            rt,
            self.wasm.to_vec(),
            roxy_wasm::LayerConfig {
                name: self.name.clone(),
                capabilities: self.caps.into_iter().collect(),
                limits: self.limits,
                config_json: self.config.to_string(),
            },
        )
        .await
        .expect("loading the addon layer");
        Arc::new(AddonSpec {
            name: self.name,
            mode: self.mode,
            kind: crate::addons::AddonImpl::Wasm(layer),
            endpoints: self.endpoints,
            state: StateLimits::default(),
            audit_endpoint: None,
            when,
            sample: self.sample,
        })
    }
}

/// Builds a [`Kit`].
pub(crate) struct KitBuilder {
    rules: String,
    addons: Vec<AddonDef>,
    limits: Limits,
    flags: HttpFlags,
    http: HttpBehaviour,
    /// An explicit metric store; `None` means a real store when there are
    /// metric definitions, otherwise one with every read unavailable.
    metrics: Option<Arc<dyn MetricSource>>,
    /// `metrics:` definitions (YAML); a real metric store holds them.
    metric_defs: String,
    metric_limits: roxy_rules::MetricLimits,
    state: Arc<dyn StateSource>,
    /// Open a capture log: `Some(true)` takes every forwarded exchange,
    /// `Some(false)` only those a `capture` action selects.
    capture: Option<bool>,
    secrets: HashMap<String, String>,
    /// `address_lists:` by name, as list source text.
    address_lists: HashMap<String, String>,
    deny_lists: Vec<String>,
    ws_message_every: u64,
    connection_events: bool,
    log_gate: Option<Arc<LogGate>>,
    ca_server: bool,
    valid_until: Option<DateTime<Utc>>,
    placeholder_policy: bool,
    /// Adjusts the connector's settings before the kit starts.
    upstream: Option<UpstreamTweak>,
}

type UpstreamTweak = Box<dyn FnOnce(&mut UpstreamSettings) + Send>;

impl KitBuilder {
    /// Adjusts the upstream connector's settings (pool size, timeouts).
    #[must_use]
    pub(crate) fn upstream(
        mut self,
        f: impl FnOnce(&mut UpstreamSettings) + Send + 'static,
    ) -> Self {
        self.upstream = Some(Box::new(f));
        self
    }

    /// Opens a capture log that takes every forwarded exchange.
    #[must_use]
    pub(crate) fn capture_all(mut self) -> Self {
        self.capture = Some(true);
        self
    }

    /// Opens a capture log that takes the exchanges a `capture` action
    /// selects.
    #[must_use]
    pub(crate) fn capture_selected(mut self) -> Self {
        self.capture = Some(false);
        self
    }

    /// A secret for `${secret:name}`, scrubbed from the flow log.
    #[must_use]
    pub(crate) fn secret(mut self, name: &str, value: &str) -> Self {
        self.secrets.insert(name.to_owned(), value.to_owned());
        self
    }

    /// An address list (`@name` in rules, or a deny list), as list source
    /// text: one address or CIDR per line.
    #[must_use]
    pub(crate) fn address_list(mut self, name: &str, text: &str) -> Self {
        self.address_lists.insert(name.to_owned(), text.to_owned());
        self
    }

    /// `upstream.deny_lists`.
    #[must_use]
    pub(crate) fn deny_lists(mut self, names: &[&str]) -> Self {
        self.deny_lists = names.iter().map(|n| (*n).to_owned()).collect();
        self
    }

    /// `log.flow.ws_message_every`.
    #[must_use]
    pub(crate) fn ws_message_every(mut self, n: u64) -> Self {
        self.ws_message_every = n;
        self
    }

    /// `log.flow.connection_events`.
    #[must_use]
    pub(crate) fn connection_events(mut self) -> Self {
        self.connection_events = true;
        self
    }

    /// Binds the plain-HTTP CA endpoint on a loopback port
    /// ([`Kit::ca_server_addr`]).
    #[must_use]
    pub(crate) fn ca_server(mut self) -> Self {
        self.ca_server = true;
        self
    }

    /// The initial policy's `valid_until`.
    #[must_use]
    pub(crate) fn valid_until(mut self, t: DateTime<Utc>) -> Self {
        self.valid_until = Some(t);
        self
    }

    /// The initial policy is the startup placeholder: nothing applied yet.
    #[must_use]
    pub(crate) fn placeholder_policy(mut self) -> Self {
        self.placeholder_policy = true;
        self
    }

    /// Puts the flow sink behind `gate`: while it is closed the sink is not
    /// ready and traffic waits.
    #[must_use]
    pub(crate) fn log_gate(mut self, gate: Arc<LogGate>) -> Self {
        self.log_gate = Some(gate);
        self
    }

    /// The real metric store's size caps.
    #[must_use]
    pub(crate) fn metric_limits(mut self, f: impl FnOnce(&mut roxy_rules::MetricLimits)) -> Self {
        f(&mut self.metric_limits);
        self
    }

    #[must_use]
    pub(crate) fn rules(mut self, yaml: &str) -> Self {
        yaml.clone_into(&mut self.rules);
        self
    }

    #[must_use]
    pub(crate) fn addon(mut self, a: AddonDef) -> Self {
        self.addons.push(a);
        self
    }

    #[must_use]
    pub(crate) fn limits(mut self, f: impl FnOnce(&mut Limits)) -> Self {
        f(&mut self.limits);
        self
    }

    #[must_use]
    pub(crate) fn flags(mut self, f: impl FnOnce(&mut HttpFlags)) -> Self {
        f(&mut self.flags);
        self
    }

    #[must_use]
    pub(crate) fn http(mut self, f: impl FnOnce(&mut HttpBehaviour)) -> Self {
        f(&mut self.http);
        self
    }

    /// The metric store, used even when there are metric definitions.
    #[must_use]
    pub(crate) fn metrics(mut self, m: Arc<dyn MetricSource>) -> Self {
        self.metrics = Some(m);
        self
    }

    /// Metric definitions (YAML, as under `metrics:`), held in a real
    /// metric store.
    #[must_use]
    pub(crate) fn metric_defs(mut self, yaml: &str) -> Self {
        yaml.clone_into(&mut self.metric_defs);
        self
    }

    /// The state store (default: none, every write fails).
    #[must_use]
    pub(crate) fn state(mut self, s: Arc<dyn StateSource>) -> Self {
        self.state = s;
        self
    }

    pub(crate) async fn start(self) -> Kit {
        roxy_tls::install_crypto_provider();
        let dir = tempfile::tempdir().unwrap();
        let ca = Arc::new(Ca::generate(dir.path()).unwrap());
        let minter = Arc::new(LeafMinter::new(ca.clone(), 64).unwrap());
        let sink = Arc::new(MemorySink::new());
        let upstream = Upstream::new(minter.clone());

        let rules: Vec<RuleConfig> = serde_yaml_ng::from_str(&self.rules).unwrap();
        let metric_defs: Vec<roxy_rules::MetricConfig> = if self.metric_defs.is_empty() {
            Vec::new()
        } else {
            serde_yaml_ng::from_str(&self.metric_defs).unwrap()
        };
        let base = PolicyBase::new(self.secrets, &self.address_lists, self.deny_lists);
        let secret_names = base.secrets.keys().cloned().collect();
        let list_names = base.address_lists.keys().cloned().collect();
        let input = PolicyInput {
            rules: &rules,
            metrics: &metric_defs,
            secret_names: &secret_names,
            address_lists: &list_names,
        };
        let policy = Policy::compile(&input).unwrap_or_else(|d| panic!("rules: {d:?}"));

        let samples = Arc::new(Mutex::new(Vec::new()));
        let metrics = metric_source(self.metrics, &policy, self.metric_limits, samples.clone());

        let rt = roxy_wasm::WasmRuntime::new().unwrap();
        let mut addons = Vec::new();
        for a in self.addons {
            addons.push(a.load(&rt, &input).await);
        }

        let (mut settings, dns) = upstream_settings(&upstream);
        if let Some(f) = self.upstream {
            f(&mut settings);
        }
        let (limits, flags, http) = (self.limits.clone(), self.flags.clone(), self.http.clone());
        let capture = self
            .capture
            .map(|all| Arc::new(capture_log(&dir.path().join("capture"), all)));
        let server_sink: Arc<dyn FlowSink> = match &self.log_gate {
            Some(gate) => Arc::new(gate::GatedSink::new(sink.clone(), gate.clone())),
            None => sink.clone(),
        };
        let server = Server::start(RuntimeConfig {
            placeholder_policy: self.placeholder_policy,
            listeners: Vec::new(),
            ca_server: self.ca_server.then(|| "127.0.0.1:0".parse().unwrap()),
            ca: ca.clone(),
            minter: minter.clone(),
            upstream_tls: UpstreamTlsOptions {
                extra_roots_pem: vec![dir.path().join(roxy_tls::CA_CERT_FILE)],
                ..UpstreamTlsOptions::default()
            },
            dns,
            max_connections: 1024,
            max_connections_per_client: 1024,
            connection_events: self.connection_events,
            ws_message_every: self.ws_message_every,
            sink: server_sink,
            capture: capture.clone(),
            metrics,
            state: self.state,
            policy: PolicyUpdate {
                policy,
                valid_until: self.valid_until,
                secrets: base.secrets.clone(),
                redactor: Redactor::new(),
                limits: self.limits,
                flags: self.flags,
                http: self.http,
                upstream: settings.clone(),
                address_lists: base.address_lists.clone(),
                deny_lists: base.deny_lists.clone(),
                addons,
            },
        })
        .await
        .unwrap();
        Kit {
            server,
            sink,
            upstream,
            minter,
            capture,
            samples,
            ca_file: dir.path().join(roxy_tls::CA_CERT_FILE),
            limits,
            flags,
            http,
            settings,
            base,
            _dir: dir,
        }
    }
}

/// The test client's connection, as the accept loop would describe it:
/// listener `main` for the proxy, `gateway` for the `http` listener.
fn client_conn(mode: ListenerMode) -> ClientConn {
    let name = match mode {
        ListenerMode::HttpProxy => "main",
        ListenerMode::Http => "gateway",
    };
    ClientConn {
        id: Ulid::generate(),
        listener: Arc::new(ListenerInfo {
            name: name.to_owned(),
            mode,
        }),
        peer: "192.0.2.7:40000".parse().unwrap(),
        original_dst: None,
    }
}

/// What every policy of a kit shares: its secrets and address lists.
struct PolicyBase {
    secrets: HashMap<String, String>,
    address_lists: Arc<AddressLists>,
    deny_lists: Vec<String>,
}

impl PolicyBase {
    /// Parses each address list's source text; a malformed list panics.
    fn new(
        secrets: HashMap<String, String>,
        lists: &HashMap<String, String>,
        deny_lists: Vec<String>,
    ) -> Self {
        let address_lists: AddressLists = lists
            .iter()
            .map(|(name, text)| {
                let list = AddressList::parse(name, text).unwrap_or_else(|e| panic!("{e}"));
                (name.clone(), Arc::new(list))
            })
            .collect();
        Self {
            secrets,
            address_lists: Arc::new(address_lists),
            deny_lists,
        }
    }
}

/// A running roxy with its scripted upstream and flow log.
pub(crate) struct Kit {
    pub server: Server,
    pub sink: Arc<MemorySink>,
    pub upstream: Arc<Upstream>,
    /// roxy's leaf minter, shared with the scripted upstream.
    pub minter: Arc<LeafMinter>,
    /// The capture log, with [`KitBuilder::capture_all`].
    pub capture: Option<Arc<crate::capture::CaptureLog>>,
    /// Every sample recorded in the kit's own metric store (the one
    /// [`KitBuilder::metric_defs`] fills; empty with an explicit
    /// [`KitBuilder::metrics`]).
    pub samples: Arc<Mutex<Vec<Sample>>>,
    ca_file: std::path::PathBuf,
    pub(crate) limits: Limits,
    pub(crate) flags: HttpFlags,
    pub(crate) http: HttpBehaviour,
    settings: UpstreamSettings,
    base: PolicyBase,
    _dir: tempfile::TempDir,
}

impl Kit {
    pub(crate) fn builder() -> KitBuilder {
        KitBuilder {
            rules: ALLOW_UP.to_owned(),
            addons: Vec::new(),
            limits: Limits::default(),
            flags: HttpFlags::default(),
            http: HttpBehaviour::default(),
            metrics: None,
            metric_defs: String::new(),
            metric_limits: roxy_rules::MetricLimits {
                max_keys: 1000,
                ..roxy_rules::MetricLimits::default()
            },
            state: Arc::new(UnavailableState),
            capture: None,
            secrets: HashMap::new(),
            address_lists: HashMap::new(),
            deny_lists: Vec::new(),
            ws_message_every: 0,
            connection_events: false,
            log_gate: None,
            ca_server: false,
            valid_until: None,
            placeholder_policy: false,
            upstream: None,
        }
    }

    /// The CA endpoint's address, with [`KitBuilder::ca_server`].
    pub(crate) fn ca_server_addr(&self) -> std::net::SocketAddr {
        self.server.ca_server_addr().expect("ca_server")
    }

    /// The CA certificate, as the CA endpoint serves it.
    pub(crate) fn ca_pem(&self) -> String {
        self.server.shared().ca.cert_pem()
    }

    /// Serves a connection the way the accept loop does, so a server
    /// shutdown reaches it (`stop`, then the kill switch).
    fn spawn_conn(&self, fut: impl std::future::Future<Output = ()> + Send + 'static) {
        let shared = self.server.shared();
        let slot = crate::server::conn_slot(shared, "192.0.2.7".parse().unwrap()).unwrap();
        shared.spawn_conn(slot, fut);
    }

    /// A raw client connection to the proxy port.
    pub(crate) fn connect(&self) -> tokio::io::DuplexStream {
        let (client, server) = tokio::io::duplex(64 * 1024);
        self.serve_client(Box::new(server));
        client
    }

    /// A raw client connection to the proxy port that the test can reset:
    /// after [`Reset::reset`], roxy's reads and writes on it fail.
    pub(crate) fn connect_resettable(&self) -> (tokio::io::DuplexStream, Reset) {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let reset = Reset::default();
        self.serve_client(Box::new(Resettable {
            inner: server,
            reset: reset.clone(),
        }));
        (client, reset)
    }

    fn serve_client(&self, server: crate::io::BoxIo) {
        self.spawn_conn(crate::conn::serve_http_proxy(
            server,
            client_conn(ListenerMode::HttpProxy),
            self.server.shared().clone(),
        ));
    }

    /// A raw client connection to an `http` listener (named `gateway`).
    pub(crate) fn connect_http(&self) -> tokio::io::DuplexStream {
        let (client, server) = tokio::io::duplex(64 * 1024);
        self.spawn_conn(crate::conn::serve_http(
            Box::new(server),
            client_conn(ListenerMode::Http),
            self.server.shared().clone(),
        ));
        client
    }

    /// Sends `bytes` on a fresh `http`-listener connection and reads until
    /// EOF (or 10 s): what came back, and whether the connection closed.
    pub(crate) async fn raw_http(&self, bytes: &[u8]) -> (String, bool) {
        let mut io = self.connect_http();
        io.write_all(bytes).await.unwrap();
        let (out, eof) = read_to_eof(&mut io).await;
        (String::from_utf8_lossy(&out).into_owned(), eof)
    }

    /// An HTTP/1.1 client on an `http` listener: origin-form requests with
    /// `Host: <host>`.
    pub(crate) async fn http_client(&self, host: &str) -> Client {
        Client::h1(self.connect_http(), Some(host)).await
    }

    /// A raw client that sent `bytes` to the proxy port and was gone before
    /// roxy read them: roxy parses what arrived, then finds nobody to write
    /// to.
    pub(crate) async fn connect_and_leave(&self, bytes: &[u8]) {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        client.write_all(bytes).await.unwrap();
        drop(client);
        self.spawn_conn(crate::conn::serve_http_proxy(
            Box::new(server),
            client_conn(ListenerMode::HttpProxy),
            self.server.shared().clone(),
        ));
    }

    /// Sends `bytes` on a fresh proxy-port connection and reads until EOF
    /// (or 10 s): what came back, and whether the connection closed.
    pub(crate) async fn raw(&self, bytes: &[u8]) -> (String, bool) {
        let mut io = self.connect();
        io.write_all(bytes).await.unwrap();
        let (out, eof) = read_to_eof(&mut io).await;
        (String::from_utf8_lossy(&out).into_owned(), eof)
    }

    /// An HTTP/1.1 client on the proxy port (absolute-form requests).
    pub(crate) async fn h1(&self) -> Client {
        Client::h1(self.connect(), None).await
    }

    /// `CONNECT host:443`, TLS with roxy's leaf, then HTTP/2 (`h2`) or
    /// HTTP/1.1 inside.
    pub(crate) async fn tunnel(&self, host: &str, h2: bool) -> Client {
        let io = self.connect_tunnel(host, 443).await;
        self.tls_client(io, host, h2).await
    }

    /// `CONNECT host:port`, answered `200`; the raw tunnel.
    pub(crate) async fn connect_tunnel(&self, host: &str, port: u16) -> tokio::io::DuplexStream {
        let mut io = self.connect();
        let connect = format!("CONNECT {host}:{port} HTTP/1.1\r\nhost: {host}:{port}\r\n\r\n");
        io.write_all(connect.as_bytes()).await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut b = [0u8; 1];
            assert_eq!(io.read(&mut b).await.unwrap(), 1, "CONNECT: EOF");
            head.push(b[0]);
        }
        let head = String::from_utf8_lossy(&head);
        assert!(head.starts_with("HTTP/1.1 200"), "CONNECT: {head}");
        io
    }

    /// Roxy's CA as a client trust store.
    pub(crate) fn client_tls(&self) -> rustls::ClientConfig {
        (*roxy_tls::client_config(&UpstreamTlsOptions {
            extra_roots_pem: vec![self.ca_file.clone()],
            ..UpstreamTlsOptions::default()
        })
        .unwrap())
        .clone()
    }

    /// TLS for `host` over `io`, trusting roxy's CA and offering `alpn`.
    pub(crate) async fn tls_connect<IO>(
        &self,
        io: IO,
        host: &str,
        alpn: &[&[u8]],
    ) -> std::io::Result<tokio_rustls::client::TlsStream<IO>>
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let mut cfg = self.client_tls();
        cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        let name = roxy_tls::server_name(&roxy_http::url::parse_host(host.as_bytes()).unwrap());
        tokio_rustls::TlsConnector::from(Arc::new(cfg))
            .connect(name, io)
            .await
    }

    async fn tls_client<IO>(&self, io: IO, host: &str, h2: bool) -> Client
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let alpn: &[&[u8]] = if h2 { &[b"h2"] } else { &[b"http/1.1"] };
        let tls = self.tls_connect(io, host, alpn).await.unwrap();
        if h2 {
            Client::h2(tls, host).await
        } else {
            Client::h1(tls, Some(host)).await
        }
    }

    /// A WebSocket upgrade to `http://up.test<path>` on the proxy port.
    /// Returns the response status and, after a `101`, the upgraded
    /// stream.
    pub(crate) async fn websocket(
        &self,
        path: &str,
        headers: &[(&str, &str)],
    ) -> (u16, Option<TokioIo<hyper::upgrade::Upgraded>>) {
        self.websocket_over(self.h1().await, path, headers).await
    }

    /// [`Kit::websocket`] over the client `c`.
    pub(crate) async fn websocket_over(
        &self,
        mut c: Client,
        path: &str,
        headers: &[(&str, &str)],
    ) -> (u16, Option<TokioIo<hyper::upgrade::Upgraded>>) {
        let mut hs = vec![
            ("connection", "upgrade"),
            ("upgrade", "websocket"),
            ("sec-websocket-version", "13"),
            ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
        ];
        hs.extend_from_slice(headers);
        let req = c.request("GET", path, &hs).body(Body::empty()).unwrap();
        let res = c.send(req).await.unwrap();
        let status = res.status().as_u16();
        if status != 101 {
            return (status, None);
        }
        let up = hyper::upgrade::on(res).await.unwrap();
        (status, Some(TokioIo::new(up)))
    }

    /// A WebSocket to `http://up.test<path>` on the proxy port, after a
    /// `101`.
    pub(crate) async fn ws(&self, path: &str, headers: &[(&str, &str)]) -> Ws {
        let (status, io) = self.websocket(path, headers).await;
        assert_eq!(status, 101);
        tokio_tungstenite::WebSocketStream::from_raw_socket(
            io.unwrap(),
            tokio_tungstenite::tungstenite::protocol::Role::Client,
            None,
        )
        .await
    }

    /// Waits until `n` events of `kind` were logged; returns them.
    pub(crate) async fn events(&self, kind: &str, n: usize) -> Vec<serde_json::Value> {
        self.sink.wait_for(kind, n, Duration::from_secs(10)).await
    }

    /// The flow's single `request` event.
    pub(crate) async fn request_event(&self) -> serde_json::Value {
        self.events("request", 1).await.remove(0)
    }

    /// Swaps in a new policy with these rules (no metrics, no addons); the
    /// limits, flags, upstream settings, secrets and address lists stay.
    pub(crate) fn reload(&self, rules: &str) {
        self.reload_lease(rules, None);
    }

    /// [`Self::reload`] with a `valid_until` on the new policy.
    pub(crate) fn reload_lease(&self, rules: &str, valid_until: Option<DateTime<Utc>>) {
        let rules: Vec<RuleConfig> = serde_yaml_ng::from_str(rules).unwrap();
        let secret_names = self.base.secrets.keys().cloned().collect();
        let list_names = self.base.address_lists.keys().cloned().collect();
        let input = PolicyInput {
            rules: &rules,
            metrics: &[],
            secret_names: &secret_names,
            address_lists: &list_names,
        };
        let policy = Policy::compile(&input).unwrap_or_else(|d| panic!("rules: {d:?}"));
        self.server
            .reload(PolicyUpdate {
                policy,
                valid_until,
                secrets: self.base.secrets.clone(),
                redactor: Redactor::new(),
                limits: self.limits.clone(),
                flags: self.flags.clone(),
                http: self.http.clone(),
                upstream: self.settings.clone(),
                address_lists: self.base.address_lists.clone(),
                deny_lists: self.base.deny_lists.clone(),
                addons: Vec::new(),
            })
            .unwrap();
    }

    /// Everything captured so far, as `(header, payload)` records.
    pub(crate) fn captured(&self) -> Vec<(serde_json::Value, Vec<u8>)> {
        let log = self.capture.as_ref().expect("capture_all");
        assert!(log.flush());
        crate::capture::tests::parse(&std::fs::read(log.path()).unwrap())
    }

    /// Waits until `n` requests have reached the upstream (their bodies may
    /// still be arriving).
    pub(crate) async fn wait_arrived(&self, n: usize) -> Vec<Seen> {
        let wait = async {
            loop {
                let seen = self.upstream.seen();
                if seen.len() >= n {
                    return seen;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(10), wait)
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "upstream: wanted {n} requests, have {:#?}",
                    self.upstream.seen()
                )
            })
    }
}

/// A client over HTTP/1.1 or HTTP/2.
pub(crate) enum Client {
    /// `tunnel`: the CONNECT host, or the `Host` on an `http` listener
    /// (origin-form requests), or `None` on the proxy port (absolute-form
    /// requests to `up.test`).
    H1 {
        send: hyper::client::conn::http1::SendRequest<Body>,
        tunnel: Option<String>,
        conn: tokio::task::JoinHandle<()>,
    },
    H2 {
        send: hyper::client::conn::http2::SendRequest<Body>,
        host: String,
        conn: tokio::task::JoinHandle<()>,
    },
}

impl Client {
    async fn h1<IO>(io: IO, tunnel: Option<&str>) -> Self
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let (send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
            .await
            .unwrap();
        let conn = tokio::spawn(async move {
            let _ = conn.with_upgrades().await;
        });
        Self::H1 {
            send,
            tunnel: tunnel.map(str::to_owned),
            conn,
        }
    }

    async fn h2<IO>(io: IO, host: &str) -> Self
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let (send, conn) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(io))
                .await
                .unwrap();
        let conn = tokio::spawn(async move {
            let _ = conn.await;
        });
        Self::H2 {
            send,
            host: host.to_owned(),
            conn,
        }
    }

    /// Drops the connection where it stands (no GOAWAY, no close frame):
    /// roxy sees the client vanish.
    pub(crate) fn kill(&self) {
        match self {
            Self::H1 { conn, .. } | Self::H2 { conn, .. } => conn.abort(),
        }
    }

    /// Waits until roxy has closed the connection.
    pub(crate) async fn closed(&mut self) {
        match self {
            Self::H1 { conn, .. } | Self::H2 { conn, .. } => {
                tokio::time::timeout(Duration::from_secs(10), conn)
                    .await
                    .expect("the connection closes")
                    .unwrap();
            }
        }
    }

    /// A request for `path` on `up.test` with `headers`; see
    /// [`Client::request_to`].
    pub(crate) fn request(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
    ) -> http::request::Builder {
        self.request_to("up.test", method, path, headers)
    }

    /// A request shaped for this client: an absolute `http://<host>` URI
    /// plus `host` on the proxy port, origin form plus `host` in an h1
    /// tunnel, an absolute `https` URI over h2. In a tunnel `host` is the
    /// tunnel's.
    pub(crate) fn request_to(
        &self,
        host: &str,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
    ) -> http::request::Builder {
        let mut b = http::Request::builder().method(method);
        b = match self {
            Self::H1 { tunnel: None, .. } => {
                b.uri(format!("http://{host}{path}")).header("host", host)
            }
            Self::H1 {
                tunnel: Some(t), ..
            } => b.uri(path).header("host", t.as_str()),
            Self::H2 { host: t, .. } => b.uri(format!("https://{t}{path}")),
        };
        for (n, v) in headers {
            b = b.header(*n, *v);
        }
        b
    }

    /// Sends `req`.
    pub(crate) async fn send(
        &mut self,
        req: http::Request<Body>,
    ) -> Result<http::Response<Incoming>, hyper::Error> {
        match self {
            Self::H1 { send, .. } => {
                send.ready().await?;
                send.send_request(req).await
            }
            Self::H2 { send, .. } => {
                send.ready().await?;
                send.send_request(req).await
            }
        }
    }

    /// Starts `req` on its own task, so the test can keep feeding its body
    /// while waiting for the answer. On h2 the connection stays usable
    /// through `self`.
    pub(crate) fn start(
        &mut self,
        req: http::Request<Body>,
    ) -> tokio::task::JoinHandle<Result<Answer, hyper::Error>> {
        match self {
            Self::H1 { send, .. } => {
                // The caller has not sent anything else on this connection,
                // so it is ready.
                let fut = send.send_request(req);
                tokio::spawn(async move { Ok(Answer::read(fut.await?).await) })
            }
            Self::H2 { send, .. } => {
                let mut send = send.clone();
                tokio::spawn(async move {
                    send.ready().await?;
                    Ok(Answer::read(send.send_request(req).await?).await)
                })
            }
        }
    }

    /// Sends a request with a fixed body and collects the answer.
    pub(crate) async fn call(
        &mut self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &'static [u8],
    ) -> Answer {
        let req = self
            .request(method, path, headers)
            .body(Body::from_bytes(Bytes::from_static(body)))
            .unwrap();
        let res = self.send(req).await.expect("response");
        Answer::read(res).await
    }
}

/// A collected response.
#[derive(Debug)]
pub(crate) struct Answer {
    pub status: u16,
    pub headers: http::HeaderMap,
    /// `Err` if the body was cut.
    pub body: Result<Bytes, String>,
}

impl Answer {
    pub(crate) async fn read(res: http::Response<Incoming>) -> Self {
        let (parts, body) = res.into_parts();
        let body = body
            .collect()
            .await
            .map(http_body_util::Collected::to_bytes)
            .map_err(|e| e.to_string());
        Self {
            status: parts.status.as_u16(),
            headers: parts.headers,
            body,
        }
    }

    pub(crate) fn text(&self) -> String {
        String::from_utf8_lossy(self.body.as_ref().expect("complete body")).into_owned()
    }

    pub(crate) fn json(&self) -> serde_json::Value {
        serde_json::from_slice(self.body.as_ref().expect("complete body")).expect("JSON body")
    }
}

/// The connector's settings, with the scripted upstream behind the dial,
/// and a resolver for the test names.
fn upstream_settings(upstream: &Arc<Upstream>) -> (UpstreamSettings, DnsSettings) {
    let mut settings = UpstreamSettings::default();
    // Never consult real DNS: unknown names fail.
    let mut dns = DnsSettings {
        servers: Some(vec!["127.0.0.1:9".parse().unwrap()]),
        ..DnsSettings::default()
    };
    for (name, ips) in [
        ("up.test", vec![UP_IP]),
        ("private.test", vec![PRIVATE_IP]),
        ("mixed.test", vec![UP_IP, PRIVATE_IP]),
        ("down.test", vec![DOWN_IP]),
        ("stall.test", vec![STALL_IP]),
    ] {
        let ips = ips.iter().map(|ip| ip.parse().unwrap()).collect();
        dns.static_hosts.insert(name.to_owned(), ips);
    }
    settings.connect_timeout = Duration::from_secs(5);
    let up = upstream.clone();
    settings.dial = Some(TestDial(Arc::new(move |addr| {
        let up = up.clone();
        Box::pin(async move {
            if addr.ip().to_string() == STALL_IP {
                return Ok(stalled());
            }
            up.dial(addr)
        })
    })));
    (settings, dns)
}

/// A connection whose peer reads everything and never writes.
fn stalled() -> crate::io::BoxIo {
    let (mut ours, theirs) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while matches!(ours.read(&mut buf).await, Ok(n) if n > 0) {}
    });
    Box::new(theirs)
}

/// Reads a response head byte by byte (so nothing after it is consumed).
pub(crate) async fn read_head<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> String {
    let mut buf = Vec::new();
    loop {
        let mut b = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(10), r.read(&mut b))
            .await
            .expect("timed out reading a response head")
            .unwrap_or(0);
        if n == 0 {
            break;
        }
        buf.push(b[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// Reads one response (head + `content-length` body).
pub(crate) async fn read_response<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> (String, Vec<u8>) {
    let head = read_head(r).await;
    let len = head
        .to_ascii_lowercase()
        .lines()
        .find_map(|l| {
            l.strip_prefix("content-length: ")
                .map(|v| v.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    tokio::time::timeout(Duration::from_secs(10), r.read_exact(&mut body))
        .await
        .expect("timed out reading a body")
        .unwrap();
    (head, body)
}

/// Reads until EOF (or 10 s). Returns what was read and whether EOF was
/// seen.
pub(crate) async fn read_to_eof<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match tokio::time::timeout(Duration::from_secs(10), r.read(&mut buf)).await {
            Ok(Ok(0) | Err(_)) => return (out, true),
            Ok(Ok(n)) => out.extend_from_slice(&buf[..n]),
            Err(_) => return (out, false),
        }
    }
}

/// A WebSocket client over a tunnel the kit opened.
pub(crate) type Ws = tokio_tungstenite::WebSocketStream<TokioIo<hyper::upgrade::Upgraded>>;

/// The metric store a kit runs with: the explicit one if given, else a
/// real store for the policy's metric definitions, else none.
fn metric_source(
    explicit: Option<Arc<dyn MetricSource>>,
    policy: &Policy,
    limits: roxy_rules::MetricLimits,
    samples: Arc<Mutex<Vec<Sample>>>,
) -> Arc<dyn MetricSource> {
    match explicit {
        Some(m) => m,
        None if policy.metric_defs().is_empty() => Arc::new(UnavailableMetrics),
        None => Arc::new(StoreMetrics {
            store: roxy_rules::MetricStore::with_limits(policy.metric_defs(), limits),
            samples,
        }),
    }
}

/// A capture log in `dir`; `all` takes every forwarded exchange.
fn capture_log(dir: &std::path::Path, all: bool) -> crate::capture::CaptureLog {
    crate::capture::CaptureLog::open(
        dir,
        crate::capture::CaptureOptions {
            max_body_bytes: 16 * 1024 * 1024,
            all,
            writer: roxy_log::WriterOptions::default(),
            rotate: roxy_log::RotateOptions::default(),
        },
    )
    .unwrap()
}

/// A request body the test feeds chunk by chunk.
pub(crate) fn streaming_body() -> (BodySender, Body) {
    Body::channel(u64::MAX, None)
}

/// What the flow log's `body_sha256` of `data` should read.
pub(crate) fn sha256_hex(data: &[u8]) -> String {
    crate::body::hex(ring::digest::digest(&ring::digest::SHA256, data).as_ref())
}

/// A real metric store behind the proxy's metric trait, keeping every
/// sample it was given for tests to inspect.
struct StoreMetrics {
    store: roxy_rules::MetricStore,
    samples: Arc<Mutex<Vec<Sample>>>,
}

impl MetricSource for StoreMetrics {
    fn get(
        &self,
        id: &str,
        view: &dyn roxy_rules::FlowView,
    ) -> Result<Option<i64>, crate::sources::MetricSourceError> {
        self.store.lookup(id, view).map_err(Into::into)
    }

    fn record(
        &self,
        view: &dyn roxy_rules::FlowView,
        sample: &Sample,
    ) -> Result<(), crate::sources::MetricSourceError> {
        self.samples.lock().unwrap().push(*sample);
        let s = roxy_rules::Sample {
            head: sample.head,
            request_bytes: sample.request_bytes,
            response_bytes: sample.response_bytes,
            denied: sample.denied,
            error: sample.error,
        };
        self.store.record(view, &s).map_err(Into::into)
    }
}

#[cfg(test)]
mod smoke {
    use super::*;

    #[tokio::test]
    async fn a_request_reaches_the_scripted_upstream() {
        let kit = Kit::builder().start().await;
        let mut c = kit.h1().await;
        let a = c.call("POST", "/hello", &[], b"abc").await;
        assert_eq!(a.status, 200, "{a:?}");
        assert_eq!(a.json()["path"], "/hello");
        assert_eq!(a.json()["body_len"], 3);
        let seen = kit.upstream.wait_seen(1).await;
        assert_eq!(seen[0].body, b"abc");
        assert_eq!(seen[0].complete, Some(true));
        let ev = kit.request_event().await;
        assert_eq!(ev["decision"], "allow", "{ev:#}");
    }

    #[tokio::test]
    async fn tunnels_carry_h1_and_h2() {
        let kit = Kit::builder().start().await;
        for h2 in [false, true] {
            let mut c = kit.tunnel("up.test", h2).await;
            let a = c.call("GET", "/t", &[], b"").await;
            assert_eq!(a.status, 200, "h2={h2} {a:?}");
            assert_eq!(a.json()["path"], "/t");
        }
        let seen = kit.upstream.wait_seen(2).await;
        assert!(seen.iter().all(|s| s.addr.port() == 443));
        let ev = kit.events("request", 2).await;
        let alpn: Vec<_> = ev.iter().map(|e| e["tls"]["alpn"].clone()).collect();
        assert_eq!(alpn, ["http/1.1", "h2"], "{ev:#?}");
    }
}

/// Resets a [`Kit::connect_resettable`] connection.
#[derive(Clone, Default)]
pub(crate) struct Reset(Arc<std::sync::atomic::AtomicBool>);

impl Reset {
    /// From now on roxy's reads and writes on the connection fail. A read
    /// already waiting fails once the client side is dropped.
    pub(crate) fn reset(&self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn is_reset(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// roxy's side of a connection the test can reset.
struct Resettable {
    inner: tokio::io::DuplexStream,
    reset: Reset,
}

fn connection_reset() -> std::io::Error {
    std::io::ErrorKind::ConnectionReset.into()
}

impl tokio::io::AsyncRead for Resettable {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.reset.is_reset() {
            return std::task::Poll::Ready(Err(connection_reset()));
        }
        let r = std::task::ready!(std::pin::Pin::new(&mut self.inner).poll_read(cx, buf));
        if self.reset.is_reset() {
            return std::task::Poll::Ready(Err(connection_reset()));
        }
        std::task::Poll::Ready(r)
    }
}

impl tokio::io::AsyncWrite for Resettable {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.reset.is_reset() {
            return std::task::Poll::Ready(Err(connection_reset()));
        }
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
