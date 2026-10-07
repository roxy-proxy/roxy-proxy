//! Node mode end to end: a scripted control plane, a roxy node and the
//! test upstream.

mod support;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use roxy::node::{Bootstrap, NodeOptions, NodeRunning};
use roxy_node::protocol::{FlowAck, FlowSettings, Lease, OnHighWater, PolicyState};
use roxy_node::testkit::{MockServer, Reply};
use roxy_proxy::MemorySink;
use serde_json::Value;
use support::{SECRET, TestCa, Upstream, start_upstream, test_ca};
use support::{read_head, read_response, rustls_pemfile_certs};

const ENROL: &str = "/roxy/v1/enrol";
const LEASE: &str = "/roxy/v1/lease";
const FLOWS: &str = "/roxy/v1/flows";

struct NodeHarness {
    mock: MockServer,
    dir: tempfile::TempDir,
    upstream: Upstream,
    _test_ca: TestCa,
    sink: Arc<MemorySink>,
    running: Option<NodeRunning>,
    /// The bootstrap proxy listener.
    bootstrap_proxy: SocketAddr,
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

impl NodeHarness {
    async fn start() -> Self {
        let mock = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let test_ca = test_ca();
        std::fs::write(dir.path().join("upstream-ca.pem"), &test_ca.pem).unwrap();
        std::fs::write(dir.path().join("token"), SECRET).unwrap();
        std::fs::write(dir.path().join("enrol-token"), "tok-1\n").unwrap();
        std::fs::write(dir.path().join("cp-ca.pem"), &mock.ca.pem).unwrap();
        let upstream = start_upstream(&test_ca);
        mock.push(ENROL, Reply::issue("n1"));
        mock.fallback(
            FLOWS,
            Reply::json(
                200,
                &FlowAck {
                    acked_through: u64::MAX,
                },
            ),
        );
        Self {
            mock,
            dir,
            upstream,
            _test_ca: test_ca,
            sink: Arc::new(MemorySink::new()),
            running: None,
            bootstrap_proxy: "127.0.0.1:0".parse().unwrap(),
        }
    }

    fn state_dir(&self) -> std::path::PathBuf {
        self.dir.path().join("state")
    }

    fn options(&self, with_token: bool) -> NodeOptions {
        NodeOptions {
            enrol_token_file: with_token.then(|| self.dir.path().join("enrol-token")),
            control_plane_ca: Some(self.dir.path().join("cp-ca.pem")),
            bootstrap: Bootstrap {
                proxy_bind: "127.0.0.1:0".parse().unwrap(),
                ca_server_bind: Some("127.0.0.1:0".parse().unwrap()),
            },
            local_sink: Some(self.sink.clone()),
            time_scale: 0.05,
            ..NodeOptions::new(&self.mock.url(), &self.state_dir())
        }
    }

    async fn run(&mut self, with_token: bool) {
        let running = roxy::node::start(self.options(with_token))
            .await
            .unwrap_or_else(|e| panic!("node failed to start: {e:#}"));
        self.bootstrap_proxy = running
            .handler
            .local_addrs()
            .await
            .into_iter()
            .find(|(n, _)| n == "proxy")
            .map(|(_, a)| a)
            .unwrap();
        self.running = Some(running);
    }

    fn running(&self) -> &NodeRunning {
        self.running.as_ref().unwrap()
    }

    /// A rendered config for the lease: the test upstream's CA and hosts,
    /// `rules` and anything in `extra` at the top level.
    fn config(&self, proxy_port: u16, rules: &str, extra: &str) -> String {
        let dir = self.dir.path().display();
        let rules = if rules.trim().is_empty() {
            "rules: []\n".to_owned()
        } else {
            format!("rules:\n{rules}")
        };
        format!(
            "version: 1\nlisteners: [{{ name: proxy, bind: 127.0.0.1:{proxy_port} }}]\n\
             ca_server: {{ bind: 127.0.0.1:0 }}\n\
             tls:\n  upstream:\n    verify: strict+extra_roots\n    extra_roots: [{dir}/upstream-ca.pem]\n\
             limits: {{ header_timeout: 5s, response_header_timeout: 2s }}\n\
             upstream:\n  connect_timeout: 2s\n  dns:\n    resolver: [\"127.0.0.1:9\"]\n    \
             static_hosts: {{ upstream.test: 127.0.0.1 }}\n\
             secrets:\n  token: {{ file: {dir}/token }}\n  lease_token: {{ lease: true }}\n{extra}{rules}"
        )
    }

    /// A lease whose `secrets` map is `{lease_token: <secret>}`.
    fn lease(id: &str, config: &str, secret: &str, epoch: &str) -> Lease {
        Lease {
            lease_id: id.to_owned(),
            valid_for_seconds: 600,
            refresh_after_seconds: 1,
            config: config.to_owned(),
            secrets: [("lease_token".to_owned(), secret.to_owned())].into(),
            state_epoch: epoch.to_owned(),
            flow: FlowSettings {
                ship: true,
                batch_max_bytes: 1 << 20,
                flush_interval_seconds: 1,
                spool_high_water_bytes: 8 << 20,
                on_high_water: OnHighWater::Spool,
            },
            interception_ca: None,
        }
    }

    /// Waits until the node reports `lease_id` as the lease it runs.
    async fn wait_applied(&self, lease_id: &str) {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if self
                    .mock
                    .requests_to(LEASE)
                    .iter()
                    .any(|r| r.node_state().lease_id.as_deref() == Some(lease_id))
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("lease {lease_id} was never reported as applied"));
    }

    async fn proxy_addr(&self) -> SocketAddr {
        self.running()
            .handler
            .local_addrs()
            .await
            .into_iter()
            .find(|(n, _)| n == "proxy")
            .map(|(_, a)| a)
            .expect("a proxy listener")
    }

    fn client(&self, proxy: SocketAddr) -> reqwest::Client {
        let ca = std::fs::read(self.state_dir().join("ca/roxy-ca.pem")).unwrap();
        reqwest::Client::builder()
            .no_proxy()
            .proxy(reqwest::Proxy::all(format!("http://{proxy}")).unwrap())
            .add_root_certificate(reqwest::Certificate::from_pem(&ca).unwrap())
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap()
    }

    fn https_url(&self, path: &str) -> String {
        format!("https://upstream.test:{}{path}", self.upstream.https.port())
    }

    /// `(status, body)` of `GET /readyz` on the running `ca_server`.
    async fn readyz(&self) -> (u16, String) {
        let ca_server = self.running().handler.ca_server_addr().await.unwrap();
        let res = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .get(format!("http://{ca_server}/readyz"))
            .send()
            .await
            .unwrap();
        (res.status().as_u16(), res.text().await.unwrap())
    }

    /// `(status, x-roxy-rule)` of a request through `proxy`.
    async fn get(&self, proxy: SocketAddr, path: &str) -> (u16, Option<String>) {
        let res = self
            .client(proxy)
            .get(self.https_url(path))
            .send()
            .await
            .unwrap();
        let rule = res
            .headers()
            .get("x-roxy-rule")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        (res.status().as_u16(), rule)
    }

    async fn stop(&mut self) {
        if let Some(r) = self.running.take() {
            r.shutdown(Duration::from_secs(1)).await;
        }
    }
}

/// One rule in block YAML, so `when` may hold quotes and brackets.
fn rule(id: &str, when: &str, then: &str) -> String {
    format!("  - id: {id}\n    when: {when}\n    then: {then}\n")
}

const ALLOW: &str = "{ allow: { private_ok: true } }";

fn files_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[tokio::test(flavor = "multi_thread")]
async fn a_node_denies_until_its_first_lease_then_serves_it_and_ships_flows() {
    let mut h = NodeHarness::start().await;
    let port = free_port();
    let config = h.config(
        port,
        &rule(
            "up",
            "host == \"upstream.test\"",
            "[{ set_header: { authorization: \"Bearer ${secret:token}\", x-lease: \"${secret:lease_token}\" } }, { allow: { private_ok: true } }]",
        ),
        "",
    );
    // The lease arrives after a while, so the bootstrap window can be seen.
    let l1 = NodeHarness::lease("L1", &config, "s1", "e1");
    h.mock.push(
        LEASE,
        Reply::Delayed(Duration::from_millis(700), Box::new(Reply::json(200, &l1))),
    );
    h.mock.fallback(LEASE, Reply::json(200, &l1));
    h.run(true).await;

    // Before the lease: the bootstrap listener is up, denies and is not ready.
    let (status, rule) = h.get(h.bootstrap_proxy, "/early").await;
    assert_eq!(status, 403);
    assert_eq!(rule.as_deref(), Some("_default"));
    assert!(h.upstream.seen().is_empty());
    assert_eq!(h.readyz().await, (503, "no_policy".to_owned()));

    h.wait_applied("L1").await;
    // The lease's listener replaced the bootstrap one.
    let proxy = h.proxy_addr().await;
    assert_eq!(proxy.port(), port);
    assert_eq!(h.readyz().await, (200, "ready".to_owned()));
    assert_eq!(h.get(proxy, "/after").await, (200, None));
    let seen = h.upstream.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].header("authorization"),
        Some(format!("Bearer {SECRET}").as_str()),
        "file-sourced secrets are resolved on the node"
    );
    assert_eq!(
        seen[0].header("x-lease"),
        Some("s1"),
        "lease secrets reach the rules"
    );

    // A lease that changes only a secret value: the next request carries
    // the new value.
    h.mock.fallback(
        LEASE,
        Reply::json(200, &NodeHarness::lease("L1b", &config, "s2", "e1")),
    );
    h.wait_applied("L1b").await;
    assert_eq!(h.get(proxy, "/rotated").await, (200, None));
    assert_eq!(h.upstream.seen()[1].header("x-lease"), Some("s2"));

    // Flow events reach the control plane with the node's sequence numbers.
    let posts = h.mock.wait_for(FLOWS, 2).await;
    let shipped: Vec<Value> = posts
        .iter()
        .flat_map(|p| p.json()["events"].as_array().unwrap().clone())
        .collect();
    assert!(
        shipped
            .iter()
            .all(|e| e["seq"].is_u64() && e["ts"].is_string()),
        "{shipped:?}"
    );
    assert!(
        shipped
            .iter()
            .any(|e| e["event"] == "request" && e["rules"][0] == "up"),
        "{shipped:?}"
    );
    assert_eq!(posts[0].json()["node_id"], "n1");
    assert_eq!(posts[0].json()["lease_id"], "L1");
    assert_eq!(posts[0].client.as_deref(), Some("n1"));
    let early_denied = h
        .sink
        .events()
        .iter()
        .any(|e| e["event"] == "request" && e["terminal_rule"] == "_default");
    assert!(early_denied, "the local flow log keeps every event too");

    // Nothing but the identity, the counter and the CA touch the disk.
    assert_eq!(
        files_in(&h.state_dir()),
        ["ca", "flow.seq", "node.crt", "node.key"]
    );
    assert_eq!(
        files_in(&h.state_dir().join("ca")),
        ["roxy-ca.key", "roxy-ca.pem"]
    );
    let state_text = std::fs::read_to_string(h.state_dir().join("node.crt")).unwrap();
    assert!(!state_text.contains(SECRET));

    h.stop().await;

    // A second start finds the identity and goes straight to the lease.
    h.mock.fallback(
        LEASE,
        Reply::json(200, &NodeHarness::lease("L2", &config, "s1", "e1")),
    );
    h.run(false).await;
    h.wait_applied("L2").await;
    assert_eq!(h.mock.requests_to(ENROL).len(), 1);
    assert_eq!(h.proxy_addr().await.port(), port);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_changed_state_epoch_clears_metric_windows_and_rule_state() {
    let mut h = NodeHarness::start().await;
    let rules = [
        rule("tripped", "state[\"tripped\"] == \"1\"", "deny"),
        rule(
            "trip",
            "path == \"/trip\"",
            "[{ set_state: { key: tripped, value: \"1\" } }, { allow: { private_ok: true } }]",
        ),
        rule("limit", "metric.hits >= 2", "deny"),
        rule("up", "host == \"upstream.test\"", ALLOW),
    ]
    .concat();
    let metrics = "metrics: [{ id: hits, count: requests, window: 1h }]\n";
    let config = h.config(0, &rules, metrics);
    h.mock.fallback(
        LEASE,
        Reply::json(200, &NodeHarness::lease("L1", &config, "s1", "e1")),
    );
    h.run(true).await;
    h.wait_applied("L1").await;
    let proxy = h.proxy_addr().await;
    assert_eq!(h.get(proxy, "/a").await.0, 200);
    assert_eq!(h.get(proxy, "/b").await.0, 200);
    assert_eq!(h.get(proxy, "/c").await, (403, Some("limit".into())));

    // Same epoch, changed config: windows and state carry over.
    let config2 = format!("{config}# v2\n");
    h.mock.fallback(
        LEASE,
        Reply::json(200, &NodeHarness::lease("L2", &config2, "s1", "e1")),
    );
    h.wait_applied("L2").await;
    assert_eq!(h.get(proxy, "/d").await, (403, Some("limit".into())));

    // A new epoch starts the windows afresh.
    h.mock.fallback(
        LEASE,
        Reply::json(200, &NodeHarness::lease("L3", &config2, "s1", "e2")),
    );
    h.wait_applied("L3").await;
    assert_eq!(h.get(proxy, "/e").await, (200, None));
    assert_eq!(h.get(proxy, "/trip").await, (200, None));
    assert_eq!(h.get(proxy, "/f").await, (403, Some("tripped".into())));

    // And clears rule state.
    h.mock.fallback(
        LEASE,
        Reply::json(200, &NodeHarness::lease("L4", &config2, "s1", "e3")),
    );
    h.wait_applied("L4").await;
    assert_eq!(h.get(proxy, "/g").await, (200, None));
    h.stop().await;
}

/// Revocation must hold for any lease, including one whose addon endpoint
/// headers reference a lease secret (the shape a rules-only rebuild would
/// refuse to validate).
#[tokio::test(flavor = "multi_thread")]
async fn revocation_denies_at_once_and_keeps_health_up() {
    let mut h = NodeHarness::start().await;
    let addon = format!(
        "addons:\n  - name: auth\n    kind: service\n    endpoint: svc\n    when: path == \"/never\"\n    \
         endpoints:\n      svc:\n        url: {}\n        private_ok: true\n        \
         headers: {{ authorization: \"Bearer ${{secret:lease_token}}\" }}\n",
        h.https_url("/svc")
    );
    let config = h.config(
        0,
        &rule(
            "up",
            "host == \"upstream.test\"",
            "[{ set_header: { x-lease: \"${secret:lease_token}\" } }, { allow: { private_ok: true } }]",
        ),
        &addon,
    );
    h.mock.fallback(
        LEASE,
        Reply::json(200, &NodeHarness::lease("L1", &config, "s1", "e1")),
    );
    h.run(true).await;
    h.wait_applied("L1").await;
    let proxy = h.proxy_addr().await;
    assert_eq!(h.get(proxy, "/ok").await.0, 200);
    assert_eq!(h.upstream.seen()[0].header("x-lease"), Some("s1"));
    h.mock.push(LEASE, Reply::status(410));
    tokio::time::timeout(Duration::from_secs(10), async {
        while !h.running().node.is_revoked() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    // The handler expires the policy before the node marks itself revoked,
    // so the very next request is denied and nothing reaches the upstream.
    assert_eq!(h.get(proxy, "/gone").await, (403, Some("_expired".into())));
    assert_eq!(h.get(proxy, "/never").await, (403, Some("_expired".into())));
    assert_eq!(
        h.upstream.seen().len(),
        1,
        "no request carries a secret after revocation"
    );
    assert_eq!(h.readyz().await, (503, "policy_expired".to_owned()));
    let ca_server = h.running().handler.ca_server_addr().await.unwrap();
    let health = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(format!("http://{ca_server}/healthz"))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let fetches = h.mock.requests_to(LEASE).len();
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(h.mock.requests_to(LEASE).len(), fetches, "polling stopped");
    h.stop().await;
}

/// Shutdown lets in-flight exchanges finish before the spool closes, so
/// their flow events still reach the control plane.
#[tokio::test(flavor = "multi_thread")]
async fn shutdown_ships_the_flow_events_of_in_flight_exchanges() {
    use tokio::io::AsyncWriteExt as _;

    let mut h = NodeHarness::start().await;
    let config = h.config(0, &rule("up", "host == \"upstream.test\"", ALLOW), "");
    let mut l1 = NodeHarness::lease("L1", &config, "s1", "e1");
    // Nothing ships on its own: only the drain at shutdown can.
    l1.flow.flush_interval_seconds = 3600;
    h.mock.fallback(LEASE, Reply::json(200, &l1));
    h.run(true).await;
    h.wait_applied("L1").await;
    let proxy = h.proxy_addr().await;
    assert_eq!(h.get(proxy, "/before").await.0, 200);

    // A request whose body is still arriving when shutdown begins.
    let authority = format!("upstream.test:{}", h.upstream.https.port());
    let mut tcp = tokio::net::TcpStream::connect(proxy).await.unwrap();
    tcp.write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    assert!(read_head(&mut tcp).await.starts_with("HTTP/1.1 200"));
    let mut roots = rustls::RootCertStore::empty();
    let ca = std::fs::read_to_string(h.state_dir().join("ca/roxy-ca.pem")).unwrap();
    for c in rustls_pemfile_certs(&ca) {
        roots.add(c).unwrap();
    }
    let tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut stream = tokio_rustls::TlsConnector::from(Arc::new(tls))
        .connect("upstream.test".try_into().unwrap(), tcp)
        .await
        .unwrap();
    stream
        .write_all(
            format!(
                "POST /in-flight HTTP/1.1\r\nHost: {authority}\r\nContent-Length: 10\r\n\r\nfirst"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let running = h.running.take().unwrap();
    let shutdown = tokio::spawn(running.shutdown(Duration::from_secs(5)));
    tokio::time::sleep(Duration::from_millis(300)).await;
    stream.write_all(b"last!").await.unwrap();
    let (head, _) = read_response(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    shutdown.await.unwrap();

    let shipped: Vec<Value> = h
        .mock
        .requests_to(FLOWS)
        .iter()
        .flat_map(|p| p.json()["events"].as_array().unwrap().clone())
        .collect();
    assert!(
        shipped
            .iter()
            .any(|e| e["event"] == "request" && e["req"]["path"] == "/in-flight"),
        "the in-flight exchange's event was shipped: {shipped:?}"
    );
    assert_eq!(h.upstream.seen().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_control_plane_lets_the_lease_run_down() {
    let mut h = NodeHarness::start().await;
    let config = h.config(0, &rule("up", "host == \"upstream.test\"", ALLOW), "");
    let mut lease = NodeHarness::lease("L1", &config, "s1", "e1");
    lease.valid_for_seconds = 1;
    h.mock.push(LEASE, Reply::json(200, &lease));
    h.mock.fallback(LEASE, Reply::status(503));
    h.run(true).await;
    h.wait_applied("L1").await;
    let proxy = h.proxy_addr().await;
    assert_eq!(h.get(proxy, "/ok").await.0, 200);
    tokio::time::sleep(Duration::from_millis(1300)).await;
    assert_eq!(h.get(proxy, "/late").await, (403, Some("_expired".into())));
    assert_eq!(h.readyz().await, (503, "policy_expired".to_owned()));
    let so_far = h.mock.requests_to(LEASE).len();
    let fetches = h.mock.wait_for(LEASE, so_far + 1).await;
    let last = fetches.last().unwrap().node_state();
    assert_eq!(last.policy_state, PolicyState::Expired);
    assert_eq!(
        last.lease_id.as_deref(),
        Some("L1"),
        "the run-down lease is still reported"
    );

    // A lease that reaches the node recovers it without a restart.
    h.mock.fallback(
        LEASE,
        Reply::json(200, &NodeHarness::lease("L2", &config, "s1", "e1")),
    );
    h.wait_applied("L2").await;
    assert_eq!(h.get(proxy, "/again").await.0, 200);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lease_the_node_cannot_apply_is_refused_and_the_old_one_stays() {
    let mut h = NodeHarness::start().await;
    let config = h.config(0, &rule("up", "host == \"upstream.test\"", ALLOW), "");
    let l1 = NodeHarness::lease("L1", &config, "s1", "e1");
    h.mock.push(LEASE, Reply::json(200, &l1));
    // Invalid rule language.
    let broken = h.config(0, &rule("bad", "host ===", ALLOW), "");
    h.mock.push(
        LEASE,
        Reply::json(200, &NodeHarness::lease("L2", &broken, "s1", "e1")),
    );
    // A config that declares a secret the lease does not supply.
    let mut unsupplied = NodeHarness::lease("L3", &config, "s1", "e1");
    unsupplied.secrets.clear();
    h.mock.push(LEASE, Reply::json(200, &unsupplied));
    h.mock.fallback(LEASE, Reply::json(200, &l1));
    h.run(true).await;
    h.wait_applied("L1").await;
    let proxy = h.proxy_addr().await;
    h.mock.wait_for(LEASE, 4).await;
    let reported: Vec<Option<String>> = h
        .mock
        .requests_to(LEASE)
        .iter()
        .map(|r| r.node_state().lease_id)
        .collect();
    assert_eq!(reported[3].as_deref(), Some("L1"), "{reported:?}");
    assert_eq!(h.get(proxy, "/still").await.0, 200);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn renewals_and_secret_rotations_do_not_rebuild_the_policy() {
    let mut h = NodeHarness::start().await;
    let config = h.config(
        0,
        &rule(
            "up",
            "host == \"upstream.test\"",
            "[{ set_header: { x-lease: \"${secret:lease_token}\" } }, { allow: { private_ok: true } }]",
        ),
        "",
    );
    // A short lease, polled every 50ms (time_scale) with the same reply:
    // every poll re-applies it with nothing changed.
    let mut l1 = NodeHarness::lease("L1", &config, "s1", "e1");
    l1.valid_for_seconds = 1;
    h.mock.fallback(LEASE, Reply::json(200, &l1));
    h.run(true).await;
    h.wait_applied("L1").await;
    let proxy = h.proxy_addr().await;
    let handle = h.running().handler.handle().await.unwrap();
    let snapshot = handle.snapshot_id();
    assert_eq!(h.get(proxy, "/a").await, (200, None));

    // Well past the first lease's end: the renewals moved valid_until
    // without touching the snapshot.
    let fetches = h.mock.requests_to(LEASE).len();
    tokio::time::sleep(Duration::from_millis(1300)).await;
    assert!(h.mock.requests_to(LEASE).len() >= fetches + 3);
    assert_eq!(h.get(proxy, "/b").await, (200, None));
    assert_eq!(h.readyz().await, (200, "ready".to_owned()));
    assert_eq!(
        handle.snapshot_id(),
        snapshot,
        "a renewal rebuilt the snapshot"
    );

    // Secrets only: the next request carries the new value, same snapshot.
    let mut l2 = NodeHarness::lease("L2", &config, "s2", "e1");
    l2.valid_for_seconds = 1;
    h.mock.fallback(LEASE, Reply::json(200, &l2));
    h.wait_applied("L2").await;
    assert_eq!(h.get(proxy, "/c").await, (200, None));
    let seen = h.upstream.seen();
    assert_eq!(seen[1].header("x-lease"), Some("s1"));
    assert_eq!(seen[2].header("x-lease"), Some("s2"));
    assert_eq!(
        handle.snapshot_id(),
        snapshot,
        "a secret swap rebuilt the snapshot"
    );

    // A config change is what rebuilds.
    let config2 = format!("{config}# v2\n");
    h.mock.fallback(
        LEASE,
        Reply::json(200, &NodeHarness::lease("L3", &config2, "s2", "e1")),
    );
    h.wait_applied("L3").await;
    assert_ne!(handle.snapshot_id(), snapshot);
    assert_eq!(h.get(proxy, "/d").await, (200, None));
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_first_lease_whose_listeners_cannot_bind_leaves_the_bootstrap_listeners_up() {
    let mut h = NodeHarness::start().await;
    let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let taken = held.local_addr().unwrap().port();
    let up = rule("up", "host == \"upstream.test\"", ALLOW);
    let unbindable = NodeHarness::lease("L1", &h.config(taken, &up, ""), "s1", "e1");
    h.mock.push(LEASE, Reply::json(200, &unbindable));
    let l2 = NodeHarness::lease("L2", &h.config(0, &up, ""), "s1", "e1");
    h.mock.push(
        LEASE,
        Reply::Delayed(Duration::from_millis(800), Box::new(Reply::json(200, &l2))),
    );
    h.mock.fallback(LEASE, Reply::json(200, &l2));
    h.run(true).await;

    // The second fetch happens once L1 has been refused.
    h.mock.wait_for(LEASE, 2).await;
    let refetch = h.mock.requests_to(LEASE)[1].node_state();
    assert_eq!(refetch.lease_id, None);
    assert_eq!(refetch.policy_state, PolicyState::None);
    assert_eq!(h.readyz().await, (503, "no_policy".to_owned()));
    let proxy = h.proxy_addr().await;
    assert_ne!(proxy.port(), taken);
    assert_eq!(h.get(proxy, "/early").await, (403, Some("_default".into())));
    assert!(h.upstream.seen().is_empty());

    // A lease that can bind still replaces them.
    h.wait_applied("L2").await;
    drop(held);
    assert_eq!(h.readyz().await, (200, "ready".to_owned()));
    assert_eq!(h.get(h.proxy_addr().await, "/late").await, (200, None));
    h.stop().await;
}
