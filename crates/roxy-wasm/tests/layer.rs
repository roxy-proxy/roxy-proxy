//! roxy-wasm against the test components in `tests/fixtures/` (sources in
//! `test-components/`, rebuilt by `test-components/build.sh`) and a mock
//! `LayerHost`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::BodyExt;
use roxy_http::{Body, BodyError, BodySender};
use roxy_wasm::{
    Budget, Capabilities, Capability, EndpointError, FlowInfo, HostError, Layer, LayerConfig,
    LayerError, LayerHost, LayerOutcome, LayerRequest, LayerResponse, LoadError, LogLevel,
    Principal, TerminateScope, WasmRuntime, async_trait,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

const TEST_LAYER: &[u8] = include_bytes!("fixtures/test_layer.wasm");
const TUNNEL_LAYER: &[u8] = include_bytes!("fixtures/tunnel_layer.wasm");

/// What the mock does when the layer calls `next`.
enum NextMode {
    /// Answer 200 with the request body streamed back as the response
    /// body.
    Echo,
    /// Hand the request to the test and answer with the response the test
    /// provided.
    Capture(Mutex<Option<(oneshot::Sender<LayerRequest>, LayerResponse)>>),
    /// Fail closed.
    Fail,
}

struct Mock {
    mode: NextMode,
    next_calls: AtomicUsize,
    /// Host-service calls, in order.
    calls: Mutex<Vec<String>>,
    /// The head of the last request passed to `next`.
    seen: Mutex<Option<http::request::Parts>>,
}

impl Mock {
    fn new(mode: NextMode) -> Arc<Self> {
        Arc::new(Self {
            mode,
            next_calls: AtomicUsize::new(0),
            calls: Mutex::new(Vec::new()),
            seen: Mutex::new(None),
        })
    }

    fn echo() -> Arc<Self> {
        Self::new(NextMode::Echo)
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    fn call(&self, c: String) {
        self.calls.lock().unwrap().push(c);
    }
}

#[async_trait]
impl LayerHost for Mock {
    async fn next(&self, req: LayerRequest) -> Result<LayerResponse, HostError> {
        self.next_calls.fetch_add(1, Ordering::SeqCst);
        let (parts, body) = req.into_parts();
        *self.seen.lock().unwrap() = Some(parts.clone());
        match &self.mode {
            NextMode::Echo => Ok(Response::builder()
                .status(200)
                .header("x-upstream", "yes")
                .body(body)
                .unwrap()),
            NextMode::Capture(slot) => {
                let (tx, resp) = slot.lock().unwrap().take().expect("one next");
                let _ = tx.send(Request::from_parts(parts, body));
                Ok(resp)
            }
            NextMode::Fail => Err(HostError::new("metric store unavailable")),
        }
    }

    async fn endpoint_call(
        &self,
        name: &str,
        req: LayerRequest,
    ) -> Result<LayerResponse, EndpointError> {
        self.call(format!("endpoint {name} {}", req.uri()));
        if name == "monitor" {
            Ok(Response::new(Body::from_bytes("score=0.1")))
        } else {
            Err(EndpointError::NotFound)
        }
    }

    fn flow_info(&self) -> FlowInfo {
        FlowInfo {
            flow_id: "flow-1".into(),
            conn_id: "conn-1".into(),
            principal: Principal {
                client_ip: "10.0.0.1".into(),
                client_user: None,
                listener: "main".into(),
                tls_sni: None,
            },
            tags: vec![],
        }
    }

    fn add_tag(&self, tag: String) {
        self.call(format!("tag {tag}"));
    }

    fn log(&self, level: LogLevel, msg: &str) {
        self.call(format!("log {level:?} {msg}"));
    }

    async fn record(&self, kind: String, json: String, audit: bool) -> Result<(), HostError> {
        self.call(format!("record {kind} {json} {audit}"));
        Ok(())
    }

    async fn terminate(
        &self,
        scope: TerminateScope,
        reason: String,
        ttl_ms: Option<u64>,
    ) -> Result<bool, HostError> {
        self.call(format!("terminate {scope:?} {reason} {ttl_ms:?}"));
        Ok(true)
    }

    async fn state_get(&self, key: String) -> Result<Option<String>, HostError> {
        self.call(format!("state_get {key}"));
        Ok(Some("{\"n\":1}".into()))
    }

    async fn state_put(
        &self,
        key: String,
        json: String,
        ttl_ms: Option<u64>,
    ) -> Result<Result<(), String>, HostError> {
        self.call(format!("state_put {key} {json} {ttl_ms:?}"));
        Ok(Ok(()))
    }

    async fn metric_get(&self, id: String, key: Vec<String>) -> Result<Option<i64>, HostError> {
        self.call(format!("metric_get {id} {key:?}"));
        Ok(Some(7))
    }
}

fn runtime() -> WasmRuntime {
    WasmRuntime::new().expect("runtime")
}

fn config() -> LayerConfig {
    LayerConfig::new("test")
}

async fn load(rt: &WasmRuntime, cfg: LayerConfig) -> Layer {
    Layer::load(rt, TEST_LAYER.to_vec(), cfg)
        .await
        .expect("load")
}

fn request(test: &str, body: Body) -> LayerRequest {
    Request::builder()
        .method(Method::POST)
        .uri("https://api.example.com:443/v1/messages?x=1")
        .header("x-test", test)
        .header("content-type", "text/plain")
        .body(body)
        .unwrap()
}

async fn collect(body: Body) -> Result<Bytes, BodyError> {
    body.collect()
        .await
        .map(http_body_util::Collected::to_bytes)
}

/// Runs a whole exchange, collecting the response body.
async fn exchange(
    layer: &Layer,
    host: Arc<Mock>,
    req: LayerRequest,
) -> Result<(StatusCode, Bytes), LayerError> {
    let resp = layer.handle(host, req).await?;
    let status = resp.status();
    let outcome = resp.extensions().get::<LayerOutcome>().cloned().unwrap();
    match collect(resp.into_body()).await {
        Ok(b) => {
            outcome.wait().await?;
            Ok((status, b))
        }
        Err(_) => Err(outcome
            .wait()
            .await
            .expect_err("body failed, so must the outcome")),
    }
}

#[tokio::test]
async fn passes_through_and_transforms() {
    let rt = runtime();
    let layer = load(&rt, config()).await;
    let host = Mock::echo();
    let mut req = request("pass", Body::from_bytes("hello layer"));
    req.headers_mut().insert("x-upper", "1".parse().unwrap());
    let resp = layer.handle(host.clone(), req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["x-upstream"], "yes");
    let body = collect(resp.into_body()).await.unwrap();
    // Upper-cased on the way down, and again (no-op) on the way up.
    assert_eq!(body, "HELLO LAYER");

    let seen = host.seen.lock().unwrap().clone().unwrap();
    assert_eq!(seen.method, Method::POST);
    assert_eq!(
        seen.uri.to_string(),
        "https://api.example.com:443/v1/messages?x=1"
    );
    assert_eq!(seen.headers["content-type"], "text/plain");
    assert!(seen.headers.get("host").is_none());
    assert_eq!(host.next_calls.load(Ordering::SeqCst), 1);
}

/// Bodies stream in both directions: each chunk crosses the layer before
/// the next one exists, and nothing is buffered on the layer's behalf
/// (the buffered-bytes budget here is smaller than either body).
#[tokio::test]
async fn streams_both_directions() {
    let rt = runtime();
    let mut cfg = config();
    cfg.limits.max_buffered_body_bytes = 32;
    let layer = load(&rt, cfg).await;

    let (mut up_tx, up_body) = Body::channel(u64::MAX, None);
    let (seen_tx, seen_rx) = oneshot::channel();
    let host = Mock::new(NextMode::Capture(Mutex::new(Some((
        seen_tx,
        Response::new(up_body),
    )))));

    let (mut client_tx, client_body) = Body::channel(u64::MAX, None);
    let mut req = request("pass", client_body);
    req.headers_mut().insert("x-upper", "1".parse().unwrap());
    let handle = tokio::spawn({
        let layer = layer.clone();
        let host = host.clone();
        async move { layer.handle(host, req).await }
    });

    // Request direction: the host sees each chunk while the client is
    // still sending.
    let upstream_req = seen_rx.await.unwrap();
    let mut upstream_body = upstream_req.into_body();
    for chunk in ["first chunk ", "second chunk ", "third"] {
        client_tx.send_data(Bytes::from(chunk)).await.unwrap();
        let frame = upstream_body.frame().await.unwrap().unwrap();
        assert_eq!(
            frame.into_data().unwrap(),
            Bytes::from(chunk.to_ascii_uppercase())
        );
    }
    client_tx.finish().await.unwrap();
    assert!(upstream_body.frame().await.is_none());

    // Response direction: the head comes back once the guest has it, and
    // each chunk reaches the client before the upstream sends the next.
    up_tx.send_data(Bytes::from("alpha ")).await.unwrap();
    let resp = handle.await.unwrap().unwrap();
    let mut body = resp.into_body();
    for chunk in ["alpha ", "beta ", "gamma"] {
        if chunk != "alpha " {
            up_tx.send_data(Bytes::from(chunk)).await.unwrap();
        }
        let frame = body.frame().await.unwrap().unwrap();
        assert_eq!(
            frame.into_data().unwrap(),
            Bytes::from(chunk.to_ascii_uppercase())
        );
    }
    up_tx.finish().await.unwrap();
    assert!(body.frame().await.is_none());
}

#[tokio::test]
async fn layer_can_deny_without_next() {
    let rt = runtime();
    let layer = load(&rt, config()).await;
    let host = Mock::echo();
    let (status, body) = exchange(&layer, host.clone(), request("deny", Body::empty()))
        .await
        .unwrap();
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, "denied by layer");
    assert_eq!(host.next_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn layer_can_rewrite_the_request() {
    let rt = runtime();
    let layer = load(&rt, config()).await;
    let host = Mock::echo();
    let (status, body) = exchange(
        &layer,
        host.clone(),
        request("rewrite", Body::from_bytes("original")),
    )
    .await
    .unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "replaced");
    let seen = host.seen.lock().unwrap().clone().unwrap();
    assert_eq!(
        seen.uri.to_string(),
        "https://api.example.com:443/rewritten"
    );
}

#[tokio::test]
async fn second_next_traps() {
    let rt = runtime();
    let layer = load(&rt, config()).await;
    let err = exchange(&layer, Mock::echo(), request("next-twice", Body::empty()))
        .await
        .unwrap_err();
    assert_eq!(err, LayerError::NextCalledTwice);
}

#[tokio::test]
async fn infinite_loop_is_stopped_by_fuel() {
    let rt = runtime();
    let mut cfg = config();
    cfg.limits.fuel_per_step = 10_000_000;
    cfg.limits.step_cpu = Duration::from_secs(30);
    let layer = load(&rt, cfg).await;
    let err = exchange(&layer, Mock::echo(), request("loop", Body::empty()))
        .await
        .unwrap_err();
    assert_eq!(err, LayerError::BudgetExceeded(Budget::Fuel));
}

#[tokio::test]
async fn infinite_loop_is_stopped_by_epoch() {
    let rt = runtime();
    let mut cfg = config();
    cfg.limits.fuel_per_step = u64::MAX / 2;
    cfg.limits.step_cpu = Duration::from_millis(20);
    let layer = load(&rt, cfg).await;
    let start = std::time::Instant::now();
    let err = exchange(&layer, Mock::echo(), request("loop", Body::empty()))
        .await
        .unwrap_err();
    assert_eq!(err, LayerError::BudgetExceeded(Budget::StepCpu));
    assert!(start.elapsed() < Duration::from_secs(5));
}

/// A loop that keeps calling the host never exhausts a step, but the
/// exchange's wall clock still stops it.
#[tokio::test]
async fn host_call_loop_is_stopped_by_wall_clock() {
    let rt = runtime();
    let mut cfg = config();
    cfg.limits.max_exchange_time = Duration::from_millis(200);
    let layer = load(&rt, cfg).await;
    let start = std::time::Instant::now();
    let err = exchange(&layer, Mock::echo(), request("host-loop", Body::empty()))
        .await
        .unwrap_err();
    assert_eq!(err, LayerError::BudgetExceeded(Budget::ExchangeTime));
    assert!(start.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn memory_hog_hits_the_limit() {
    let rt = runtime();
    let mut cfg = config();
    cfg.limits.max_memory = 16 << 20;
    let layer = load(&rt, cfg).await;
    let err = exchange(&layer, Mock::echo(), request("memory", Body::empty()))
        .await
        .unwrap_err();
    assert_eq!(err, LayerError::BudgetExceeded(Budget::Memory));
}

#[tokio::test]
async fn buffering_past_the_budget_fails() {
    let rt = runtime();
    let mut cfg = config();
    cfg.limits.max_buffered_body_bytes = 1024;
    let layer = load(&rt, cfg).await;

    // Within budget: fine.
    let (_, body) = exchange(
        &layer,
        Mock::echo(),
        request("buffer", Body::from_bytes(vec![b'a'; 1000])),
    )
    .await
    .unwrap();
    assert_eq!(body.len(), 1000);

    // Reading the whole body before passing it on holds too much.
    let (mut tx, body) = Body::channel(u64::MAX, None);
    tokio::spawn(async move {
        for _ in 0..8 {
            if tx.send_data(Bytes::from(vec![b'a'; 512])).await.is_err() {
                return;
            }
        }
        let _ = tx.finish().await;
    });
    let host = Mock::echo();
    let err = exchange(&layer, host.clone(), request("buffer", body))
        .await
        .unwrap_err();
    assert_eq!(err, LayerError::BudgetExceeded(Budget::BufferedBody));
    assert_eq!(host.next_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn traps_fail_closed() {
    let rt = runtime();
    let layer = load(&rt, config()).await;
    let err = exchange(&layer, Mock::echo(), request("trap", Body::empty()))
        .await
        .unwrap_err();
    assert!(matches!(err, LayerError::Trap(_)), "{err:?}");

    let err = exchange(&layer, Mock::echo(), request("no-response", Body::empty()))
        .await
        .unwrap_err();
    assert_eq!(err, LayerError::NoResponse);

    let err = exchange(
        &layer,
        Mock::echo(),
        request("error-response", Body::empty()),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, LayerError::ErrorResponse(_)), "{err:?}");
}

/// Failures after the response head is out cut the body with an error; a
/// truncated body never ends cleanly.
#[tokio::test]
async fn failures_after_the_head_cut_the_body() {
    let rt = runtime();
    let layer = load(&rt, config()).await;
    for (test, check) in [
        ("trap-after-head", "trap"),
        ("trap-after-finish", "trap"),
        ("leak", "leak"),
    ] {
        let resp = layer
            .handle(Mock::echo(), request(test, Body::empty()))
            .await
            .unwrap_or_else(|e| panic!("{test}: head should be out: {e}"));
        let outcome = resp.extensions().get::<LayerOutcome>().cloned().unwrap();
        let err = collect(resp.into_body()).await.unwrap_err();
        assert_eq!(err, BodyError::Stopped, "{test}");
        let failure = outcome.wait().await.unwrap_err();
        match check {
            "trap" => assert!(
                matches!(failure, LayerError::Trap(_)),
                "{test}: {failure:?}"
            ),
            _ => assert!(
                matches!(failure, LayerError::InvalidResponse(_)),
                "{test}: {failure:?}"
            ),
        }
    }
}

#[tokio::test]
async fn host_failure_in_next_fails_closed() {
    let rt = runtime();
    let layer = load(&rt, config()).await;
    let err = exchange(
        &layer,
        Mock::new(NextMode::Fail),
        request("pass", Body::empty()),
    )
    .await
    .unwrap_err();
    assert_eq!(
        err,
        LayerError::Host(HostError::new("metric store unavailable"))
    );
}

#[tokio::test]
async fn invalid_next_request_fails_closed() {
    let rt = runtime();
    let layer = load(&rt, config()).await;
    let host = Mock::echo();
    let err = exchange(&layer, host.clone(), request("invalid-next", Body::empty()))
        .await
        .unwrap_err();
    assert!(matches!(err, LayerError::InvalidRequest(_)), "{err:?}");
    assert_eq!(host.next_calls.load(Ordering::SeqCst), 0);
}

async fn cap_test(layer: &Layer, host: Arc<Mock>, cap: &str) -> Result<String, LayerError> {
    let mut req = request("caps", Body::empty());
    req.headers_mut().insert("x-cap", cap.parse().unwrap());
    let (_, body) = exchange(layer, host, req).await?;
    Ok(String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test]
async fn capabilities_gate_host_services() {
    let rt = runtime();
    // Each gated call, the capability it needs, and what it returns once
    // granted.
    let cases: [(&str, Capability, &str, &str); 7] = [
        (
            "log",
            Capability::Log,
            "ok",
            "log Info hello from the layer",
        ),
        (
            "record",
            Capability::Record,
            "ok",
            "record verdict {\"score\":0.9} true",
        ),
        (
            "terminate",
            Capability::Terminate,
            "true",
            "terminate Principal bad actor Some(1000)",
        ),
        (
            "state",
            Capability::State,
            "Ok(()) Some(\"{\\\"n\\\":1}\")",
            "state_put k {\"n\":1} None",
        ),
        (
            "metric",
            Capability::Metrics,
            "Some(7)",
            "metric_get requests [\"10.0.0.1\"]",
        ),
        (
            "endpoint",
            Capability::Endpoints,
            "200 score=0.1",
            "endpoint monitor /score?q=1",
        ),
        (
            "unknown-endpoint",
            Capability::Endpoints,
            "error ErrorCode::DestinationNotFound",
            "endpoint nope /",
        ),
    ];

    // Nothing granted: every gated call traps, and nothing reaches the host.
    let none = load(&rt, config()).await;
    for (cap, needs, _, _) in cases {
        let host = Mock::echo();
        let err = cap_test(&none, host.clone(), cap).await.unwrap_err();
        assert!(
            matches!(err, LayerError::CapabilityDenied { capability, .. } if capability == needs),
            "{cap}: {err:?}"
        );
        assert!(host.calls().is_empty(), "{cap}");
    }

    // Everything else granted, but not the one needed: still denied.
    for (cap, needs, _, _) in cases {
        let mut cfg = config();
        cfg.capabilities = Capability::ALL
            .into_iter()
            .filter(|c| *c != needs)
            .collect();
        let layer = load(&rt, cfg).await;
        let err = cap_test(&layer, Mock::echo(), cap).await.unwrap_err();
        assert!(
            matches!(err, LayerError::CapabilityDenied { capability, .. } if capability == needs),
            "{cap}: {err:?}"
        );
    }

    // Granted: the call works.
    let mut cfg = config();
    cfg.capabilities = Capabilities::all();
    let all = load(&rt, cfg).await;
    for (cap, _, expect, call) in cases {
        let host = Mock::echo();
        assert_eq!(
            cap_test(&all, host.clone(), cap).await.unwrap(),
            expect,
            "{cap}"
        );
        assert!(
            host.calls().iter().any(|c| c == call),
            "{cap}: {:?}",
            host.calls()
        );
    }
}

#[tokio::test]
async fn flow_basics_need_no_capability() {
    let rt = runtime();
    let none = load(&rt, config()).await;
    let host = Mock::echo();
    assert_eq!(
        cap_test(&none, host.clone(), "current").await.unwrap(),
        "flow-1 10.0.0.1 main"
    );
    assert_eq!(
        cap_test(&none, host.clone(), "add-tag").await.unwrap(),
        "ok"
    );
    assert_eq!(host.calls(), vec!["tag tagged".to_owned()]);
    let mut cfg = config();
    cfg.config_json = "{\"reject_at\":0.8}".into();
    let configured = load(&rt, cfg).await;
    assert_eq!(
        cap_test(&configured, Mock::echo(), "config").await.unwrap(),
        "{\"reject_at\":0.8}"
    );
}

async fn count(layer: &Layer) -> u64 {
    let (_, body) = exchange(layer, Mock::echo(), request("count", Body::empty()))
        .await
        .unwrap();
    std::str::from_utf8(&body).unwrap().parse().unwrap()
}

#[tokio::test]
async fn instances_are_reused_and_recycled_after_n_exchanges() {
    let rt = runtime();
    let mut cfg = config();
    cfg.limits.max_instances = 1;
    cfg.limits.recycle_after_exchanges = 3;
    let layer = load(&rt, cfg).await;
    let mut seen = Vec::new();
    for _ in 0..7 {
        seen.push(count(&layer).await);
    }
    assert_eq!(seen, [1, 2, 3, 1, 2, 3, 1]);
}

#[tokio::test]
async fn instances_are_recycled_above_memory() {
    let rt = runtime();
    let mut cfg = config();
    cfg.limits.max_instances = 1;
    cfg.limits.recycle_above_memory = 6 << 20;
    let layer = load(&rt, cfg).await;
    assert_eq!(count(&layer).await, 1);
    assert_eq!(count(&layer).await, 2);
    let (_, body) = exchange(&layer, Mock::echo(), request("grow", Body::empty()))
        .await
        .unwrap();
    assert_eq!(body, "grown");
    // The grown instance was replaced.
    assert_eq!(count(&layer).await, 1);
}

#[tokio::test]
async fn failed_instances_are_discarded() {
    let rt = runtime();
    let mut cfg = config();
    cfg.limits.max_instances = 1;
    let layer = load(&rt, cfg).await;
    assert_eq!(count(&layer).await, 1);
    assert_eq!(count(&layer).await, 2);
    exchange(&layer, Mock::echo(), request("trap", Body::empty()))
        .await
        .unwrap_err();
    assert_eq!(count(&layer).await, 1);
}

#[tokio::test]
async fn max_instances_bounds_concurrency() {
    let rt = runtime();
    let mut cfg = config();
    cfg.limits.max_instances = 1;
    let layer = load(&rt, cfg).await;

    // The first exchange holds the only instance while its upstream
    // response is open...
    let (mut up_tx, up_body) = Body::channel(u64::MAX, None);
    let (seen_tx, seen_rx) = oneshot::channel();
    let host = Mock::new(NextMode::Capture(Mutex::new(Some((
        seen_tx,
        Response::new(up_body),
    )))));
    let first = tokio::spawn({
        let layer = layer.clone();
        async move { exchange(&layer, host, request("pass", Body::empty())).await }
    });
    let _upstream = seen_rx.await.unwrap();

    // ...so the second waits for it.
    let mut second = tokio::spawn({
        let layer = layer.clone();
        async move { count(&layer).await }
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(300), &mut second)
            .await
            .is_err(),
        "second exchange ran while the only instance was busy"
    );

    up_tx.send_data(Bytes::from("done")).await.unwrap();
    up_tx.finish().await.unwrap();
    assert_eq!(first.await.unwrap().unwrap().1, "done");
    // The same (only) instance served it next.
    assert_eq!(second.await.unwrap(), 2);
}

#[tokio::test]
async fn exchange_wall_clock_covers_streaming() {
    let rt = runtime();
    let mut cfg = config();
    cfg.limits.max_instances = 1;
    cfg.limits.max_exchange_time = Duration::from_millis(300);
    let layer = load(&rt, cfg).await;

    let (_up_tx, up_body): (BodySender, Body) = Body::channel(u64::MAX, None);
    let (seen_tx, seen_rx) = oneshot::channel();
    let host = Mock::new(NextMode::Capture(Mutex::new(Some((
        seen_tx,
        Response::new(up_body),
    )))));
    let first = tokio::spawn({
        let layer = layer.clone();
        async move { exchange(&layer, host, request("pass", Body::empty())).await }
    });
    let _upstream = seen_rx.await.unwrap();
    assert_eq!(
        first.await.unwrap().unwrap_err(),
        LayerError::BudgetExceeded(Budget::ExchangeTime)
    );
}

#[tokio::test]
async fn dropping_the_exchange_cancels_it() {
    let rt = runtime();
    let mut cfg = config();
    cfg.limits.max_instances = 1;
    let layer = load(&rt, cfg).await;
    assert_eq!(count(&layer).await, 1);

    let (_up_tx, up_body): (BodySender, Body) = Body::channel(u64::MAX, None);
    let (seen_tx, seen_rx) = oneshot::channel();
    let host = Mock::new(NextMode::Capture(Mutex::new(Some((
        seen_tx,
        Response::new(up_body),
    )))));
    // The client is still sending when the exchange is dropped.
    let (mut client_tx, client_body) = Body::channel(u64::MAX, None);
    client_tx.send_data(Bytes::from("partial")).await.unwrap();
    let (done_tx, mut done_rx) = mpsc::channel::<()>(1);
    let task = tokio::spawn({
        let layer = layer.clone();
        async move {
            let _done = done_tx;
            layer.handle(host, request("pass", client_body)).await
        }
    });
    let upstream = seen_rx.await.unwrap();
    let mut upstream_body = upstream.into_body();
    assert_eq!(
        upstream_body
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        "partial"
    );
    task.abort();
    let _ = done_rx.recv().await;
    // The upstream request body is cut, not ended cleanly.
    assert_eq!(
        collect(upstream_body).await.unwrap_err(),
        BodyError::Stopped
    );
    drop(client_tx);
    // The instance was discarded; a fresh one serves the next exchange.
    assert_eq!(count(&layer).await, 1);
}

#[tokio::test]
async fn init_runs_at_load() {
    let rt = runtime();
    let mut cfg = config();
    cfg.config_json = "{\"fail_init\":true}".into();
    let err = Layer::load(&rt, TEST_LAYER.to_vec(), cfg)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, LoadError::Start { source: LayerError::Init(m), .. } if m == "init asked to fail"),
        "{err:?}"
    );

    // No flow during init.
    let mut cfg = config();
    cfg.config_json = "{\"flow_in_init\":true}".into();
    let err = Layer::load(&rt, TEST_LAYER.to_vec(), cfg)
        .await
        .unwrap_err();
    assert!(
        matches!(
            &err,
            LoadError::Start {
                source: LayerError::OutsideExchange("flow.current"),
                ..
            }
        ),
        "{err:?}"
    );

    // Capabilities apply during init too.
    let mut cfg = config();
    cfg.config_json = "{\"log_in_init\":true}".into();
    let err = Layer::load(&rt, TEST_LAYER.to_vec(), cfg.clone())
        .await
        .unwrap_err();
    assert!(
        matches!(
            &err,
            LoadError::Start {
                source: LayerError::CapabilityDenied {
                    capability: Capability::Log,
                    ..
                },
                ..
            }
        ),
        "{err:?}"
    );
    cfg.capabilities = Capabilities::NONE.with(Capability::Log);
    Layer::load(&rt, TEST_LAYER.to_vec(), cfg).await.unwrap();
}

#[tokio::test]
async fn bad_components_fail_to_load() {
    let rt = runtime();
    let err = Layer::load(&rt, b"not wasm".to_vec(), config())
        .await
        .unwrap_err();
    assert!(matches!(err, LoadError::Compile { .. }), "{err:?}");

    // A core module is not a component.
    let core = b"\0asm\x01\0\0\0".to_vec();
    let err = Layer::load(&rt, core, config()).await.unwrap_err();
    assert!(matches!(err, LoadError::Compile { .. }), "{err:?}");

    let mut cfg = config();
    cfg.limits.max_instances = 0;
    let err = Layer::load(&rt, TEST_LAYER.to_vec(), cfg)
        .await
        .unwrap_err();
    assert!(matches!(err, LoadError::Limits { .. }), "{err:?}");
}

#[tokio::test]
async fn tunnel_is_detected_and_relays() {
    let rt = runtime();
    let plain = load(&rt, config()).await;
    assert!(!plain.has_tunnel());
    let (a, _b) = tokio::io::duplex(64);
    let (c, _d) = tokio::io::duplex(64);
    let (ar, aw) = tokio::io::split(a);
    let (cr, cw) = tokio::io::split(c);
    assert_eq!(
        plain
            .tunnel(Mock::echo(), ar, aw, cr, cw)
            .await
            .unwrap_err(),
        LayerError::NoTunnel
    );

    let layer = Layer::load(&rt, TUNNEL_LAYER.to_vec(), config())
        .await
        .unwrap();
    assert!(layer.has_tunnel());
    // The tunnel layer also handles plain exchanges.
    let (_, body) = exchange(&layer, Mock::echo(), request("x", Body::empty()))
        .await
        .unwrap();
    assert_eq!(body, "tunnel layer");

    // client <-> [layer] <-> upstream
    let (client, client_side) = tokio::io::duplex(1024);
    let (upstream, upstream_side) = tokio::io::duplex(1024);
    let (from_client, to_client) = tokio::io::split(client_side);
    let (from_upstream, to_upstream) = tokio::io::split(upstream_side);
    let relay = tokio::spawn({
        let layer = layer.clone();
        async move {
            layer
                .tunnel(
                    Mock::echo(),
                    from_client,
                    to_upstream,
                    from_upstream,
                    to_client,
                )
                .await
        }
    });
    let (mut client_r, mut client_w) = tokio::io::split(client);
    let (mut up_r, mut up_w) = tokio::io::split(upstream);

    client_w.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    up_r.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"PING");
    up_w.write_all(b"pong").await.unwrap();
    client_r.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"pong");

    client_w.shutdown().await.unwrap();
    up_w.shutdown().await.unwrap();
    relay.await.unwrap().unwrap();
    // Both directions closed through the layer.
    let mut rest = Vec::new();
    up_r.read_to_end(&mut rest).await.unwrap();
    client_r.read_to_end(&mut rest).await.unwrap();
    assert_eq!(rest, b"");
}
