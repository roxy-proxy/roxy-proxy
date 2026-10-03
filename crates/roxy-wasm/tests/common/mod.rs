//! A mock `LayerHost` and helpers shared by the integration tests.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::BodyExt;
use roxy_http::{Body, BodyError};
use roxy_wasm::{
    EndpointError, FlowInfo, HostError, Layer, LayerConfig, LayerError, LayerHost, LayerOutcome,
    LayerRequest, LayerResponse, LogLevel, Principal, WasmRuntime, async_trait,
};
use tokio::sync::oneshot;

pub const TEST_LAYER: &[u8] = include_bytes!("../fixtures/test_layer.wasm");

/// What the mock does when the layer calls `next`.
pub enum NextMode {
    /// Answer 200 with the request body streamed back as the response
    /// body.
    Echo,
    /// Hand the request to the test and answer with the response the test
    /// provided.
    Capture(Mutex<Option<(oneshot::Sender<LayerRequest>, LayerResponse)>>),
    /// Fail closed.
    Fail,
    /// Read the whole request body (kept in `seen_body`), then answer
    /// with this status, content type and body.
    Canned(u16, &'static str, Vec<u8>),
}

pub struct Mock {
    pub mode: NextMode,
    pub next_calls: AtomicUsize,
    /// Host-service calls, in order.
    pub calls: Mutex<Vec<String>>,
    /// The head of the last request passed to `next`.
    pub seen: Mutex<Option<http::request::Parts>>,
    /// The body of the last request passed to `next` (`Canned` mode).
    pub seen_body: Mutex<Option<Bytes>>,
    /// The layer's keyed store.
    pub state: Mutex<HashMap<String, String>>,
}

impl Mock {
    pub fn new(mode: NextMode) -> Arc<Self> {
        Arc::new(Self {
            mode,
            next_calls: AtomicUsize::new(0),
            calls: Mutex::new(Vec::new()),
            seen: Mutex::new(None),
            seen_body: Mutex::new(None),
            state: Mutex::new(HashMap::new()),
        })
    }

    pub fn echo() -> Arc<Self> {
        Self::new(NextMode::Echo)
    }

    pub fn calls(&self) -> Vec<String> {
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
            NextMode::Canned(status, content_type, canned) => {
                let got = collect(body)
                    .await
                    .map_err(|e| HostError::new(e.to_string()))?;
                *self.seen_body.lock().unwrap() = Some(got);
                Ok(Response::builder()
                    .status(*status)
                    .header("content-type", *content_type)
                    .body(Body::from_bytes(canned.clone()))
                    .unwrap())
            }
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

    async fn state_get(&self, key: String) -> Result<Option<String>, HostError> {
        self.call(format!("state_get {key}"));
        Ok(self.state.lock().unwrap().get(&key).cloned())
    }

    async fn state_put(
        &self,
        key: String,
        json: String,
        ttl_ms: Option<u64>,
    ) -> Result<Result<(), String>, HostError> {
        self.call(format!("state_put {key} {json} {ttl_ms:?}"));
        self.state.lock().unwrap().insert(key, json);
        Ok(Ok(()))
    }

    async fn metric_get(&self, id: String, key: Vec<String>) -> Result<Option<i64>, HostError> {
        self.call(format!("metric_get {id} {key:?}"));
        Ok(Some(7))
    }
}

pub fn runtime() -> WasmRuntime {
    WasmRuntime::new().expect("runtime")
}

pub fn config() -> LayerConfig {
    LayerConfig::new("test")
}

pub async fn load(rt: &WasmRuntime, cfg: LayerConfig) -> Layer {
    Layer::load(rt, TEST_LAYER.to_vec(), cfg)
        .await
        .expect("load")
}

pub fn request(test: &str, body: Body) -> LayerRequest {
    Request::builder()
        .method(Method::POST)
        .uri("https://api.example.com:443/v1/messages?x=1")
        .header("x-test", test)
        .header("content-type", "text/plain")
        .body(body)
        .unwrap()
}

pub async fn collect(body: Body) -> Result<Bytes, BodyError> {
    body.collect()
        .await
        .map(http_body_util::Collected::to_bytes)
}

/// Runs a whole exchange, collecting the response body.
pub async fn exchange(
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
