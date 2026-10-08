//! How many calls a guest makes into the host per exchange: the fixed cost
//! of the interface shape, which the WIT is designed to keep small. Each
//! case asserts a ceiling and prints its count (`--nocapture`).

use bytes::Bytes;
use http::Request;
use roxy_http::Body;
use roxy_wasm::{Layer, LayerConfig, WasmRuntime};

mod common;
use common::{Mock, TEST_LAYER, exchange, request};

const REDACT: &[u8] = include_bytes!("fixtures/redact.wasm");

async fn load(rt: &WasmRuntime, wasm: &[u8], name: &str, config: &str) -> Layer {
    let mut cfg = LayerConfig::new(name);
    cfg.config_json = config.into();
    Layer::load(rt, wasm.to_vec(), cfg).await.unwrap()
}

/// Runs the exchange twice (the first warms the instance) and returns the
/// host calls the second made.
async fn calls(layer: &Layer, req: impl Fn() -> roxy_wasm::LayerRequest) -> u64 {
    exchange(layer, Mock::echo(), req()).await.unwrap();
    let before = layer.host_calls();
    exchange(layer, Mock::echo(), req()).await.unwrap();
    layer.host_calls() - before
}

fn sdk_post(body: &'static str) -> roxy_wasm::LayerRequest {
    Request::builder()
        .method("POST")
        .uri("https://api.example.com:443/upload")
        .header("content-type", "text/plain")
        .body(Body::from_bytes(Bytes::from_static(body.as_bytes())))
        .unwrap()
}

#[tokio::test]
async fn host_calls_per_exchange() {
    let rt = WasmRuntime::new().unwrap();
    // Raw bindings: the floor for an answer (respond, drop the request
    // body) and a layer that streams both bodies chunk by chunk.
    let raw = load(&rt, TEST_LAYER, "raw", "null").await;
    let deny = calls(&raw, || request("deny", Body::empty())).await;
    let relay = calls(&raw, || request("pass", Body::from_bytes("hello"))).await;
    // The SDK: a no-op layer passing both heads and bodies through untouched
    // (what the performance page measures), and one transforming both
    // bodies in the guest.
    let noop = load(&rt, REDACT, "noop", r#"{"needles": []}"#).await;
    let passthrough = calls(&noop, || sdk_post("hello")).await;
    let redact = load(&rt, REDACT, "redact", r#"{"needles": ["x"]}"#).await;
    let transform = calls(&redact, || sdk_post("hello")).await;

    eprintln!("host calls per exchange:");
    eprintln!("  raw answer (deny)            {deny}");
    eprintln!("  raw streaming relay (pass)   {relay}");
    eprintln!("  SDK no-op pass-through       {passthrough}");
    eprintln!("  SDK transform both bodies    {transform}");

    // The answer reads its config (one call), answers (one) and drops the
    // request body it never read (one). The no-op layer passes the request
    // on (one), takes the response (one) and answers with it (one).
    assert!(deny <= 3, "answer: {deny}");
    assert!(passthrough <= 3, "no-op pass-through: {passthrough}");
    assert!(transform <= 20, "transform: {transform}");
}
