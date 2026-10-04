//! A layer built with the `roxy-addon` SDK (`test-components/redact`, rebuilt by
//! `test-components/build.sh`) under the real host with a mock `LayerHost`: the SDK
//! and the host agree on the WIT contract.

use bytes::Bytes;
use http::Request;
use http_body_util::BodyExt;
use roxy_http::Body;
use roxy_wasm::{Layer, LayerConfig, WasmRuntime};

mod common;
use common::{Mock, collect};

const REDACT: &[u8] = include_bytes!("fixtures/redact.wasm");

async fn redact() -> Layer {
    let rt = WasmRuntime::new().unwrap();
    let mut cfg = LayerConfig::new("redact");
    cfg.config_json = r#"{"needles": ["sk-live-1234"], "replacement": "[x]"}"#.into();
    Layer::load(&rt, REDACT.to_vec(), cfg).await.unwrap()
}

fn post(body: Body) -> roxy_wasm::LayerRequest {
    Request::builder()
        .method("POST")
        .uri("https://api.example.com:443/upload")
        .body(body)
        .unwrap()
}

#[tokio::test]
async fn redacts_both_directions_while_streaming() {
    let layer = redact().await;
    let host = Mock::echo();

    // The needle straddles two chunks of the client's body.
    let (mut tx, body) = Body::channel(u64::MAX, None);
    let handle = tokio::spawn({
        let layer = layer.clone();
        let host = host.clone();
        async move { layer.handle(host, post(body)).await }
    });
    for chunk in ["key=sk-li", "ve-1234&x=1"] {
        tx.send_data(Bytes::from(chunk)).await.unwrap();
    }
    tx.finish().await.unwrap();

    let resp = handle.await.unwrap().unwrap();
    // The mock echoes the request body, so this is what went upstream,
    // redacted again on the way back.
    assert_eq!(collect(resp.into_body()).await.unwrap(), "key=[x]&x=1");
}

#[tokio::test]
async fn streams_without_buffering() {
    let layer = redact().await;
    let host = Mock::echo();
    let (mut tx, body) = Body::channel(u64::MAX, None);
    let handle = tokio::spawn({
        let layer = layer.clone();
        let host = host.clone();
        async move { layer.handle(host, post(body)).await }
    });
    // The first chunk reaches the client before the second is sent (all
    // but the held-back tail of `longest needle - 1` bytes).
    let first = "a".repeat(64);
    tx.send_data(Bytes::from(first.clone())).await.unwrap();
    tx.send_data(Bytes::from(first.clone())).await.unwrap();
    let resp = handle.await.unwrap().unwrap();
    let mut body = resp.into_body();
    let frame = body.frame().await.unwrap().unwrap().into_data().unwrap();
    assert!(!frame.is_empty());
    tx.finish().await.unwrap();
    let remainder = collect(body).await.unwrap();
    assert_eq!(frame.len() + remainder.len(), 128);
}

/// The layer below answers while the request body is still streaming (the
/// mock echoes it), so the SDK must write the request body and read the
/// response at the same time. Many writes, needles across chunk borders.
#[tokio::test]
async fn request_and_response_stream_concurrently() {
    let layer = redact().await;
    let host = Mock::echo();
    let (mut tx, body) = Body::channel(u64::MAX, None);
    let handle = tokio::spawn({
        let layer = layer.clone();
        let host = host.clone();
        async move { layer.handle(host, post(body)).await }
    });
    let unit = "0123456789abcdef-sk-live-1234-";
    let sender = tokio::spawn(async move {
        let all = unit.repeat(35_000); // ~1 MiB
        for piece in all.as_bytes().chunks(7_919) {
            tx.send_data(Bytes::copy_from_slice(piece)).await.unwrap();
        }
        tx.finish().await.unwrap();
    });
    let resp = handle.await.unwrap().unwrap();
    let out = collect(resp.into_body()).await.unwrap();
    sender.await.unwrap();
    assert_eq!(out, "0123456789abcdef-[x]-".repeat(35_000));
}
