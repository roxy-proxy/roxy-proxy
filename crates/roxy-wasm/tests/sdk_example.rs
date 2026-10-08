//! A layer built with the `roxy-addon` SDK (`test-components/redact`, rebuilt by
//! `test-components/build.sh`) under the real host with a mock `LayerHost`: the SDK
//! and the host agree on the WIT contract.

use std::sync::Mutex;

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::BodyExt;
use roxy_http::{Body, BodyError};
use roxy_wasm::{Layer, LayerConfig, LayerError, WasmRuntime};
use tokio::sync::oneshot;

mod common;
use common::{Mock, NextMode, collect, exchange};

const REDACT: &[u8] = include_bytes!("fixtures/redact.wasm");

async fn load(config: &str) -> Layer {
    let rt = WasmRuntime::new().unwrap();
    let mut cfg = LayerConfig::new("redact");
    cfg.config_json = config.into();
    Layer::load(&rt, REDACT.to_vec(), cfg).await.unwrap()
}

async fn redact() -> Layer {
    load(r#"{"needles": ["sk-live-1234"], "replacement": "[x]"}"#).await
}

/// Nothing to redact: the layer passes both bodies on untouched, which the
/// SDK moves host-side without reading them into the guest.
async fn passthrough() -> Layer {
    load(r#"{"needles": []}"#).await
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

/// A body passed on untouched still streams in both directions at once:
/// each client chunk reaches the layer below while the client is still
/// sending, and the response flows back while the request body is open.
#[tokio::test]
async fn untouched_bodies_stream_both_ways_at_once() {
    let layer = passthrough().await;
    let (mut up_tx, up_body) = Body::channel(u64::MAX, None);
    let (seen_tx, seen_rx) = oneshot::channel();
    let host = Mock::new(NextMode::Capture(Mutex::new(Some((
        seen_tx,
        Response::new(up_body),
    )))));
    let (mut client_tx, client_body) = Body::channel(u64::MAX, None);
    let handle = tokio::spawn({
        let layer = layer.clone();
        let host = host.clone();
        async move { layer.handle(host, post(client_body)).await }
    });

    let mut upstream_body = seen_rx.await.unwrap().into_body();
    client_tx.send_data(Bytes::from("first ")).await.unwrap();
    let frame = upstream_body.frame().await.unwrap().unwrap();
    assert_eq!(frame.into_data().unwrap(), "first ");

    // The response starts while the request body is still open.
    let resp = handle.await.unwrap().unwrap();
    let mut client_body = resp.into_body();
    up_tx.send_data(Bytes::from("pong ")).await.unwrap();
    let frame = client_body.frame().await.unwrap().unwrap();
    assert_eq!(frame.into_data().unwrap(), "pong ");

    client_tx.send_data(Bytes::from("second")).await.unwrap();
    let frame = upstream_body.frame().await.unwrap().unwrap();
    assert_eq!(frame.into_data().unwrap(), "second");
    client_tx.finish().await.unwrap();
    assert!(upstream_body.frame().await.is_none());

    up_tx.send_data(Bytes::from("done")).await.unwrap();
    up_tx.finish().await.unwrap();
    assert_eq!(collect(client_body).await.unwrap(), "done");
}

/// A request body that fails while the layer passes it on untouched (moved
/// host-side, with the layer still waiting on the response) fails the
/// exchange closed: the body handed down is never finished as if complete.
#[tokio::test]
async fn a_failing_untouched_request_body_fails_closed() {
    let layer = passthrough().await;
    let host = Mock::new(NextMode::Upload);
    let (mut client_tx, client_body) = Body::channel(u64::MAX, None);
    let handle = tokio::spawn({
        let layer = layer.clone();
        let host = host.clone();
        async move { exchange(&layer, host, post(client_body)).await }
    });
    host.entered.notified().await;
    client_tx.send_data(Bytes::from("partial")).await.unwrap();
    client_tx.abort(BodyError::Incomplete);

    let outcome = handle.await.unwrap();
    assert!(
        matches!(outcome, Err(LayerError::InvalidRequest(_))),
        "{outcome:?}"
    );
    assert_eq!(host.upload_ended().await, Err(BodyError::Stopped));
}

/// The same failure once the layer below has answered (without reading the
/// body to its end): the layer's answer stands, and the body it passed on
/// is cut at the upstream rather than ended as complete.
#[tokio::test]
async fn a_failing_untouched_request_body_is_cut_after_the_answer() {
    let layer = passthrough().await;
    let (seen_tx, seen_rx) = oneshot::channel();
    let host = Mock::new(NextMode::Capture(Mutex::new(Some((
        seen_tx,
        Response::new(Body::from_bytes("ok")),
    )))));
    let (mut client_tx, client_body) = Body::channel(u64::MAX, None);
    let handle = tokio::spawn({
        let layer = layer.clone();
        let host = host.clone();
        async move { exchange(&layer, host, post(client_body)).await }
    });
    let mut upstream_body = seen_rx.await.unwrap().into_body();
    client_tx.send_data(Bytes::from("partial")).await.unwrap();
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
    client_tx.abort(BodyError::Incomplete);

    let (status, body) = handle.await.unwrap().unwrap();
    assert_eq!((status.as_u16(), body.as_ref()), (200, b"ok".as_slice()));
    assert_eq!(
        collect(upstream_body).await.unwrap_err(),
        BodyError::Stopped
    );
}
