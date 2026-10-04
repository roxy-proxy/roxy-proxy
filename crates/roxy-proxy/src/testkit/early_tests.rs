//! Answers while the client is still uploading: from the upstream, and
//! from a layer before calling `next` (nothing leaves) or after (the
//! forwarded request is abandoned mid-body). Each must reach the client
//! without waiting for the rest of the upload.
//!
//! An outer layer relays an early answer from below only if it streams
//! full duplex (the test layer's `relay`); its sequential `pass` sends the
//! whole request body before reading the response, as a guest may.

use std::time::Duration;

use bytes::Bytes;
use roxy_http::BodySender;

use super::{AddonDef, Answer, Client, Kit, streaming_body};

const CHUNK: usize = 4096;

async fn stack(names: &[&str]) -> Kit {
    let mut b = Kit::builder();
    for n in names {
        b = b.addon(AddonDef::test_layer(n));
    }
    b.start().await
}

/// Starts a POST whose body the test feeds, sends `chunks` chunks, and
/// returns the body sender (still open) and the pending answer.
async fn upload(
    c: &mut Client,
    headers: &[(&str, &str)],
    chunks: usize,
) -> (
    BodySender,
    tokio::task::JoinHandle<Result<Answer, hyper::Error>>,
) {
    let (mut tx, body) = streaming_body();
    let req = c.request("POST", "/upload", headers).body(body).unwrap();
    let pending = c.start(req);
    for _ in 0..chunks {
        tx.send_data(Bytes::from(vec![b'x'; CHUNK])).await.unwrap();
    }
    (tx, pending)
}

/// The answer, which must arrive while the upload is still open.
async fn answer_mid_upload(
    pending: tokio::task::JoinHandle<Result<Answer, hyper::Error>>,
) -> Answer {
    tokio::time::timeout(Duration::from_secs(10), pending)
        .await
        .expect("the answer arrives while the client is still uploading")
        .unwrap()
        .expect("a response")
}

fn strs(v: &serde_json::Value) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().map(|x| x.as_str().unwrap().to_owned()).collect())
        .unwrap_or_default()
}

// ---- the upstream answering early ---------------------------------------

/// The upstream answers `/early` before reading the body.
async fn upstream_answers_early(addons: &[&str], h2: bool) {
    let kit = stack(addons).await;
    let mut c = if h2 {
        kit.tunnel("up.test", true).await
    } else {
        kit.h1().await
    };
    let (mut tx, body) = streaming_body();
    let req = c
        .request("POST", "/early", &[("x-test-a", "relay")])
        .body(body)
        .unwrap();
    let pending = c.start(req);
    tx.send_data(Bytes::from(vec![b'x'; CHUNK])).await.unwrap();
    let a = answer_mid_upload(pending).await;
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.body.as_deref().ok(), Some(&b"early"[..]), "{a:?}");
    drop(tx);
    let ev = kit.request_event().await;
    assert_eq!(ev["decision"], "allow", "{ev:#}");
}

#[tokio::test]
async fn h1_the_upstream_answering_mid_upload_reaches_the_client() {
    upstream_answers_early(&[], false).await;
}

#[tokio::test]
async fn h2_the_upstream_answering_mid_upload_reaches_the_client() {
    upstream_answers_early(&[], true).await;
}

#[tokio::test]
async fn the_upstream_answering_mid_upload_reaches_the_client_through_a_relaying_layer() {
    upstream_answers_early(&["a"], false).await;
}

// ---- a layer answering before `next` -----------------------------------

#[tokio::test]
async fn h1_a_layer_answers_before_next_mid_upload() {
    let kit = stack(&["a"]).await;
    let mut c = kit.h1().await;
    let (tx, pending) = upload(
        &mut c,
        &[("x-test-a", "read-then-answer"), ("x-read-bytes", "8192")],
        2,
    )
    .await;
    let a = answer_mid_upload(pending).await;
    assert_eq!(a.status, 200, "{a:?}");
    assert!(a.text().starts_with("answered by a after "), "{a:?}");
    drop(tx);
    let ev = kit.request_event().await;
    assert_eq!(ev["terminal_rule"], "layer:a", "{ev:#}");
    assert!(kit.upstream.seen().is_empty(), "nothing left");
}

#[tokio::test]
async fn h2_a_layer_answers_before_next_mid_upload_and_the_connection_lives_on() {
    let kit = stack(&["a"]).await;
    let mut c = kit.tunnel("up.test", true).await;
    let (tx, pending) = upload(
        &mut c,
        &[("x-test-a", "read-then-answer"), ("x-read-bytes", "8192")],
        2,
    )
    .await;
    let a = answer_mid_upload(pending).await;
    assert_eq!(a.status, 200, "{a:?}");
    assert!(a.text().starts_with("answered by a after "), "{a:?}");
    drop(tx);
    // Only the stream ended: the connection carries the next request.
    let b = c.call("GET", "/next", &[], b"").await;
    assert_eq!(b.status, 200, "{b:?}");
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].path, "/next");
}

#[tokio::test]
async fn an_inner_layer_answers_before_next_mid_upload_through_the_outer_one() {
    let kit = stack(&["a", "b"]).await;
    let mut c = kit.h1().await;
    let (tx, pending) = upload(
        &mut c,
        &[
            ("x-test-a", "relay"),
            ("x-test-b", "read-then-answer"),
            ("x-read-bytes", "8192"),
        ],
        2,
    )
    .await;
    let a = answer_mid_upload(pending).await;
    assert_eq!(a.status, 200, "{a:?}");
    assert!(a.text().starts_with("answered by b after "), "{a:?}");
    drop(tx);
    let ev = kit.request_event().await;
    assert_eq!(ev["terminal_rule"], "layer:b", "{ev:#}");
    assert!(kit.upstream.seen().is_empty(), "nothing left");
}

// ---- a layer answering after `next` ---------------------------------------------

#[tokio::test]
async fn h1_a_layer_answers_after_next_mid_upload() {
    let kit = stack(&["a"]).await;
    let mut c = kit.h1().await;
    let (tx, pending) = upload(
        &mut c,
        &[("x-test-a", "next-then-answer"), ("x-read-bytes", "8192")],
        2,
    )
    .await;
    let a = answer_mid_upload(pending).await;
    assert_eq!(a.status, 200, "{a:?}");
    assert!(
        a.text().starts_with("answered by a after forwarding "),
        "{a:?}"
    );
    drop(tx);
    // The forwarded request reached the upstream and was abandoned: its
    // body must not end as if complete.
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].path, "/upload");
    assert_eq!(seen[0].complete, Some(false), "{:?}", seen[0]);
}

#[tokio::test]
async fn h2_a_layer_answers_after_next_mid_upload() {
    let kit = stack(&["a"]).await;
    let mut c = kit.tunnel("up.test", true).await;
    let (tx, pending) = upload(
        &mut c,
        &[("x-test-a", "next-then-answer"), ("x-read-bytes", "8192")],
        2,
    )
    .await;
    let a = answer_mid_upload(pending).await;
    assert_eq!(a.status, 200, "{a:?}");
    drop(tx);
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].complete, Some(false), "{:?}", seen[0]);
    let b = c.call("GET", "/next", &[], b"").await;
    assert_eq!(b.status, 200, "{b:?}");
}

#[tokio::test]
async fn answering_after_next_keeps_what_the_rules_decided() {
    let kit = stack(&["a"]).await;
    let mut c = kit.h1().await;
    let (tx, pending) = upload(
        &mut c,
        &[("x-test-a", "next-then-answer"), ("x-read-bytes", "8192")],
        2,
    )
    .await;
    answer_mid_upload(pending).await;
    drop(tx);
    let ev = kit.request_event().await;
    assert_eq!(ev["decision"], "answered", "{ev:#}");
    assert_eq!(ev["terminal_rule"], "layer:a");
    assert_eq!(ev["reason"], "upstream_aborted");
    assert!(strs(&ev["rules"]).contains(&"up".to_owned()), "{ev:#}");
    assert!(ev["req"]["body_bytes"].as_u64().unwrap() >= 8192, "{ev:#}");
}

#[tokio::test]
async fn an_outer_layer_answering_after_the_inner_one_forwarded_is_the_one_named() {
    let kit = stack(&["a", "b"]).await;
    let mut c = kit.h1().await;
    let (tx, pending) = upload(
        &mut c,
        &[
            ("x-test-a", "next-then-answer"),
            ("x-test-b", "relay"),
            ("x-read-bytes", "8192"),
        ],
        2,
    )
    .await;
    let a = answer_mid_upload(pending).await;
    assert!(a.text().starts_with("answered by a"), "{a:?}");
    drop(tx);
    let ev = kit.request_event().await;
    assert_eq!(ev["terminal_rule"], "layer:a", "{ev:#}");
}
