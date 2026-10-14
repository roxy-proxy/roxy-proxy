//! Answers while the client is still uploading: from the upstream, and
//! from a layer before calling `next` (nothing leaves), after it (the
//! forwarded request is abandoned mid-body) or while keeping it (the
//! forward runs to its end). Each must reach the client without waiting
//! for the rest of the upload.
//!
//! An outer layer relays an early answer from below only if it streams
//! full duplex (the test layer's `relay`); its sequential `pass` sends the
//! whole request body before reading the response, as a guest may.

use std::time::Duration;

use bytes::Bytes;
use roxy_http::BodySender;

use super::{AddonDef, Answer, Client, Kit, streaming_body, strs};
use crate::addons::AddonMode;
use crate::addons::service::testing;

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

// ---- a layer answering while its forward runs on ----------------------------

/// The head of an upload the layer answers early: the response head
/// reaches the client while the upload is still open, and the rest of
/// the response is read once the upload has ended.
async fn head_mid_upload(
    c: &mut Client,
    headers: &[(&str, &str)],
) -> (BodySender, http::Response<hyper::body::Incoming>) {
    let (mut tx, body) = streaming_body();
    let req = c.request("POST", "/upload", headers).body(body).unwrap();
    let pending = c.send(req);
    tokio::pin!(pending);
    for _ in 0..2 {
        tx.send_data(Bytes::from(vec![b'x'; CHUNK])).await.unwrap();
    }
    let res = tokio::time::timeout(Duration::from_secs(10), pending)
        .await
        .expect("the head arrives while the client is still uploading")
        .expect("a response");
    (tx, res)
}

/// The answer reaches the client at once and says nothing about the
/// forward: the layer keeps streaming the upload into `next`, the upstream
/// gets it whole, and the flow is logged as the layer's answer with what
/// the rules decided of the forward.
async fn answer_then_forward(kit: &Kit, mut c: Client, headers: &[(&str, &str)], body: &[u8]) {
    let (mut tx, res) = head_mid_upload(&mut c, headers).await;
    assert_eq!(res.status(), 200, "{res:?}");
    tx.send_data(Bytes::from(vec![b'x'; CHUNK])).await.unwrap();
    tx.finish().await.unwrap();
    let a = Answer::read(res).await;
    assert_eq!(a.body.as_deref().ok(), Some(body), "{a:?}");
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].path, "/upload");
    assert_eq!(seen[0].complete, Some(true), "{:?}", seen[0]);
    assert_eq!(seen[0].body.len(), 3 * CHUNK);
    let ev = kit.request_event().await;
    assert_eq!(ev["decision"], "answered", "{ev:#}");
    assert!(ev["reason"].is_null(), "nothing was abandoned: {ev:#}");
    assert!(strs(&ev["rules"]).contains(&"up".to_owned()), "{ev:#}");
}

#[tokio::test]
async fn h1_a_wasm_layer_answering_before_next_leaves_the_forward_to_complete() {
    let kit = stack(&["a"]).await;
    let c = kit.h1().await;
    answer_then_forward(
        &kit,
        c,
        &[("x-test-a", "answer-then-next")],
        b"answered before forwarding",
    )
    .await;
    let ev = kit.request_event().await;
    assert_eq!(ev["terminal_rule"], "layer:a", "{ev:#}");
}

#[tokio::test]
async fn h2_a_wasm_layer_answering_before_next_leaves_the_forward_to_complete() {
    let kit = stack(&["a"]).await;
    let c = kit.tunnel("up.test", true).await;
    answer_then_forward(
        &kit,
        c,
        &[("x-test-a", "answer-then-next")],
        b"answered before forwarding",
    )
    .await;
}

#[tokio::test]
async fn a_service_answering_while_it_forwards_leaves_the_forward_to_complete() {
    let kit = testing::kit(
        super::ALLOW_UP,
        vec![testing::addon("s", "early", AddonMode::Enforce, |_| {})],
    )
    .await;
    let c = kit.h1().await;
    answer_then_forward(&kit, c, &[], b"early").await;
    let ev = kit.request_event().await;
    assert_eq!(ev["terminal_rule"], "layer:s", "{ev:#}");
    let svc = kit.upstream.service();
    assert!(
        svc.resets().is_empty(),
        "nothing reset the stream: {:?}",
        svc.resets()
    );
}

/// The rules' verdict on a forward stands in the record whatever the
/// client was given: a layer answers `200` early, the request it forwards
/// is denied, and the flow is logged as that deny with the client's status
/// beside it.
#[tokio::test]
async fn a_deny_of_the_forward_outlives_the_layers_early_answer() {
    let kit = Kit::builder()
        .rules(
            r#"
- id: up
  when: host == "up.test"
  then: allow
- id: no-denied
  when: path == "/denied"
  then: deny
"#,
        )
        .addon(AddonDef::test_layer("a"))
        .start()
        .await;
    let mut c = kit.h1().await;
    let (mut tx, body) = streaming_body();
    let req = c
        .request("POST", "/denied", &[("x-test-a", "answer-then-next")])
        .body(body)
        .unwrap();
    let pending = c.start(req);
    tx.send_data(Bytes::from(vec![b'x'; CHUNK])).await.unwrap();
    tx.finish().await.unwrap();
    let a = answer_mid_upload(pending).await;
    assert_eq!(a.status, 200, "{a:?}");
    let ev = kit.request_event().await;
    assert_eq!(ev["decision"], "deny", "{ev:#}");
    assert_eq!(ev["terminal_rule"], "no-denied");
    assert_eq!(ev["res"]["status"], 200);
    assert!(kit.upstream.seen().is_empty(), "nothing left");
}

#[tokio::test]
async fn a_service_answering_before_it_forwards_leaves_the_forward_to_complete() {
    let kit = testing::kit(
        super::ALLOW_UP,
        vec![testing::addon(
            "s",
            "answer-first",
            AddonMode::Enforce,
            |_| {},
        )],
    )
    .await;
    let c = kit.h1().await;
    answer_then_forward(&kit, c, &[], b"early").await;
    let ev = kit.request_event().await;
    assert_eq!(ev["terminal_rule"], "layer:s", "{ev:#}");
}

#[tokio::test]
async fn h2_a_service_answering_while_it_forwards_leaves_the_forward_to_complete() {
    let kit = testing::kit(
        super::ALLOW_UP,
        vec![testing::addon("s", "early", AddonMode::Enforce, |_| {})],
    )
    .await;
    let c = kit.tunnel("up.test", true).await;
    answer_then_forward(&kit, c, &[], b"early").await;
}
