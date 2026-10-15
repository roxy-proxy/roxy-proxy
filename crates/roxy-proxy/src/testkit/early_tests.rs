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
use crate::addons::service::testing;
use crate::addons::{AddonMode, Part};

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

/// The head of an upload the layer answers early, with the upload still
/// open. Unlike [`upload`], the response is not collected: a WASM layer's
/// response body ends only once its handler returns, which here waits on
/// the forward, which waits on the rest of the upload.
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

async fn wasm_answers_then_forwards(h2: bool) {
    let kit = stack(&["a"]).await;
    let c = if h2 {
        kit.tunnel("up.test", true).await
    } else {
        kit.h1().await
    };
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
async fn h1_a_wasm_layer_answering_before_next_leaves_the_forward_to_complete() {
    wasm_answers_then_forwards(false).await;
}

#[tokio::test]
async fn h2_a_wasm_layer_answering_before_next_leaves_the_forward_to_complete() {
    wasm_answers_then_forwards(true).await;
}

/// A service that forwards and answers at once: the stream's state machine
/// takes the two heads in either order; here the forward is first on the
/// wire, as a stream ends on the service's last message.
async fn service_answers_while_forwarding(h2: bool) {
    let kit = testing::kit(
        super::ALLOW_UP,
        vec![testing::addon("s", "early", AddonMode::Enforce, |_| {})],
    )
    .await;
    let c = if h2 {
        kit.tunnel("up.test", true).await
    } else {
        kit.h1().await
    };
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

#[tokio::test]
async fn h1_a_service_answering_while_it_forwards_leaves_the_forward_to_complete() {
    service_answers_while_forwarding(false).await;
}

#[tokio::test]
async fn h2_a_service_answering_while_it_forwards_leaves_the_forward_to_complete() {
    service_answers_while_forwarding(true).await;
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

// ---- answers with no body ------------------------------------------------

/// A bodiless answer is complete with its head: the front writes no body
/// to poll to its end, so the request lane is snipped as the head goes.
/// On HTTP/2 the client's upload is reset at once rather than left to its
/// idle timeout.
#[tokio::test(start_paused = true)]
async fn h2_a_bodiless_answer_without_a_forward_snips_the_upload_at_once() {
    let kit = testing::kit(
        super::ALLOW_UP,
        vec![testing::subscribed(
            testing::addon("s", "no-content", AddonMode::Enforce, |_| {}),
            Part::Head,
            Part::Full,
        )],
    )
    .await;
    let mut c = kit.tunnel("up.test", true).await;
    let (mut tx, pending) = upload(&mut c, &[], 2).await;
    let a = answer_mid_upload(pending).await;
    assert_eq!(a.status, 204, "{a:?}");
    let (cut, took) = super::timed(async {
        loop {
            if tx.send_data(Bytes::from(vec![b'x'; CHUNK])).await.is_err() {
                return true;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(cut);
    assert_eq!(took, Duration::ZERO, "the stream is reset, not timed out");
    assert!(kit.upstream.seen().is_empty(), "nothing left");
}

/// A WASM guest that answers with no body and then forwards: the front
/// writes nothing for the answer, and the guest still runs to its end, so
/// the forward completes.
#[tokio::test]
async fn h2_a_guest_answering_bodiless_still_completes_its_forward() {
    let kit = stack(&["a"]).await;
    let mut c = kit.tunnel("up.test", true).await;
    let (mut tx, pending) = upload(&mut c, &[("x-test-a", "answer-204-then-next")], 1).await;
    let a = answer_mid_upload(pending).await;
    assert_eq!(a.status, 204, "{a:?}");
    tx.send_data(Bytes::from(vec![b'x'; CHUNK])).await.unwrap();
    tx.finish().await.unwrap();
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].complete, Some(true), "{:?}", seen[0]);
    assert_eq!(seen[0].body.len(), 2 * CHUNK);
}

/// A guest that answered and then cuts its forward short keeps its answer:
/// nothing comes back for the cut forward, so `next` fails for the guest,
/// and the client's body is not cut with it. The cut is the guest's own
/// doing, not a fault: the record is the layer's answer, with
/// `forward_aborted` as its reason.
#[tokio::test]
async fn a_guest_that_answered_keeps_its_answer_when_its_forward_is_cut() {
    let kit = stack(&["a"]).await;
    let a = kit
        .h1()
        .await
        .call(
            "POST",
            "/upload",
            &[("x-test-a", "answer-then-cut-next")],
            b"body",
        )
        .await;
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(
        a.body.as_deref().ok(),
        Some(b"answered and kept".as_slice()),
        "{a:?}"
    );
    let ev = kit.request_event().await;
    assert_eq!(ev["decision"], "answered", "{ev:#}");
    assert_eq!(ev["reason"], "forward_aborted", "{ev:#}");
    assert_eq!(ev["terminal_rule"], "layer:a", "{ev:#}");
    assert_eq!(ev["res"]["status"], 200, "{ev:#}");
    assert!(
        kit.sink
            .events()
            .iter()
            .all(|e| e["event"] != "layer_error"),
        "nothing failed"
    );
    assert!(kit.upstream.seen().is_empty(), "nothing complete left");
}

/// A layer above gives a service up while its forward is upstream whole,
/// waiting on the head, and answers itself: the service's stream is reset,
/// and its forward is given up with it, so the record is finished on the
/// answer rather than held until an upstream nothing will read answers.
#[tokio::test(start_paused = true)]
async fn a_service_given_up_by_the_layer_above_gives_up_its_forward() {
    let kit = testing::kit(
        super::ALLOW_UP,
        vec![
            AddonDef::test_layer("a").spec().await,
            testing::addon("s", "forward", AddonMode::Enforce, |_| {}),
        ],
    )
    .await;
    let ((a, ev), took) = super::timed(async {
        let a = kit
            .h1()
            .await
            .call(
                "POST",
                "/late?ms=5000",
                &[("x-test-a", "next-then-abandon"), ("x-delay-ms", "200")],
                b"hello",
            )
            .await;
        (a, kit.request_event().await)
    })
    .await;
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(ev["decision"], "answered", "{ev:#}");
    assert_eq!(ev["terminal_rule"], "layer:a", "{ev:#}");
    assert!(
        took < Duration::from_secs(1),
        "the record is not held for the upstream: {took:?}"
    );
    let svc = kit.upstream.service();
    let resets = svc.resets();
    assert_eq!(resets.len(), 1, "the service's stream is reset: {resets:?}");
}

/// A service that forwards, answers with no body, and ends its answer only
/// once the response from below has: the front writes nothing for the
/// answer and drops its body lane while the forward is still running,
/// which is not the client going away. Nothing resets the stream, the
/// forward completes, and the stream ends on the service's last message.
#[tokio::test]
async fn h2_a_service_answering_bodiless_still_completes_its_forward() {
    let kit = testing::kit(
        super::ALLOW_UP,
        vec![testing::addon(
            "s",
            "early-no-content",
            AddonMode::Enforce,
            |_| {},
        )],
    )
    .await;
    let mut c = kit.tunnel("up.test", true).await;
    let (mut tx, pending) = upload(&mut c, &[], 1).await;
    let a = answer_mid_upload(pending).await;
    assert_eq!(a.status, 204, "{a:?}");
    tx.send_data(Bytes::from(vec![b'x'; CHUNK])).await.unwrap();
    tx.finish().await.unwrap();
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].complete, Some(true), "{:?}", seen[0]);
    assert_eq!(seen[0].body.len(), 2 * CHUNK);
    let ev = kit.request_event().await;
    assert_eq!(ev["decision"], "answered", "{ev:#}");
    let svc = kit.upstream.service();
    assert!(
        svc.resets().is_empty(),
        "nothing reset the stream: {:?}",
        svc.resets()
    );
}
