//! Answers while the client is still uploading: from the upstream, and
//! from a layer before calling `next` (nothing leaves), after it (the
//! forwarded request is abandoned mid-body) or while keeping it (the
//! forward runs to its end). Each must reach the client without waiting
//! for the rest of the upload.
//!
//! A layer relays an early answer from upstream only if it streams
//! full duplex (the test layer's `relay`); its sequential `pass` sends the
//! whole request body before reading the response, as a guest may.

use std::time::Duration;

use bytes::Bytes;
use roxy_http::BodySender;

use super::{AddonDef, Answer, Client, Kit, streaming_body, strs};
use crate::addons::service::testing;
use crate::addons::{AddonMode, Part};

const CHUNK: usize = 4096;

#[tokio::test]
async fn h2_reset_after_bodiless_answer_releases_service() {
    for (method, status) in [("POST", 204), ("HEAD", 200)] {
        let kit = testing::kit(
            super::ALLOW_UP,
            vec![testing::subscribed(
                testing::addon("s", "answer-open", AddonMode::Enforce, |s| {
                    s.max_connections = 1;
                    s.max_streams = 1;
                }),
                Part::Head,
                Part::Full,
            )],
        )
        .await;
        let (send, _conn) = super::h2_client(&kit).await;
        let mut ready = send.ready().await.unwrap();
        let req = http::Request::builder()
            .method(method)
            .uri("https://up.test/upload")
            .body(())
            .unwrap();
        let (response, mut upload) = ready.send_request(req, false).unwrap();
        let response = tokio::time::timeout(Duration::from_secs(2), response)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), status);
        // A healthy stream must remain alive while the service is still
        // working, even though its HTTP response is already complete.
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(kit.upstream.service().resets(), []);
        assert!(kit.sink.events().iter().all(|e| e["event"] != "request"));
        upload.send_reset(h2::Reason::CANCEL);
        let svc = kit.upstream.service();
        tokio::time::timeout(Duration::from_millis(500), async {
            while svc.resets().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("RST_STREAM after a bodiless answer must cancel the service stage");
        let event = kit.request_event().await;
        assert_eq!(event["res"]["status"], status, "{event:#}");
        assert_eq!(event["decision"], "answered", "{event:#}");
        assert_eq!(event["reason"], "client_gone", "{event:#}");
        assert!(
            kit.sink
                .events()
                .iter()
                .all(|e| e["event"] != "response_error")
        );

        // Reuse both the HTTP/2 connection and the only service slot.
        let req = http::Request::get("https://up.test/again")
            .body(())
            .unwrap();
        let mut ready = ready.ready().await.unwrap();
        let (response, mut upload) = ready.send_request(req, false).unwrap();
        let response = tokio::time::timeout(Duration::from_secs(2), response)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), 204);
        upload.send_reset(h2::Reason::CANCEL);
    }
}

#[tokio::test(start_paused = true)]
async fn headless_forward_completion_restarts_answer_timeout() {
    let kit = testing::kit(
        super::ALLOW_UP,
        vec![testing::addon("s", "cut-wait", AddonMode::Enforce, |s| {
            s.first_byte_timeout = Duration::from_millis(100);
        })],
    )
    .await;
    let mut c = kit.h1().await;
    let result =
        tokio::time::timeout(Duration::from_secs(1), c.call("POST", "/x", &[], b"body")).await;
    assert!(
        result.is_ok(),
        "a completed, cut forward leaves the answer clock disabled forever"
    );
    assert_eq!(result.unwrap().status, 503);
    let errors = kit.events("layer_error", 1).await;
    assert_eq!(errors[0]["kind"], "service:timeout", "{errors:#?}");
}

#[tokio::test]
async fn trailers_do_not_turn_a_cut_service_response_into_success() {
    for h2 in [false, true] {
        let kit = testing::kit(
            super::ALLOW_UP,
            vec![testing::addon(
                "s",
                "trailers-cut",
                AddonMode::Enforce,
                |_| {},
            )],
        )
        .await;
        let a = kit
            .tunnel("up.test", h2)
            .await
            .call("GET", "/x", &[], b"")
            .await;
        assert!(
            a.body.is_err(),
            "response_end(error) was delivered as complete: {a:?}"
        );
    }
}

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

#[tokio::test]
async fn refusing_an_early_response_does_not_wait_for_the_upload() {
    for h2 in [false, true] {
        let kit = Kit::builder()
            .rules(
                r#"
- id: allow-up
  when: host == "up.test"
  then: allow
- id: refuse-response
  when: response.status == 200
  then: deny
"#,
            )
            .start()
            .await;
        let mut client = kit.tunnel("up.test", h2).await;
        let (mut upload, body) = streaming_body();
        let req = client
            .request("POST", "/early-drip?n=10&ms=1000", &[])
            .body(body)
            .unwrap();
        let response = client.start(req);
        upload
            .send_data(Bytes::from_static(b"started"))
            .await
            .unwrap();
        let response = tokio::time::timeout(Duration::from_secs(2), response)
            .await
            .expect("the refusal must not wait for the remaining upload")
            .unwrap()
            .unwrap();
        assert_eq!(response.status, 403);
        let event = kit.request_event().await;
        assert_eq!(event["terminal_rule"], "refuse-response");
        drop(upload);
    }
}

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

/// A service that answers without forwarding releases its held upload
/// when its stream ends. HTTP/2 resets that upload without waiting for
/// the body-idle timeout.
#[tokio::test(start_paused = true)]
async fn h2_a_bodiless_answer_without_a_forward_releases_the_upload_at_once() {
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

/// A WASM guest that answers with no body and then forwards: the transport
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

/// A downstream layer answers and abandons a service's pending response.
/// The service and its upstream request are cancelled, so the final record
/// does not wait for an upstream response that nobody will read.
#[tokio::test(start_paused = true)]
async fn abandoning_a_services_response_cancels_its_forward() {
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
/// once the response from upstream has: the transport writes nothing for the
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
