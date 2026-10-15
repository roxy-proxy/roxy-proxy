//! roxy-wasm against the test components in `tests/fixtures/` (sources in
//! `test-components/`, rebuilt by `test-components/build.sh`) and a mock
//! `LayerHost`.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Response, StatusCode};
use http_body_util::BodyExt;
use roxy_http::{Body, BodyError, BodySender};
use roxy_wasm::{
    Budget, Capabilities, Capability, HostError, Layer, LayerError, LoadError, MAX_FIELDS_BYTES,
    MAX_MESSAGE_BYTES,
};
use tokio::sync::{mpsc, oneshot};

mod common;
use common::*;

#[tokio::test]
async fn handle_failure_waits_for_driver_cleanup() {
    let rt = runtime();
    let mut cfg = config();
    cfg.limits.first_byte_timeout = Duration::from_millis(100);
    let layer = load(&rt, cfg).await;
    let host = Mock::echo();
    let live_host = Arc::downgrade(&host);
    let result = layer.handle(host, request("loop", Body::empty())).await;
    assert_eq!(result, Err(LayerError::BudgetExceeded(Budget::FirstByte)));
    assert!(
        live_host.upgrade().is_none(),
        "handle returned while the guest driver still owns the host"
    );
}

#[tokio::test]
async fn passes_through_and_transforms() {
    let rt = runtime();
    let layer = load(&rt, config()).await;
    let host = Mock::echo();
    let mut req = request("pass", Body::from_bytes("hello layer"));
    req.headers_mut().insert("x-upper", "1".parse().unwrap());
    let mut started = start(&layer, host.clone(), req);
    let resp = started.response().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["x-upstream"], "yes");
    let body = collect(resp.into_body()).await.unwrap();
    // Upper-cased on the way down, and again (no-op) on the way up.
    assert_eq!(body, "HELLO LAYER");
    started.outcome().await.unwrap();

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
/// the next one exists, and nothing is buffered on the layer's behalf.
#[tokio::test]
async fn streams_both_directions() {
    let rt = runtime();
    let layer = load(&rt, config()).await;

    let (mut up_tx, up_body) = Body::channel(u64::MAX, None);
    let (seen_tx, seen_rx) = oneshot::channel();
    let host = Mock::new(NextMode::Capture(Mutex::new(Some((
        seen_tx,
        Response::new(up_body),
    )))));

    let (mut client_tx, client_body) = Body::channel(u64::MAX, None);
    let mut req = request("pass", client_body);
    req.headers_mut().insert("x-upper", "1".parse().unwrap());
    let mut started = start(&layer, host.clone(), req);

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
    let resp = started.response().await.unwrap();
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

/// A layer that never sets a response head, computing or calling the
/// host, is broken: its head deadline fails it closed.
#[tokio::test]
async fn no_head_in_time_fails_closed() {
    let rt = runtime();
    let mut cfg = config();
    cfg.limits.first_byte_timeout = Duration::from_millis(200);
    let layer = load(&rt, cfg).await;
    for test in ["loop", "host-loop"] {
        let start = std::time::Instant::now();
        let err = exchange(&layer, Mock::echo(), request(test, Body::empty()))
            .await
            .unwrap_err();
        assert_eq!(err, LayerError::BudgetExceeded(Budget::FirstByte), "{test}");
        assert!(start.elapsed() < Duration::from_secs(5), "{test}");
    }
}

/// The time `next` spends below the layer is not the layer's.
#[tokio::test]
async fn the_head_deadline_excludes_time_below() {
    let rt = runtime();
    let mut cfg = config();
    cfg.limits.first_byte_timeout = Duration::from_millis(200);
    let layer = load(&rt, cfg).await;
    let host = Mock::new(NextMode::SlowEcho(Duration::from_millis(600)));
    let (status, body) = exchange(&layer, host, request("pass", Body::from_bytes("slow")))
        .await
        .unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "slow");
}

/// A request holding the request head, calling `next`, then holding the
/// response head, each for most of the limit.
fn held_heads(before_next: Duration, after_next: Duration) -> roxy_wasm::LayerRequest {
    let mut req = request("buffer", Body::from_bytes("held"));
    for (name, d) in [
        ("x-delay-request-ms", before_next),
        ("x-delay-response-ms", after_next),
    ] {
        req.headers_mut()
            .insert(name, d.as_millis().to_string().parse().unwrap());
    }
    req
}

/// Each head has the whole limit to itself: holding the request head for
/// most of it leaves the response head its own.
#[tokio::test]
async fn each_head_gets_the_whole_deadline() {
    let rt = runtime();
    let mut cfg = config();
    cfg.limits.first_byte_timeout = Duration::from_secs(1);
    let layer = load(&rt, cfg).await;
    let hold = Duration::from_millis(800);
    let (status, body) = exchange(&layer, Mock::echo(), held_heads(hold, hold))
        .await
        .unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "held");
}

/// Overrunning either head's hold alone fails the exchange closed. The
/// error is proof enough that the deadline fired: had it not, the hold
/// would have ended and the exchange succeeded.
#[tokio::test]
async fn overrunning_either_head_fails_closed() {
    let rt = runtime();
    let mut cfg = config();
    cfg.limits.first_byte_timeout = Duration::from_millis(300);
    let layer = load(&rt, cfg).await;
    let over = Duration::from_millis(1500);
    for (before, after) in [(over, Duration::ZERO), (Duration::ZERO, over)] {
        let err = exchange(&layer, Mock::echo(), held_heads(before, after))
            .await
            .unwrap_err();
        assert_eq!(
            err,
            LayerError::BudgetExceeded(Budget::FirstByte),
            "before {before:?}, after {after:?}"
        );
    }
}

/// A guest computing for a long time is slow, not failed: nothing
/// limits CPU between host calls, and the guest still yields.
#[tokio::test]
async fn a_long_computation_is_not_a_failure() {
    let rt = runtime();
    let layer = load(&rt, config()).await;
    // A loop with no host calls, dropped after a second: the instance is
    // reclaimed and the next exchange gets one.
    let looping = exchange(&layer, Mock::echo(), request("loop", Body::empty()));
    assert!(
        tokio::time::timeout(Duration::from_secs(1), looping)
            .await
            .is_err()
    );
    let (status, _) = exchange(&layer, Mock::echo(), request("pass", Body::empty()))
        .await
        .unwrap();
    assert_eq!(status, StatusCode::OK);
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

/// A layer may read a whole body before passing it on; only its memory
/// bounds what it holds.
#[tokio::test]
async fn a_layer_may_buffer_a_body() {
    let rt = runtime();
    let layer = load(&rt, config()).await;
    let (mut tx, body) = Body::channel(u64::MAX, None);
    tokio::spawn(async move {
        for _ in 0..64 {
            if tx
                .send_data(Bytes::from(vec![b'a'; 16 * 1024]))
                .await
                .is_err()
            {
                return;
            }
        }
        let _ = tx.finish().await;
    });
    let host = Mock::new(NextMode::Canned(200, "text/plain", b"ok".to_vec()));
    let (_, body) = exchange(&layer, host.clone(), request("buffer", body))
        .await
        .unwrap();
    assert_eq!(body, "ok");
    assert_eq!(
        host.seen_body.lock().unwrap().as_ref().unwrap().len(),
        1 << 20
    );
}

#[tokio::test]
async fn traps_fail_closed() {
    let rt = runtime();
    let layer = load(&rt, config()).await;
    let host = Mock::echo();
    let err = exchange(&layer, host.clone(), request("trap", Body::empty()))
        .await
        .unwrap_err();
    assert!(matches!(err, LayerError::Trap(_)), "{err:?}");
    // The host heard of it before `handle` returned it.
    assert_eq!(host.failed.lock().unwrap().as_slice(), [err]);

    let host = Mock::echo();
    let err = exchange(&layer, host.clone(), request("no-response", Body::empty()))
        .await
        .unwrap_err();
    assert_eq!(err, LayerError::NoResponse);
    assert_eq!(host.failed.lock().unwrap().as_slice(), [err]);
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
        let host = Mock::echo();
        let mut started = start(&layer, host.clone(), request(test, Body::empty()));
        let resp = started
            .response()
            .await
            .unwrap_or_else(|e| panic!("{test}: head should be out: {e}"));
        let err = collect(resp.into_body()).await.unwrap_err();
        assert_eq!(err, BodyError::Stopped, "{test}");
        // The body ended on a failure the host already had.
        let told = host.failed.lock().unwrap().clone();
        let failure = started.outcome().await.unwrap_err();
        assert_eq!(told.as_slice(), std::slice::from_ref(&failure), "{test}");
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

/// Tags live on the host, outside `max_memory`, so the host caps them: a
/// guest that keeps tagging after its head is out is failed at the cap,
/// and its body cut, rather than growing the host's memory until the
/// client gives up. The cap here is the mock host's (`MOCK_TAG_CAP`); this
/// pins the guest-side failure, and roxy-proxy's tests pin the production
/// cap.
#[tokio::test]
async fn looping_on_add_tag_after_the_head_fails_at_the_cap() {
    let rt = runtime();
    let layer = load(&rt, config()).await;
    let host = Mock::echo();
    let mut started = start(
        &layer,
        host.clone(),
        request("tags-after-head", Body::empty()),
    );
    let resp = started.response().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        collect(resp.into_body()).await.unwrap_err(),
        BodyError::Stopped
    );
    assert_eq!(
        started.outcome().await.unwrap_err(),
        LayerError::BudgetExceeded(Budget::Tags)
    );
    // The refused tag is the first one past the cap.
    assert_eq!(host.tags.lock().unwrap().len(), MOCK_TAG_CAP);
    let tag_calls = host
        .calls()
        .iter()
        .filter(|c| c.starts_with("tag "))
        .count();
    assert_eq!(tag_calls, MOCK_TAG_CAP + 1);
}

/// A head a guest hands the host is host memory outside `max_memory`, so
/// its size is capped; one over the cap fails the exchange, named.
#[tokio::test]
async fn an_oversized_fields_is_refused() {
    let rt = runtime();
    let layer = load(&rt, config()).await;
    let under = format!("fields:{}", MAX_FIELDS_BYTES / 2);
    let (status, body) = exchange(&layer, Mock::echo(), request(&under, Body::empty()))
        .await
        .unwrap();
    assert_eq!(
        (status, body.as_ref()),
        (StatusCode::OK, b"fields ok".as_slice())
    );
    let over = format!("fields:{}", MAX_FIELDS_BYTES + 1);
    let err = exchange(&layer, Mock::echo(), request(&over, Body::empty()))
        .await
        .unwrap_err();
    assert_eq!(err, LayerError::BudgetExceeded(Budget::Fields));
}

/// A head a guest hands the host is held to `max_headers`, like any head
/// roxy parses. One with more fields fails the exchange closed, named for
/// the message it was part of, before anything below the layer sees it.
#[tokio::test]
async fn too_many_header_fields_are_refused() {
    let rt = runtime();
    let mut cfg = config();
    cfg.capabilities = Capabilities::NONE.with(Capability::Endpoints);
    cfg.max_headers = 8;
    let layer = load(&rt, cfg).await;
    for entry in ["respond", "next", "call"] {
        let host = Mock::echo();
        let under = format!("headers:{entry}:8");
        let (status, body) = exchange(&layer, host.clone(), request(&under, Body::empty()))
            .await
            .unwrap();
        assert_eq!(
            (status, body.as_ref()),
            (StatusCode::OK, b"headers ok".as_slice()),
            "{entry}"
        );
        if entry == "next" {
            let seen = host.seen.lock().unwrap().clone().unwrap();
            assert_eq!(seen.headers.len(), 8);
        }

        let host = Mock::echo();
        let over = format!("headers:{entry}:9");
        let err = exchange(&layer, host.clone(), request(&over, Body::empty()))
            .await
            .unwrap_err();
        let msg = "9 header fields, more than max_headers (8)".to_owned();
        let expected = if entry == "respond" {
            LayerError::InvalidResponse(msg)
        } else {
            LayerError::InvalidRequest(msg)
        };
        assert_eq!(err, expected, "{entry}");
        assert_eq!(host.next_calls.load(Ordering::SeqCst), 0, "{entry}");
        assert!(host.calls().is_empty(), "{entry}: {:?}", host.calls());
    }

    // A list longer than an `http` header map can hold at all is refused
    // the same way, under the default `max_headers`.
    let layer = load(&rt, config()).await;
    let err = exchange(
        &layer,
        Mock::echo(),
        request("headers:respond:32768", Body::empty()),
    )
    .await
    .unwrap_err();
    assert_eq!(
        err,
        LayerError::InvalidResponse("32768 header fields, more than max_headers (100)".to_owned())
    );
}

/// `flow.log` messages and `flow.record` documents are held by the host, so
/// their length is capped.
#[tokio::test]
async fn an_oversized_log_or_record_payload_is_refused() {
    let rt = runtime();
    let mut cfg = config();
    cfg.capabilities = Capabilities::NONE
        .with(Capability::Log)
        .with(Capability::Record);
    let layer = load(&rt, cfg).await;
    for (test, answer) in [("log", "logged"), ("record", "recorded")] {
        let host = Mock::echo();
        let under = format!("{test}:{}", MAX_MESSAGE_BYTES / 2);
        let (status, body) = exchange(&layer, host.clone(), request(&under, Body::empty()))
            .await
            .unwrap();
        assert_eq!(
            (status, body.as_ref()),
            (StatusCode::OK, answer.as_bytes()),
            "{test}"
        );
        assert_eq!(host.calls().len(), 1, "{test}: {:?}", host.calls());

        let host = Mock::echo();
        let over = format!("{test}:{}", MAX_MESSAGE_BYTES + 1);
        let err = exchange(&layer, host.clone(), request(&over, Body::empty()))
            .await
            .unwrap_err();
        assert_eq!(err, LayerError::BudgetExceeded(Budget::Message), "{test}");
        assert!(host.calls().is_empty(), "{test}: never reached the host");
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

/// A request body passed to `next` and left unfinished while the guest is
/// still waiting on the response is the guest's own cut of its forward,
/// not a failure: nothing comes back for it, so `next` fails for the
/// guest, which answers as it likes.
#[tokio::test]
async fn unfinished_next_body_while_awaiting_cuts_the_forward() {
    let rt = runtime();
    let layer = load(&rt, config()).await;
    let host = Mock::new(NextMode::Upload);
    let (status, body) = exchange(
        &layer,
        host.clone(),
        request("cut-then-await", Body::from_bytes("partial")),
    )
    .await
    .unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "answered after next failed");
    assert_eq!(host.next_calls.load(Ordering::SeqCst), 1);
    assert_eq!(host.upload_ended().await, Err(BodyError::Incomplete));
    assert!(host.failed.lock().unwrap().is_empty());
}

/// A guest that has answered and then leaves its `next` body unfinished
/// while waiting on the response has cut its forward: `next` fails for
/// the guest, nothing has failed, and the answer stands.
#[tokio::test]
async fn unfinished_next_body_after_answering_cuts_the_forward_only() {
    let rt = runtime();
    let layer = load(&rt, config()).await;
    let host = Mock::new(NextMode::Upload);
    let (status, body) = exchange(
        &layer,
        host.clone(),
        request("answer-then-cut-next", Body::from_bytes("partial")),
    )
    .await
    .unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "answered and kept");
    assert_eq!(host.upload_ended().await, Err(BodyError::Incomplete));
    assert!(host.failed.lock().unwrap().is_empty());
}

/// An endpoint call's future the guest holds is not a wait on `next`: a
/// guest that drops `next`'s future and then its unfinished body has
/// abandoned the forward, at no fault, whatever else it holds.
#[tokio::test]
async fn a_held_endpoint_call_does_not_make_an_abandoned_next_a_cut() {
    let rt = runtime();
    let mut cfg = config();
    cfg.capabilities = Capabilities::NONE.with(Capability::Endpoints);
    let layer = load(&rt, cfg).await;
    let host = Mock::new(NextMode::Upload);
    let (mut client_tx, client_body) = Body::channel(u64::MAX, None);
    let handle = tokio::spawn({
        let layer = layer.clone();
        let host = host.clone();
        async move { exchange(&layer, host, request("endpoint-held-abandon", client_body)).await }
    });
    // The guest reads a byte before it abandons `next`, so the host has
    // the request by then.
    host.entered.notified().await;
    client_tx.send_data(Bytes::from("partial")).await.unwrap();
    let (status, body) = handle.await.unwrap().unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "abandoned with a call held");
    assert_eq!(host.upload_ended().await, Err(BodyError::Incomplete));
    let failed = host.failed.lock().unwrap().clone();
    assert!(failed.is_empty(), "{failed:?}");
}

/// A guest that drops `next`'s response future, then the unfinished body,
/// has abandoned the forwarded request: its own answer stands, and the
/// forwarded body is cut. The host goes on reading that body after the
/// guest dropped the future, as an upstream connection does; whether it
/// sees the cut before the guest's answer goes out is a race, so this runs
/// a few times.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unfinished_next_body_after_dropping_the_future_is_not_a_failure() {
    let rt = runtime();
    let layer = load(&rt, config()).await;
    for _ in 0..50 {
        let host = Mock::new(NextMode::Upload);
        let (mut client_tx, client_body) = Body::channel(u64::MAX, None);
        let handle = tokio::spawn({
            let layer = layer.clone();
            let host = host.clone();
            async move { exchange(&layer, host, request("next-then-answer", client_body)).await }
        });
        // The guest waits for this before it abandons `next`, so the host
        // has the request by then.
        host.entered.notified().await;
        client_tx.send_data(Bytes::from("partial")).await.unwrap();
        let (status, body) = handle.await.unwrap().unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "answered by  after forwarding 7 bytes");
        assert_eq!(host.upload_ended().await, Err(BodyError::Incomplete));
    }
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
            "record verdict {\"score\":0.9}",
        ),
        (
            "state",
            Capability::State,
            "Ok(()) Some(\"from-layer\")",
            "state_put k from-layer None",
        ),
        (
            "metric",
            Capability::Metrics,
            "Some(7)",
            "metric_get requests [\"10.0.0.1\"]",
        ),
        ("quarantine", Capability::Quarantine, "ok", "quarantine"),
        (
            "endpoint",
            Capability::Endpoints,
            "200 score=0.1",
            "endpoint monitor /score?q=1",
        ),
        (
            "unknown-endpoint",
            Capability::Endpoints,
            "error Error::DestinationNotFound",
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

/// A call made while the exchange has its permitted calls in flight waits
/// in `endpoints.call`, before the host takes its body: however many calls
/// a guest makes without reading them, the host holds at most a permit's
/// worth of bodies.
#[tokio::test]
async fn endpoint_bodies_wait_for_a_permit() {
    let rt = runtime();
    let mut cfg = config();
    cfg.capabilities = Capabilities::all();
    let layer = load(&rt, cfg).await;
    let host = Mock::echo();
    let count = 3 * MOCK_ENDPOINT_CALLS;

    let mut flood = tokio::spawn({
        let (layer, host) = (layer.clone(), host.clone());
        async move {
            let mut req = request("caps", Body::empty());
            req.headers_mut()
                .insert("x-cap", "endpoint-flood".parse().unwrap());
            req.headers_mut()
                .insert("x-cap-count", count.to_string().parse().unwrap());
            exchange(&layer, host, req).await
        }
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(300), &mut flood)
            .await
            .is_err(),
        "the exchange answered while its calls were parked"
    );
    let parked = host
        .calls()
        .iter()
        .filter(|c| c.starts_with("endpoint park"))
        .count();
    assert_eq!(parked, MOCK_ENDPOINT_CALLS);

    host.unpark.send_replace(true);
    let (status, body) = flood.await.unwrap().unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, format!("flooded {count}"));
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
    for test in ["trap", "no-response"] {
        assert_eq!(count(&layer).await, 2, "{test}");
        exchange(&layer, Mock::echo(), request(test, Body::empty()))
            .await
            .unwrap_err();
        assert_eq!(count(&layer).await, 1, "{test}");
    }
}

/// A guest that prints keeps a handle to its WASI stdout or stderr stream
/// across exchanges. Those are the host's streams, not the exchange's, so
/// holding them is not an unfinished body.
#[tokio::test]
async fn printing_to_stdio_is_not_a_failure() {
    let rt = runtime();
    let mut cfg = config();
    cfg.limits.max_instances = 1;
    let layer = load(&rt, cfg).await;
    for _ in 0..2 {
        let (status, body) = exchange(&layer, Mock::echo(), request("print", Body::empty()))
            .await
            .unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "printed");
    }
    // The same instance served both: printing did not get it discarded.
    assert_eq!(count(&layer).await, 3);
}

/// Each host resource a guest holds (streams, pollables, pending responses)
/// costs host memory outside its `max_memory`, so the table is capped per
/// instance.
#[tokio::test]
async fn a_guest_holding_too_many_resources_fails_closed() {
    let rt = runtime();
    let mut cfg = config();
    cfg.limits.max_instances = 1;
    let layer = load(&rt, cfg).await;
    let err = exchange(&layer, Mock::echo(), request("hoard:5000", Body::empty()))
        .await
        .unwrap_err();
    assert!(matches!(err, LayerError::Trap(_)), "{err:?}");
    // Under the cap the same guest answers, on a fresh instance: the
    // failed one was discarded, not returned to the pool.
    let (status, body) = exchange(&layer, Mock::echo(), request("hoard:1000", Body::empty()))
        .await
        .unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "hoarded");
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

/// The wait for a slot is bounded by `first_byte_timeout`: an exchange
/// that finds every instance busy for that long fails with `NoInstance`
/// rather than queueing behind them indefinitely.
#[tokio::test(start_paused = true)]
async fn waiting_for_a_slot_times_out() {
    let rt = runtime();
    let mut cfg = config();
    cfg.limits.max_instances = 1;
    cfg.limits.first_byte_timeout = Duration::from_millis(200);
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

    let err = exchange(&layer, Mock::echo(), request("count", Body::empty()))
        .await
        .unwrap_err();
    assert!(matches!(err, LayerError::NoInstance), "{err:?}");
    // The exchange holding the instance is untouched by the refusal.
    assert!(!first.is_finished());
}

/// The head clock does not limit bodies: a stream outliving that deadline many
/// times over goes through whole.
#[tokio::test]
async fn a_long_stream_is_not_cut() {
    let rt = runtime();
    let mut cfg = config();
    cfg.limits.first_byte_timeout = Duration::from_millis(100);
    let layer = load(&rt, cfg).await;

    let (mut up_tx, up_body): (BodySender, Body) = Body::channel(u64::MAX, None);
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
    for chunk in ["one ", "two ", "three"] {
        tokio::time::sleep(Duration::from_millis(200)).await;
        up_tx.send_data(Bytes::from(chunk)).await.unwrap();
    }
    up_tx.finish().await.unwrap();
    let (status, body) = first.await.unwrap().unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "one two three");
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
            let _answer = host.expect_answer();
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
    // Dropping the exchange: the call if it is still running, and the
    // response it returned if it is not (a layer that streams both bodies
    // answers as soon as `next` does).
    task.abort();
    drop(task);
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

/// Both bodies stream at once: each chunk of a request body that has not
/// ended comes back (through an echo below the layer) before the next is
/// sent. A WebSocket through a layer is exactly this.
#[tokio::test]
async fn both_bodies_stream_at_once() {
    let rt = runtime();
    let layer = load(&rt, config()).await;
    let (mut client_tx, client_body) = Body::channel(u64::MAX, None);
    let mut req = request("pass", client_body);
    req.headers_mut().insert("x-upper", "1".parse().unwrap());
    let mut started = start(&layer, Mock::echo(), req);
    let resp = started.response().await.unwrap();
    let mut body = resp.into_body();
    for msg in ["ping", "pong", "done"] {
        client_tx.send_data(Bytes::from(msg)).await.unwrap();
        let mut got = Vec::new();
        while got.len() < msg.len() {
            let frame = tokio::time::timeout(Duration::from_secs(5), body.frame())
                .await
                .expect("each chunk comes back before the request body ends")
                .unwrap()
                .unwrap();
            got.extend_from_slice(frame.data_ref().unwrap());
        }
        assert_eq!(got, msg.to_ascii_uppercase().as_bytes());
    }
    client_tx.finish().await.unwrap();
    assert!(body.frame().await.is_none());
}

async fn sse_approval(hold_response: bool, edit: bool) {
    const TOOL: &str = "event: tool_call\ndata: delete_file\n\n";
    let rt = runtime();
    let mut cfg = config();
    cfg.capabilities = Capabilities::NONE.with(Capability::Endpoints);
    let layer = load(&rt, cfg).await;
    let (mut up_tx, up_body) = Body::channel(u64::MAX, None);
    let (seen_tx, mut seen_rx) = oneshot::channel();
    let host = Mock::new(NextMode::Capture(Mutex::new(Some((
        seen_tx,
        Response::new(up_body),
    )))));
    let mode = if hold_response {
        "sse-approve-response"
    } else {
        "sse-approve-request"
    };
    let mut req = request(mode, Body::from_bytes(TOOL));
    req.headers_mut()
        .insert("x-read-bytes", TOOL.len().to_string().parse().unwrap());
    if edit {
        req.headers_mut()
            .insert("x-edit-tool", "1".parse().unwrap());
    }
    let mut started = start(&layer, host.clone(), req);
    let mut response = started.response().await.unwrap().into_body();
    sse_bytes(&mut response, b"event: start\ndata: {}\n\n").await;
    if hold_response {
        let forwarded = (&mut seen_rx).await.unwrap();
        assert_eq!(collect(forwarded.into_body()).await.unwrap(), TOOL);
        up_tx
            .send_data(Bytes::from_static(TOOL.as_bytes()))
            .await
            .unwrap();
    }
    for _ in 0..3 {
        sse_bytes(&mut response, b": approval pending\n\n").await;
    }
    if !hold_response {
        assert!(
            matches!(seen_rx.try_recv(), Err(oneshot::error::TryRecvError::Empty)),
            "the request is held until approval"
        );
    }
    host.unpark.send_replace(true);
    let expected = if edit {
        TOOL.replace("delete_file", "read_file")
    } else {
        TOOL.to_owned()
    };
    if !hold_response {
        let forwarded = seen_rx.await.unwrap();
        assert_eq!(collect(forwarded.into_body()).await.unwrap(), expected);
        up_tx
            .send_data(Bytes::from(expected.clone()))
            .await
            .unwrap();
    }
    sse_bytes(&mut response, expected.as_bytes()).await;
    // The approved chunk arrives before the next upstream chunk exists.
    up_tx
        .send_data(Bytes::from_static(b"event: done\ndata: {}\n\n"))
        .await
        .unwrap();
    sse_bytes(&mut response, b"event: done\ndata: {}\n\n").await;
    up_tx.finish().await.unwrap();
    assert!(response.frame().await.is_none());
    started.outcome().await.unwrap();
}

async fn sse_bytes(body: &mut Body, expected: &[u8]) {
    let mut bytes = Vec::new();
    while bytes.len() < expected.len() {
        let frame = tokio::time::timeout(Duration::from_secs(5), body.frame())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        bytes.extend_from_slice(frame.data_ref().unwrap());
    }
    assert_eq!(bytes, expected);
}

#[tokio::test]
async fn sse_keepalives_continue_while_a_guest_holds_a_request_for_approval() {
    for edit in [false, true] {
        sse_approval(false, edit).await;
    }
}

#[tokio::test]
async fn sse_keepalives_continue_while_a_guest_holds_a_tool_call_for_approval() {
    for edit in [false, true] {
        sse_approval(true, edit).await;
    }
}
