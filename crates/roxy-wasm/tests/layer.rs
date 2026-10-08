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
    Budget, Capabilities, Capability, HostError, Layer, LayerError, LayerOutcome, LoadError,
    MAX_FIELDS_BYTES, MAX_MESSAGE_BYTES,
};
use tokio::sync::{mpsc, oneshot};

mod common;
use common::*;

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
        let host = Mock::echo();
        let resp = layer
            .handle(host.clone(), request(test, Body::empty()))
            .await
            .unwrap_or_else(|e| panic!("{test}: head should be out: {e}"));
        let outcome = resp.extensions().get::<LayerOutcome>().cloned().unwrap();
        let err = collect(resp.into_body()).await.unwrap_err();
        assert_eq!(err, BodyError::Stopped, "{test}");
        // The body ended on a failure the host already had.
        let told = host.failed.lock().unwrap().clone();
        let failure = outcome.wait().await.unwrap_err();
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
    let resp = layer
        .handle(host.clone(), request("tags-after-head", Body::empty()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let outcome = resp.extensions().get::<LayerOutcome>().cloned().unwrap();
    assert_eq!(
        collect(resp.into_body()).await.unwrap_err(),
        BodyError::Stopped
    );
    assert_eq!(
        outcome.wait().await.unwrap_err(),
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

/// A `fields` a guest builds is host memory outside `max_memory`, so its
/// size is capped; one over the cap fails the exchange, named.
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
/// still waiting on the response fails the exchange, whatever the guest
/// answers next.
#[tokio::test]
async fn unfinished_next_body_while_awaiting_fails_closed() {
    let rt = runtime();
    let layer = load(&rt, config()).await;
    let host = Mock::new(NextMode::Upload);
    let err = exchange(
        &layer,
        host.clone(),
        request("cut-then-await", Body::from_bytes("partial")),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, LayerError::InvalidRequest(_)), "{err:?}");
    assert_eq!(host.next_calls.load(Ordering::SeqCst), 1);
    assert_eq!(host.upload_ended().await, Err(BodyError::Stopped));
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
        assert_eq!(host.upload_ended().await, Err(BodyError::Stopped));
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
    let cases: [(&str, Capability, &str, &str); 6] = [
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

/// Each host resource a guest holds (fields, bodies, streams) costs host
/// memory outside its `max_memory`, so the table is capped per instance.
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

/// Bodies have no clock: a stream that outlives the head deadline many
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
    let resp = layer.handle(Mock::echo(), req).await.unwrap();
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
