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
async fn h1_reset_during_backpressured_reclamation_releases_service() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let kit = testing::kit_with(
        super::ALLOW_UP,
        vec![testing::subscribed(
            testing::addon("s", "answer-open", AddonMode::Enforce, |s| {
                s.max_connections = 1;
                s.max_streams = 1;
            }),
            Part::Head,
            Part::Full,
        )],
        |b| {
            b.limits(|l| {
                l.max_header_bytes = 512;
                l.header_timeout = Duration::from_millis(200);
            })
        },
    )
    .await;
    let (mut client, reset) = kit.connect_resettable();
    client
        .write_all(
            b"POST http://up.test/x HTTP/1.1\r\nHost: up.test\r\nContent-Length: 2097152\r\n\r\n",
        )
        .await
        .unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(client.read_u8().await.unwrap());
    }
    assert!(head.starts_with(b"HTTP/1.1 204"));
    // The head-only service holds this upload for a possible later forward.
    // Drive the upload until the codec's bounded channel applies backpressure.
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            client.write_all(&vec![b'x'; 2 * 1024 * 1024]),
        )
        .await
        .is_err()
    );
    reset.reset();
    drop(client);
    tokio::time::timeout(Duration::from_millis(500), async {
        while kit.upstream.service().resets().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("a reset during reclamation must release the service slot");
    let event = kit.request_event().await;
    assert_eq!(event["reason"], "header_timeout", "{event:#}");
}

/// The same boundary contract for both addon backends and HTTP transports:
/// bypassed data, empty bodies with trailers, suppressed bodies and cuts.
#[tokio::test]
async fn head_only_completion_conforms_across_backends_and_transports() {
    use http_body_util::BodyExt as _;
    for service in [false, true] {
        for h2 in [false, true] {
            for (method, path) in [
                ("POST", "/x"),
                ("GET", "/trailers"),
                ("HEAD", "/status/200"),
                ("GET", "/cut"),
            ] {
                let kit = if service {
                    testing::kit(
                        super::ALLOW_UP,
                        vec![testing::subscribed(
                            testing::addon("a", "pass", AddonMode::Enforce, |_| {}),
                            Part::Head,
                            Part::Head,
                        )],
                    )
                    .await
                } else {
                    Kit::builder()
                        .rules(super::ALLOW_UP)
                        .addon(AddonDef::test_layer("a").subscribe(Part::Head, Part::Head))
                        .start()
                        .await
                };
                // Keep the origin on HTTP/2 for its empty-body trailers;
                // exercise both downstream transports independently.
                let mut client = kit.tunnel("up.test", h2).await;
                let data: &[u8] = if method == "POST" {
                    b"twelve bytes"
                } else {
                    b""
                };
                let req = client
                    .request(method, path, &[])
                    .body(roxy_http::Body::from_bytes(Bytes::from_static(data)))
                    .unwrap();
                let (parts, body) = client.send(req).await.unwrap().into_parts();
                let body = body.collect().await;
                if path == "/trailers" {
                    assert_eq!(
                        body.as_ref().unwrap().trailers().unwrap()["x-checksum"],
                        "none"
                    );
                }
                let answer = Answer {
                    status: parts.status.as_u16(),
                    headers: parts.headers,
                    body: body
                        .map(http_body_util::Collected::to_bytes)
                        .map_err(|e| e.to_string()),
                };
                assert_eq!(
                    answer.status, 200,
                    "service={service} h2={h2} {method} {path}: {answer:?}"
                );
                assert_eq!(
                    answer.body.is_ok(),
                    method == "HEAD" || path != "/cut",
                    "{answer:?}"
                );
                if method == "POST" {
                    assert_eq!(answer.json()["body_len"], 12);
                }
                let event = kit.request_event().await;
                if path == "/cut" {
                    assert_eq!(event["reason"], "upstream_body_failed", "{event:#}");
                } else {
                    assert!(event["reason"].is_null(), "{event:#}");
                }
                if method == "HEAD" {
                    assert_eq!(event["res"]["body_bytes"], 0);
                }
                super::no_layer_error(&kit);
            }
        }
    }
}

#[tokio::test]
async fn head_only_bodiless_h1_still_requires_a_timed_end() {
    for (method, status) in [("GET", 204), ("HEAD", 200)] {
        head_only_bodiless(false, false, method, status).await;
    }
}

#[tokio::test]
async fn head_only_bodiless_h2_still_requires_a_timed_end() {
    for (method, status) in [("GET", 204), ("HEAD", 200)] {
        head_only_bodiless(true, false, method, status).await;
    }
}

#[tokio::test]
async fn head_only_bodiless_clean_end_releases_the_exchange() {
    for h2 in [false, true] {
        for (method, status) in [("GET", 204), ("HEAD", 200)] {
            head_only_bodiless(h2, true, method, status).await;
        }
    }
}

async fn head_only_bodiless(h2: bool, clean_end: bool, method: &'static str, status: u16) {
    use serde_json::json;
    let kit = testing::kit_with(
        super::ALLOW_UP,
        vec![testing::subscribed(
            testing::addon("s", "scripted", AddonMode::Enforce, |_| {}),
            Part::Full,
            Part::Head,
        )],
        |b| b.limits(|l| l.response_body_idle_timeout = Duration::from_millis(50)),
    )
    .await;
    let mut client = if h2 {
        kit.tunnel("up.test", true).await
    } else {
        kit.h1().await
    };
    let call = tokio::spawn(async move {
        let answer = client.call(method, "/x", &[], b"").await;
        (client, answer)
    });
    let mut script = kit.upstream.service().script().await;
    script.control("open").await;
    script.control("request").await;
    script.body(0).await;
    script.send(json!({"type":"request_end"}));
    script.control("response_end").await;
    script.send(json!({"type":"response", "status":status, "headers":[]}));
    if clean_end {
        script.send(json!({"type":"response_end"}));
    }
    let (_client, answer) = call.await.unwrap();
    assert_eq!(answer.status, status);
    let event = tokio::time::timeout(Duration::from_secs(2), kit.request_event())
        .await
        .expect("head-only response_end is still outstanding and must time out");
    if clean_end {
        assert!(event["reason"].is_null(), "{event:#}");
    } else {
        assert_eq!(event["reason"], "response_body_timeout", "{event:#}");
        script.control("reset").await;
    }
    assert_eq!(event["res"]["body_bytes"], 0, "{event:#}");
    assert!(
        kit.sink
            .events()
            .iter()
            .all(|e| e["event"] != "response_error")
    );
}

#[tokio::test]
async fn response_validation_fault_attribution_is_independent_of_suppression() {
    for h2 in [false, true] {
        for (method, status) in [("HEAD", 200), ("GET", 204), ("GET", 200)] {
            response_validation_fault(h2, method, status).await;
        }
    }
}

async fn response_validation_fault(h2: bool, method: &'static str, status: u16) {
    use serde_json::json;
    let kit = testing::kit(
        super::ALLOW_UP,
        vec![testing::addon("s", "scripted", AddonMode::Enforce, |_| {})],
    )
    .await;
    let mut client = if h2 {
        kit.tunnel("up.test", true).await
    } else {
        kit.h1().await
    };
    let call = tokio::spawn(async move {
        let answer = client.call(method, "/x", &[], b"").await;
        (client, answer)
    });
    let mut script = kit.upstream.service().script().await;
    script.control("open").await;
    script.control("request").await;
    script.body(0).await;
    script.send(json!({"type":"request_end"}));
    script.control("response_end").await;
    script.send(json!({"type":"response", "status":status, "headers":[["content-length","10"]]}));
    let suppressed = method == "HEAD" || status == 204;
    let mut call = Some(call);
    // A suppressed answer must finish on the wire before the internal
    // body fails. Keep the client connected through reclamation.
    let early = if suppressed {
        Some(call.take().unwrap().await.unwrap())
    } else {
        None
    };
    script.bytes(1, b"short");
    script.send(json!({"type":"response_end"}));
    let (_client, answer) = match early {
        Some(answer) => answer,
        None => call.unwrap().await.unwrap(),
    };
    assert_eq!(answer.status, status);
    assert_eq!(answer.body.is_ok(), suppressed, "{answer:?}");
    let event = kit.request_event().await;
    let errors = kit.events("layer_error", 1).await;
    assert_eq!(errors[0]["kind"], "service:protocol");
    assert_eq!(event["reason"], "layer_error", "{event:#}");
    if suppressed {
        assert_eq!(event["res"]["body_bytes"], 0, "{event:#}");
        assert!(
            kit.sink
                .events()
                .iter()
                .all(|e| e["event"] != "response_error")
        );
    }
}

#[tokio::test]
async fn bodiless_response_consumption_obeys_idle_timeout_on_both_transports() {
    for h2 in [false, true] {
        for (method, status) in [("GET", 204), ("HEAD", 200)] {
            let kit = testing::kit_with(
                super::ALLOW_UP,
                vec![testing::addon(
                    "s",
                    "answer-open",
                    AddonMode::Enforce,
                    |_| {},
                )],
                |b| b.limits(|l| l.response_body_idle_timeout = Duration::from_millis(50)),
            )
            .await;
            let mut client = if h2 {
                kit.tunnel("up.test", true).await
            } else {
                kit.h1().await
            };
            let answer = client.call(method, "/x", &[], b"").await;
            assert_eq!(answer.status, status);
            let event = tokio::time::timeout(Duration::from_secs(2), kit.request_event())
                .await
                .expect("the internal response lane must reach its idle deadline");
            assert_eq!(event["reason"], "response_body_timeout", "{event:#}");
            assert_eq!(
                event["res"]["body_bytes"], 0,
                "discarded bytes are not written: {event:#}"
            );
            assert_ne!(kit.upstream.service().resets(), Vec::new());
            assert!(
                kit.sink
                    .events()
                    .iter()
                    .all(|e| e["event"] != "response_error")
            );
        }
    }
}

#[tokio::test]
async fn h1_declared_request_length_does_not_commit_a_later_cut() {
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
    kit.upstream.h1_only();
    let mut client = kit.h1().await;
    let answer = client.call("GET", "/declared-request-cut", &[], b"").await;
    assert_eq!(answer.status, 204);
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(
        seen[0].complete,
        Some(false),
        "an aborted upload reached the origin complete: {:?}",
        seen[0]
    );
}

#[tokio::test]
async fn h1_declared_length_does_not_commit_a_later_cut() {
    for path in ["/declared-cut", "/declared-empty-cut"] {
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
        let mut client = kit.h1().await;
        let answer = client.call("GET", path, &[], b"").await;
        let event = kit.request_event().await;
        assert_eq!(event["reason"], "answer_aborted", "{event:#}");
        assert!(
            answer.body.is_err(),
            "a cut response was accepted as complete: {answer:?}"
        );
    }
}

#[tokio::test]
async fn h1_disconnect_after_bodiless_answer_releases_service() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    let (mut client, reset) = kit.connect_resettable();
    client
        .write_all(b"GET http://up.test/x HTTP/1.1\r\nHost: up.test\r\n\r\n")
        .await
        .unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(client.read_u8().await.unwrap());
    }
    assert!(head.starts_with(b"HTTP/1.1 204"));
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(kit.upstream.service().resets(), Vec::new());
    reset.reset();
    drop(client);
    tokio::time::timeout(Duration::from_millis(500), async {
        while kit.upstream.service().resets().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("a disconnected HTTP/1 client must release its service slot");
}

/// An empty 200 is not complete until its producer ends the lane. The
/// producer can finish the upload after publishing the response head.
#[tokio::test]
async fn h2_empty_success_waits_for_the_forward_to_finish() {
    let kit = testing::kit(
        super::ALLOW_UP,
        vec![testing::addon(
            "s",
            "early-empty",
            AddonMode::Enforce,
            |_| {},
        )],
    )
    .await;
    let (send, _conn) = super::h2_client(&kit).await;
    let mut ready = send.ready().await.unwrap();
    let request = http::Request::post("https://up.test/upload")
        .body(())
        .unwrap();
    let (response, mut upload) = ready.send_request(request, false).unwrap();
    upload
        .send_data(Bytes::from_static(b"first"), false)
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(2), response)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(!response.headers().contains_key("content-length"));
    let mut body = response.into_body();
    assert!(!body.is_end_stream(), "the response lane is still open");
    upload
        .send_data(Bytes::from_static(b"second"), true)
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(data) = body.data().await {
            assert!(data.unwrap().is_empty());
        }
    })
    .await
    .expect("the response ends after forwarding completes");
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].body, b"firstsecond");
    assert_eq!(seen[0].complete, Some(true));
    let event = kit.request_event().await;
    assert_eq!(event["decision"], "answered", "{event:#}");
    assert_eq!(kit.upstream.service().resets(), []);
}

/// A reset after a complete response still explains why an admitted
/// forward was cancelled; it is not a failure writing that response.
#[tokio::test]
async fn h2_reset_after_an_early_answer_records_the_cause_of_forward_cancellation() {
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
    let (send, _conn) = super::h2_client(&kit).await;
    let mut ready = send.ready().await.unwrap();
    let request = http::Request::post("https://up.test/late?ms=5000")
        .body(())
        .unwrap();
    let (response, mut upload) = ready.send_request(request, false).unwrap();
    upload
        .send_data(Bytes::from_static(b"partial"), false)
        .unwrap();
    assert_eq!(response.await.unwrap().status(), 204);
    tokio::time::timeout(Duration::from_secs(2), async {
        while kit.upstream.seen().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    upload.send_reset(h2::Reason::CANCEL);
    let event = kit.request_event().await;
    assert_eq!(event["res"]["status"], 204, "{event:#}");
    assert_eq!(event["decision"], "answered", "{event:#}");
    assert_eq!(event["reason"], "client_gone", "{event:#}");
    assert!(
        kit.sink
            .events()
            .iter()
            .all(|e| e["event"] != "response_error")
    );
}

/// A service can stop waiting for the upstream response before its head.
/// Its still-open answer must not keep the abandoned forward running.
#[tokio::test]
async fn service_response_stop_cancels_a_forward_waiting_for_its_head() {
    let kit = testing::kit(
        super::ALLOW_UP,
        vec![testing::addon(
            "s",
            "stop-response",
            AddonMode::Enforce,
            |_| {},
        )],
    )
    .await;
    let (send, _conn) = super::h2_client(&kit).await;
    let mut ready = send.ready().await.unwrap();
    let request = http::Request::post("https://up.test/upload")
        .body(())
        .unwrap();
    let (response, mut upload) = ready.send_request(request, false).unwrap();
    upload
        .send_data(Bytes::from_static(b"partial"), false)
        .unwrap();
    assert_eq!(response.await.unwrap().status(), 204);
    let seen = tokio::time::timeout(Duration::from_secs(2), kit.upstream.wait_seen(1))
        .await
        .expect("stopping the response cancels the incomplete upload");
    assert_eq!(seen[0].complete, Some(false));
    assert!(
        kit.upstream
            .service()
            .controls(1)
            .iter()
            .all(|e| e["type"] != "response")
    );
    upload.send_reset(h2::Reason::CANCEL);
    kit.request_event().await;
}

/// The request body is available even when a head-only service forwards
/// immediately on open, before receiving roxy's request head.
#[tokio::test]
async fn a_head_only_service_forwarding_on_open_keeps_the_request_body() {
    let kit = testing::kit(
        super::ALLOW_UP,
        vec![testing::subscribed(
            testing::addon("s", "forward-on-open", AddonMode::Enforce, |_| {}),
            Part::Head,
            Part::Full,
        )],
    )
    .await;
    let answer = kit
        .h1()
        .await
        .call("POST", "/x", &[], b"bypassed upload")
        .await;
    assert_eq!(answer.status, 200, "{answer:?}");
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].body, b"bypassed upload");
    assert_eq!(seen[0].complete, Some(true));
}

/// A completed bodiless response still leaves the service cancellable.
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

/// A cut arriving after the original answer deadline starts a fresh deadline.
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
        "the service must answer within its renewed deadline after the forward ends"
    );
    assert_eq!(result.unwrap().status, 503);
    let errors = kit.events("layer_error", 1).await;
    assert_eq!(errors[0]["kind"], "service:timeout", "{errors:#?}");
}

/// Trailers cannot commit success before the producer supplies a clean end.
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
async fn an_upstream_layer_answers_before_next_mid_upload_through_the_downstream_one() {
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
    // End the client's upload cleanly. Dropping its source would introduce
    // an independent malformed upload during transport reclamation.
    tx.finish().await.unwrap();
    let ev = kit.request_event().await;
    assert_eq!(ev["decision"], "answered", "{ev:#}");
    assert_eq!(ev["terminal_rule"], "layer:a");
    assert_eq!(ev["reason"], "upstream_aborted");
    assert!(strs(&ev["rules"]).contains(&"up".to_owned()), "{ev:#}");
    assert!(ev["req"]["body_bytes"].as_u64().unwrap() >= 8192, "{ev:#}");
}

#[tokio::test]
async fn a_downstream_layer_answering_after_the_upstream_one_forwarded_is_the_one_named() {
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
