//! Approval with a live synthetic response: the test acts as the service,
//! and releases held content only after observing keepalives at the client.

use std::time::Duration;

use http_body_util::BodyExt as _;
use hyper::body::Incoming;
use roxy_http::Body;
use serde_json::{Value, json};

use super::upstream::service::Script;
use super::{Client, Kit};
use crate::addons::AddonMode;
use crate::addons::service::testing::{addon, kit_with};

const RULES: &str = "- { id: up, when: 'host == \"up.test\"', then: allow }";
const REQUEST: u8 = 0;
const RESPONSE: u8 = 1;
const TOOL: &[u8] = b"event: tool_call\ndata: {\"name\":\"delete_file\",\"path\":\"notes\"}\n\n";
const EDITED: &[u8] = b"event: tool_call\ndata: {\"name\":\"read_file\",\"path\":\"notes\"}\n\n";
const DENIED: &[u8] = b"event: denied\ndata: {}\n\n";
const START: &[u8] = b"event: start\ndata: {}\n\n";
const KEEPALIVE: &[u8] = b": approval pending\n\n";
const IDLE: Duration = Duration::from_secs(1);

struct Approval {
    kit: Kit,
    client: Client,
    response: http::Response<Incoming>,
    script: Script,
    request: Value,
    body: Vec<u8>,
}

async fn read_bytes(body: &mut Incoming, expected: &[u8]) {
    let mut got = Vec::new();
    while got.len() < expected.len() {
        let frame = tokio::time::timeout(IDLE, body.frame())
            .await
            .expect("the client receives bytes before its idle timeout")
            .expect("the response stays open")
            .expect("the response is not cut");
        got.extend_from_slice(frame.data_ref().expect("body data"));
    }
    assert_eq!(got, expected);
}

impl Approval {
    async fn new(h2: bool, path: &str) -> Self {
        let kit = kit_with(
            RULES,
            vec![addon("approval", "scripted", AddonMode::Enforce, |_| {})],
            |b| b.limits(|l| l.response_body_idle_timeout = IDLE),
        )
        .await;
        let mut client = if h2 {
            kit.tunnel("up.test", true).await
        } else {
            kit.h1().await
        };
        let req = client
            .request("POST", path, &[("x-echo-status", "201")])
            .body(Body::from_bytes(TOOL))
            .unwrap();
        let pending = tokio::spawn(async move {
            let response = client.send(req).await.unwrap();
            (client, response)
        });
        let mut script = kit.upstream.service().script().await;
        script.control("open").await;
        let request = script.control("request").await;
        let body = script.body(REQUEST).await;
        assert_eq!(body, TOOL);
        script.send(json!({
            "type": "response", "status": 200,
            "headers": [["content-type", "text/event-stream"]],
        }));
        script.bytes(RESPONSE, START);
        let (client, mut response) = pending.await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["content-type"], "text/event-stream");
        read_bytes(response.body_mut(), START).await;
        Self {
            kit,
            client,
            response,
            script,
            request,
            body,
        }
    }

    async fn keep_alive_while_holding(&mut self) {
        let start = tokio::time::Instant::now();
        for _ in 0..6 {
            // Any leaked content, clean EOF or cut would resolve this.
            assert!(
                tokio::time::timeout(Duration::from_millis(10), self.response.body_mut().frame())
                    .await
                    .is_err(),
                "held content must not reach the client"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
            self.script.bytes(RESPONSE, KEEPALIVE);
            read_bytes(self.response.body_mut(), KEEPALIVE).await;
        }
        assert!(start.elapsed() > IDLE, "keepalives renew the idle deadline");
    }

    fn forward(&self, body: &[u8]) {
        let mut request = self.request.clone();
        request["headers"]
            .as_array_mut()
            .unwrap()
            .retain(|h| h[0] != "content-length");
        self.script.send(request);
        self.script.bytes(REQUEST, body);
        self.script.send(json!({"type": "request_end"}));
    }

    async fn upstream_body(&mut self) -> Vec<u8> {
        let head = self.script.control("response").await;
        assert_eq!(head["status"], 201, "the upstream head is independent");
        self.script.body(RESPONSE).await
    }

    async fn finish(mut self, expected: &[u8]) {
        self.script.bytes(RESPONSE, expected);
        self.script.send(json!({"type": "response_end"}));
        let rest = tokio::time::timeout(IDLE, self.response.body_mut().collect())
            .await
            .unwrap()
            .unwrap()
            .to_bytes();
        assert_eq!(rest, expected);
        let event = self.kit.request_event().await;
        assert!(event["reason"].is_null(), "{event:#}");
        assert!(
            self.kit
                .sink
                .events()
                .iter()
                .all(|e| e["event"] != "layer_error")
        );
    }
}

#[derive(Clone, Copy)]
enum Decision {
    Approve,
    Edit,
    Deny,
}

async fn held_request(decision: Decision) {
    for h2 in [false, true] {
        let mut a = Approval::new(h2, "/echo").await;
        assert!(a.kit.upstream.seen().is_empty());
        a.keep_alive_while_holding().await;
        assert!(
            a.kit.upstream.seen().is_empty(),
            "nothing leaves before approval"
        );
        match decision {
            Decision::Approve | Decision::Edit => {
                let approved = if matches!(decision, Decision::Edit) {
                    EDITED
                } else {
                    &a.body
                };
                a.forward(approved);
                let expected = approved.to_vec();
                let received = a.upstream_body().await;
                assert_eq!(received, expected);
                let seen = a.kit.upstream.wait_seen(1).await;
                assert_eq!(seen[0].body, expected);
                assert_eq!(seen[0].complete, Some(true));
                a.finish(&received).await;
            }
            Decision::Deny => {
                a.script.send(json!({"type": "request_end"}));
                a.script.control("response_end").await;
                assert!(
                    a.kit.upstream.seen().is_empty(),
                    "denied requests never leave"
                );
                a.finish(DENIED).await;
            }
        }
    }
}

async fn held_response(decision: Decision) {
    for h2 in [false, true] {
        let mut a = Approval::new(h2, "/echo").await;
        a.forward(&a.body);
        let received = a.upstream_body().await;
        assert_eq!(received, TOOL);
        a.keep_alive_while_holding().await;
        let output = match decision {
            Decision::Approve => received.as_slice(),
            Decision::Edit => EDITED,
            Decision::Deny => DENIED,
        };
        a.finish(output).await;
    }
}

#[tokio::test]
async fn held_request_is_forwarded_after_sse_keepalives_and_approval() {
    held_request(Decision::Approve).await;
}

#[tokio::test]
async fn held_request_is_edited_after_sse_keepalives_and_approval() {
    held_request(Decision::Edit).await;
}

#[tokio::test]
async fn held_request_can_be_denied_after_sse_keepalives_without_forwarding() {
    held_request(Decision::Deny).await;
}

#[tokio::test]
async fn held_tool_call_is_released_after_sse_keepalives_and_approval() {
    held_response(Decision::Approve).await;
}

#[tokio::test]
async fn held_tool_call_is_edited_after_sse_keepalives_and_approval() {
    held_response(Decision::Edit).await;
}

#[tokio::test]
async fn held_tool_call_can_be_denied_after_sse_keepalives() {
    held_response(Decision::Deny).await;
}

#[tokio::test]
async fn a_second_response_head_after_a_synthetic_head_cuts_the_answer() {
    for h2 in [false, true] {
        let mut a = Approval::new(h2, "/echo").await;
        a.forward(&a.body);
        let head = a.script.control("response").await;
        a.script.send(head);
        let result = tokio::time::timeout(IDLE, a.response.body_mut().collect())
            .await
            .unwrap();
        assert!(result.is_err(), "the committed synthetic response is cut");
        let errors = a.kit.events("layer_error", 1).await;
        assert_eq!(errors[0]["layer"], "approval");
        assert_eq!(errors[0]["kind"], "service:protocol");
        a.kit.request_event().await;
    }
}

#[tokio::test]
async fn client_loss_during_approval_cancels_the_held_exchange() {
    for h2 in [false, true] {
        let mut a = Approval::new(h2, "/echo").await;
        // Hyper's HTTP/2 socket driver is separate from the request task;
        // release the response too so this actually cancels the stream.
        drop(a.response);
        drop(a.client);
        a.script.control("reset").await;
        let event = a.kit.request_event().await;
        assert_eq!(event["reason"], "client_gone", "{event:#}");
        assert!(a.kit.upstream.seen().is_empty());
    }
}

#[tokio::test]
async fn approval_releases_a_held_chunk_then_streams_the_remaining_upstream_body() {
    for h2 in [false, true] {
        let mut a = Approval::new(h2, "/early-drip?n=3&ms=400&first=0").await;
        a.forward(&a.body);
        a.script.control("response").await;
        let held = a.script.chunk(RESPONSE).await;
        assert_eq!(held, b"chunk0;");
        a.script.bytes(RESPONSE, KEEPALIVE);
        read_bytes(a.response.body_mut(), KEEPALIVE).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(50), a.response.body_mut().frame())
                .await
                .is_err()
        );
        a.script.bytes(RESPONSE, &held);
        read_bytes(a.response.body_mut(), &held).await;
        for expected in [b"chunk1;", b"chunk2;"] {
            let chunk = a.script.chunk(RESPONSE).await;
            assert_eq!(chunk, expected);
            a.script.bytes(RESPONSE, &chunk);
            read_bytes(a.response.body_mut(), expected).await;
        }
        a.script.control("response_end").await;
        a.finish(b"").await;
    }
}

#[tokio::test]
async fn grpc_status_trailers_survive_service_layers() {
    let kit = kit_with(
        RULES,
        vec![
            addon("outer", "pass", AddonMode::Enforce, |_| {}),
            addon("inner", "pass", AddonMode::Enforce, |_| {}),
        ],
        |b| b,
    )
    .await;
    let mut client = kit.tunnel("up.test", true).await;
    let request = client
        .request("POST", "/grpc", &[])
        .body(Body::from_bytes("request"))
        .unwrap();
    let response = client.send(request).await.unwrap();
    assert_eq!(response.headers()["content-type"], "application/grpc");
    let body = response.into_body().collect().await.unwrap();
    assert_eq!(body.trailers().unwrap()["grpc-status"], "0");
    assert_eq!(body.trailers().unwrap()["grpc-message"], "OK");
    assert_eq!(body.to_bytes(), "hello");
    let event = kit.request_event().await;
    assert!(event["reason"].is_null(), "{event:#}");
}
