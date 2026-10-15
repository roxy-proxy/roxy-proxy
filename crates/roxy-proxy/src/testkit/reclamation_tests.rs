//! Exchange reclamation across transport and addon lifetimes.
use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::addons::AddonMode;
use crate::addons::service::testing::{addon, kit_with};

const RULES: &str = "- { id: up, when: 'host == \"up.test\"', then: allow }\n- { id: no_denied, when: 'path == \"/denied\"', then: deny }";

#[tokio::test]
async fn late_deny_controls_h1_pipelined_connection_reuse() {
    for close in [true, false] {
        let rules = RULES.replace(
            "then: deny",
            &format!("then: {{ deny: {{ close: {close} }} }}"),
        );
        let kit = kit_with(
            &rules,
            vec![addon("s", "scripted", AddonMode::Enforce, |_| {})],
            |b| b,
        )
        .await;
        let mut client = kit.connect();
        client
            .write_all(b"GET http://up.test/denied HTTP/1.1\r\nHost: up.test\r\n\r\n")
            .await
            .unwrap();
        let mut script = kit.upstream.service().script().await;
        script.control("open").await;
        let request = script.control("request").await;
        script.body(0).await;
        script.send(json!({"type":"response", "status":204, "headers":[]}));
        script.send(json!({"type":"response_end"}));
        assert!(read_head(&mut client).await.starts_with("HTTP/1.1 204"));
        // This is already queued when the late refusal asks to close.
        client
            .write_all(b"GET http://up.test/next HTTP/1.1\r\nHost: up.test\r\n\r\n")
            .await
            .unwrap();
        script.send(request);
        script.send(json!({"type":"request_end"}));
        assert_eq!(script.control("response").await["status"], 403);
        script.body(1).await;
        let event = kit.request_event().await;
        assert_eq!(event["decision"], "deny");
        assert!(kit.upstream.seen().is_empty());
        if close {
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), client.read(&mut [0]))
                    .await
                    .unwrap()
                    .unwrap(),
                0
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(50), script.control("open"))
                    .await
                    .is_err()
            );
        } else {
            script.control("open").await;
            assert_eq!(
                script.control("request").await["url"],
                "http://up.test/next"
            );
            script.body(0).await;
            script.send(json!({"type":"response", "status":204, "headers":[]}));
            script.send(json!({"type":"response_end"}));
            script.send(json!({"type":"request_end"}));
            assert!(read_head(&mut client).await.starts_with("HTTP/1.1 204"));
            kit.request_event().await;
        }
    }
}

async fn read_head(client: &mut (impl tokio::io::AsyncRead + Unpin)) -> String {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(client.read_u8().await.unwrap());
    }
    String::from_utf8(head).unwrap()
}

#[tokio::test]
async fn suppressed_response_drains_a_large_upload_before_connection_reuse() {
    for (method, status) in [("HEAD", "200"), ("POST", "204")] {
        let kit = super::Kit::builder()
            .addon(super::AddonDef::test_layer("a"))
            .flags(|f| f.allow_body_on_get = true)
            .limits(|l| {
                l.body_idle_timeout = Duration::from_millis(500);
                l.response_body_idle_timeout = Duration::from_millis(500);
            })
            .start()
            .await;
        // A raw client deliberately continues the upload after an early
        // final head; HTTP client libraries may abandon it at that point.
        let mut client = kit.connect();
        client.write_all(format!("{method} http://up.test/x HTTP/1.1\r\nHost: up.test\r\nContent-Length: 2097152\r\nX-Test-A: answer-request-body\r\nX-Status: {status}\r\n\r\n").as_bytes()).await.unwrap();
        let (mut reader, mut writer) = tokio::io::split(client);
        let uploading = tokio::spawn(async move {
            writer
                .write_all(&vec![b'x'; 2 * 1024 * 1024])
                .await
                .unwrap();
            writer
        });
        assert!(
            read_head(&mut reader)
                .await
                .starts_with(&format!("HTTP/1.1 {status}"))
        );
        let writer = tokio::time::timeout(Duration::from_secs(2), uploading)
            .await
            .unwrap()
            .unwrap();
        let mut client = reader.unsplit(writer);
        let event = kit.request_event().await;
        assert!(event["reason"].is_null(), "{method}: {event:#}");
        assert_eq!(event["res"]["body_bytes"], 0);
        assert!(
            kit.sink
                .events()
                .iter()
                .all(|e| e["event"] != "response_error")
        );
        client
            .write_all(
                b"GET http://up.test/next HTTP/1.1\r\nHost: up.test\r\nX-Test-A: answer\r\n\r\n",
            )
            .await
            .unwrap();
        // No suppressed body bytes may appear before the next HTTP head.
        assert!(read_head(&mut client).await.starts_with("HTTP/1.1 200"));
    }
}

#[tokio::test]
async fn h1_disconnect_with_a_full_pipeline_buffer_releases_service() {
    disconnect_with_pipeline_bytes(512).await;
    disconnect_with_pipeline_bytes(513).await;
}

#[tokio::test]
async fn control_h1_disconnect_with_room_in_pipeline_buffer_releases_service() {
    disconnect_with_pipeline_bytes(511).await;
}

async fn disconnect_with_pipeline_bytes(buffered: usize) {
    let kit = kit_with(
        RULES,
        vec![addon("s", "scripted", AddonMode::Enforce, |s| {
            s.max_connections = 1;
            s.max_streams = 1;
        })],
        |b| {
            b.limits(|l| {
                l.max_header_bytes = 512;
                l.header_timeout = Duration::from_millis(400);
                l.response_body_idle_timeout = Duration::from_millis(100);
            })
        },
    )
    .await;
    let (mut client, reset) = kit.connect_resettable();
    client
        .write_all(b"GET http://up.test/x HTTP/1.1\r\nHost: up.test\r\n\r\n")
        .await
        .unwrap();
    let mut script = kit.upstream.service().script().await;
    script.control("open").await;
    script.control("request").await;
    script.body(0).await;
    script.send(json!({"type":"response", "status":204, "headers":[]}));
    script.send(json!({"type":"response_end"}));
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(client.read_u8().await.unwrap());
    }
    assert!(head.starts_with(b"HTTP/1.1 204"));
    client.write_all(&vec![b'x'; buffered]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    reset.reset();
    drop(client);
    tokio::time::timeout(Duration::from_millis(500), script.control("reset"))
        .await
        .expect("disconnect must release the service even when the pipeline buffer is full");
}
