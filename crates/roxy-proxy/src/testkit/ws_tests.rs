//! The WebSocket relay: message rules, protocol limits, extension
//! stripping, sampling and byte budgets, against the framed echo upstream.

use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::frame::Frame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::{Data, OpCode};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::{AddonDef, Answer, Client, Kit, KitBuilder, Ws};

const WS_ALLOW: &str = r#"
- id: ws
  when: host == "up.test" and path starts_with "/ws"
  then: { allow: { upgrade: websocket } }
- id: up
  when: host == "up.test"
  then: allow
"#;

/// `WS_ALLOW` plus `more` rules.
fn with(more: &str) -> KitBuilder {
    Kit::builder().rules(&format!("{WS_ALLOW}{more}"))
}

#[tokio::test]
async fn disconnect_after_upgrade_cancels_a_holding_service() {
    held_upgrade_ends(UpgradeEnd::Disconnect).await;
}

#[tokio::test]
async fn a_cut_upgraded_answer_ends_the_exchange_without_claiming_client_loss() {
    held_upgrade_ends(UpgradeEnd::Cut).await;
}

#[tokio::test]
async fn an_upgraded_response_fault_reaches_final_attribution() {
    held_upgrade_ends(UpgradeEnd::Fault).await;
}

#[derive(Clone, Copy)]
enum UpgradeEnd {
    Disconnect,
    Cut,
    Fault,
}

async fn held_upgrade_ends(end: UpgradeEnd) {
    use crate::addons::service::testing;
    use crate::addons::{AddonMode, CLIENT_GONE};

    let kit = testing::kit(
        WS_ALLOW,
        vec![testing::addon("s", "scripted", AddonMode::Enforce, |_| {})],
    )
    .await;
    let (mut client, reset) = kit.connect_resettable();
    client.write_all(b"GET http://up.test/ws/echo HTTP/1.1\r\nHost: up.test\r\nConnection: upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").await.unwrap();
    let mut script = kit.upstream.service().script().await;
    script.control("open").await;
    let request = script.control("request").await;
    script.send(request);
    let response = script.control("response").await;
    assert_eq!(response["status"], 101);
    script.send(response);
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(client.read_u8().await.unwrap());
    }
    assert!(head.starts_with(b"HTTP/1.1 101"));
    match end {
        UpgradeEnd::Cut => script.send(serde_json::json!({"type":"response_end", "error":"cut"})),
        UpgradeEnd::Fault => {
            script.send(serde_json::json!({"type":"response", "status":101, "headers":[]}));
        }
        UpgradeEnd::Disconnect => {
            reset.reset();
            drop(client);
        }
    }
    let message = tokio::time::timeout(Duration::from_secs(3), script.control("reset"))
        .await
        .expect("a disconnected upgraded client must cancel the service");
    let expected = match end {
        UpgradeEnd::Disconnect => {
            assert_eq!(message["message"], CLIENT_GONE, "{message}");
            "client_gone"
        }
        UpgradeEnd::Cut => {
            assert_eq!(message["message"], crate::addons::ENDED, "{message}");
            "answer_aborted"
        }
        UpgradeEnd::Fault => {
            assert!(
                message["message"]
                    .as_str()
                    .unwrap()
                    .contains("second response head"),
                "{message}"
            );
            "layer_error"
        }
    };
    let event = kit.request_event().await;
    assert_eq!(event["reason"], expected, "{event:#}");
    if matches!(end, UpgradeEnd::Fault) {
        assert_eq!(
            kit.events("layer_error", 1).await[0]["kind"],
            "service:protocol"
        );
    } else {
        super::no_layer_error(&kit);
    }
}

#[tokio::test]
async fn failed_upgrade_write_publishes_client_loss_before_releasing_lanes() {
    use crate::addons::service::testing;
    use crate::addons::{AddonMode, CLIENT_GONE, Part};

    let kit = testing::kit(
        WS_ALLOW,
        vec![testing::subscribed(
            testing::addon("s", "scripted", AddonMode::Enforce, |_| {}),
            Part::Head,
            Part::Full,
        )],
    )
    .await;
    let (mut client, reset) = kit.connect_resettable();
    client.write_all(b"GET http://up.test/ws/echo HTTP/1.1\r\nHost: up.test\r\nConnection: upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").await.unwrap();
    let mut script = kit.upstream.service().script().await;
    script.control("open").await;
    // A head-only request is its head: nothing follows it either way.
    let request = script.control("request").await;
    script.send(request);
    let response = script.control("response").await;
    assert_eq!(response["status"], 101);
    // Keep the read pending, but make the impending handshake write fail.
    reset.reset();
    script.send(response);
    let reset = script.control("reset").await;
    assert_eq!(reset["message"], CLIENT_GONE, "{reset}");
    kit.request_event().await;
}

/// Opens `/ws/echo` against the framed echo, offering `extensions` if
/// given.
async fn open(kit: &Kit, extensions: Option<&str>) -> Ws {
    let mut headers = vec![("x-echo", "frames")];
    if let Some(e) = extensions {
        headers.push(("sec-websocket-extensions", e));
    }
    kit.ws("/ws/echo", &headers).await
}

async fn echo(ws: &mut Ws, m: Message) -> Message {
    ws.send(m).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), ws.next())
        .await
        .expect("no echo")
        .unwrap()
        .unwrap()
}

/// Faithful addons preserve a TLS WebSocket through its close handshake.
#[tokio::test]
async fn wss_survives_pass_through_wasm_service_and_mixed_stacks() {
    use crate::addons::AddonMode;
    use crate::addons::service::testing;

    for inspect_messages in [false, true] {
        let rules = if inspect_messages {
            format!("{WS_ALLOW}\n- id: message-limit\n  when: ws.size > 1mb\n  then: deny\n")
        } else {
            WS_ALLOW.to_owned()
        };
        for (wasm, service) in [(false, false), (true, false), (false, true), (true, true)] {
            let mut addons = Vec::new();
            if wasm {
                addons.push(AddonDef::test_layer("a").spec().await);
            }
            if service {
                addons.push(testing::addon("s", "pass", AddonMode::Enforce, |_| {}));
            }
            if wasm {
                addons.push(AddonDef::test_layer("b").spec().await);
            }
            let names: Vec<_> = addons.iter().map(|a| a.name.clone()).collect();
            let kit = testing::kit(&rules, addons).await;
            // The outer CONNECT and TLS handshake precede the upgrade
            // that the addons forward. The origin connection uses TLS too.
            let client = kit.tunnel("up.test", false).await;
            let (status, io) = kit
                .websocket_over(client, "/ws/echo", &[("x-echo", "frames")])
                .await;
            assert_eq!(status, 101);
            let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
                io.unwrap(),
                tokio_tungstenite::tungstenite::protocol::Role::Client,
                None,
            )
            .await;
            assert_eq!(
                echo(&mut ws, Message::text("hello over TLS")).await,
                Message::text("hello over TLS")
            );
            let binary = Message::binary(vec![0, 1, 127, 128, 255]);
            assert_eq!(echo(&mut ws, binary.clone()).await, binary);
            assert_eq!(
                echo(&mut ws, Message::Ping(vec![1, 2].into())).await,
                Message::Pong(vec![1, 2].into())
            );
            ws.close(None).await.unwrap();
            let close = tokio::time::timeout(Duration::from_secs(2), ws.next())
                .await
                .expect("the close handshake finishes")
                .expect("a close frame, not bare EOF")
                .unwrap_or_else(|e| {
                    panic!(
                        "close with wasm={wasm}, service={service}, inspect={inspect_messages}: {e}"
                    )
                });
            assert_eq!(close, Message::Close(None));
            drop(ws);
            kit.upstream.wait_ws_closed(1).await;
            let event = kit.request_event().await;
            assert_eq!(event["res"]["status"], 101, "{event:#}");
            assert_eq!(event["decision"], "allow", "{event:#}");
            assert_eq!(event["tls"]["alpn"], "http/1.1", "{event:#}");
            assert_eq!(event["req"]["port"], 443, "{event:#}");
            assert_eq!(super::strs(&event["addons"]), names, "{event:#}");
            let seen = kit.upstream.wait_seen(1).await;
            assert_eq!(seen[0].addr.port(), 443);
            assert_eq!(seen[0].version, http::Version::HTTP_11);
            assert_eq!(
                kit.upstream.ws_received(),
                [b"hello over TLS".to_vec(), vec![0, 1, 127, 128, 255]]
            );
            super::no_layer_error(&kit);
        }
    }
}

/// Reads until the close frame roxy sends; returns its code. Data
/// messages before it are returned too.
async fn read_to_close(ws: &mut Ws) -> (Vec<Message>, Option<u16>) {
    let mut got = Vec::new();
    loop {
        let next = tokio::time::timeout(Duration::from_secs(10), ws.next())
            .await
            .expect("the WebSocket did not close");
        match next {
            Some(Ok(Message::Close(c))) => return (got, c.map(|c| u16::from(c.code))),
            Some(Ok(m)) => got.push(m),
            Some(Err(_)) | None => return (got, None),
        }
    }
}

/// A text rule denies one message: it never reaches the upstream, both
/// sides get a 1008 close, and the flow log names the rule.
#[tokio::test]
async fn a_text_rule_denies_a_message() {
    let kit = with(
        r#"
- id: no-secrets
  when: ws.direction == "c2s" and ws.opcode == 1 and ws.text contains "secret"
  then: deny
"#,
    )
    .start()
    .await;
    let mut ws = open(&kit, None).await;
    let back = echo(&mut ws, Message::text("hello")).await;
    assert_eq!(back.into_text().unwrap().as_str(), "hello");
    // Binary messages have no `ws.text`: the rule does not match them.
    let back = echo(&mut ws, Message::binary(b"secret".to_vec())).await;
    assert_eq!(back.into_data().as_ref(), b"secret");
    ws.send(Message::text("the secret is 42")).await.unwrap();
    let (got, code) = read_to_close(&mut ws).await;
    assert!(got.is_empty(), "{got:?}");
    assert_eq!(code, Some(1008));
    let msg = kit.events("ws_message", 1).await;
    assert_eq!(msg[0]["decision"], "deny");
    assert_eq!(msg[0]["direction"], "c2s");
    assert_eq!(msg[0]["opcode"], 1);
    assert_eq!(msg[0]["size"], 16);
    assert_eq!(msg[0]["rules"][0], "no-secrets");
    let close = kit.events("ws_close", 1).await;
    assert_eq!(close[0]["close_code"], 1008);
    let ev = kit.request_event().await;
    assert_eq!(ev["decision"], "deny", "{ev:#}");
    assert_eq!(ev["stage"], "websocket");
    assert_eq!(ev["terminal_rule"], "no-secrets");
    assert_eq!(
        kit.upstream.ws_received(),
        vec![b"hello".to_vec(), b"secret".to_vec()]
    );
}

/// Opcode and size rules, here on what the upstream sends back.
#[tokio::test]
async fn opcode_and_size_rules() {
    let kit = with(
        r#"
- id: no-binary-down
  when: ws.direction == "s2c" and ws.opcode == 2
  then: deny
- id: small-up
  when: ws.direction == "c2s" and ws.size > 1kb
  then: deny
"#,
    )
    .start()
    .await;
    let mut ws = open(&kit, None).await;
    let back = echo(&mut ws, Message::text("x".repeat(1024))).await;
    assert_eq!(back.into_text().unwrap().len(), 1024);
    // The upstream gets the binary message; its echo is denied.
    ws.send(Message::binary(vec![1, 2, 3])).await.unwrap();
    let (got, code) = read_to_close(&mut ws).await;
    assert!(got.is_empty(), "{got:?}");
    assert_eq!(code, Some(1008));
    assert_eq!(kit.upstream.ws_received().len(), 2);
    let msg = kit.events("ws_message", 1).await;
    assert_eq!(msg[0]["direction"], "s2c");
    assert_eq!(msg[0]["rules"][0], "no-binary-down");

    let mut ws = open(&kit, None).await;
    ws.send(Message::text("x".repeat(1025))).await.unwrap();
    let (_, code) = read_to_close(&mut ws).await;
    assert_eq!(code, Some(1008));
    assert_eq!(kit.upstream.ws_received().len(), 2);
}

/// A fragmented message is checked whole, and re-sent as one frame.
#[tokio::test]
async fn a_fragmented_message_is_checked_whole() {
    let kit = with(
        r#"
- id: no-hello-world
  when: ws.text == "hello world"
  then: deny
"#,
    )
    .start()
    .await;
    let mut ws = open(&kit, None).await;
    let frag = |data: &str, op, fin| Message::Frame(Frame::message(data.to_owned(), op, fin));
    ws.feed(frag("hello", OpCode::Data(Data::Text), false))
        .await
        .unwrap();
    ws.feed(frag(" there", OpCode::Data(Data::Continue), true))
        .await
        .unwrap();
    ws.flush().await.unwrap();
    let back = ws.next().await.unwrap().unwrap();
    assert_eq!(back.into_text().unwrap().as_str(), "hello there");
    ws.feed(frag("hello", OpCode::Data(Data::Text), false))
        .await
        .unwrap();
    ws.feed(frag(" ", OpCode::Data(Data::Continue), false))
        .await
        .unwrap();
    ws.feed(frag("world", OpCode::Data(Data::Continue), true))
        .await
        .unwrap();
    ws.flush().await.unwrap();
    let (got, code) = read_to_close(&mut ws).await;
    assert!(got.is_empty(), "{got:?}");
    assert_eq!(code, Some(1008));
    assert_eq!(kit.upstream.ws_received(), vec![b"hello there".to_vec()]);
}

/// A message over `limits.max_ws_message_bytes` closes both sides with
/// 1009; invalid UTF-8 in a text message with 1007.
#[tokio::test]
async fn protocol_limits_close_with_their_codes() {
    let kit = with(
        r"
- id: no-binary
  when: ws.opcode == 2
  then: deny
",
    )
    .limits(|l| l.max_ws_message_bytes = 1024)
    .start()
    .await;
    let mut ws = open(&kit, None).await;
    let back = echo(&mut ws, Message::text("y".repeat(1024))).await;
    assert_eq!(back.into_text().unwrap().len(), 1024);
    ws.send(Message::text("y".repeat(1025))).await.unwrap();
    let (_, code) = read_to_close(&mut ws).await;
    assert_eq!(code, Some(1009));
    let close = kit.events("ws_close", 1).await;
    assert_eq!(close[0]["close_code"], 1009);
    assert_eq!(close[0]["close_reason"], "message too big");

    let mut ws = open(&kit, None).await;
    let bad = Frame::message(vec![0xc3, 0x28], OpCode::Data(Data::Text), true);
    ws.send(Message::Frame(bad)).await.unwrap();
    let (_, code) = read_to_close(&mut ws).await;
    assert_eq!(code, Some(1007));
    assert_eq!(kit.upstream.ws_received().len(), 1);
}

/// The upgrade request goes to the upstream over HTTP/1.1 with the
/// canonical authority as `host`.
#[tokio::test]
async fn the_upgrade_request_carries_host() {
    let kit = with("").start().await;
    let mut ws = open(&kit, None).await;
    let back = echo(&mut ws, Message::text("hi")).await;
    assert_eq!(back.into_text().unwrap().as_str(), "hi");
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].version, http::Version::HTTP_11);
    assert_eq!(seen[0].headers["host"], "up.test", "{:?}", seen[0].headers);
    assert_eq!(seen[0].headers["upgrade"], "websocket");
}

/// Extensions are stripped from the offer only when rules read messages.
#[tokio::test]
async fn extensions_are_stripped_only_for_message_rules() {
    let kit = with("").start().await;
    let mut ws = open(&kit, Some("permessage-deflate")).await;
    let back = echo(&mut ws, Message::text("plain relay")).await;
    assert_eq!(back.into_text().unwrap().as_str(), "plain relay");
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(
        seen[0]
            .headers
            .get("sec-websocket-extensions")
            .map(http::HeaderValue::as_bytes),
        Some(b"permessage-deflate".as_slice()),
        "{:?}",
        seen[0].headers
    );

    let kit = with(
        r"
- id: no-binary
  when: ws.opcode == 2
  then: deny
",
    )
    .start()
    .await;
    let mut ws = open(&kit, Some("permessage-deflate")).await;
    let back = echo(&mut ws, Message::text("parsed relay")).await;
    assert_eq!(back.into_text().unwrap().as_str(), "parsed relay");
    let seen = kit.upstream.wait_seen(1).await;
    assert!(
        !seen[0].headers.contains_key("sec-websocket-extensions"),
        "{:?}",
        seen[0].headers
    );
}

/// `log.flow.ws_message_every` samples allowed messages; a clean close
/// handshake passes through the message relay.
#[tokio::test]
async fn messages_are_sampled_and_a_clean_close_passes_through() {
    let kit = with(
        r"
- id: no-binary
  when: ws.opcode == 2
  then: deny
",
    )
    .ws_message_every(2)
    .start()
    .await;
    let mut ws = open(&kit, None).await;
    for i in 0..3 {
        let back = echo(&mut ws, Message::text(format!("m{i}"))).await;
        assert_eq!(back.into_text().unwrap().as_str(), format!("m{i}"));
    }
    ws.close(None).await.unwrap();
    let (_, code) = read_to_close(&mut ws).await;
    assert_eq!(code, None, "the upstream's close carries no code");
    drop(ws);
    let close = kit.events("ws_close", 1).await;
    assert!(close[0].get("close_code").is_none(), "{close:?}");
    // Messages 1, 3 and 5 of: m0 up, m0 down, m1 up, m1 down, m2 up, m2
    // down, close up, close down.
    let msgs = kit.events("ws_message", 3).await;
    assert!(msgs.iter().all(|m| m["decision"] == "allow"), "{msgs:?}");
    assert_eq!(msgs[0]["direction"], "c2s");
    let ev = kit.request_event().await;
    assert_eq!(ev["decision"], "allow", "{ev:#}");
    // The relay's byte counts are not HTTP bodies: no digest in either
    // direction.
    assert!(ev["req"]["body_bytes"].as_u64().unwrap() > 0, "{ev:#}");
    assert!(ev["req"].get("body_sha256").is_none(), "{ev:#}");
    assert!(ev["res"].get("body_sha256").is_none(), "{ev:#}");
}

/// A byte budget applies to the relay: it closes before writing the bytes
/// that cross it.
#[tokio::test]
async fn a_byte_budget_closes_the_relay() {
    let kit = with(
        r"
- id: ws-budget
  when: metric.ws_down > 50kb
  then: deny
",
    )
    .metric_defs(r#"- { id: ws_down, count: response_bytes, where: 'host == "up.test"' }"#)
    .start()
    .await;
    let mut ws = open(&kit, None).await;
    let back = echo(&mut ws, Message::text("small")).await;
    assert_eq!(back.into_text().unwrap().as_str(), "small");
    // The echo of 100 KB crosses the 50 KiB budget: the relay closes.
    ws.send(Message::binary(vec![7u8; 100_000])).await.unwrap();
    let (got, _) = read_to_close(&mut ws).await;
    let got: usize = got.into_iter().map(|m| m.into_data().len()).sum();
    assert!(
        got < 100_000,
        "the over-budget echo was relayed ({got} bytes)"
    );
    let ev = kit.request_event().await;
    assert_eq!(ev["decision"], "deny", "{ev:#}");
    assert_eq!(ev["stage"], "websocket");
    assert_eq!(ev["terminal_rule"], "ws-budget");
    let close = kit.events("ws_close", 1).await;
    assert!(close[0]["bytes_s2c"].as_u64().unwrap() <= 50 * 1024 + 64);
}

/// A WebSocket silent for `idle_timeout` ends with a `1001` close frame on
/// both sides, not a bare EOF, whether roxy splices bytes or relays
/// messages. The flow log carries the close.
async fn idle_closes_both_sides_with_1001(more: &str) {
    let kit = with(more)
        .limits(|l| l.idle_timeout = Duration::from_millis(300))
        .start()
        .await;
    let mut ws = open(&kit, None).await;
    let back = echo(&mut ws, Message::text("hi")).await;
    assert_eq!(back.into_text().unwrap().as_str(), "hi");
    let (got, code) = read_to_close(&mut ws).await;
    assert!(got.is_empty(), "{got:?}");
    assert_eq!(code, Some(1001));
    kit.upstream.wait_ws_closed(1).await;
    assert_eq!(kit.upstream.ws_close_codes(), vec![Some(1001)]);
    let close = kit.events("ws_close", 1).await;
    assert_eq!(close[0]["close_code"], 1001, "{:#}", close[0]);
    assert_eq!(close[0]["close_reason"], "idle timeout");
    let ev = kit.request_event().await;
    assert_eq!(ev["decision"], "allow", "{ev:#}");
    assert!(ev["reason"].is_null(), "{ev:#}");
}

#[tokio::test]
async fn an_idle_byte_splice_closes_both_sides_with_1001() {
    idle_closes_both_sides_with_1001("").await;
}

#[tokio::test]
async fn an_idle_message_relay_closes_both_sides_with_1001() {
    idle_closes_both_sides_with_1001(
        r#"
- id: read-messages
  when: ws.direction == "c2s" and ws.size > 1mb
  then: deny
"#,
    )
    .await;
}

/// Without `upgrade: websocket` on the allow, the upgrade is stripped and
/// an ordinary request goes out.
#[tokio::test]
async fn an_upgrade_the_rule_does_not_allow_is_stripped() {
    let kit = Kit::builder().start().await;
    let (status, io) = kit.websocket("/echo", &[("x-echo", "frames")]).await;
    assert_eq!(status, 200);
    assert!(io.is_none());
    let seen = kit.upstream.wait_seen(1).await;
    assert!(
        !seen[0].headers.contains_key("upgrade"),
        "{:?}",
        seen[0].headers
    );
    let ev = kit.events("upgrade_stripped", 1).await;
    assert_eq!(ev[0]["upgrade"], "websocket");
    kit.request_event().await;
    assert!(kit.sink.events().iter().all(|e| e["event"] != "ws_open"));
}

/// With a stack, an upgrade request carrying a body is refused as `400
/// ws_bad_handshake`, as it is without addons.
#[tokio::test]
async fn upgrade_with_body_is_refused_with_a_stack() {
    let kit = Kit::builder()
        .rules(WS_ALLOW)
        .addon(AddonDef::test_layer("a"))
        .flags(|f| f.allow_body_on_get = true)
        .start()
        .await;
    let mut c = kit.h1().await;
    let hs = vec![
        ("connection", "upgrade"),
        ("upgrade", "websocket"),
        ("sec-websocket-version", "13"),
        ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
    ];
    let req = c
        .request("GET", "/ws/echo", &hs)
        .body(roxy_http::Body::from_bytes("hello"))
        .unwrap();
    let res = c.send(req).await.unwrap();
    assert_eq!(res.status(), 400);
    let ev = kit.request_event().await;
    assert_eq!(ev["decision"], "deny");
    assert_eq!(ev["terminal_rule"], "_websocket");
    assert_eq!(ev["reason"], "ws_bad_handshake");
}

/// Sends `POST /up` asking to upgrade to h2c, with `body`.
async fn h2c_post(kit: &Kit, body: roxy_http::Body) -> Answer {
    let mut c = kit.h1().await;
    let req = c
        .request(
            "POST",
            "/up",
            &[("connection", "upgrade"), ("upgrade", "h2c")],
        )
        .body(body)
        .unwrap();
    Answer::read(c.send(req).await.unwrap()).await
}

/// Only a WebSocket upgrade is relayed. Through a stack, any other is
/// the ordinary request the core forwards once it strips the upgrade:
/// its body goes out intact and the upstream's response comes back.
async fn non_websocket_upgrade_is_an_ordinary_request(kit: &Kit) {
    let a = h2c_post(kit, roxy_http::Body::from_bytes("hello")).await;
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.json()["body_len"], 5);
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].body, b"hello");
    assert!(
        !seen[0].headers.contains_key("upgrade"),
        "{:?}",
        seen[0].headers
    );
    let ev = kit.events("upgrade_stripped", 1).await;
    assert_eq!(ev[0]["upgrade"], "h2c");
    assert_eq!(kit.request_event().await["decision"], "allow");
}

#[tokio::test]
async fn non_websocket_upgrade_through_a_layer_is_an_ordinary_request() {
    let kit = Kit::builder()
        .rules(WS_ALLOW)
        .addon(AddonDef::test_layer("a"))
        .start()
        .await;
    non_websocket_upgrade_is_an_ordinary_request(&kit).await;
}

#[tokio::test]
async fn non_websocket_upgrade_through_a_service_is_an_ordinary_request() {
    use crate::addons::AddonMode;
    use crate::addons::service::testing::{addon, kit};
    let kit = kit(
        WS_ALLOW,
        vec![addon("s", "pass", AddonMode::Enforce, |_| {})],
    )
    .await;
    non_websocket_upgrade_is_an_ordinary_request(&kit).await;
}

/// A non-WebSocket upgrade's body streamed through a stack is held to
/// the request body cap.
#[tokio::test]
async fn non_websocket_upgrade_through_a_stack_keeps_the_body_cap() {
    let kit = Kit::builder()
        .rules(WS_ALLOW)
        .addon(AddonDef::test_layer("a"))
        .limits(|l| l.max_request_body_bytes = 1024)
        .start()
        .await;
    let (mut tx, body) = super::streaming_body();
    tokio::spawn(async move {
        for _ in 0..4 {
            let _ = tx.send_data(bytes::Bytes::from(vec![b'z'; 1024])).await;
        }
        let _ = tx.finish().await;
    });
    let a = h2c_post(&kit, body).await;
    assert_eq!(a.status, 413, "{a:?}");
    let ev = kit.events("parse_error", 1).await;
    assert_eq!(ev[0]["reason"], "body_too_large");
    assert!(kit.upstream.seen().iter().all(|s| s.body.len() <= 1024));
}

/// The capture `end` record of a WebSocket's client-to-server direction
/// after the client's connection is reset, with or without a layer
/// between the client and the relay.
async fn end_after_client_reset(layer: bool) -> serde_json::Value {
    let mut b = Kit::builder()
        .rules(
            r#"
- id: ws
  when: host == "up.test"
  then: [{ capture: both }, { allow: { upgrade: websocket } }]
"#,
        )
        .capture_selected();
    if layer {
        b = b.addon(AddonDef::test_layer("t"));
    }
    let kit = b.start().await;
    let (io, reset) = kit.connect_resettable();
    let (status, io) = kit
        .websocket_over(Client::h1(io, None).await, "/ws", &[])
        .await;
    assert_eq!(status, 101);
    let mut io = io.unwrap();
    io.write_all(b"hello").await.unwrap();
    let mut got = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(10), io.read_exact(&mut got))
        .await
        .expect("echo in time")
        .unwrap();
    reset.reset();
    drop(io);
    kit.events("ws_close", 1).await;
    let flow = kit.request_event().await["flow"]
        .as_str()
        .unwrap()
        .to_owned();
    kit.captured()
        .into_iter()
        .map(|(h, _)| h)
        .filter(|h| h["flow"] == flow.as_str() && h["dir"] == "request")
        .find(|h| h["kind"] == "end")
        .expect("an end record")
}

/// A client reset is captured as an aborted end, through a layer as
/// without one: the layer's failed request body is not a clean close.
#[tokio::test]
async fn a_client_reset_is_captured_as_aborted_through_a_layer_too() {
    let direct = end_after_client_reset(false).await;
    assert_eq!(direct["aborted"], true, "{direct}");
    let layered = end_after_client_reset(true).await;
    assert_eq!(layered["aborted"], true, "{layered}");
}

/// Service layers: a WebSocket runs through the service's stream like
/// any exchange, the `101` as the response head and the two directions
/// as the bodies.
mod service {
    use std::time::Duration;

    use futures_util::SinkExt as _;
    use tokio_tungstenite::tungstenite::Message;

    use super::{WS_ALLOW, echo, open, read_to_close};
    use crate::addons::AddonMode;
    use crate::addons::service::testing::{addon, kit};
    use crate::testkit::{Kit, no_layer_error};

    /// A masked client frame of `payload` bytes, and the unmasked echo.
    const fn frame_sizes(payload: usize) -> (usize, usize) {
        (2 + 4 + payload, 2 + payload)
    }

    /// The one stream the service saw opened.
    async fn stream_id(kit: &Kit) -> u32 {
        let opens = kit.upstream.service().until_opened(1).await;
        u32::try_from(opens[0]["stream"].as_u64().unwrap()).unwrap()
    }

    /// Both directions of a WebSocket go through a pass-through service
    /// and come back: the client's masked frames as the request body, the
    /// upstream's as the response body, and the close handshake with them.
    #[tokio::test]
    async fn frames_both_ways_go_through_the_service() {
        let kit = kit(
            WS_ALLOW,
            vec![addon("s", "pass", AddonMode::Enforce, |_| {})],
        )
        .await;
        let mut ws = open(&kit, None).await;
        let back = echo(&mut ws, Message::text("hello")).await;
        assert_eq!(back.into_text().unwrap().as_str(), "hello");
        let back = echo(&mut ws, Message::binary(vec![1, 2, 3])).await;
        assert_eq!(back.into_data().as_ref(), &[1, 2, 3]);
        let id = stream_id(&kit).await;
        let (up_text, down_text) = frame_sizes(5);
        let (up_bin, down_bin) = frame_sizes(3);
        let service = kit.upstream.service();
        assert_eq!(service.received_in(id, "request"), up_text + up_bin);
        assert_eq!(service.received_in(id, "response"), down_text + down_bin);
        ws.close(None).await.unwrap();
        let (got, code) = read_to_close(&mut ws).await;
        assert!(got.is_empty(), "{got:?}");
        assert_eq!(code, None, "the upstream's close carries no code");
        drop(ws);
        kit.events("ws_close", 1).await;
        let ev = kit.request_event().await;
        assert_eq!(ev["decision"], "allow", "{ev:#}");
        assert_eq!(ev["addons"][0], "s");
        assert_eq!(
            kit.upstream.ws_received(),
            vec![b"hello".to_vec(), vec![1, 2, 3]]
        );
        no_layer_error(&kit);
    }

    /// A service rewrites a frame on its way to the client; the upstream
    /// got what the client sent.
    #[tokio::test]
    async fn a_service_rewrites_a_frame_toward_the_client() {
        let kit = kit(
            WS_ALLOW,
            vec![addon("s", "shout", AddonMode::Enforce, |_| {})],
        )
        .await;
        let mut ws = open(&kit, None).await;
        let back = echo(&mut ws, Message::text("hello")).await;
        assert_eq!(back.into_text().unwrap().as_str(), "HELLO");
        assert_eq!(kit.upstream.ws_received(), vec![b"hello".to_vec()]);
        no_layer_error(&kit);
    }

    /// A service that resets its stream mid-WebSocket cuts both sides: the
    /// client's connection and the upstream's close, and the failure is
    /// the service's.
    #[tokio::test]
    async fn a_service_resetting_mid_websocket_closes_both_sides() {
        let kit = kit(
            WS_ALLOW,
            vec![addon("s", "sever", AddonMode::Enforce, |_| {})],
        )
        .await;
        let mut ws = open(&kit, None).await;
        // The echo is the first response body byte the service sees.
        ws.send(Message::text("hello")).await.unwrap();
        let (got, code) = read_to_close(&mut ws).await;
        assert!(got.is_empty(), "{got:?}");
        assert_eq!(code, None, "the client is cut, not closed with a code");
        kit.upstream.wait_ws_closed(1).await;
        kit.events("ws_close", 1).await;
        let errs = kit.events("layer_error", 1).await;
        assert_eq!(errs[0]["layer"], "s", "{errs:#?}");
        assert_eq!(errs[0]["kind"], "service:closed");
        kit.request_event().await;
    }

    /// An observing service gets copies of both directions on its stream.
    #[tokio::test]
    async fn an_observing_service_gets_copies_of_both_directions() {
        let kit = kit(
            WS_ALLOW,
            vec![addon("o", "pass", AddonMode::Observe, |_| {})],
        )
        .await;
        let mut ws = open(&kit, None).await;
        let back = echo(&mut ws, Message::text("hello")).await;
        assert_eq!(back.into_text().unwrap().as_str(), "hello");
        let id = stream_id(&kit).await;
        let (up, down) = frame_sizes(5);
        let service = kit.upstream.service();
        service.until_received(id, up + down).await;
        assert_eq!(service.received_in(id, "request"), up);
        assert_eq!(service.received_in(id, "response"), down);
        no_layer_error(&kit);
    }

    /// A WebSocket holds its stream for as long as it is open: with one
    /// stream per connection, another exchange through the layer waits for
    /// it, and gets it once the WebSocket has closed.
    #[tokio::test]
    async fn a_websocket_holds_its_place_on_the_connection() {
        let kit = kit(
            WS_ALLOW,
            vec![addon("s", "pass", AddonMode::Enforce, |s| {
                s.max_connections = 1;
                s.max_streams = 1;
                s.first_byte_timeout = Duration::from_millis(500);
            })],
        )
        .await;
        let mut ws = open(&kit, None).await;
        let back = echo(&mut ws, Message::text("hello")).await;
        assert_eq!(back.into_text().unwrap().as_str(), "hello");
        let a = kit.h1().await.call("GET", "/x", &[], b"").await;
        assert_eq!(a.status, 503, "no stream is free: {a:?}");
        let errs = kit.events("layer_error", 1).await;
        assert_eq!(errs[0]["kind"], "service:timeout", "{errs:#?}");
        ws.close(None).await.unwrap();
        read_to_close(&mut ws).await;
        drop(ws);
        kit.events("ws_close", 1).await;
        let a = kit.h1().await.call("GET", "/x", &[], b"").await;
        assert_eq!(a.status, 200, "the WebSocket's stream is free: {a:?}");
    }
}
