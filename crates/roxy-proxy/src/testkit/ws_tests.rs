//! The WebSocket relay: message rules, protocol limits, extension
//! stripping, sampling and byte budgets, against the framed echo upstream.

use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::frame::Frame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::{Data, OpCode};

use super::{Kit, KitBuilder, Ws};

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
    use super::AddonDef;
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
