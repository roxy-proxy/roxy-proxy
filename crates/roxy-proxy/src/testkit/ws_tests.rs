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
    use crate::testkit::Kit;

    /// A masked client frame of `payload` bytes, and the unmasked echo.
    const fn frame_sizes(payload: usize) -> (usize, usize) {
        (2 + 4 + payload, 2 + payload)
    }

    /// The one stream the service saw opened.
    async fn stream_id(kit: &Kit) -> u32 {
        let opens = kit.upstream.service().until_opened(1).await;
        u32::try_from(opens[0]["stream"].as_u64().unwrap()).unwrap()
    }

    fn no_layer_error(kit: &Kit) {
        let events = kit.sink.events();
        assert!(
            events.iter().all(|e| e["event"] != "layer_error"),
            "{events:#?}"
        );
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
