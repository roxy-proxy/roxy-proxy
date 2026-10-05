//! The capture log: what `capture.all` and the `capture` action record of
//! uploads, responses and WebSocket relays, byte for byte.

use bytes::Bytes;
use futures_util::{SinkExt as _, StreamExt as _};
use serde_json::Value;
use tokio_tungstenite::tungstenite::Message;

use super::{AddonDef, Kit, streaming_body};

/// The records of one flow and direction, in order.
fn capture_of<'a>(
    recs: &'a [(Value, Vec<u8>)],
    flow: &str,
    dir: &str,
) -> Vec<&'a (Value, Vec<u8>)> {
    recs.iter()
        .filter(|(h, _)| h["flow"] == flow && h["dir"] == dir)
        .collect()
}

/// Concatenated `data` payloads.
fn capture_body(recs: &[&(Value, Vec<u8>)]) -> Vec<u8> {
    recs.iter()
        .filter(|(h, _)| h["kind"] == "data")
        .flat_map(|(_, p)| p.iter().copied())
        .collect()
}

fn kinds(recs: &[&(Value, Vec<u8>)]) -> Vec<String> {
    recs.iter()
        .map(|(h, _)| h["kind"].as_str().unwrap().to_owned())
        .collect()
}

/// `capture.all` tees every forwarded exchange: heads as forwarded and
/// bodies byte for byte, here a chunked h1 upload and its response.
#[tokio::test]
async fn capture_all_records_exactly_what_was_forwarded() {
    let kit = Kit::builder().capture_all().start().await;
    let mut c = kit.h1().await;
    let (mut tx, body) = streaming_body();
    let req = c.request("POST", "/echo?x=1", &[]).body(body).unwrap();
    let pending = c.start(req);
    let sent: Vec<u8> = (0..20u8).flat_map(|i| vec![i; 16 * 1024]).collect();
    for chunk in sent.chunks(16 * 1024) {
        tx.send_data(Bytes::copy_from_slice(chunk)).await.unwrap();
    }
    tx.finish().await.unwrap();
    let a = pending.await.unwrap().unwrap();
    assert_eq!(a.status, 200, "{a:?}");
    let got = a.body.unwrap();
    let ev = kit.request_event().await;
    let flow = ev["flow"].as_str().unwrap();
    let records = kit.captured();
    let req = capture_of(&records, flow, "request");
    assert_eq!(req[0].0["kind"], "head");
    let head: Value = serde_json::from_slice(&req[0].1).unwrap();
    assert_eq!(head["method"], "POST");
    assert!(
        head["url"].as_str().unwrap().ends_with("/echo?x=1"),
        "{head}"
    );
    assert_eq!(capture_body(&req), sent);
    let end = req.last().unwrap();
    assert_eq!(end.0["kind"], "end");
    assert_eq!(end.0["bytes"], sent.len());
    assert!(end.0.get("aborted").is_none(), "{}", end.0);
    let res = capture_of(&records, flow, "response");
    let head: Value = serde_json::from_slice(&res[0].1).unwrap();
    assert_eq!(head["status"], 200);
    assert_eq!(capture_body(&res), got.to_vec());
    assert_eq!(res.last().unwrap().0["kind"], "end");
    // Sequence numbers count up per direction.
    let seqs: Vec<u64> = req
        .iter()
        .map(|(h, _)| h["seq"].as_u64().unwrap())
        .collect();
    assert_eq!(seqs, (0..seqs.len() as u64).collect::<Vec<_>>());
}

/// The `capture` action selects exchanges (and directions) at the head;
/// here over h2.
#[tokio::test]
async fn the_capture_action_selects_exchanges() {
    let kit = Kit::builder()
        .rules(
            r#"
- id: up
  when: host == "up.test"
  then: allow
- id: capture-uploads
  when: path starts_with "/cap"
  then: { capture: request }
"#,
        )
        .capture_selected()
        .start()
        .await;
    let mut c = kit.tunnel("up.test", true).await;
    let body = vec![b'q'; 50_000];
    let req = c
        .request("POST", "/cap/one", &[])
        .body(roxy_http::Body::from_bytes(Bytes::from(body.clone())))
        .unwrap();
    let a = super::Answer::read(c.send(req).await.unwrap()).await;
    assert_eq!(a.status, 200, "{a:?}");
    let a = c.call("GET", "/other", &[], b"").await;
    assert_eq!(a.status, 200, "{a:?}");
    let ev = kit.events("request", 2).await;
    let flow_of = |path: &str| {
        ev.iter()
            .find(|e| e["req"]["path"] == path)
            .unwrap_or_else(|| panic!("no request event for {path}"))["flow"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let (cap, other) = (flow_of("/cap/one"), flow_of("/other"));
    let records = kit.captured();
    let req = capture_of(&records, &cap, "request");
    assert_eq!(capture_body(&req), body);
    assert!(
        capture_of(&records, &cap, "response").is_empty(),
        "request only"
    );
    assert!(
        records.iter().all(|(h, _)| h["flow"] != other),
        "not selected"
    );
}

const WS_CAPTURE: &str = r#"
- id: ws
  when: host == "up.test"
  then: [{ capture: both }, { allow: { upgrade: websocket } }]
"#;

/// Echoes a text and a binary message, then closes.
async fn ws_echo(kit: &Kit, headers: &[(&str, &str)]) {
    let mut ws = kit.ws("/ws", headers).await;
    ws.send(Message::text("captured hello")).await.unwrap();
    let back = ws.next().await.unwrap().unwrap();
    assert_eq!(back.into_text().unwrap().as_str(), "captured hello");
    ws.send(Message::binary(vec![7u8; 100_000])).await.unwrap();
    let back = ws.next().await.unwrap().unwrap();
    assert_eq!(back.into_data().len(), 100_000);
    ws.close(None).await.unwrap();
}

/// Both heads (the upgrade as it left, the 101) and the relayed bytes
/// both ways are captured, and the byte counts match the flow log's.
async fn assert_ws_captured(kit: &Kit) {
    let close = kit.events("ws_close", 1).await;
    let ev = kit.request_event().await;
    let flow = ev["flow"].as_str().unwrap();
    let records = kit.captured();
    let c2s = capture_of(&records, flow, "request");
    let s2c = capture_of(&records, flow, "response");
    assert_eq!(
        kinds(&c2s).first().map(String::as_str),
        Some("head"),
        "{c2s:?}"
    );
    assert_eq!(
        kinds(&s2c).first().map(String::as_str),
        Some("head"),
        "{s2c:?}"
    );
    assert_eq!(
        capture_body(&c2s).len() as u64,
        close[0]["bytes_c2s"].as_u64().unwrap()
    );
    assert_eq!(
        capture_body(&s2c).len() as u64,
        close[0]["bytes_s2c"].as_u64().unwrap()
    );
    // The server-to-client frame is unmasked: the text is visible.
    let down = String::from_utf8_lossy(&capture_body(&s2c)).into_owned();
    assert!(down.contains("captured hello"), "{down:?}");
}

#[tokio::test]
async fn the_websocket_relay_is_captured_both_ways() {
    let kit = Kit::builder()
        .rules(WS_CAPTURE)
        .capture_selected()
        .start()
        .await;
    ws_echo(&kit, &[("x-echo", "frames")]).await;
    assert_ws_captured(&kit).await;
}

/// A WebSocket relayed through a layer is captured like any other.
#[tokio::test]
async fn a_websocket_through_a_layer_is_captured() {
    let kit = Kit::builder()
        .rules(WS_CAPTURE)
        .addon(AddonDef::test_layer("t"))
        .capture_selected()
        .start()
        .await;
    ws_echo(&kit, &[("x-echo", "frames")]).await;
    assert_ws_captured(&kit).await;
}
