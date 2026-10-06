//! The policy as a lease: `valid_until` on the snapshot, `_expired` denies
//! past it, one `policy_expired` event per snapshot, recovery by reload.

use std::time::Duration;

use chrono::{TimeDelta, Utc};
use futures_util::{SinkExt as _, StreamExt as _};
use tokio_tungstenite::tungstenite::Message;

use super::{ALLOW_UP, AddonDef, Kit, Ws};

const WS_RULES: &str = r#"
- id: ws
  when: host == "up.test" and path starts_with "/ws"
  then: { allow: { upgrade: websocket } }
- id: up
  when: host == "up.test"
  then: allow
"#;

fn past() -> chrono::DateTime<Utc> {
    Utc::now() - TimeDelta::seconds(1)
}

fn future() -> chrono::DateTime<Utc> {
    Utc::now() + TimeDelta::hours(1)
}

/// Past `valid_until` every request is denied with `_expired` and reason
/// `policy_expired`, logged once per snapshot; a reload whose lease is
/// later, or absent, lets traffic through again.
#[tokio::test]
async fn an_expired_lease_denies_until_a_reload_moves_it() {
    let kit = Kit::builder().valid_until(future()).start().await;
    let a = kit.h1().await.call("GET", "/x", &[], b"").await;
    assert_eq!(a.status, 200, "{a:?}");

    kit.reload_lease(ALLOW_UP, Some(past()));
    for _ in 0..2 {
        let a = kit.h1().await.call("GET", "/x", &[], b"").await;
        assert_eq!(a.status, 403, "{a:?}");
        assert_eq!(a.headers["x-roxy-rule"], "_expired");
        assert_eq!(a.json()["rule"], "_expired");
    }
    let events = kit.events("request", 3).await;
    for ev in &events[1..] {
        assert_eq!(ev["decision"], "deny", "{ev:#}");
        assert_eq!(ev["terminal_rule"], "_expired", "{ev:#}");
        assert_eq!(ev["reason"], "policy_expired", "{ev:#}");
        assert_eq!(ev["stage"], "head", "{ev:#}");
    }
    let expired = kit.events("policy_expired", 1).await;
    assert_eq!(expired.len(), 1, "once per snapshot: {expired:#?}");
    assert!(expired[0]["valid_until"].is_string(), "{expired:#?}");

    kit.reload_lease(ALLOW_UP, Some(future()));
    let a = kit.h1().await.call("GET", "/x", &[], b"").await;
    assert_eq!(a.status, 200, "{a:?}");
    kit.reload_lease(ALLOW_UP, None);
    let a = kit.h1().await.call("GET", "/x", &[], b"").await;
    assert_eq!(a.status, 200, "{a:?}");

    // A new snapshot that is itself expired is logged in its own right.
    kit.reload_lease(ALLOW_UP, Some(past()));
    let a = kit.h1().await.call("GET", "/x", &[], b"").await;
    assert_eq!(a.status, 403, "{a:?}");
    assert_eq!(kit.events("policy_expired", 2).await.len(), 2);
}

/// The lease is checked above the addon stack: an expired policy denies
/// before any layer sees the request, so a layer cannot answer for it.
#[tokio::test]
async fn an_expired_lease_denies_before_the_addons_run() {
    let kit = Kit::builder()
        .addon(AddonDef::test_layer("a"))
        .valid_until(past())
        .start()
        .await;
    let a = kit
        .h1()
        .await
        .call("GET", "/x", &[("x-test-a", "answer")], b"")
        .await;
    assert_eq!(a.status, 403, "{a:?}");
    assert_eq!(a.headers["x-roxy-rule"], "_expired");
    let ev = kit.request_event().await;
    assert_eq!(ev["addons"], serde_json::json!([]), "{ev:#}");
    assert_eq!(ev["terminal_rule"], "_expired", "{ev:#}");
}

async fn read_to_close(ws: &mut Ws) -> Option<u16> {
    loop {
        match tokio::time::timeout(Duration::from_secs(10), ws.next())
            .await
            .expect("the WebSocket did not close")
        {
            Some(Ok(Message::Close(c))) => return c.map(|c| u16::from(c.code)),
            Some(Ok(_)) => {}
            Some(Err(_)) | None => return None,
        }
    }
}

/// A relay opened under a live lease stops at the first message after the
/// lease runs out, whether or not any rule reads `ws.*`.
#[tokio::test]
async fn an_open_websocket_stops_when_the_lease_runs_out() {
    let lease = Duration::from_millis(600);
    let kit = Kit::builder()
        .rules(WS_RULES)
        .valid_until(Utc::now() + TimeDelta::from_std(lease).unwrap())
        .start()
        .await;
    let mut ws = kit.ws("/ws/echo", &[("x-echo", "frames")]).await;
    ws.send(Message::text("hello")).await.unwrap();
    let back = tokio::time::timeout(Duration::from_secs(10), ws.next())
        .await
        .expect("no echo")
        .unwrap()
        .unwrap();
    assert_eq!(back.into_text().unwrap().as_str(), "hello");

    tokio::time::sleep(lease + Duration::from_millis(200)).await;
    ws.send(Message::text("late")).await.unwrap();
    // No rule reads `ws.*`, so the relay is byte-level and a stop drops
    // both sides without a close frame.
    assert_eq!(read_to_close(&mut ws).await, None);
    let ev = kit.request_event().await;
    assert_eq!(ev["decision"], "deny", "{ev:#}");
    assert_eq!(ev["stage"], "websocket", "{ev:#}");
    assert_eq!(ev["terminal_rule"], "_expired", "{ev:#}");
    assert_eq!(ev["reason"], "policy_expired", "{ev:#}");
    assert_eq!(kit.upstream.ws_received(), vec![b"hello".to_vec()]);
    assert_eq!(kit.events("policy_expired", 1).await.len(), 1);
}
