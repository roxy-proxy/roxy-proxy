//! Quarantine: a rule's `quarantine` action or a listener's parse-error
//! threshold puts the process into a durable state in which every exchange
//! is refused with `_quarantined`; only a release naming the incident, or
//! a restart without the marker, lifts it.

use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt as _, StreamExt as _};
use tokio_tungstenite::tungstenite::Message;

use super::{ALLOW_UP, AddonDef, Kit, Ws, streaming_body};

const RULES: &str = r#"
- id: trip
  when: host == "up.test" and path == "/exfil"
  then: quarantine
- id: ws
  when: host == "up.test" and path starts_with "/ws"
  then: { allow: { upgrade: websocket } }
- id: up
  when: host == "up.test"
  then: allow
"#;

async fn probe(kit: &Kit, path: &str) -> String {
    let (head, _, _) =
        super::ca_server_tests::fetch(kit, &format!("GET {path} HTTP/1.1\r\nhost: roxy\r\n\r\n"))
            .await;
    head
}

/// The tripping exchange is refused by its own rule; every exchange after
/// it by `_quarantined`, before the rules. The marker survives into a new
/// server on the same state dir, and a release lifts it only when it names
/// the incident in force.
#[tokio::test]
async fn a_quarantine_rule_trips_persists_and_is_released_by_id() {
    let dir = tempfile::tempdir().unwrap();
    let kit = Kit::builder()
        .rules(RULES)
        .ca_server()
        .quarantine_dir(dir.path())
        .start()
        .await;
    let a = kit.h1().await.call("GET", "/x", &[], b"").await;
    assert_eq!(a.status, 200, "{a:?}");
    assert!(probe(&kit, "/readyz").await.starts_with("HTTP/1.1 200"));

    let a = kit.h1().await.call("GET", "/exfil", &[], b"").await;
    assert_eq!(a.status, 403, "{a:?}");
    assert_eq!(a.headers["x-roxy-rule"], "trip");
    let tripped = kit.events("quarantined", 1).await.remove(0);
    assert_eq!(tripped["cause"]["kind"], "rule", "{tripped:#}");
    assert_eq!(tripped["cause"]["rule"], "trip", "{tripped:#}");
    assert_eq!(tripped["restored"], false, "{tripped:#}");
    let id = tripped["id"].as_str().unwrap().to_owned();
    assert!(id.starts_with("q-"), "{id}");
    let record = kit.server.handle().quarantine().expect("quarantined");
    assert_eq!(record.id, id);
    assert!(dir.path().join("quarantine").is_file(), "the marker");

    for _ in 0..2 {
        let a = kit.h1().await.call("GET", "/x", &[], b"").await;
        assert_eq!(a.status, 403, "{a:?}");
        assert_eq!(a.headers["x-roxy-rule"], "_quarantined");
        assert_eq!(a.json()["rule"], "_quarantined");
    }
    let events = kit.events("request", 4).await;
    assert_eq!(events[1]["terminal_rule"], "trip", "{:#}", events[1]);
    for ev in &events[2..] {
        assert_eq!(ev["decision"], "deny", "{ev:#}");
        assert_eq!(ev["terminal_rule"], "_quarantined", "{ev:#}");
        assert_eq!(ev["reason"], "quarantined", "{ev:#}");
        assert_eq!(ev["stage"], "head", "{ev:#}");
    }
    let ready = probe(&kit, "/readyz").await;
    assert!(ready.starts_with("HTTP/1.1 503"), "{ready}");
    let health = probe(&kit, "/healthz").await;
    assert!(health.starts_with("HTTP/1.1 200"), "{health}");
    assert!(
        health
            .to_ascii_lowercase()
            .contains("x-roxy-policy: quarantined"),
        "{health}"
    );

    // A reload does not lift it.
    kit.reload(ALLOW_UP);
    let a = kit.h1().await.call("GET", "/x", &[], b"").await;
    assert_eq!(a.status, 403, "{a:?}");
    assert_eq!(a.headers["x-roxy-rule"], "_quarantined");

    // Nor does a release naming another incident.
    assert!(!kit.server.handle().release_quarantine("q-other").unwrap());
    let a = kit.h1().await.call("GET", "/x", &[], b"").await;
    assert_eq!(a.status, 403, "{a:?}");
    assert!(
        kit.sink
            .events()
            .iter()
            .all(|e| e["event"] != "quarantine_released")
    );

    // A new server on the same state dir starts quarantined.
    let again = Kit::builder()
        .rules(RULES)
        .quarantine_dir(dir.path())
        .start()
        .await;
    let restored = again.events("quarantined", 1).await.remove(0);
    assert_eq!(restored["id"], id, "{restored:#}");
    assert_eq!(restored["restored"], true, "{restored:#}");
    assert_eq!(restored["since"], tripped["since"], "{restored:#}");
    let a = again.h1().await.call("GET", "/x", &[], b"").await;
    assert_eq!(a.status, 403, "{a:?}");
    assert_eq!(a.headers["x-roxy-rule"], "_quarantined");

    // The release names the incident: traffic flows and the marker is gone.
    assert!(again.server.handle().release_quarantine(&id).unwrap());
    let released = again.events("quarantine_released", 1).await.remove(0);
    assert_eq!(released["id"], id, "{released:#}");
    assert!(again.server.handle().quarantine().is_none());
    assert!(!dir.path().join("quarantine").exists());
    let a = again.h1().await.call("GET", "/x", &[], b"").await;
    assert_eq!(a.status, 200, "{a:?}");
    let clear = Kit::builder().quarantine_dir(dir.path()).start().await;
    assert!(
        clear.server.handle().quarantine().is_none(),
        "a start after the release is clear"
    );
}

/// The listener's threshold: the `count`th parse error within the window
/// trips the quarantine, with the listener and the counter in the cause.
#[tokio::test]
async fn parse_errors_over_the_threshold_quarantine() {
    let kit = Kit::builder()
        .quarantine_on(3, Duration::from_secs(60))
        .start()
        .await;
    for i in 0..2 {
        let (out, eof) = kit
            .raw(b"GET http://up.test/ HTTP/1.1\nhost: up.test\n\n")
            .await;
        assert!(out.starts_with("HTTP/1.1 400"), "{i}: {out}");
        assert!(eof);
    }
    let a = kit.h1().await.call("GET", "/x", &[], b"").await;
    assert_eq!(a.status, 200, "two errors are under the threshold: {a:?}");
    assert_eq!(kit.events("parse_error", 2).await.len(), 2);

    let (out, _) = kit
        .raw(b"GET http://up.test/ HTTP/1.1\nhost: up.test\n\n")
        .await;
    assert!(out.starts_with("HTTP/1.1 400"), "{out}");
    let tripped = kit.events("quarantined", 1).await.remove(0);
    assert_eq!(
        tripped["cause"],
        serde_json::json!({
            "kind": "threshold",
            "listener": "main",
            "counter": "parse_errors",
            "count": 3,
            "window_seconds": 60,
        }),
        "{tripped:#}"
    );
    let a = kit.h1().await.call("GET", "/x", &[], b"").await;
    assert_eq!(a.status, 403, "{a:?}");
    assert_eq!(a.headers["x-roxy-rule"], "_quarantined");
}

/// The quarantine is checked above the addon stack, like the lease: no
/// layer sees a request while it is in force.
#[tokio::test]
async fn a_quarantine_refuses_before_the_addons_run() {
    let kit = Kit::builder()
        .rules(RULES)
        .addon(AddonDef::test_layer("a"))
        .start()
        .await;
    let a = kit.h1().await.call("GET", "/exfil", &[], b"").await;
    assert_eq!(a.status, 403, "{a:?}");
    let a = kit
        .h1()
        .await
        .call("GET", "/x", &[("x-test-a", "answer")], b"")
        .await;
    assert_eq!(a.status, 403, "{a:?}");
    assert_eq!(a.headers["x-roxy-rule"], "_quarantined");
    let ev = kit.events("request", 2).await.remove(1);
    assert_eq!(ev["addons"], serde_json::json!([]), "{ev:#}");
    assert_eq!(ev["terminal_rule"], "_quarantined", "{ev:#}");
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

/// Exchanges open at the trip do not carry on: a WebSocket relay stops at
/// its next message with `_quarantined`, and a streaming upload's
/// connection is cut once the grace period is over.
#[tokio::test]
async fn exchanges_in_flight_at_the_trip_are_stopped() {
    let kit = Kit::builder().rules(RULES).start().await;
    let mut ws = kit.ws("/ws/echo", &[("x-echo", "frames")]).await;
    ws.send(Message::text("hello")).await.unwrap();
    let back = tokio::time::timeout(Duration::from_secs(10), ws.next())
        .await
        .expect("no echo")
        .unwrap()
        .unwrap();
    assert_eq!(back.into_text().unwrap().as_str(), "hello");

    let mut c = kit.h1().await;
    let (mut tx, body) = streaming_body();
    let req = c.request("POST", "/upload", &[]).body(body).unwrap();
    let pending = c.start(req);
    tx.send_data(Bytes::from_static(b"the start"))
        .await
        .unwrap();
    kit.upstream.wait_seen(1).await;

    let a = kit.h1().await.call("GET", "/exfil", &[], b"").await;
    assert_eq!(a.status, 403, "{a:?}");

    ws.send(Message::text("late")).await.unwrap();
    assert_eq!(read_to_close(&mut ws).await, None);

    let cut = tokio::time::timeout(crate::server::CUT_GRACE + Duration::from_secs(5), pending)
        .await
        .expect("the upload's connection is cut after the grace")
        .unwrap();
    assert!(
        cut.is_err() || cut.as_ref().is_ok_and(|a| a.body.is_err()),
        "{cut:?}"
    );
    drop(tx);

    let events = kit.events("request", 3).await;
    let by_path = |p: &str| {
        events
            .iter()
            .find(|e| e["req"]["path"] == p)
            .unwrap_or_else(|| panic!("{p}: {events:#?}"))
    };
    let ws_ev = by_path("/ws/echo");
    assert_eq!(ws_ev["terminal_rule"], "_quarantined", "{ws_ev:#}");
    assert_eq!(ws_ev["stage"], "websocket", "{ws_ev:#}");
    let up = by_path("/upload");
    assert_eq!(up["decision"], "allow", "{up:#}");
    assert_eq!(up["reason"], "aborted", "{up:#}");
}
