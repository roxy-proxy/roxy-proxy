//! The buffer budget: an exchange that inspects reserves what its body can
//! need before it buffers, so the exchanges holding a buffer at once are
//! bounded by `max_buffered_bytes`, and one the budget cannot cover fails
//! closed rather than waiting. A body known to be empty reserves nothing.
//! An observer's copy is charged for what it has queued, and cut when the
//! budget cannot cover its next frame.

use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt as _, StreamExt as _};
use tokio_tungstenite::tungstenite::Message;

use super::{AddonDef, Kit, streaming_body};
use crate::addons::AddonMode;
use crate::addons::service::testing::{addon, reload};

const BODY_RULES: &str = r#"
- id: no-secret-out
  when: host == "up.test" and body.text contains "SECRET"
  then: deny
- id: up
  when: host == "up.test"
  then: allow
"#;

const ALLOW: &str = r#"
- id: up
  when: host == "up.test"
  then: allow
"#;

/// Reads the body only on one path, so an over-cap body elsewhere is
/// forwarded rather than failed closed.
const BODY_RULES_ON_SECRET_PATH: &str = r#"
- id: no-secret-out
  when: host == "up.test" and path == "/secret" and body.text contains "SECRET"
  then: deny
- id: up
  when: host == "up.test"
  then: allow
"#;

const BODY_RULES_WS: &str = r#"
- id: no-secret-out
  when: host == "up.test" and body.text contains "SECRET"
  then: deny
- id: ws
  when: host == "up.test" and path starts_with "/ws"
  then: { allow: { upgrade: websocket } }
- id: up
  when: host == "up.test"
  then: allow
"#;

const CAP: u64 = 64 * 1024;

/// Waits until `n` requests have reached the upstream, whether or not
/// their bodies have (the drip answers without reading the body).
async fn until_seen(kit: &Kit, n: usize) {
    let arrived = tokio::time::timeout(Duration::from_secs(10), async {
        while kit.upstream.seen().len() < n {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(arrived.is_ok(), "{:#?}", kit.upstream.seen());
}

/// Waits until exactly `n` bytes of the budget are reserved.
async fn until_buffered(kit: &Kit, n: u64) {
    let shared = kit.server.shared();
    let settled = tokio::time::timeout(Duration::from_secs(10), async {
        while shared.buffered() != n {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(settled.is_ok(), "buffered {} != {n}", shared.buffered());
}

/// With room for two inspected bodies, two stalled uploads hold the
/// budget, the third is refused without waiting, and once one of the two
/// completes a new upload is admitted.
#[tokio::test]
async fn stalled_uploads_fill_the_budget_and_the_next_is_refused() {
    let kit = Kit::builder()
        .rules(BODY_RULES)
        .limits(|l| {
            l.max_inspect_body_bytes = CAP;
            l.max_buffered_bytes = 2 * CAP;
        })
        .start()
        .await;
    let mut stalled = Vec::new();
    for _ in 0..2 {
        let mut c = kit.h1().await;
        let (mut tx, body) = streaming_body();
        let req = c.request("POST", "/x", &[]).body(body).unwrap();
        let answer = c.start(req);
        tx.send_data(Bytes::from_static(b"the start of an upload"))
            .await
            .unwrap();
        stalled.push((c, tx, answer));
    }
    until_buffered(&kit, 2 * CAP).await;

    let a = kit.h1().await.call("POST", "/x", &[], b"one more").await;
    assert_eq!(a.status, 503, "{a:?}");
    let ev = kit.request_event().await;
    assert_eq!(ev["terminal_rule"], "_fail_closed", "{ev:#}");
    assert_eq!(ev["reason"], "buffer_budget_exhausted");
    assert!(kit.upstream.seen().is_empty());

    let (_c, tx, answer) = stalled.remove(0);
    tx.finish().await.unwrap();
    let a = answer.await.unwrap().unwrap();
    assert_eq!(a.status, 200, "{a:?}");
    until_buffered(&kit, CAP).await;
    let a = kit.h1().await.call("POST", "/x", &[], b"admitted").await;
    assert_eq!(a.status, 200, "{a:?}");

    let (_c, tx, answer) = stalled.remove(0);
    tx.finish().await.unwrap();
    assert_eq!(answer.await.unwrap().unwrap().status, 200);
    until_buffered(&kit, 0).await;
}

/// A request with no body holds none of the budget however long its
/// exchange lasts: with room for two inspected bodies, three bodiless GETs
/// to a slow upstream are all forwarded, and an upload is still admitted
/// while their responses stream. The upload, of unknown length, reserves
/// the cap while it arrives and only what it held once it is buffered.
#[tokio::test]
async fn bodiless_requests_reserve_nothing() {
    let kit = Kit::builder()
        .rules(BODY_RULES)
        .limits(|l| {
            l.max_inspect_body_bytes = CAP;
            l.max_buffered_bytes = 2 * CAP;
        })
        .start()
        .await;
    let mut open = Vec::new();
    for _ in 0..3 {
        let mut c = kit.h1().await;
        let req = c
            .request("GET", "/drip?n=2&ms=2000", &[])
            .body(roxy_http::Body::empty())
            .unwrap();
        let answer = c.start(req);
        open.push((c, answer));
    }
    until_seen(&kit, 3).await;
    assert_eq!(kit.server.shared().buffered(), 0);

    let (mut tx, body) = streaming_body();
    let mut c = kit.h1().await;
    let req = c
        .request("POST", "/drip?n=2&ms=2000", &[])
        .body(body)
        .unwrap();
    let answer = c.start(req);
    tx.send_data(Bytes::from_static(b"an upload"))
        .await
        .unwrap();
    until_buffered(&kit, CAP).await;
    tx.finish().await.unwrap();
    until_buffered(&kit, 9).await;
    open.push((c, answer));

    for (_c, answer) in open {
        let a = answer.await.unwrap().unwrap();
        assert_eq!(a.status, 200, "{a:?}");
        assert_eq!(a.text(), "chunk0;chunk1;");
    }
    until_buffered(&kit, 0).await;
}

/// A body declared larger than the cap is never buffered, so it holds none
/// of the budget however long its exchange lasts: the lease taken at the
/// head goes back once the body is known to be too large. An upload of
/// unknown length that turns out too large holds exactly the prefix it
/// chained, the frame that overshot included.
#[tokio::test]
async fn an_over_cap_body_holds_only_what_it_chained() {
    let kit = Kit::builder()
        .rules(BODY_RULES_ON_SECRET_PATH)
        .limits(|l| {
            l.max_inspect_body_bytes = CAP;
            l.max_buffered_bytes = 2 * CAP;
        })
        .start()
        .await;
    let mut c = kit.h1().await;
    let declared = usize::try_from(2 * CAP).unwrap();
    let req = c
        .request(
            "POST",
            "/drip?n=2&ms=2000",
            &[("content-length", &declared.to_string())],
        )
        .body(roxy_http::Body::from_bytes(vec![b'x'; declared]))
        .unwrap();
    let answer = c.start(req);
    until_seen(&kit, 1).await;
    assert_eq!(kit.server.shared().buffered(), 0);

    let (mut tx, body) = streaming_body();
    let mut c2 = kit.h1().await;
    let req = c2
        .request("POST", "/drip?n=2&ms=2000", &[])
        .body(body)
        .unwrap();
    let answer2 = c2.start(req);
    let chunk = Bytes::from(vec![b'x'; usize::try_from(CAP).unwrap()]);
    tx.send_data(chunk.clone()).await.unwrap();
    tx.send_data(chunk).await.unwrap();
    until_seen(&kit, 2).await;
    // The codec frames the upload its own way, so the overshoot is one
    // codec frame past the cap, whatever the client sent.
    let held = kit.server.shared().buffered();
    assert!(
        (CAP + 1..=2 * CAP).contains(&held),
        "{held} held for the chained prefix"
    );
    tx.finish().await.unwrap();

    for a in [answer, answer2] {
        let a = a.await.unwrap().unwrap();
        assert_eq!(a.status, 200, "{a:?}");
    }
    until_buffered(&kit, 0).await;
}

/// An observer whose instances are all busy waits at most its
/// `first_byte_timeout` for one; then its copy is dropped, giving back
/// what it had queued, and `observer_lagged` says `no_instance`. The real
/// exchange never waits.
#[tokio::test]
async fn an_observer_without_an_instance_gives_its_copy_back_within_the_bound() {
    use http_body_util::BodyExt as _;
    let kit = Kit::builder()
        .rules(ALLOW)
        .addon(AddonDef::test_layer("o").observe().limits(|l| {
            l.max_instances = 1;
            l.first_byte_timeout = Duration::from_millis(300);
        }))
        .start()
        .await;
    // The only instance relays a response that drips for a minute.
    let mut c = kit.h1().await;
    let req = c
        .request("GET", "/drip?n=1000&ms=50", &[("x-test-o", "pass")])
        .body(roxy_http::Body::empty())
        .unwrap();
    let mut res = c.send(req).await.unwrap();
    assert_eq!(res.status(), 200);
    assert!(res.body_mut().frame().await.unwrap().is_ok());

    let (mut tx, body) = streaming_body();
    let mut c2 = kit.h1().await;
    let req = c2
        .request("POST", "/x", &[("x-test-o", "pass")])
        .body(body)
        .unwrap();
    let answer = c2.start(req);
    tx.send_data(Bytes::from(vec![b'x'; 1024])).await.unwrap();
    let queued = tokio::time::timeout(Duration::from_secs(10), async {
        while kit.server.shared().buffered() < 1024 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(queued.is_ok(), "the copy queued nothing");
    let lagged = kit.events("observer_lagged", 1).await;
    assert_eq!(lagged[0]["layer"], "o", "{lagged:#?}");
    assert_eq!(lagged[0]["direction"], "request");
    assert_eq!(lagged[0]["reason"], "no_instance");
    until_buffered(&kit, 0).await;

    tx.finish().await.unwrap();
    let a = answer.await.unwrap().unwrap();
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.json()["body_len"], 1024);
    c.kill();
    drop(res);
}

/// A body with a declared length reserves that length, not the cap: three
/// small declared uploads fit in a budget with room for two bodies of
/// unknown length.
#[tokio::test]
async fn a_declared_length_reserves_only_that_much() {
    let kit = Kit::builder()
        .rules(BODY_RULES)
        .limits(|l| {
            l.max_inspect_body_bytes = CAP;
            l.max_buffered_bytes = 2 * CAP;
        })
        .start()
        .await;
    let mut open = Vec::new();
    for _ in 0..3 {
        let mut c = kit.h1().await;
        let req = c
            .request("POST", "/drip?n=2&ms=2000", &[("content-length", "9")])
            .body(roxy_http::Body::from_bytes(Bytes::from_static(
                b"an upload",
            )))
            .unwrap();
        let answer = c.start(req);
        open.push((c, answer));
    }
    until_seen(&kit, 3).await;
    assert_eq!(kit.server.shared().buffered(), 3 * 9);
    for (_c, answer) in open {
        let a = answer.await.unwrap().unwrap();
        assert_eq!(a.status, 200, "{a:?}");
    }
    until_buffered(&kit, 0).await;
}

/// An encoded body is held decoded for the rest of the exchange, and can
/// decode to anything up to the cap: a small declared length does not
/// bound what the exchange holds, so the budget charges the decoded size.
#[tokio::test]
async fn an_encoded_body_is_charged_at_its_decoded_size() {
    use std::io::Write as _;
    let kit = Kit::builder()
        .rules(BODY_RULES)
        .limits(|l| {
            l.max_inspect_body_bytes = CAP;
            l.max_buffered_bytes = 2 * CAP;
        })
        .start()
        .await;
    let text = vec![b'a'; 32 * 1024];
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(&text).unwrap();
    let gz = e.finish().unwrap();
    assert!(gz.len() < 1024, "{} bytes compressed", gz.len());
    let mut c = kit.h1().await;
    let req = c
        .request(
            "POST",
            "/drip?n=2&ms=2000",
            &[
                ("content-length", &gz.len().to_string()),
                ("content-encoding", "gzip"),
            ],
        )
        .body(roxy_http::Body::from_bytes(Bytes::from(gz)))
        .unwrap();
    let answer = c.start(req);
    until_seen(&kit, 1).await;
    assert_eq!(kit.server.shared().buffered(), text.len() as u64);
    let a = answer.await.unwrap().unwrap();
    assert_eq!(a.status, 200, "{a:?}");
    until_buffered(&kit, 0).await;
}

/// A WebSocket under a body-reading policy is a bodiless GET answered with
/// a `101`: it holds none of the budget for the life of the session.
#[tokio::test]
async fn a_websocket_under_a_body_policy_holds_no_lease() {
    let kit = Kit::builder()
        .rules(BODY_RULES_WS)
        .limits(|l| {
            l.max_inspect_body_bytes = CAP;
            l.max_buffered_bytes = 2 * CAP;
        })
        .start()
        .await;
    let mut ws = kit.ws("/ws/echo", &[("x-echo", "frames")]).await;
    assert_eq!(kit.server.shared().buffered(), 0);
    ws.send(Message::Text("hello".into())).await.unwrap();
    let echoed = tokio::time::timeout(Duration::from_secs(10), ws.next())
        .await
        .expect("no echo")
        .unwrap()
        .unwrap();
    assert_eq!(echoed, Message::Text("hello".into()));
    assert_eq!(kit.server.shared().buffered(), 0);
}

/// An observer's copy is charged for what it has queued, not for its
/// cap: many small observed exchanges fit at once in a budget smaller
/// than one copy's `max_observer_lag_bytes`, and none is cut.
#[tokio::test]
async fn small_observed_exchanges_fit_in_a_budget_under_one_copys_cap() {
    let kit = Kit::builder()
        .rules(ALLOW)
        .limits(|l| {
            l.max_observer_lag_bytes = CAP;
            l.max_buffered_bytes = CAP / 2;
        })
        .start()
        .await;
    reload(
        &kit,
        ALLOW,
        &[],
        vec![addon("o", "pass", AddonMode::Observe, |_| {})],
    );
    let mut open = Vec::new();
    for _ in 0..16 {
        let mut c = kit.h1().await;
        let (mut tx, body) = streaming_body();
        let req = c.request("POST", "/x", &[]).body(body).unwrap();
        let answer = c.start(req);
        tx.send_data(Bytes::from(vec![b'x'; 1024])).await.unwrap();
        open.push((c, tx, answer));
    }
    for (_c, tx, answer) in open {
        tx.finish().await.unwrap();
        let a = answer.await.unwrap().unwrap();
        assert_eq!(a.status, 200, "{a:?}");
        assert_eq!(a.json()["body_len"], 1024);
    }
    let seen = kit.upstream.wait_seen(16).await;
    assert!(seen.iter().all(|s| s.complete == Some(true)), "{seen:#?}");
    until_buffered(&kit, 0).await;
    let lagged: Vec<_> = kit
        .sink
        .events()
        .into_iter()
        .filter(|e| e["event"] == "observer_lagged")
        .collect();
    assert!(lagged.is_empty(), "{lagged:#?}");
}

/// A copy whose next frame the budget cannot cover is cut and reported
/// with its own reason, while the real exchange goes through whole. The
/// observer never reads, so its copy queues until the budget is full
/// well before the copy reaches its own cap.
#[tokio::test]
async fn a_copy_the_budget_cannot_cover_is_cut_while_the_exchange_goes_through() {
    let kit = Kit::builder()
        .rules(ALLOW)
        .limits(|l| {
            l.max_observer_lag_bytes = 8 * CAP;
            l.max_buffered_bytes = CAP;
        })
        .start()
        .await;
    reload(
        &kit,
        ALLOW,
        &[],
        vec![addon("o", "stall", AddonMode::Observe, |_| {})],
    );
    let mut c = kit.h1().await;
    let (mut tx, body) = streaming_body();
    let req = c.request("POST", "/x", &[]).body(body).unwrap();
    let answer = c.start(req);
    let chunk = Bytes::from(vec![b'x'; 16 * 1024]);
    let chunks = 40;
    for _ in 0..chunks {
        tx.send_data(chunk.clone()).await.unwrap();
    }
    tx.finish().await.unwrap();
    let a = answer.await.unwrap().unwrap();
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.json()["body_len"], chunks * chunk.len());
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].complete, Some(true));
    let lagged = kit.events("observer_lagged", 1).await;
    let request = lagged
        .iter()
        .find(|e| e["direction"] == "request")
        .unwrap_or_else(|| panic!("{lagged:#?}"));
    assert_eq!(request["layer"], "o", "{request:#}");
    assert_eq!(request["reason"], "buffer_budget_exhausted", "{request:#}");
    assert!(kit.server.shared().buffered() <= CAP);
}
