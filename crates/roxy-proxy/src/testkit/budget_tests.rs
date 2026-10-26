//! The buffer budget: what exchanges hold at once is bounded by
//! `max_buffered_bytes`. Rules on body text hold nothing, as they read it
//! streaming. An observer's copy is charged for what it has queued, and
//! cut when the budget cannot cover its next frame.

use std::time::Duration;

use bytes::Bytes;

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

/// Rules on body text read it as it streams, so they hold none of the
/// budget: stalled uploads under them, more than the budget could hold
/// if they were buffered, all reach the upstream with nothing reserved.
#[tokio::test]
async fn body_text_rules_hold_no_buffer() {
    let kit = Kit::builder()
        .rules(BODY_RULES)
        .limits(|l| l.max_buffered_bytes = CAP)
        .start()
        .await;
    let mut stalled = Vec::new();
    for _ in 0..3 {
        let mut c = kit.h1().await;
        let (mut tx, body) = streaming_body();
        let req = c
            .request("POST", "/drip?n=2&ms=2000", &[])
            .body(body)
            .unwrap();
        let answer = c.start(req);
        tx.send_data(Bytes::from(vec![b'x'; usize::try_from(CAP).unwrap()]))
            .await
            .unwrap();
        stalled.push((c, tx, answer));
    }
    until_seen(&kit, 3).await;
    assert_eq!(kit.server.shared().buffered(), 0);
    for (_c, tx, answer) in stalled {
        tx.finish().await.unwrap();
        let a = answer.await.unwrap().unwrap();
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
