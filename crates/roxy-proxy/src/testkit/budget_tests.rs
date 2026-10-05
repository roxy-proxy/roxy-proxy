//! The buffer budget: each exchange reserves its cap before it buffers,
//! so the exchanges holding a buffer at once are bounded by
//! `max_buffered_bytes`, and one the budget cannot cover fails closed
//! (an observer's copy is cut) rather than waiting.

use std::time::Duration;

use bytes::Bytes;

use super::{Kit, streaming_body};
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

    let (_c, mut tx, answer) = stalled.remove(0);
    tx.finish().await.unwrap();
    let a = answer.await.unwrap().unwrap();
    assert_eq!(a.status, 200, "{a:?}");
    until_buffered(&kit, CAP).await;
    let a = kit.h1().await.call("POST", "/x", &[], b"admitted").await;
    assert_eq!(a.status, 200, "{a:?}");

    let (_c, mut tx, answer) = stalled.remove(0);
    tx.finish().await.unwrap();
    assert_eq!(answer.await.unwrap().unwrap().status, 200);
    until_buffered(&kit, 0).await;
}

/// An observer's copy takes `max_observer_lag_bytes` of the budget per
/// direction; when the budget cannot cover one the copy is cut and
/// reported with its own reason, and the real exchange goes through whole.
#[tokio::test]
async fn a_copy_the_budget_cannot_cover_is_cut_while_the_exchange_goes_through() {
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
    let a = kit.h1().await.call("POST", "/x", &[], b"body").await;
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.json()["body_len"], 4);
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].body, b"body");
    assert_eq!(seen[0].complete, Some(true));
    let lagged = kit.events("observer_lagged", 2).await;
    let mut directions: Vec<&str> = lagged
        .iter()
        .map(|e| e["direction"].as_str().unwrap())
        .collect();
    directions.sort_unstable();
    assert_eq!(directions, ["request", "response"], "{lagged:#?}");
    for e in &lagged {
        assert_eq!(e["layer"], "o", "{e:#}");
        assert_eq!(e["reason"], "buffer_budget_exhausted", "{e:#}");
    }
    until_buffered(&kit, 0).await;
}
