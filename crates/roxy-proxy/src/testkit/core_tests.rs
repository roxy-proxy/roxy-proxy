//! The exchange core without addons: decisions, watching stops, upstream
//! errors and the address floor, as the client, the upstream and the flow
//! log see them.

use bytes::Bytes;

use super::{Answer, Kit, streaming_body};

const RULES: &str = r#"
- id: no-admin
  when: host == "up.test" and path starts_with "/admin"
  then: deny
- id: upload-cap
  when: host == "up.test" and body.bytes > 10kb
  then: { deny: { status: 413 } }
- id: up
  when: host == "up.test"
  then: allow
- id: down
  when: host == "down.test"
  then: allow
- id: private
  when: host == "private.test" and path starts_with "/ok"
  then: { allow: { private_ok: true } }
- id: private-strict
  when: host == "private.test"
  then: allow
"#;

async fn kit() -> Kit {
    Kit::builder().rules(RULES).start().await
}

#[tokio::test]
async fn an_allowed_request_is_forwarded_and_logged() {
    let kit = kit().await;
    let a = kit.h1().await.call("POST", "/x?q=1", &[], b"hello").await;
    assert_eq!(a.status, 200, "{a:?}");
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].path, "/x?q=1");
    assert_eq!(seen[0].body, b"hello");
    let ev = kit.request_event().await;
    assert_eq!(ev["decision"], "allow", "{ev:#}");
    assert_eq!(ev["terminal_rule"], "up");
    assert_eq!(ev["res"]["status"], 200);
}

#[tokio::test]
async fn the_default_denies_and_nothing_leaves() {
    let kit = kit().await;
    let mut c = kit.h1().await;
    let req = c
        .request_to("other.test", "GET", "/", &[])
        .body(roxy_http::Body::empty())
        .unwrap();
    let a = Answer::read(c.send(req).await.unwrap()).await;
    assert_eq!(a.status, 403, "{a:?}");
    let ev = kit.request_event().await;
    assert_eq!(ev["decision"], "deny", "{ev:#}");
    assert_eq!(ev["terminal_rule"], "_default");
    assert!(kit.upstream.seen().is_empty());
}

#[tokio::test]
async fn a_deny_rule_wins_at_the_head() {
    let kit = kit().await;
    let a = kit.h1().await.call("GET", "/admin/users", &[], b"").await;
    assert_eq!(a.status, 403, "{a:?}");
    let ev = kit.request_event().await;
    assert_eq!(ev["decision"], "deny", "{ev:#}");
    assert_eq!(ev["terminal_rule"], "no-admin");
    assert!(kit.upstream.seen().is_empty());
}

#[tokio::test]
async fn a_watching_rule_stops_an_upload_mid_body() {
    let kit = kit().await;
    let mut c = kit.h1().await;
    let (mut tx, body) = streaming_body();
    let req = c.request("POST", "/upload", &[]).body(body).unwrap();
    let feed = tokio::spawn(async move {
        for _ in 0..64 {
            if tx.send_data(Bytes::from(vec![b'x'; 1024])).await.is_err() {
                return;
            }
        }
        let _ = tx.finish().await;
    });
    let a = Answer::read(c.send(req).await.unwrap()).await;
    feed.abort();
    assert_eq!(a.status, 413, "{a:?}");
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].complete, Some(false), "the upstream body is cut");
    assert!(seen[0].body.len() < 64 * 1024);
    let ev = kit.request_event().await;
    assert_eq!(ev["decision"], "deny", "{ev:#}");
    assert_eq!(ev["terminal_rule"], "upload-cap");
}

#[tokio::test]
async fn an_unreachable_upstream_is_a_502() {
    let kit = kit().await;
    let mut c = kit.h1().await;
    let req = c
        .request_to("down.test", "GET", "/", &[])
        .body(roxy_http::Body::empty())
        .unwrap();
    let a = Answer::read(c.send(req).await.unwrap()).await;
    assert_eq!(a.status, 502, "{a:?}");
    let err = kit.events("upstream_error", 1).await;
    assert_eq!(err[0]["reason"], "connect_failed", "{err:#?}");
    let ev = kit.request_event().await;
    assert_eq!(ev["decision"], "allow", "{ev:#}");
    assert_eq!(ev["terminal_rule"], "down");
}

#[tokio::test]
async fn an_upstream_error_status_is_relayed() {
    let kit = kit().await;
    let a = kit.h1().await.call("GET", "/status/503", &[], b"").await;
    assert_eq!(a.status, 503, "{a:?}");
    let ev = kit.request_event().await;
    assert_eq!(ev["decision"], "allow", "{ev:#}");
    assert_eq!(ev["res"]["status"], 503);
}

#[tokio::test]
async fn the_address_floor_refuses_private_addresses_without_private_ok() {
    let kit = kit().await;
    let mut c = kit.h1().await;
    for (path, status) in [("/strict", 403), ("/ok", 200)] {
        let req = c
            .request_to("private.test", "GET", path, &[])
            .body(roxy_http::Body::empty())
            .unwrap();
        let a = Answer::read(c.send(req).await.unwrap()).await;
        assert_eq!(a.status, status, "{path}: {a:?}");
        if status == 403 {
            // A refusal closes the connection.
            c = kit.h1().await;
        }
    }
    let denied = kit.events("upstream_denied", 1).await;
    assert_eq!(denied[0]["reason"], "private_range:private", "{denied:#?}");
    let reqs = kit.events("request", 2).await;
    assert_eq!(reqs[0]["terminal_rule"], "_address_policy", "{reqs:#?}");
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].path, "/ok");
}

#[tokio::test]
async fn h2_clients_get_the_same_decisions() {
    let kit = kit().await;
    let mut c = kit.tunnel("up.test", true).await;
    assert_eq!(c.call("GET", "/x", &[], b"").await.status, 200);
    assert_eq!(c.call("GET", "/admin", &[], b"").await.status, 403);
    let reqs = kit.events("request", 2).await;
    let rules: Vec<_> = reqs.iter().map(|r| r["terminal_rule"].clone()).collect();
    assert_eq!(rules, ["up", "no-admin"], "{reqs:#?}");
}

/// Plaintext inside a CONNECT tunnel (`http.allow_plain_in_connect`) is
/// recognised even when the request line arrives in pieces.
#[tokio::test]
async fn plaintext_in_connect_in_pieces_is_still_http() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let kit = Kit::builder()
        .rules(RULES)
        .flags(|f| f.allow_plain_in_connect = true)
        .start()
        .await;
    let mut io = kit.connect_tunnel("up.test", 80).await;
    io.write_all(b"G").await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    io.write_all(b"ET / HTTP/1.1\r\nhost: up.test\r\nconnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut out = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(10), io.read_to_end(&mut out))
        .await
        .expect("the connection closes")
        .unwrap();
    let out = String::from_utf8_lossy(&out);
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    assert_eq!(kit.upstream.wait_seen(1).await[0].addr.port(), 80);
}
