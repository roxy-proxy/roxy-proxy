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
- id: stall
  when: host == "stall.test"
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

async fn a_watching_rule_stops_an_upload_mid_body(h2: bool) {
    let kit = kit().await;
    let mut c = if h2 {
        kit.tunnel("up.test", true).await
    } else {
        kit.h1().await
    };
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
    assert_eq!(ev["stage"], "request_body");
}

#[tokio::test]
async fn h1_a_watching_rule_stops_an_upload_mid_body() {
    a_watching_rule_stops_an_upload_mid_body(false).await;
}

#[tokio::test]
async fn h2_a_watching_rule_stops_an_upload_mid_body() {
    a_watching_rule_stops_an_upload_mid_body(true).await;
}

/// A watching rule stopping the response mid-body cuts it: the h1 body
/// ends without its terminating chunk and the connection closes, the h2
/// stream is reset. Either way the client cannot take it for complete.
async fn a_watching_rule_stops_a_response_mid_body(h2: bool) {
    let kit = Kit::builder()
        .rules(
            r#"
- id: download-cap
  when: host == "up.test" and response.body.bytes > 10kb
  then: deny
- id: up
  when: host == "up.test"
  then: allow
"#,
        )
        .start()
        .await;
    let mut c = if h2 {
        kit.tunnel("up.test", true).await
    } else {
        kit.h1().await
    };
    let req = c
        .request("POST", "/echo", &[])
        .body(roxy_http::Body::from_bytes(Bytes::from(vec![
            b'x';
            64 * 1024
        ])))
        .unwrap();
    match c.send(req).await {
        Ok(res) => {
            let a = Answer::read(res).await;
            assert_eq!(a.status, 200, "{a:?}");
            assert!(a.body.is_err(), "the body is cut: {a:?}");
        }
        // The reset may reach an h2 client with the head still unread.
        Err(e) => assert!(h2, "{e}"),
    }
    let ev = kit.request_event().await;
    assert_eq!(ev["decision"], "deny", "{ev:#}");
    assert_eq!(ev["terminal_rule"], "download-cap");
    assert_eq!(ev["stage"], "response_body");
    assert!(
        ev["res"]["body_bytes"].as_u64().unwrap() < 64 * 1024,
        "{ev:#}"
    );
}

#[tokio::test]
async fn h1_a_watching_rule_stops_a_response_mid_body() {
    a_watching_rule_stops_a_response_mid_body(false).await;
}

#[tokio::test]
async fn h2_a_watching_rule_stops_a_response_mid_body() {
    a_watching_rule_stops_a_response_mid_body(true).await;
}

/// An upstream that takes the request but never answers is a `504` once
/// `response_header_timeout` passes.
#[tokio::test]
async fn an_upstream_that_never_answers_is_a_504() {
    let kit = Kit::builder()
        .rules(RULES)
        .limits(|l| l.response_header_timeout = std::time::Duration::from_millis(300))
        .start()
        .await;
    let mut c = kit.h1().await;
    let req = c
        .request_to("stall.test", "GET", "/", &[])
        .body(roxy_http::Body::empty())
        .unwrap();
    let a = Answer::read(c.send(req).await.unwrap()).await;
    assert_eq!(a.status, 504, "{a:?}");
    assert_eq!(a.json()["reason"], "timeout");
    let err = kit.events("upstream_error", 1).await;
    assert_eq!(err[0]["reason"], "timeout", "{err:#?}");
    let ev = kit.request_event().await;
    assert_eq!(ev["decision"], "allow", "{ev:#}");
    assert_eq!(ev["reason"], "timeout", "{ev:#}");
}

/// A client that stops sending its body is cut off after
/// `body_idle_timeout`: the connection closes (h1) or the stream is reset
/// (h2), with a `parse_error`.
async fn a_stalled_upload_is_cut_off(h2: bool) {
    let kit = Kit::builder()
        .rules(RULES)
        .limits(|l| l.body_idle_timeout = std::time::Duration::from_millis(300))
        .start()
        .await;
    let mut c = if h2 {
        kit.tunnel("up.test", true).await
    } else {
        kit.h1().await
    };
    let (mut tx, body) = streaming_body();
    let req = c.request("POST", "/upload", &[]).body(body).unwrap();
    let pending = c.start(req);
    tx.send_data(Bytes::from_static(b"the start"))
        .await
        .unwrap();
    let a = tokio::time::timeout(std::time::Duration::from_secs(10), pending)
        .await
        .expect("the stall is cut off")
        .unwrap();
    // h1 gets a 408 before the close; an h2 stream is reset.
    if let Ok(a) = &a {
        assert_eq!(a.status, 408, "{a:?}");
    }
    drop(tx);
    let errs = kit.events("parse_error", 1).await;
    assert_eq!(errs[0]["reason"], "body_timeout", "{errs:#?}");
    let ev = kit.request_event().await;
    assert_eq!(ev["reason"], "body_timeout", "{ev:#}");
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].complete, Some(false), "{:?}", seen[0]);
}

#[tokio::test]
async fn h1_a_stalled_upload_is_cut_off() {
    a_stalled_upload_is_cut_off(false).await;
}

#[tokio::test]
async fn h2_a_stalled_upload_is_cut_off() {
    a_stalled_upload_is_cut_off(true).await;
}

/// An exchange finishes under the policy it started with; the next one
/// runs under the reloaded policy.
#[tokio::test]
async fn a_reload_mid_exchange_does_not_change_its_policy() {
    let kit = kit().await;
    let mut c = kit.h1().await;
    let (mut tx, body) = streaming_body();
    let req = c.request("POST", "/upload", &[]).body(body).unwrap();
    let pending = c.start(req);
    tx.send_data(Bytes::from_static(b"first half"))
        .await
        .unwrap();
    kit.wait_arrived(1).await;
    kit.reload(
        r#"
- id: nothing
  when: host == "up.test"
  then: deny
"#,
    );
    tx.send_data(Bytes::from_static(b" second half"))
        .await
        .unwrap();
    tx.finish().await.unwrap();
    let a = pending.await.unwrap().unwrap();
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.json()["body_len"], 22);
    let b = c.call("GET", "/next", &[], b"").await;
    assert_eq!(b.status, 403, "{b:?}");
    assert_eq!(b.json()["rule"], "nothing");
}

/// A reload releases the old snapshot, its upstream pool included, while
/// a client connection accepted before it stays open: the connection task
/// keeps only its codec settings and takes a snapshot per exchange, so the
/// pooled upstream connection closes with the pool rather than living on
/// for as long as the client does.
#[tokio::test]
async fn a_reload_releases_the_old_upstream_pool_under_an_open_client_connection() {
    let kit = kit().await;
    let mut c = kit.h1().await;
    let a = c.call("GET", "/one", &[], b"").await;
    assert_eq!(a.status, 200, "{a:?}");
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    assert_eq!(kit.upstream.open_connections(), 1, "pooled and idle");
    let old = {
        let snap = kit.server.shared().snapshot();
        std::sync::Arc::downgrade(&snap.upstream)
    };
    kit.reload(RULES);
    kit.upstream.wait_open(0).await;
    assert!(old.upgrade().is_none(), "the old upstream pool is still held");
    // The client connection is still usable and dials afresh.
    let b = c.call("GET", "/two", &[], b"").await;
    assert_eq!(b.status, 200, "{b:?}");
    assert_eq!(kit.upstream.open_connections(), 1);
}

/// A client that vanishes mid-upload still gets its exchange logged, on
/// h1 (the codec sees EOF) and on h2 (the connection ends under the
/// stream's task).
async fn a_client_gone_mid_upload_is_logged(h2: bool) {
    let kit = kit().await;
    let mut c = if h2 {
        kit.tunnel("up.test", true).await
    } else {
        kit.h1().await
    };
    let (mut tx, body) = streaming_body();
    let req = c.request("POST", "/upload", &[]).body(body).unwrap();
    let pending = c.start(req);
    tx.send_data(Bytes::from(vec![b'x'; 1024])).await.unwrap();
    kit.wait_arrived(1).await;
    c.kill();
    drop(tx);
    let _ = pending.await;
    let ev = kit.request_event().await;
    assert_eq!(ev["decision"], "allow", "{ev:#}");
    let reason = if h2 { "client_gone" } else { "unexpected_eof" };
    assert_eq!(ev["reason"], reason, "{ev:#}");
}

/// An h2 client cancelling its stream (`RST_STREAM`) is not a protocol
/// error: the flow is logged as `client_gone`, nothing is reset back, and
/// the connection carries on.
#[tokio::test]
async fn h2_a_cancelled_stream_is_logged_as_client_gone() {
    let kit = kit().await;
    let mut c = kit.tunnel("up.test", true).await;
    let (mut tx, body) = streaming_body();
    let req = c.request("POST", "/upload", &[]).body(body).unwrap();
    let pending = c.start(req);
    tx.send_data(Bytes::from(vec![b'x'; 1024])).await.unwrap();
    kit.wait_arrived(1).await;
    // Dropping the response future cancels the stream.
    pending.abort();
    drop(tx);
    let ev = kit.request_event().await;
    assert_eq!(ev["reason"], "client_gone", "{ev:#}");
    assert_eq!(ev["decision"], "allow", "{ev:#}");
    assert!(ev["res"].is_null(), "{ev:#}");
    let b = c.call("GET", "/next", &[], b"").await;
    assert_eq!(b.status, 200, "{b:?}");
    assert!(
        kit.sink
            .events()
            .iter()
            .all(|e| e["event"] != "parse_error"),
        "{:#?}",
        kit.sink.events()
    );
}

#[tokio::test]
async fn h1_a_client_gone_mid_upload_is_logged() {
    a_client_gone_mid_upload_is_logged(false).await;
}

#[tokio::test]
async fn h2_a_client_gone_mid_upload_is_logged() {
    a_client_gone_mid_upload_is_logged(true).await;
}

/// The server's kill switch drops exchanges in flight; each is still
/// logged, as `aborted`.
async fn a_server_killed_mid_exchange_logs_it_as_aborted(h2: bool) {
    let kit = kit().await;
    let mut c = if h2 {
        kit.tunnel("up.test", true).await
    } else {
        kit.h1().await
    };
    let (mut tx, body) = streaming_body();
    let req = c.request("POST", "/upload", &[]).body(body).unwrap();
    let pending = c.start(req);
    tx.send_data(Bytes::from(vec![b'x'; 1024])).await.unwrap();
    kit.wait_arrived(1).await;
    kit.server
        .shutdown(std::time::Duration::from_millis(100))
        .await;
    let ev = kit
        .sink
        .wait_for("request", 1, std::time::Duration::from_secs(10))
        .await
        .remove(0);
    assert_eq!(ev["reason"], "aborted", "{ev:#}");
    assert_eq!(ev["decision"], "allow", "{ev:#}");
    drop(tx);
    let _ = pending.await;
}

#[tokio::test]
async fn h1_a_server_killed_mid_exchange_logs_it_as_aborted() {
    a_server_killed_mid_exchange_logs_it_as_aborted(false).await;
}

#[tokio::test]
async fn h2_a_server_killed_mid_exchange_logs_it_as_aborted() {
    a_server_killed_mid_exchange_logs_it_as_aborted(true).await;
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

/// Capture records what left: a refusal before the head leaves (here the
/// address floor at preflight) leaves nothing in the capture, not a
/// headless aborted end.
#[tokio::test]
async fn a_refusal_before_forwarding_captures_nothing() {
    let kit = Kit::builder().rules(RULES).capture_all().start().await;
    let mut c = kit.h1().await;
    let req = c
        .request_to("private.test", "GET", "/strict", &[])
        .body(roxy_http::Body::empty())
        .unwrap();
    assert_eq!(Answer::read(c.send(req).await.unwrap()).await.status, 403);
    kit.request_event().await;
    assert!(kit.captured().is_empty(), "{:#?}", kit.captured());

    let a = kit.h1().await.call("GET", "/x", &[], b"").await;
    assert_eq!(a.status, 200, "{a:?}");
    kit.events("request", 2).await;
    let kinds: Vec<(String, String)> = kit
        .captured()
        .iter()
        .map(|(h, _)| {
            (
                h["dir"].as_str().unwrap().to_owned(),
                h["kind"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert!(
        kinds.contains(&("request".to_owned(), "head".to_owned()))
            && kinds.contains(&("response".to_owned(), "end".to_owned())),
        "{kinds:?}"
    );
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

/// Roxy's own time before it reads the request body (here a slow
/// `set_state` at the head) does not count against the client's
/// `body_idle_timeout` on h2.
#[tokio::test(flavor = "multi_thread")]
async fn h2_body_idle_timeout_runs_from_when_the_body_is_read() {
    struct SlowState;
    impl crate::sources::StateSource for SlowState {
        fn get(&self, _key: &str) -> Option<String> {
            None
        }
        fn set(
            &self,
            _key: &str,
            _value: &str,
            _ttl: Option<std::time::Duration>,
        ) -> Result<(), crate::sources::StateFull> {
            std::thread::sleep(std::time::Duration::from_millis(600));
            Ok(())
        }
    }
    let kit = Kit::builder()
        .rules(
            r#"
- id: up
  when: host == "up.test"
  then: [{ set_state: { key: k, value: "1" } }, allow]
"#,
        )
        .limits(|l| l.body_idle_timeout = std::time::Duration::from_millis(300))
        .state(std::sync::Arc::new(SlowState))
        .start()
        .await;
    let mut c = kit.tunnel("up.test", true).await;
    let (mut tx, body) = streaming_body();
    let req = c.request("POST", "/upload", &[]).body(body).unwrap();
    let pending = c.start(req);
    // The head is upstream: roxy is now reading the body.
    kit.wait_arrived(1).await;
    tx.send_data(Bytes::from_static(b"hello")).await.unwrap();
    tx.finish().await.unwrap();
    let a = pending.await.unwrap().expect("a response");
    assert_eq!(a.status, 200, "{a:?}");
}

// ---- refusals and the h1 connection ---------------------------------------

const OPEN_DENY_RULES: &str = r#"
- id: denied-open
  when: host == "up.test" and path == "/denied"
  then: { deny: { close: false } }
- id: denied
  when: host == "up.test" and path == "/denied-close"
  then: deny
- id: up
  when: host == "up.test"
  then: allow
"#;

/// Reads one h1 response (head, then a `content-length` body) as text.
async fn read_response(io: &mut tokio::io::DuplexStream) -> String {
    use tokio::io::AsyncReadExt;
    let read = async {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut b = [0u8; 1];
            assert_eq!(io.read(&mut b).await.unwrap(), 1, "EOF in response head");
            head.push(b[0]);
        }
        let head = String::from_utf8(head).unwrap();
        let len: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("content-length: "))
            .map_or(0, |v| v.parse().unwrap());
        let mut body = vec![0u8; len];
        io.read_exact(&mut body).await.unwrap();
        head
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), read)
        .await
        .expect("a response")
}

/// A deny with `close: false` leaves the connection usable: the unread
/// request body is consumed, and the next request parses from where it
/// starts.
#[tokio::test]
async fn a_non_closing_deny_keeps_the_connection_in_sync() {
    use tokio::io::AsyncWriteExt;
    let kit = Kit::builder().rules(OPEN_DENY_RULES).start().await;
    let mut io = kit.connect();
    io.write_all(
        b"POST http://up.test/denied HTTP/1.1\r\nhost: up.test\r\ncontent-length: 5\r\n\r\nhello\
          GET http://up.test/second HTTP/1.1\r\nhost: up.test\r\n\r\n",
    )
    .await
    .unwrap();
    let first = read_response(&mut io).await;
    assert!(first.starts_with("HTTP/1.1 403"), "{first}");
    assert!(!first.contains("connection: close"), "{first}");
    let second = read_response(&mut io).await;
    assert!(second.starts_with("HTTP/1.1 200"), "{second}");
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].path, "/second");
}

/// A denied request waiting on `100 Continue` never gets one; the
/// connection closes, since the client may or may not send the body.
#[tokio::test]
async fn a_deny_never_answers_100_continue() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let kit = Kit::builder().rules(OPEN_DENY_RULES).start().await;
    let mut io = kit.connect();
    io.write_all(
        b"POST http://up.test/denied HTTP/1.1\r\nhost: up.test\r\ncontent-length: 5\r\nexpect: 100-continue\r\n\r\n",
    )
    .await
    .unwrap();
    let res = read_response(&mut io).await;
    assert!(res.starts_with("HTTP/1.1 403"), "{res}");
    assert!(res.contains("connection: close"), "{res}");
    let mut rest = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(5), io.read_to_end(&mut rest))
        .await
        .expect("the connection closes")
        .unwrap();
    assert!(rest.is_empty(), "{}", String::from_utf8_lossy(&rest));
    assert!(kit.upstream.seen().is_empty());
}

/// A closing deny of a large upload does not wait for the rest of the
/// body: the connection closes as soon as the response is written.
#[tokio::test]
async fn a_closing_deny_does_not_drain_the_upload() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let kit = Kit::builder()
        .rules(OPEN_DENY_RULES)
        .limits(|l| l.body_idle_timeout = std::time::Duration::from_secs(5))
        .start()
        .await;
    let mut io = kit.connect();
    io.write_all(
        b"POST http://up.test/denied-close HTTP/1.1\r\nhost: up.test\r\ncontent-length: 2000000\r\n\r\nabc",
    )
    .await
    .unwrap();
    let res = read_response(&mut io).await;
    assert!(res.starts_with("HTTP/1.1 403"), "{res}");
    assert!(res.contains("connection: close"), "{res}");
    let mut rest = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(2), io.read_to_end(&mut rest))
        .await
        .expect("the connection closes without waiting for the body")
        .unwrap();
}

/// Records every metric sample and keeps state in memory.
#[derive(Default)]
struct Recording {
    samples: std::sync::Mutex<Vec<crate::sources::Sample>>,
    state: std::sync::Mutex<std::collections::HashMap<String, String>>,
}

impl crate::sources::MetricSource for Recording {
    fn get(
        &self,
        _id: &str,
        _view: &dyn roxy_rules::FlowView,
    ) -> Result<i64, crate::sources::MetricSourceError> {
        Ok(0)
    }

    fn record(
        &self,
        _view: &dyn roxy_rules::FlowView,
        sample: &crate::sources::Sample,
    ) -> Result<(), crate::sources::MetricSourceError> {
        self.samples.lock().unwrap().push(*sample);
        Ok(())
    }
}

impl crate::sources::StateSource for Recording {
    fn get(&self, key: &str) -> Option<String> {
        self.state.lock().unwrap().get(key).cloned()
    }

    fn set(
        &self,
        key: &str,
        value: &str,
        _ttl: Option<std::time::Duration>,
    ) -> Result<(), crate::sources::StateFull> {
        self.state
            .lock()
            .unwrap()
            .insert(key.to_owned(), value.to_owned());
        Ok(())
    }
}

async fn recording_kit(rules: &str) -> (Kit, std::sync::Arc<Recording>) {
    let rec = std::sync::Arc::new(Recording::default());
    let kit = Kit::builder()
        .rules(rules)
        .metrics(rec.clone())
        .state(rec.clone())
        .start()
        .await;
    (kit, rec)
}

/// A refused head decision still applies the `log` and `set_state` of the
/// rules that matched, and counts as denied.
#[tokio::test]
async fn a_head_deny_still_logs_and_writes_state() {
    let (kit, rec) = recording_kit(
        r#"
- id: no-admin
  when: path starts_with "/admin"
  then: [{ log: { level: warn, message: admin blocked } }, { set_state: { key: seen, value: "1" } }, deny]
- id: up
  when: host == "up.test"
  then: allow
"#,
    )
    .await;
    let a = kit.h1().await.call("GET", "/admin", &[], b"").await;
    assert_eq!(a.status, 403, "{a:?}");
    let log = kit.events("log", 1).await;
    assert_eq!(log[0]["message"], "admin blocked", "{log:#?}");
    assert_eq!(
        rec.state.lock().unwrap().get("seen").map(String::as_str),
        Some("1")
    );
    let samples = rec.samples.lock().unwrap().clone();
    assert!(samples[0].head && samples[0].denied, "{samples:?}");
}

/// An allowed request whose change fails is refused, and its head sample
/// counts it as denied, not allowed.
#[tokio::test]
async fn a_failing_effect_counts_as_denied() {
    let (kit, rec) = recording_kit(
        r#"
- id: up
  when: host == "up.test"
  then: [{ rewrite_path: { match: "/(.*)", to: "/../$1" } }, allow]
"#,
    )
    .await;
    let a = kit.h1().await.call("GET", "/x", &[], b"").await;
    assert_eq!(a.status, 503, "{a:?}");
    assert_eq!(a.json()["rule"], "_fail_closed");
    assert!(kit.upstream.seen().is_empty());
    let samples = rec.samples.lock().unwrap().clone();
    assert_eq!(samples.len(), 1, "{samples:?}");
    assert!(samples[0].head && samples[0].denied, "{samples:?}");
}

/// The samples after the head sample.
fn final_samples(rec: &Recording) -> Vec<crate::sources::Sample> {
    rec.samples
        .lock()
        .unwrap()
        .iter()
        .copied()
        .filter(|s| !s.head)
        .collect()
}

/// A deny after the forwarding decision that is not a watching stop (the
/// address floor at preflight) still counts as denied in its final sample.
#[tokio::test]
async fn an_address_floor_deny_counts_as_denied() {
    let (kit, rec) = recording_kit(RULES).await;
    let mut c = kit.h1().await;
    let req = c
        .request_to("private.test", "GET", "/strict", &[])
        .body(roxy_http::Body::empty())
        .unwrap();
    assert_eq!(Answer::read(c.send(req).await.unwrap()).await.status, 403);
    kit.request_event().await;
    let finals = final_samples(&rec);
    assert_eq!(finals.len(), 1, "{finals:?}");
    assert!(finals[0].denied && !finals[0].error, "{finals:?}");
}

#[tokio::test]
async fn an_upstream_failure_counts_as_an_error() {
    let (kit, rec) = recording_kit(RULES).await;
    let mut c = kit.h1().await;
    let req = c
        .request_to("down.test", "GET", "/", &[])
        .body(roxy_http::Body::empty())
        .unwrap();
    assert_eq!(Answer::read(c.send(req).await.unwrap()).await.status, 502);
    kit.request_event().await;
    let finals = final_samples(&rec);
    assert_eq!(finals.len(), 1, "{finals:?}");
    assert!(finals[0].error && !finals[0].denied, "{finals:?}");
}

#[tokio::test]
async fn a_watching_stop_counts_as_denied() {
    let (kit, rec) = recording_kit(RULES).await;
    let mut c = kit.h1().await;
    let (mut tx, body) = streaming_body();
    let req = c.request("POST", "/upload", &[]).body(body).unwrap();
    let pending = c.start(req);
    for _ in 0..16 {
        if tx.send_data(Bytes::from(vec![b'x'; 1024])).await.is_err() {
            break;
        }
    }
    let a = pending.await.unwrap().unwrap();
    assert_eq!(a.status, 413, "{a:?}");
    drop(tx);
    kit.request_event().await;
    let finals = final_samples(&rec);
    assert_eq!(finals.len(), 1, "{finals:?}");
    assert!(finals[0].denied && !finals[0].error, "{finals:?}");
}

/// A client that stops reading the response is not an upstream failure:
/// the exchange leaves no final sample.
#[tokio::test]
async fn a_client_write_failure_is_not_an_upstream_error() {
    let (kit, rec) = recording_kit(super::ALLOW_UP).await;
    let mut c = kit.h1().await;
    let req = c
        .request("POST", "/echo", &[])
        .body(roxy_http::Body::from_bytes(Bytes::from(vec![
            b'x';
            1 << 20
        ])))
        .unwrap();
    let res = c.send(req).await.unwrap();
    assert_eq!(res.status(), 200);
    c.kill();
    drop(res);
    let err = kit.events("response_error", 1).await;
    assert_eq!(err[0]["reason"], "client_gone", "{err:#?}");
    let ev = kit.request_event().await;
    assert_eq!(ev["reason"], "client_gone", "{ev:#}");
    assert!(final_samples(&rec).is_empty(), "{:?}", final_samples(&rec));
}

/// A `redirect` that keeps the client's `Host` goes upstream over
/// HTTP/1.1, even to an h2-capable upstream: over h2, `:authority` would
/// name the new target while `host` named the old one (RFC 9113 §8.3.1).
/// A redirect that rewrites `Host` may use h2.
#[tokio::test]
async fn a_redirect_keeping_host_goes_over_http1() {
    let kit = Kit::builder()
        .rules(
            r#"
- id: keep-host
  when: host == "alias.test"
  then: [{ redirect: { host: up.test, port: 443, scheme: https } }, allow]
- id: rewrite-host
  when: host == "other.test"
  then: [{ redirect: { host: up.test, port: 443, scheme: https, rewrite_host: true } }, allow]
"#,
        )
        .start()
        .await;
    let mut c = kit.h1().await;
    let req = c
        .request_to("alias.test", "GET", "/kept", &[])
        .body(roxy_http::Body::empty())
        .unwrap();
    assert_eq!(Answer::read(c.send(req).await.unwrap()).await.status, 200);
    let req = c
        .request_to("other.test", "GET", "/rewritten", &[])
        .body(roxy_http::Body::empty())
        .unwrap();
    assert_eq!(Answer::read(c.send(req).await.unwrap()).await.status, 200);
    let seen = kit.upstream.wait_seen(2).await;
    let kept = seen.iter().find(|s| s.path == "/kept").unwrap();
    assert_eq!(kept.version, http::Version::HTTP_11);
    assert_eq!(kept.headers["host"], "alias.test");
    let rewritten = seen.iter().find(|s| s.path == "/rewritten").unwrap();
    assert_eq!(rewritten.version, http::Version::HTTP_2);
}
