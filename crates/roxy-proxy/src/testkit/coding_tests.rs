//! Body rules on encoded bodies (docs/rules.md#body-access): the rules see
//! the decoded text, the bytes forwarded are the bytes received, and a body
//! that cannot be decoded fails closed.

use std::io::Write as _;

use bytes::Bytes;
use roxy_http::Body;

use super::{Answer, Client, Kit};

const RULES: &str = r#"
- id: no-secret-out
  when: host == "up.test" and body.text contains "SECRET"
  then: deny
- id: no-secret-in
  when: host == "up.test" and response.body.text contains "SECRET"
  then: deny
- id: up
  when: host == "up.test"
  then: allow
"#;

async fn kit() -> Kit {
    Kit::builder()
        .rules(RULES)
        .limits(|l| l.max_inspect_body_bytes = 64 * 1024)
        .start()
        .await
}

fn gzip(b: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(b).unwrap();
    e.finish().unwrap()
}

async fn post(c: &mut Client, path: &str, headers: &[(&str, &str)], body: Vec<u8>) -> Answer {
    let req = c
        .request("POST", path, headers)
        .body(Body::from_bytes(Bytes::from(body)))
        .unwrap();
    Answer::read(c.send(req).await.expect("response")).await
}

/// The response's `content-encoding` comes from the request's
/// `x-echo-encoding`, which the request rules never see as an encoding.
async fn echo(kit: &Kit, h2: bool, encoding: &str, body: Vec<u8>) -> Answer {
    let mut c = if h2 {
        kit.tunnel("up.test", true).await
    } else {
        kit.h1().await
    };
    post(&mut c, "/echo", &[("x-echo-encoding", encoding)], body).await
}

#[tokio::test]
async fn a_rule_reads_a_gzip_request_body() {
    let kit = kit().await;
    for h2 in [false, true] {
        let mut c = if h2 {
            kit.tunnel("up.test", true).await
        } else {
            kit.h1().await
        };
        let a = post(
            &mut c,
            "/x",
            &[("content-encoding", "gzip")],
            gzip(b"the SECRET"),
        )
        .await;
        assert_eq!(a.status, 403, "h2 {h2}: {a:?}");
        let ev = kit.request_event().await;
        assert_eq!(ev["terminal_rule"], "no-secret-out", "{ev:#}");
    }
    assert!(kit.upstream.seen().is_empty());
}

#[tokio::test]
async fn an_encoded_request_body_is_forwarded_as_received() {
    let kit = kit().await;
    let enc = gzip(b"nothing to see");
    let a = post(
        &mut kit.h1().await,
        "/x",
        &[("content-encoding", "gzip")],
        enc.clone(),
    )
    .await;
    assert_eq!(a.status, 200, "{a:?}");
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].body, enc);
    assert_eq!(seen[0].headers["content-encoding"], "gzip");
}

#[tokio::test]
async fn a_rule_reads_a_gzip_response_body() {
    let kit = kit().await;
    for h2 in [false, true] {
        let a = echo(&kit, h2, "gzip", gzip(b"the SECRET")).await;
        assert_eq!(a.status, 403, "h2 {h2}: {a:?}");
        let ev = kit.request_event().await;
        assert_eq!(ev["terminal_rule"], "no-secret-in", "{ev:#}");
    }
}

#[tokio::test]
async fn an_encoded_response_is_forwarded_as_received() {
    let kit = kit().await;
    let enc = gzip(b"nothing to see");
    let a = echo(&kit, false, "gzip", enc.clone()).await;
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.headers["content-encoding"], "gzip");
    assert_eq!(a.body.as_deref().unwrap(), enc.as_slice());
}

/// The flow fails closed with `reason`.
async fn assert_fails_closed(kit: &Kit, a: &Answer, reason: &str) {
    assert_eq!(a.status, 503, "{a:?}");
    let ev = kit.request_event().await;
    assert_eq!(ev["terminal_rule"], "_fail_closed", "{ev:#}");
    assert_eq!(ev["reason"], reason, "{ev:#}");
}

#[tokio::test]
async fn a_corrupt_body_fails_closed() {
    let kit = kit().await;
    let mut enc = gzip(b"nothing to see");
    let n = enc.len();
    enc[n - 8] ^= 1;
    let a = echo(&kit, false, "gzip", enc.clone()).await;
    assert_fails_closed(&kit, &a, "body_decode_failed").await;

    // Bytes after the end of the stream: a rule cannot see them, so they
    // may not pass.
    let mut enc = gzip(b"nothing to see");
    enc.extend_from_slice(b"SECRET");
    let mut c = kit.h1().await;
    let a = post(&mut c, "/x", &[("content-encoding", "gzip")], enc).await;
    assert_fails_closed(&kit, &a, "body_decode_failed").await;
}

#[tokio::test]
async fn an_unknown_coding_fails_closed() {
    let kit = kit().await;
    let mut c = kit.h1().await;
    let a = post(
        &mut c,
        "/x",
        &[("content-encoding", "compress")],
        b"x".to_vec(),
    )
    .await;
    assert_fails_closed(&kit, &a, "unsupported_content_encoding").await;
    assert!(kit.upstream.seen().is_empty());
}

#[tokio::test]
async fn the_inspect_cap_applies_to_the_decoded_body() {
    let kit = kit().await;
    // 1 MiB of zeros gzips to about 1 KiB, well under the 64 KiB cap.
    let enc = gzip(&vec![0u8; 1 << 20]);
    assert!(enc.len() < 4096);
    let a = echo(&kit, false, "gzip", enc).await;
    assert_fails_closed(&kit, &a, "body_too_large_to_inspect").await;
}

#[tokio::test]
async fn identity_and_no_coding_read_as_before() {
    let kit = kit().await;
    let a = echo(&kit, false, "identity", b"the SECRET".to_vec()).await;
    assert_eq!(a.status, 403, "{a:?}");
    let mut c = kit.h1().await;
    let a = post(&mut c, "/x", &[], b"the SECRET".to_vec()).await;
    assert_eq!(a.status, 403, "{a:?}");
}
