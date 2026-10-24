//! `http.redact_response_secrets`: an upstream that echoes an injected
//! secret hands the client a mask of the same length, not the value, in
//! whichever parts are switched on, and only on exchanges that injected
//! that value.

use std::io::Write as _;

use bytes::Bytes;
use roxy_http::Body;

use super::{AddonDef, Answer, Client, Kit};
use crate::config::ResponseRedaction;

const SECRET: &str = "s3cr3t-token-value-0123456789";
/// [`SECRET`] masked.
const MASKED: &str = "*****************************";

const RULES: &str = r#"
- id: inject
  when: host == "up.test" and header["x-plain"] != "1"
  then:
    - set_header: { authorization: "Bearer ${secret:token}" }
    - allow
- id: up
  when: host == "up.test"
  then: allow
"#;

async fn kit(switches: ResponseRedaction) -> Kit {
    Kit::builder()
        .secret("token", SECRET)
        .rules(RULES)
        .http(|h| h.redact_response_secrets = switches)
        .start()
        .await
}

const BOTH: ResponseRedaction = ResponseRedaction {
    headers: true,
    bodies: true,
    quarantine: false,
    min_length: 8,
};

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

fn body(a: &Answer) -> String {
    String::from_utf8_lossy(a.body.as_ref().expect("a whole body")).into_owned()
}

#[tokio::test]
async fn a_reflected_secret_is_scrubbed_from_the_head_and_the_body() {
    let kit = kit(BOTH).await;
    for h2 in [false, true] {
        let mut c = if h2 {
            kit.tunnel("up.test", true).await
        } else {
            kit.h1().await
        };
        let a = c.call("GET", "/reflect", &[], b"").await;
        assert_eq!(a.status, 200, "h2 {h2}: {a:?}");
        let masked = format!("Bearer {MASKED}");
        assert_eq!(a.headers["x-reflect"], masked.as_str(), "h2 {h2}");
        assert_eq!(body(&a), masked, "h2 {h2}");
    }
    let seen = kit.upstream.wait_seen(2).await;
    assert_eq!(seen[0].headers["authorization"], format!("Bearer {SECRET}"));
}

/// Each switch scrubs its own part only.
#[tokio::test]
async fn headers_and_bodies_switch_separately() {
    for (headers, bodies) in [(true, false), (false, true), (false, false)] {
        let kit = kit(ResponseRedaction {
            headers,
            bodies,
            ..BOTH
        })
        .await;
        let a = kit.h1().await.call("GET", "/reflect", &[], b"").await;
        let scrubbed = |on: bool| {
            if on {
                format!("Bearer {MASKED}")
            } else {
                format!("Bearer {SECRET}")
            }
        };
        assert_eq!(a.headers["x-reflect"], scrubbed(headers).as_str());
        assert_eq!(body(&a), scrubbed(bodies));
        // Masking keeps the body's length.
        assert!(a.headers.contains_key("content-length"), "{a:?}");
    }
}

/// An exchange that injected nothing is not scrubbed: the value is the
/// client's own.
#[tokio::test]
async fn an_exchange_that_injected_nothing_is_left_alone() {
    let kit = kit(BOTH).await;
    let mut c = kit.h1().await;
    let a = post(&mut c, "/echo", &[("x-plain", "1")], SECRET.into()).await;
    assert_eq!(body(&a), SECRET);
}

#[tokio::test]
async fn an_encoded_body_is_decoded_then_scrubbed() {
    let kit = kit(BOTH).await;
    let mut c = kit.h1().await;
    let echoed = format!("before {SECRET} after");
    let a = post(
        &mut c,
        "/echo",
        &[("x-echo-encoding", "gzip"), ("accept-encoding", "gzip")],
        gzip(echoed.as_bytes()),
    )
    .await;
    assert_eq!(a.status, 200, "{a:?}");
    assert!(!a.headers.contains_key("content-encoding"), "{a:?}");
    assert_eq!(body(&a), format!("before {MASKED} after"));
    let seen = kit.upstream.wait_seen(1).await;
    assert!(
        !seen[0].headers.contains_key("accept-encoding"),
        "an injecting request asks for no coding"
    );
}

/// `accept-encoding` is only dropped when bodies are scrubbed.
#[tokio::test]
async fn accept_encoding_stays_when_only_headers_are_scrubbed() {
    let kit = kit(ResponseRedaction {
        headers: true,
        ..ResponseRedaction::default()
    })
    .await;
    let a = kit
        .h1()
        .await
        .call("GET", "/reflect", &[("accept-encoding", "gzip")], b"")
        .await;
    assert_eq!(a.status, 200, "{a:?}");
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].headers["accept-encoding"], "gzip");
}

/// A body roxy cannot read as plain bytes is refused rather than passed
/// unscrubbed: a coding it does not decode, or a range of an encoded body.
#[tokio::test]
async fn a_body_that_cannot_be_decoded_fails_closed() {
    let kit = kit(BOTH).await;
    for headers in [
        &[("x-echo-encoding", "compress")][..],
        &[("x-echo-encoding", "gzip"), ("x-echo-status", "206")][..],
    ] {
        let mut c = kit.h1().await;
        let a = post(&mut c, "/echo", headers, gzip(SECRET.as_bytes())).await;
        assert_eq!(a.status, 503, "{headers:?}: {a:?}");
        let ev = kit.request_event().await;
        assert_eq!(ev["terminal_rule"], "_fail_closed", "{ev:#}");
        assert_eq!(ev["reason"], "unsupported_content_encoding", "{ev:#}");
    }
}

/// A range of a plain body is scrubbed as it is.
#[tokio::test]
async fn a_plain_range_is_scrubbed() {
    let kit = kit(BOTH).await;
    let mut c = kit.h1().await;
    let a = post(
        &mut c,
        "/echo",
        &[("x-echo-status", "206")],
        format!("[{SECRET}]").into(),
    )
    .await;
    assert_eq!(a.status, 206, "{a:?}");
    assert_eq!(body(&a), format!("[{MASKED}]"));
    assert!(a.headers.contains_key("content-length"), "{a:?}");
}

/// Layers downstream of the core see the scrubbed response, and the
/// client gets what they pass on.
#[tokio::test]
async fn the_addon_stack_sees_the_scrubbed_response() {
    let kit = Kit::builder()
        .secret("token", SECRET)
        .rules(RULES)
        .http(|h| h.redact_response_secrets = BOTH)
        .addon(AddonDef::test_layer("a"))
        .start()
        .await;
    let a = kit.h1().await.call("GET", "/reflect", &[], b"").await;
    assert_eq!(a.status, 200, "{a:?}");
    let masked = format!("Bearer {MASKED}");
    assert_eq!(a.headers["x-reflect"], masked.as_str());
    assert_eq!(body(&a), masked);
}

/// With `quarantine`, a secret in the head refuses the exchange that found
/// it and every one after; one in the body trips it as it streams.
#[tokio::test]
async fn a_found_secret_trips_the_quarantine() {
    for (path, part) in [("/reflect", "headers"), ("/echo", "body")] {
        let dir = tempfile::tempdir().unwrap();
        let kit = Kit::builder()
            .secret("token", SECRET)
            .rules(RULES)
            .http(|h| {
                h.redact_response_secrets = ResponseRedaction {
                    quarantine: true,
                    ..BOTH
                };
            })
            .quarantine_dir(dir.path())
            .start()
            .await;
        let mut c = kit.h1().await;
        let a = post(&mut c, path, &[], SECRET.into()).await;
        if part == "headers" {
            assert_eq!(a.status, 403, "{a:?}");
            assert_eq!(a.headers["x-roxy-rule"], "_quarantined");
        } else if let Ok(b) = &a.body {
            assert!(!String::from_utf8_lossy(b).contains(SECRET), "{a:?}");
        }
        let tripped = kit.events("quarantined", 1).await.remove(0);
        assert_eq!(
            tripped["cause"]["kind"], "secret_in_response",
            "{tripped:#}"
        );
        assert_eq!(tripped["cause"]["part"], part, "{tripped:#}");
        let a = kit
            .h1()
            .await
            .call("GET", "/x", &[("x-plain", "1")], b"")
            .await;
        assert_eq!(a.status, 403, "{a:?}");
        assert_eq!(a.headers["x-roxy-rule"], "_quarantined");
    }
}

/// The flow log and captured heads never held the value; the scrubbed
/// response does not change that.
#[tokio::test]
async fn nothing_logged_holds_the_secret() {
    let kit = kit(BOTH).await;
    let a = kit.h1().await.call("GET", "/reflect", &[], b"").await;
    assert_eq!(a.status, 200, "{a:?}");
    kit.request_event().await;
    let all = serde_json::to_string(&kit.sink.events()).unwrap();
    assert!(!all.contains(SECRET), "secret leaked into the flow log");
}

/// A value shorter than `min_length` is left alone, and so is a secret
/// this exchange did not inject.
#[tokio::test]
async fn only_injected_values_of_min_length_are_masked() {
    let kit = Kit::builder()
        .secret("token", SECRET)
        .secret("short", "abc123")
        .secret("other", "an-unrelated-secret-value")
        .rules(
            r#"
- id: inject
  when: host == "up.test"
  then:
    - set_header: { authorization: "${secret:token} ${secret:short}" }
    - allow
"#,
        )
        .http(|h| h.redact_response_secrets = BOTH)
        .start()
        .await;
    let mut c = kit.h1().await;
    let a = post(&mut c, "/echo", &[], b"an-unrelated-secret-value".to_vec()).await;
    assert_eq!(body(&a), "an-unrelated-secret-value");
    let a = kit.h1().await.call("GET", "/reflect", &[], b"").await;
    assert_eq!(body(&a), format!("{MASKED} abc123"));
}
