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

/// A body of length 0 can still end with trailers on h2: they are masked
/// with the head.
#[tokio::test]
async fn trailers_after_an_empty_body_are_masked() {
    let kit = kit(BOTH).await;
    let (send, _conn) = super::h2_client(&kit).await;
    let req = http::Request::get("https://up.test/reflect-trailers")
        .body(())
        .unwrap();
    let mut ready = send.clone().ready().await.unwrap();
    let (resp, _) = ready.send_request(req, true).unwrap();
    let resp = resp.await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["content-length"], "0");
    let mut body = resp.into_body();
    while let Some(chunk) = body.data().await {
        assert!(chunk.unwrap().is_empty());
    }
    let trailers = body.trailers().await.unwrap().expect("the trailers");
    assert_eq!(trailers["x-reflect"], format!("Bearer {MASKED}").as_str());
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

/// An encoded body is decoded, masked and encoded again, so the client
/// gets the coding it asked for.
#[tokio::test]
async fn an_encoded_body_is_masked_and_re_encoded() {
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
    assert_eq!(a.headers["content-encoding"], "gzip", "{a:?}");
    let plain = roxy_http::coding::decode(
        &[roxy_http::coding::Coding::Gzip],
        a.body.as_ref().expect("a whole body"),
        1 << 20,
        roxy_http::coding::unmetered(),
    )
    .unwrap();
    assert_eq!(plain, format!("before {MASKED} after").as_bytes());
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(
        seen[0].headers["accept-encoding"], "gzip",
        "the client's accept-encoding goes to the upstream"
    );
}

/// Masking and the layers share one decoding in each direction: the
/// layer reads both bodies plain, the response masked, and each leaves in
/// the coding it came in.
#[tokio::test]
async fn masking_and_a_reading_layer_share_the_decoding() {
    // Upper case, so the layer's upper-casing leaves it as injected.
    const LOUD: &str = "S3CR3T-TOKEN-VALUE-0123456789";
    let kit = Kit::builder()
        .secret("token", LOUD)
        .rules(RULES)
        .http(|h| h.redact_response_secrets = BOTH)
        .addon(AddonDef::test_layer("a"))
        .start()
        .await;
    let mut c = kit.h1().await;
    let a = post(
        &mut c,
        "/echo",
        &[
            ("content-encoding", "gzip"),
            ("x-echo-encoding", "gzip"),
            ("x-upper", "1"),
        ],
        gzip(format!("before {LOUD} after").as_bytes()),
    )
    .await;
    assert_eq!(a.status, 200, "{a:?}");
    let gunzip = |b: &[u8]| {
        roxy_http::coding::decode(
            &[roxy_http::coding::Coding::Gzip],
            b,
            1 << 20,
            roxy_http::coding::unmetered(),
        )
        .unwrap()
    };
    // The layer upper-cased the request it read plain; it went on gzipped.
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].headers["content-encoding"], "gzip");
    assert_eq!(
        gunzip(&seen[0].body),
        format!("BEFORE {LOUD} AFTER").as_bytes()
    );
    // The echo came back gzipped, was masked, read by the layer and gzipped
    // again for the client.
    assert_eq!(a.headers["content-encoding"], "gzip", "{a:?}");
    let body = gunzip(a.body.as_ref().expect("a whole body"));
    assert_eq!(body, format!("BEFORE {MASKED} AFTER").as_bytes());
}

/// The capture records traffic as it crosses roxy's edge: the response
/// as the upstream sent it, in its coding and before masking.
#[tokio::test]
async fn the_capture_records_the_response_as_the_upstream_sent_it() {
    let kit = Kit::builder()
        .secret("token", SECRET)
        .rules(RULES)
        .http(|h| h.redact_response_secrets = BOTH)
        .capture_all()
        .start()
        .await;
    let mut c = kit.h1().await;
    let sent = gzip(format!("before {SECRET} after").as_bytes());
    let a = post(
        &mut c,
        "/echo",
        &[("x-echo-encoding", "gzip")],
        sent.clone(),
    )
    .await;
    assert_eq!(a.status, 200, "{a:?}");
    let ev = kit.request_event().await;
    let flow = ev["flow"].as_str().unwrap();
    let records = kit.captured();
    let response: Vec<_> = records
        .iter()
        .filter(|(h, _)| h["flow"] == flow && h["dir"] == "response")
        .collect();
    let head: serde_json::Value = serde_json::from_slice(&response[0].1).unwrap();
    assert!(
        head["headers"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!(["content-encoding", "gzip"])),
        "{head:#}"
    );
    let data: Vec<u8> = response
        .iter()
        .filter(|(h, _)| h["kind"] == "data")
        .flat_map(|(_, d)| d.clone())
        .collect();
    assert_eq!(data, sent, "the upstream's bytes");
}

/// `response.body.bytes` counts the bytes the upstream sent, whether or
/// not roxy decodes the body for masking or a layer: a small gzip of a
/// large body stays under a download cap.
#[tokio::test]
async fn in_flight_byte_counts_see_the_encoded_body() {
    for (masking, layer) in [(false, false), (true, false), (false, true)] {
        let mut b = Kit::builder().secret("token", SECRET).rules(
            r#"
- id: inject
  when: host == "up.test"
  then:
    - set_header: { authorization: "Bearer ${secret:token}" }
    - allow
- id: download-cap
  when: host == "up.test" and response.body.bytes > 10kb
  then: deny
"#,
        );
        if masking {
            b = b.http(|h| h.redact_response_secrets = BOTH);
        }
        if layer {
            b = b.addon(AddonDef::test_layer("a"));
        }
        let kit = b.start().await;
        let sent = gzip(&vec![b'x'; 64 * 1024]);
        let a = post(
            &mut kit.h1().await,
            "/echo",
            &[("x-echo-encoding", "gzip")],
            sent,
        )
        .await;
        let case = format!("masking {masking}, layer {layer}");
        assert_eq!(a.status, 200, "{case}: {a:?}");
        assert!(a.body.is_ok(), "{case}: the body is whole: {a:?}");
        let ev = kit.request_event().await;
        assert_eq!(ev["decision"], "allow", "{case}: {ev:#}");
    }
}

/// A body roxy cannot decode is refused rather than passed unmasked.
#[tokio::test]
async fn a_body_that_cannot_be_decoded_fails_closed() {
    let kit = kit(BOTH).await;
    let mut c = kit.h1().await;
    let headers = [("x-echo-encoding", "compress")];
    let a = post(&mut c, "/echo", &headers, gzip(SECRET.as_bytes())).await;
    assert_eq!(a.status, 503, "{a:?}");
    let ev = kit.request_event().await;
    assert_eq!(ev["terminal_rule"], "_fail_closed", "{ev:#}");
    assert_eq!(ev["reason"], "unsupported_content_encoding", "{ev:#}");
}

/// The client chooses a range's bounds, so two ranges that each cut the
/// secret would carry it out in pieces past a mask of whole occurrences.
/// The request goes without `range` and `if-range`, the in-flight rules
/// see it without them (`saw-range` does not fire), and a `206` that
/// comes back anyway, plain or encoded, is refused.
#[tokio::test]
async fn a_range_is_never_masked() {
    let kit = Kit::builder()
        .secret("token", SECRET)
        .rules(&format!(
            r#"{RULES}
- id: saw-range
  when: host == "up.test" and header["range"] != null and response.status == 200
  then: deny
"#
        ))
        .http(|h| h.redact_response_secrets = BOTH)
        .start()
        .await;
    let mut c = kit.h1().await;
    let a = c
        .call(
            "GET",
            "/x",
            &[("range", "bytes=1-"), ("if-range", "\"v1\"")],
            b"",
        )
        .await;
    assert_eq!(a.status, 200, "{a:?}");
    let seen = kit.upstream.wait_seen(1).await;
    assert!(
        !seen[0].headers.contains_key("range"),
        "{:?}",
        seen[0].headers
    );
    assert!(
        !seen[0].headers.contains_key("if-range"),
        "{:?}",
        seen[0].headers
    );
    for (n, body) in [
        (2, format!("[{SECRET}]").into_bytes()),
        (3, gzip(SECRET.as_bytes())),
    ] {
        let encoded = body.starts_with(&[0x1f, 0x8b]);
        let mut headers = vec![("x-echo-status", "206")];
        if encoded {
            headers.push(("x-echo-encoding", "gzip"));
        }
        let a = post(&mut kit.h1().await, "/echo", &headers, body).await;
        assert_eq!(a.status, 503, "encoded {encoded}: {a:?}");
        let ev = kit.events("request", n).await.remove(n - 1);
        assert_eq!(ev["terminal_rule"], "_fail_closed", "{ev:#}");
        assert_eq!(ev["reason"], "partial_response", "{ev:#}");
    }
}

/// Without masking, a range is the client's business.
#[tokio::test]
async fn a_range_passes_when_only_headers_are_masked() {
    let kit = kit(ResponseRedaction {
        bodies: false,
        ..BOTH
    })
    .await;
    let mut c = kit.h1().await;
    let a = c.call("GET", "/x", &[("range", "bytes=1-")], b"").await;
    assert_eq!(a.status, 200, "{a:?}");
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].headers["range"], "bytes=1-");
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
