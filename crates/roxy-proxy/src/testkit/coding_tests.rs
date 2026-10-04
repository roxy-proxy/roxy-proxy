//! Body rules on encoded bodies: the rules see
//! the decoded text, the bytes forwarded are the bytes received, and a body
//! that cannot be decoded fails closed.

use std::io::Write as _;

use bytes::Bytes;
use roxy_http::Body;

use super::{AddonDef, Answer, Client, Kit};

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

#[tokio::test]
async fn strip_accept_encoding_removes_it_before_the_rules() {
    const RULES: &str = r#"
- id: wants-compression
  when: header["accept-encoding"] != null
  then: deny
- id: up
  when: host == "up.test"
  then: allow
"#;
    let strip = Kit::builder()
        .rules(RULES)
        .flags(|f| f.strip_accept_encoding = true)
        .start()
        .await;
    for h2 in [false, true] {
        let mut c = if h2 {
            strip.tunnel("up.test", true).await
        } else {
            strip.h1().await
        };
        let a = post(&mut c, "/x", &[("accept-encoding", "gzip, br")], Vec::new()).await;
        assert_eq!(a.status, 200, "h2 {h2}: {a:?}");
    }
    let seen = strip.upstream.wait_seen(2).await;
    assert!(
        seen.iter()
            .all(|s| !s.headers.contains_key("accept-encoding"))
    );

    // Off by default.
    let keep = Kit::builder().rules(RULES).start().await;
    let a = post(
        &mut keep.h1().await,
        "/x",
        &[("accept-encoding", "gzip")],
        Vec::new(),
    )
    .await;
    assert_eq!(a.status, 403, "{a:?}");
}

// ---------------------------------------------------------------------------
// Addons
// ---------------------------------------------------------------------------

/// No body rules, so what reaches the client is the layer's doing.
async fn with_layer(decode: bool) -> Kit {
    Kit::builder()
        .addon(AddonDef::test_layer("a"))
        .flags(|f| f.decode_for_addons = decode)
        .start()
        .await
}

#[tokio::test]
async fn a_layer_sees_the_request_body_decoded() {
    let kit = with_layer(true).await;
    // The layer upper-cases what it reads, so the upstream gets "HELLO"
    // only if the layer was given the decoded text.
    let headers = [("content-encoding", "gzip"), ("x-upper", "1")];
    let a = post(&mut kit.h1().await, "/x", &headers, gzip(b"hello")).await;
    assert_eq!(a.status, 200, "{a:?}");
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].body, b"HELLO");
    assert!(!seen[0].headers.contains_key("content-encoding"));
}

#[tokio::test]
async fn a_layer_sees_the_response_body_decoded() {
    let kit = with_layer(true).await;
    for h2 in [false, true] {
        let mut c = if h2 {
            kit.tunnel("up.test", true).await
        } else {
            kit.h1().await
        };
        let headers = [("x-echo-encoding", "gzip"), ("x-upper", "1")];
        // An identity request body, which the upstream echoes as gzip.
        let a = post(&mut c, "/echo", &headers, gzip(b"hello")).await;
        assert_eq!(a.status, 200, "h2 {h2}: {a:?}");
        assert!(!a.headers.contains_key("content-encoding"), "{a:?}");
        // Upper-cased by the layer after decoding.
        assert_eq!(a.text(), "HELLO");
    }
}

#[tokio::test]
async fn decode_for_addons_off_leaves_bodies_encoded() {
    let kit = with_layer(false).await;
    let enc = gzip(b"hello");
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

    let a = echo(&kit, false, "gzip", enc.clone()).await;
    assert_eq!(a.headers["content-encoding"], "gzip");
    assert_eq!(a.body.as_deref().unwrap(), enc.as_slice());
}

#[tokio::test]
async fn a_layer_gets_unknown_codings_and_ranges_as_they_are() {
    let kit = with_layer(true).await;
    let a = echo(&kit, false, "compress", b"opaque".to_vec()).await;
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.headers["content-encoding"], "compress");
    assert_eq!(a.text(), "opaque");

    // Part of a gzip body is not decodable on its own.
    let part = gzip(b"hello")[..5].to_vec();
    let headers = [("x-echo-encoding", "gzip"), ("x-echo-status", "206")];
    let a = post(&mut kit.h1().await, "/echo", &headers, part.clone()).await;
    assert_eq!(a.status, 206, "{a:?}");
    assert_eq!(a.headers["content-encoding"], "gzip");
    assert_eq!(a.body.as_deref().unwrap(), part.as_slice());
}

#[tokio::test]
async fn a_corrupt_body_is_cut_on_its_way_to_a_layer() {
    let kit = with_layer(true).await;
    let mut enc = gzip(b"hello");
    let n = enc.len();
    enc[n - 8] ^= 1;
    let a = echo(&kit, false, "gzip", enc).await;
    assert!(a.body.is_err(), "{a:?}");
}

// ---------------------------------------------------------------------------
// WebSocket extensions with `tunnel` layers
// ---------------------------------------------------------------------------

const WS_RULES: &str = r#"
- id: ws
  when: host == "up.test"
  then: { allow: { upgrade: websocket } }
"#;

async fn with_tunnel(decode: bool) -> Kit {
    Kit::builder()
        .rules(WS_RULES)
        .addon(AddonDef::tunnel_layer("t", false))
        .flags(|f| f.decode_for_addons = decode)
        .start()
        .await
}

const DEFLATE: (&str, &str) = ("sec-websocket-extensions", "permessage-deflate");

#[tokio::test]
async fn a_tunnel_layer_gets_websockets_without_extensions() {
    let kit = with_tunnel(true).await;
    let (status, _io) = kit.websocket("/ws", &[DEFLATE]).await;
    assert_eq!(status, 101);
    let seen = kit.upstream.wait_seen(1).await;
    assert!(!seen[0].headers.contains_key("sec-websocket-extensions"));
}

#[tokio::test]
async fn a_tunnel_layer_refuses_an_extension_the_upstream_forces() {
    let kit = with_tunnel(true).await;
    let (status, _) = kit
        .websocket("/ws", &[DEFLATE, ("x-accept-extension", "1")])
        .await;
    assert_eq!(status, 502);
}

#[tokio::test]
async fn decode_for_addons_off_lets_tunnel_layers_negotiate_extensions() {
    let kit = with_tunnel(false).await;
    let (status, _io) = kit
        .websocket("/ws", &[DEFLATE, ("x-accept-extension", "1")])
        .await;
    assert_eq!(status, 101);
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(
        seen[0].headers["sec-websocket-extensions"],
        "permessage-deflate"
    );
}

#[tokio::test]
async fn without_a_tunnel_layer_extensions_pass_through() {
    let kit = Kit::builder().rules(WS_RULES).start().await;
    let (status, _io) = kit.websocket("/ws", &[DEFLATE]).await;
    assert_eq!(status, 101);
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(
        seen[0].headers["sec-websocket-extensions"],
        "permessage-deflate"
    );
}

/// A flow no layer runs on is not decoded: the upstream gets the request
/// body as sent, and the client the response as the origin sent it.
#[tokio::test]
async fn a_flow_no_layer_runs_on_keeps_its_codings() {
    let kit = Kit::builder()
        .addon(AddonDef::test_layer("a").when(r#"path == "/layered""#))
        .start()
        .await;
    let enc = gzip(b"hello");
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

    let a = echo(&kit, false, "gzip", enc.clone()).await;
    assert_eq!(a.headers["content-encoding"], "gzip", "{a:?}");
    assert_eq!(a.body.as_deref().unwrap(), enc.as_slice());
}

/// Skipped layers above the first that runs change nothing: it still gets
/// both bodies decoded.
#[tokio::test]
async fn the_first_layer_that_runs_gets_bodies_decoded() {
    let kit = Kit::builder()
        .addon(AddonDef::test_layer("skipped").when("false"))
        .addon(AddonDef::test_layer("a"))
        .start()
        .await;
    let headers = [("content-encoding", "gzip"), ("x-upper", "1")];
    let a = post(&mut kit.h1().await, "/x", &headers, gzip(b"hello")).await;
    assert_eq!(a.status, 200, "{a:?}");
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].body, b"HELLO");
    assert!(!seen[0].headers.contains_key("content-encoding"));

    let headers = [("x-echo-encoding", "gzip"), ("x-upper", "1")];
    let a = post(&mut kit.h1().await, "/echo", &headers, gzip(b"hello")).await;
    assert!(!a.headers.contains_key("content-encoding"), "{a:?}");
    assert_eq!(a.text(), "HELLO");
}

/// A `tunnel` layer its `when` skips is not in the WebSocket, so the
/// WebSocket keeps its extensions.
#[tokio::test]
async fn a_skipped_tunnel_layer_leaves_extensions_alone() {
    let kit = Kit::builder()
        .rules(WS_RULES)
        .addon(AddonDef::tunnel_layer("t", false).when(r#"path != "/ws""#))
        .start()
        .await;
    let (status, _io) = kit
        .websocket("/ws", &[DEFLATE, ("x-accept-extension", "1")])
        .await;
    assert_eq!(status, 101);
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(
        seen[0].headers["sec-websocket-extensions"],
        "permessage-deflate"
    );
}
