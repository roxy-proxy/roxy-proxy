//! Body rules on encoded bodies: the rules see the decoded text, a body
//! that streams goes on encoded again in its own codings, and a body that
//! cannot be decoded fails closed.

use std::io::Write as _;

use bytes::Bytes;
use roxy_http::Body;
use roxy_http::coding::{self, Coding};

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
    Kit::builder().rules(RULES).start().await
}

fn gzip(b: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(b).unwrap();
    e.finish().unwrap()
}

fn gunzip(b: &[u8]) -> Vec<u8> {
    coding::decode(&[Coding::Gzip], b, 1 << 20, coding::unmetered()).expect("a gzip body")
}

async fn post(c: &mut Client, path: &str, headers: &[(&str, &str)], body: Vec<u8>) -> Answer {
    let req = c
        .request("POST", path, headers)
        .body(Body::from_bytes(Bytes::from(body)))
        .unwrap();
    Answer::read(c.send(req).await.expect("response")).await
}

async fn client(kit: &Kit, h2: bool) -> Client {
    if h2 {
        kit.tunnel("up.test", true).await
    } else {
        kit.h1().await
    }
}

/// The response's `content-encoding` comes from the request's
/// `x-echo-encoding`, which the request rules never see as an encoding.
async fn echo(kit: &Kit, h2: bool, encoding: &str, body: Vec<u8>) -> Answer {
    try_echo(kit, h2, encoding, body).await.expect("response")
}

/// [`echo`], for a response that may be reset before its head is read.
async fn try_echo(kit: &Kit, h2: bool, encoding: &str, body: Vec<u8>) -> Result<Answer, String> {
    let mut c = client(kit, h2).await;
    let req = c
        .request("POST", "/echo", &[("x-echo-encoding", encoding)])
        .body(Body::from_bytes(Bytes::from(body)))
        .unwrap();
    match c.send(req).await {
        Ok(res) => Ok(Answer::read(res).await),
        Err(e) => Err(e.to_string()),
    }
}

/// The response was stopped mid-body by `rule` (`reason` for a fail
/// closed): its head had gone, so the client sees the body cut, or over
/// h2 perhaps only the reset.
async fn assert_cut(kit: &Kit, a: Result<Answer, String>, rule: &str, reason: Option<&str>) {
    if let Ok(a) = a {
        assert_eq!(a.status, 200, "{a:?}");
        assert!(a.body.is_err(), "the body is cut: {a:?}");
    }
    let ev = kit.request_event().await;
    assert_eq!(ev["terminal_rule"], rule, "{ev:#}");
    assert_eq!(ev["stage"], "response_body", "{ev:#}");
    if let Some(reason) = reason {
        assert_eq!(ev["reason"], reason, "{ev:#}");
    }
}

#[tokio::test]
async fn a_rule_reads_a_gzip_request_body() {
    let kit = kit().await;
    for h2 in [false, true] {
        let a = post(
            &mut client(&kit, h2).await,
            "/x",
            &[("content-encoding", "gzip")],
            gzip(b"the SECRET"),
        )
        .await;
        assert_eq!(a.status, 403, "h2 {h2}: {a:?}");
        let ev = kit.request_event().await;
        assert_eq!(ev["terminal_rule"], "no-secret-out", "{ev:#}");
    }
    let seen = kit.upstream.seen();
    assert!(seen.iter().all(|s| s.complete != Some(true)), "{seen:#?}");
}

/// A streamed encoded body is decoded for the rules and encoded again, in
/// the same coding, for the upstream.
#[tokio::test]
async fn an_encoded_request_body_goes_on_in_its_coding() {
    let kit = kit().await;
    for h2 in [false, true] {
        let a = post(
            &mut client(&kit, h2).await,
            "/x",
            &[("content-encoding", "gzip")],
            gzip(b"nothing to see"),
        )
        .await;
        assert_eq!(a.status, 200, "h2 {h2}: {a:?}");
    }
    for seen in kit.upstream.wait_seen(2).await {
        assert_eq!(seen.headers["content-encoding"], "gzip");
        assert_eq!(gunzip(&seen.body), b"nothing to see");
    }
}

/// `body` in `codings`, as a client would send it.
async fn encode(codings: &[Coding], body: &[u8]) -> Vec<u8> {
    let body = coding::encode_body(
        Body::from_bytes(Bytes::copy_from_slice(body)),
        codings,
        coding::unmetered(),
    );
    http_body_util::BodyExt::collect(body)
        .await
        .expect("encoded")
        .to_bytes()
        .to_vec()
}

/// Every coding roxy decodes, alone and stacked, is read by the rules and
/// goes on in its own codings.
#[tokio::test]
async fn every_coding_is_read_and_goes_on_in_it() {
    let kit = kit().await;
    let cases: [&[Coding]; 5] = [
        &[Coding::Gzip],
        &[Coding::Deflate],
        &[Coding::Br],
        &[Coding::Zstd],
        &[Coding::Gzip, Coding::Br],
    ];
    for codings in cases {
        let header = coding::header_value(codings);
        let mut c = kit.h1().await;
        let a = post(
            &mut c,
            "/x",
            &[("content-encoding", &header)],
            encode(codings, b"the SECRET").await,
        )
        .await;
        assert_eq!(a.status, 403, "{header}: {a:?}");
        let mut c = kit.h1().await;
        let a = post(
            &mut c,
            "/x",
            &[("content-encoding", &header)],
            encode(codings, b"nothing to see").await,
        )
        .await;
        assert_eq!(a.status, 200, "{header}: {a:?}");
        let seen = kit.upstream.seen();
        let last = seen.last().unwrap();
        assert_eq!(last.headers["content-encoding"], header.as_str());
        assert_eq!(
            coding::decode(codings, &last.body, 1 << 20, coding::unmetered()).unwrap(),
            b"nothing to see",
            "{header}"
        );
    }
}

#[tokio::test]
async fn a_rule_reads_a_gzip_response_body() {
    let kit = kit().await;
    for h2 in [false, true] {
        let a = try_echo(&kit, h2, "gzip", gzip(b"the SECRET")).await;
        assert_cut(&kit, a, "no-secret-in", None).await;
    }
}

#[tokio::test]
async fn an_encoded_response_goes_on_in_its_coding() {
    let kit = kit().await;
    let a = echo(&kit, false, "gzip", gzip(b"nothing to see")).await;
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.headers["content-encoding"], "gzip");
    assert_eq!(gunzip(a.body.as_deref().unwrap()), b"nothing to see");
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
    let a = try_echo(&kit, false, "gzip", enc.clone()).await;
    assert_cut(&kit, a, "_fail_closed", Some("body_decode_failed")).await;

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
    // A response is refused before its head goes.
    let a = echo(&kit, false, "compress", b"x".to_vec()).await;
    assert_fails_closed(&kit, &a, "unsupported_content_encoding").await;
}

#[tokio::test]
async fn identity_and_no_coding_read_as_before() {
    // The echoed request carries the text plain, so only the response rule
    // may see it.
    let inbound = Kit::builder()
        .rules(
            r#"
- id: no-secret-in
  when: host == "up.test" and response.body.text contains "SECRET"
  then: deny
- id: up
  when: host == "up.test"
  then: allow
"#,
        )
        .start()
        .await;
    let a = try_echo(&inbound, false, "identity", b"the SECRET".to_vec()).await;
    assert_cut(&inbound, a, "no-secret-in", None).await;
    let kit = kit().await;
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
        .http(|h| h.strip_accept_encoding = true)
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
        .http(|h| h.decode_for_addons = decode)
        .start()
        .await
}

#[tokio::test]
async fn a_layer_sees_the_request_body_decoded() {
    let kit = with_layer(true).await;
    // The layer upper-cases what it reads, so the upstream gets "HELLO"
    // only if the layer was given the decoded text. It gets it in the
    // client's coding.
    let headers = [("content-encoding", "gzip"), ("x-upper", "1")];
    let a = post(&mut kit.h1().await, "/x", &headers, gzip(b"hello")).await;
    assert_eq!(a.status, 200, "{a:?}");
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].headers["content-encoding"], "gzip");
    assert_eq!(gunzip(&seen[0].body), b"HELLO");
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
        // Upper-cased by the layer after decoding, and encoded again in
        // the upstream's coding.
        assert_eq!(a.headers["content-encoding"], "gzip", "{a:?}");
        assert_eq!(gunzip(a.body.as_deref().unwrap()), b"HELLO");
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
// WebSocket extensions with layers in the byte path
// ---------------------------------------------------------------------------

const WS_RULES: &str = r#"
- id: ws
  when: host == "up.test"
  then: { allow: { upgrade: websocket } }
"#;

async fn with_ws_layer(decode: bool) -> Kit {
    Kit::builder()
        .rules(WS_RULES)
        .addon(AddonDef::test_layer("t"))
        .http(|h| h.decode_for_addons = decode)
        .start()
        .await
}

const DEFLATE: (&str, &str) = ("sec-websocket-extensions", "permessage-deflate");

#[tokio::test]
async fn a_layer_gets_websockets_without_extensions() {
    let kit = with_ws_layer(true).await;
    let (status, _io) = kit.websocket("/ws", &[DEFLATE]).await;
    assert_eq!(status, 101);
    let seen = kit.upstream.wait_seen(1).await;
    assert!(!seen[0].headers.contains_key("sec-websocket-extensions"));
}

#[tokio::test]
async fn a_layer_refuses_an_extension_the_upstream_forces() {
    let kit = with_ws_layer(true).await;
    let (status, _) = kit
        .websocket("/ws", &[DEFLATE, ("x-accept-extension", "1")])
        .await;
    assert_eq!(status, 502);
}

#[tokio::test]
async fn decode_for_addons_off_lets_layers_negotiate_extensions() {
    let kit = with_ws_layer(false).await;
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
async fn without_a_layer_extensions_pass_through() {
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
    assert_eq!(gunzip(&seen[0].body), b"HELLO");
    assert_eq!(seen[0].headers["content-encoding"], "gzip");

    let headers = [("x-echo-encoding", "gzip"), ("x-upper", "1")];
    let a = post(&mut kit.h1().await, "/echo", &headers, gzip(b"hello")).await;
    assert_eq!(a.headers["content-encoding"], "gzip", "{a:?}");
    assert_eq!(gunzip(a.body.as_deref().unwrap()), b"HELLO");
}

/// A layer its `when` skips is not in the WebSocket, so the WebSocket
/// keeps its extensions.
#[tokio::test]
async fn a_skipped_layer_leaves_extensions_alone() {
    let kit = Kit::builder()
        .rules(WS_RULES)
        .addon(AddonDef::test_layer("t").when(r#"path != "/ws""#))
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

/// A body decoded for the layers charges its decoder's window to the
/// budget from the first byte until the body is done, so a client's
/// decoders are bounded like every other buffer; a window the budget
/// cannot cover fails the exchange closed rather than being allocated.
#[tokio::test]
async fn a_decoder_window_is_charged_while_a_layer_reads_the_body() {
    use std::time::Duration;

    const FLATE_WINDOW: u64 = 32 * 1024;
    // No rule reads the body, so the window is all the budget sees.
    const ALLOW: &str = r#"
- id: up
  when: host == "up.test"
  then: allow
"#;
    let text = vec![b'a'; 100 * 1024];
    let gz = gzip(&text);
    let kit = Kit::builder()
        .rules(ALLOW)
        .addon(AddonDef::test_layer("t"))
        .start()
        .await;
    let (mut tx, body) = roxy_http::Body::channel(u64::MAX, None);
    let mut c = kit.h1().await;
    let req = c
        .request(
            "POST",
            "/x",
            &[("content-encoding", "gzip"), ("x-test-t", "pass")],
        )
        .body(body)
        .unwrap();
    let answer = c.start(req);
    tx.send_data(Bytes::copy_from_slice(&gz[..16]))
        .await
        .unwrap();
    // The request is encoded again on its way to the core, and that
    // encoder is charged too.
    let charged = tokio::time::timeout(Duration::from_secs(10), async {
        while kit.server.shared().buffered() < FLATE_WINDOW {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(
        charged.is_ok(),
        "buffered {}",
        kit.server.shared().buffered()
    );
    tx.send_data(Bytes::copy_from_slice(&gz[16..]))
        .await
        .unwrap();
    tx.finish().await.unwrap();
    let a = answer.await.unwrap().unwrap();
    assert_eq!(a.status, 200, "{a:?}");
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(gunzip(&seen[0].body), text);
    let freed = tokio::time::timeout(Duration::from_secs(10), async {
        while kit.server.shared().buffered() != 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(freed.is_ok(), "buffered {}", kit.server.shared().buffered());

    let kit = Kit::builder()
        .rules(ALLOW)
        .addon(AddonDef::test_layer("t"))
        .limits(|l| l.max_buffered_bytes = FLATE_WINDOW - 1)
        .start()
        .await;
    let a = post(
        &mut kit.h1().await,
        "/x",
        &[("content-encoding", "gzip"), ("x-test-t", "pass")],
        gz,
    )
    .await;
    assert!(a.status >= 500, "{a:?}");
    assert_eq!(kit.server.shared().buffered(), 0);
    assert!(kit.upstream.seen().is_empty(), "{:#?}", kit.upstream.seen());
}
