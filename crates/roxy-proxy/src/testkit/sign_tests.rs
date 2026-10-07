//! The `sign: aws_sigv4` effect as an exchange sees it: the client's
//! credentials replaced, the body hashed or streamed, presigned requests
//! left alone, and the refusals when it cannot sign.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::time::SystemTime;

use aws_sigv4::http_request::SignableBody;
use bytes::Bytes;
use roxy_http::url::{parse_authority, parse_origin_form};
use roxy_http::{
    Body, CanonicalRequest, Headers, HttpFlags, Limits, Method, RequestMeta, Scheme, TargetForm,
    Version,
};
use roxy_rules::{AwsSigV4, Credential};

use super::upstream::Seen;
use super::{Answer, Kit, streaming_body};

const AKID: &str = "AKIDEXAMPLE";
const SK: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
const TOKEN: &str = "session-token-value-0123456789";

fn rules(service: &str, extra: &str) -> String {
    format!(
        r#"
- id: aws
  when: host == "up.test"
  then:
    - sign:
        aws_sigv4:
          service: {service}
          region: eu-west-2
          access_key_id: "${{secret:akid}}"
          secret_access_key: "${{secret:sk}}"
          session_token: "${{secret:token}}"
          {extra}
    - allow
"#
    )
}

fn signing(service: &str, extra: &str) -> super::KitBuilder {
    Kit::builder()
        .secret("akid", AKID)
        .secret("sk", SK)
        .secret("token", TOKEN)
        .rules(&rules(service, extra))
}

/// `SignedHeaders=...` of an `Authorization` value.
fn signed_headers(authorization: &str) -> &str {
    authorization
        .split("SignedHeaders=")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .unwrap_or_else(|| panic!("{authorization}"))
}

#[tokio::test]
async fn sign_replaces_the_client_credentials_and_leaves_framing_fields_unsigned() {
    let kit = signing("bedrock", "").capture_all().start().await;
    let a = kit
        .h1()
        .await
        .call(
            "POST",
            "/model/invoke",
            &[
                (
                    "authorization",
                    "AWS4-HMAC-SHA256 Credential=CLIENT/x, Signature=0",
                ),
                ("x-amz-date", "19990101T000000Z"),
                ("x-amz-security-token", "client-placeholder"),
                ("x-amz-content-sha256", "deadbeef"),
                ("accept-encoding", "gzip"),
                ("content-type", "application/json"),
                ("x-custom", "1"),
            ],
            br#"{"prompt":"hi"}"#,
        )
        .await;
    assert_eq!(a.status, 200, "{a:?}");
    let seen = kit.upstream.wait_seen(1).await;
    let auth = seen[0].headers["authorization"].to_str().unwrap();
    assert!(
        auth.starts_with(&format!("AWS4-HMAC-SHA256 Credential={AKID}/"))
            && auth.contains("/eu-west-2/bedrock/aws4_request, "),
        "{auth}"
    );
    assert_eq!(
        signed_headers(auth),
        "content-type;host;x-amz-date;x-amz-security-token;x-custom"
    );
    assert_ne!(seen[0].headers["x-amz-date"], "19990101T000000Z");
    assert_eq!(seen[0].headers["x-amz-security-token"], TOKEN);
    assert!(!seen[0].headers.contains_key("x-amz-content-sha256"));
    assert_eq!(seen[0].headers["accept-encoding"], "gzip");
    assert_eq!(seen[0].body, br#"{"prompt":"hi"}"#);
    let ev = kit.request_event().await;
    assert_eq!(ev["decision"], "allow", "{ev:#}");
    let muts = ev["mutations"].as_array().unwrap();
    assert!(muts.contains(&"sign:aws_sigv4".into()), "{ev:#}");
    // The capture head records the signed request's headers: the key id
    // and the session token in them are redacted.
    let flow = ev["flow"].as_str().unwrap();
    let records = kit.captured();
    let (_, head) = records
        .iter()
        .find(|(h, _)| h["flow"] == flow && h["dir"] == "request" && h["kind"] == "head")
        .unwrap();
    let head: serde_json::Value = serde_json::from_slice(head).unwrap();
    let headers: HashMap<&str, &str> = head["headers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| (p[0].as_str().unwrap(), p[1].as_str().unwrap()))
        .collect();
    assert!(
        headers["authorization"].starts_with("AWS4-HMAC-SHA256 Credential=[REDACTED]/"),
        "{head:#}"
    );
    assert_eq!(headers["x-amz-security-token"], "[REDACTED]", "{head:#}");
}

/// A header value with obs-text cannot go into the canonical request. The
/// request is refused rather than forwarded with that header unsigned.
#[tokio::test]
async fn an_obs_text_header_is_refused_not_left_unsigned() {
    let kit = signing("bedrock", "")
        .flags(|f| f.allow_obs_text = true)
        .start()
        .await;
    let mut c = kit.h1().await;
    let req = c
        .request("POST", "/model/invoke", &[])
        .header("x-note", http::HeaderValue::from_bytes(b"caf\xe9").unwrap())
        .body(roxy_http::Body::from_bytes(Bytes::from_static(b"{}")))
        .unwrap();
    let a = Answer::read(c.send(req).await.unwrap()).await;
    assert_eq!(a.status, 400, "{a:?}");
    assert_eq!(a.headers["x-roxy-rule"], "_sign");
    let ev = kit.request_event().await;
    assert_eq!(ev["decision"], "deny", "{ev:#}");
    assert_eq!(ev["reason"], "sign_header_invalid", "{ev:#}");
    assert_eq!(ev["terminal_rule"], "_sign", "{ev:#}");
    assert!(kit.upstream.seen().is_empty());
}

/// S3 gets the payload hash as `x-amz-content-sha256`; with
/// `unsigned_payload` the body is not buffered, so one over the signing
/// cap streams through under `UNSIGNED-PAYLOAD`.
#[tokio::test]
async fn s3_signs_the_payload_hash_or_streams_an_unsigned_payload() {
    let kit = signing("s3", "").start().await;
    let body = b"Welcome to Amazon S3.";
    let a = kit.h1().await.call("PUT", "/bucket/key", &[], body).await;
    assert_eq!(a.status, 200, "{a:?}");
    let seen = kit.upstream.wait_seen(1).await;
    let digest = ring::digest::digest(&ring::digest::SHA256, body);
    let hex = digest.as_ref().iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    });
    assert_eq!(seen[0].headers["x-amz-content-sha256"], hex);
    let auth = seen[0].headers["authorization"].to_str().unwrap();
    assert!(auth.contains("/eu-west-2/s3/aws4_request, "), "{auth}");
    assert_eq!(
        signed_headers(auth),
        "host;x-amz-content-sha256;x-amz-date;x-amz-security-token"
    );

    let kit = signing("s3", "unsigned_payload: true")
        .limits(|l| l.max_sign_body_bytes = 1024)
        .start()
        .await;
    let mut c = kit.h1().await;
    let req = c
        .request("PUT", "/bucket/big", &[])
        .body(roxy_http::Body::from_bytes(Bytes::from(vec![b'a'; 4096])))
        .unwrap();
    let a = Answer::read(c.send(req).await.unwrap()).await;
    assert_eq!(a.status, 200, "{a:?}");
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].headers["x-amz-content-sha256"], "UNSIGNED-PAYLOAD");
    assert_eq!(seen[0].body.len(), 4096);
}

/// A presigned request goes out under its query signature alone: roxy
/// adds no signature, strips the client's signature headers, and records
/// the passthrough so the log shows the request left without roxy's
/// identity.
#[tokio::test]
async fn a_presigned_request_passes_with_its_query_signature_only() {
    let kit = signing("s3", "").start().await;
    let a = kit
        .h1()
        .await
        .call(
            "GET",
            "/bucket/key?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=abc123",
            &[
                ("authorization", "AWS4-HMAC-SHA256 Credential=CLIENT/x"),
                ("x-amz-date", "19990101T000000Z"),
                ("x-amz-security-token", "client-token"),
                ("x-amz-content-sha256", "deadbeef"),
                ("x-custom", "kept"),
            ],
            b"",
        )
        .await;
    assert_eq!(a.status, 200, "{a:?}");
    let seen = kit.upstream.wait_seen(1).await;
    for h in [
        "authorization",
        "x-amz-date",
        "x-amz-security-token",
        "x-amz-content-sha256",
    ] {
        assert!(
            !seen[0].headers.contains_key(h),
            "{h}: {:?}",
            seen[0].headers
        );
    }
    assert_eq!(seen[0].headers["x-custom"], "kept");
    assert!(
        seen[0].path.contains("X-Amz-Signature=abc123"),
        "{}",
        seen[0].path
    );
    let ev = kit.request_event().await;
    assert_eq!(
        ev["mutations"],
        serde_json::json!(["sign:presigned"]),
        "{ev:#}"
    );
}

/// A body the hash needs but the cap does not allow is refused with 413,
/// whether its length is declared or it is chunked and grows past the cap.
#[tokio::test]
async fn a_body_over_max_sign_body_bytes_is_refused_with_413() {
    let kit = signing("bedrock", "")
        .limits(|l| l.max_sign_body_bytes = 1024)
        .start()
        .await;
    let mut c = kit.h1().await;
    let req = c
        .request("POST", "/declared", &[])
        .body(roxy_http::Body::from_bytes(Bytes::from(vec![b'a'; 4096])))
        .unwrap();
    let a = Answer::read(c.send(req).await.unwrap()).await;
    assert_eq!(a.status, 413, "{a:?}");
    assert_eq!(a.headers["x-roxy-rule"], "_sign");

    let mut c = kit.h1().await;
    let (mut tx, body) = streaming_body();
    let req = c.request("POST", "/chunked", &[]).body(body).unwrap();
    let pending = c.start(req);
    for _ in 0..4 {
        tx.ready().await.unwrap();
        tx.try_push(Bytes::from(vec![b'b'; 512])).unwrap();
    }
    let a = pending.await.unwrap().unwrap();
    assert_eq!(a.status, 413, "{a:?}");
    assert_eq!(a.headers["x-roxy-rule"], "_sign");

    let ev = kit.events("request", 2).await;
    for e in &ev {
        assert_eq!(e["decision"], "deny", "{e:#}");
        assert_eq!(e["reason"], "sign_body_too_large", "{e:#}");
        assert_eq!(e["terminal_rule"], "_sign", "{e:#}");
    }
    assert!(kit.upstream.seen().is_empty());
}

/// Waits until the buffer budget holds exactly `bytes`.
async fn wait_buffered(kit: &Kit, bytes: u64) {
    let shared = kit.server.shared();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while shared.buffered() != bytes {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("budget holds {} bytes, not {bytes}", shared.buffered()));
}

/// A chunked body being hashed holds only the bytes read so far, not the
/// signing cap; one the budget cannot cover part-way fails closed.
#[tokio::test]
async fn a_chunked_signed_body_reserves_only_what_it_has_read() {
    let kit = signing("bedrock", "")
        .limits(|l| l.max_sign_body_bytes = 1 << 20)
        .start()
        .await;
    let mut c = kit.h1().await;
    let (mut tx, body) = streaming_body();
    let req = c.request("POST", "/chunked", &[]).body(body).unwrap();
    let pending = c.start(req);
    tx.ready().await.unwrap();
    tx.try_push(Bytes::from(vec![b'a'; 512])).unwrap();
    wait_buffered(&kit, 512).await;
    tx.ready().await.unwrap();
    tx.try_push(Bytes::from(vec![b'b'; 256])).unwrap();
    wait_buffered(&kit, 768).await;
    tx.finish().await.unwrap();
    let a = pending.await.unwrap().unwrap();
    assert_eq!(a.status, 200, "{a:?}");
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].body.len(), 768);
    assert!(seen[0].headers.contains_key("authorization"));

    let kit = signing("bedrock", "")
        .limits(|l| {
            l.max_sign_body_bytes = 1 << 20;
            l.max_buffered_bytes = 1024;
        })
        .start()
        .await;
    let mut c = kit.h1().await;
    let (mut tx, body) = streaming_body();
    let req = c.request("POST", "/chunked", &[]).body(body).unwrap();
    let pending = c.start(req);
    for _ in 0..4 {
        tx.ready().await.unwrap();
        tx.try_push(Bytes::from(vec![b'c'; 512])).unwrap();
    }
    let a = pending.await.unwrap().unwrap();
    assert_eq!(a.status, 503, "{a:?}");
    assert_eq!(a.headers["x-roxy-rule"], "_fail_closed");
    let ev = kit.request_event().await;
    assert_eq!(ev["reason"], "buffer_budget_exhausted", "{ev:#}");
    assert!(kit.upstream.seen().is_empty());
}

/// The `authorization` an upstream would compute for `seen`, taking its
/// authority from `host`, at the `x-amz-date` roxy signed at.
fn resign(seen: &Seen, host: &str, spec: &AwsSigV4) -> String {
    let unsigned = [
        "authorization",
        "x-amz-date",
        "x-amz-security-token",
        "content-length",
    ];
    let raw: Vec<(&[u8], &[u8])> = seen
        .headers
        .iter()
        .filter(|(n, _)| !unsigned.contains(&n.as_str()))
        .map(|(n, v)| (n.as_str().as_bytes(), v.as_bytes()))
        .collect();
    let (path, query) = parse_origin_form(seen.path.as_bytes()).unwrap();
    let mut req = CanonicalRequest {
        method: Method::parse(seen.method.as_bytes()).unwrap(),
        scheme: Scheme::Https,
        authority: parse_authority(host.as_bytes(), 443).unwrap(),
        path,
        query,
        headers: Headers::try_from_raw(raw, &Limits::default(), &HttpFlags::default()).unwrap(),
        body: Body::from_bytes(seen.body.clone()),
        meta: RequestMeta::new(Version::H1_1, TargetForm::Origin),
    };
    let date = seen.headers["x-amz-date"].to_str().unwrap();
    let now: SystemTime = chrono::NaiveDateTime::parse_from_str(date, "%Y%m%dT%H%M%SZ")
        .unwrap()
        .and_utc()
        .into();
    crate::sign::sign_request(&mut req, host, SignableBody::Bytes(&seen.body), spec, now).unwrap();
    req.headers.get("authorization").unwrap().to_owned()
}

/// Over h2 AWS takes `host` from `:authority`, so the signature must cover
/// the authority roxy sends there: recomputing it from what the upstream
/// received, with `:authority` as `host`, gives the same `authorization`.
#[tokio::test]
async fn an_h2_signature_covers_the_authority() {
    let kit = signing("bedrock", "").start().await;
    let mut c = kit.tunnel("up.test", false).await;
    let a = c
        .call(
            "POST",
            "/model/invoke",
            &[("content-type", "application/json"), ("x-custom", "1")],
            br#"{"prompt":"hi"}"#,
        )
        .await;
    assert_eq!(a.status, 200, "{a:?}");
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].version, http::Version::HTTP_2);
    assert!(
        !seen[0].headers.contains_key("host"),
        "{:?}",
        seen[0].headers
    );
    let authority = seen[0].authority.as_deref().unwrap();
    assert_eq!(authority, "up.test");
    let auth = seen[0].headers["authorization"].to_str().unwrap();
    assert_eq!(
        signed_headers(auth),
        "content-type;host;x-amz-date;x-amz-security-token;x-custom"
    );
    let spec = AwsSigV4 {
        service: "bedrock".into(),
        region: "eu-west-2".into(),
        access_key_id: Credential::new(AKID),
        secret_access_key: Credential::new(SK),
        session_token: Some(Credential::new(TOKEN)),
        unsigned_payload: false,
    };
    assert_eq!(resign(&seen[0], authority, &spec), auth);
    assert_ne!(resign(&seen[0], "other.test", &spec), auth);
}

#[tokio::test]
async fn a_missing_credential_secret_fails_closed() {
    let kit = signing("bedrock", "").start().await;
    kit.server.handle().swap_secrets(HashMap::new());
    let a = kit
        .h1()
        .await
        .call("POST", "/model/invoke", &[], b"{}")
        .await;
    assert_eq!(a.status, 503, "{a:?}");
    assert_eq!(a.headers["x-roxy-rule"], "_fail_closed");
    let ev = kit.request_event().await;
    assert_eq!(ev["reason"], "secret_missing", "{ev:#}");
    assert!(kit.upstream.seen().is_empty());
}
