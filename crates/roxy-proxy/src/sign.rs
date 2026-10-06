//! `sign: aws_sigv4`: AWS Signature Version 4 over the request as roxy
//! forwards it, with credentials the client never held.
//!
//! The signature covers the request after every other head effect, so it
//! is applied last, by the pipeline, once the body (or its absence) is
//! known. The payload hash needs the whole body, which the pipeline
//! buffers under `limits.max_sign_body_bytes`; `unsigned_payload` signs
//! `UNSIGNED-PAYLOAD` instead and streams it.

use std::borrow::Cow;
use std::time::SystemTime;

use aws_credential_types::Credentials;
use aws_sigv4::http_request::{
    PayloadChecksumKind, PercentEncodingMode, SignableBody, SignableRequest, SigningParams,
    SigningSettings, UriPathNormalizationMode, sign,
};
use aws_sigv4::sign::v4;
use aws_smithy_runtime_api::client::identity::Identity;
use roxy_http::{CanonicalRequest, Query};
use roxy_rules::AwsSigV4;

/// Fields a client may have signed with: removed before signing, so the
/// client's own attempt never reaches AWS beside roxy's.
const CLIENT_SIGNATURE_HEADERS: &[&str] = &[
    "authorization",
    "x-amz-date",
    "x-amz-security-token",
    "x-amz-content-sha256",
];

/// Fields roxy re-serialises, or an intermediary may change, so a
/// signature over them would not survive the trip. The signer's own
/// defaults (`authorization`, `user-agent`, `x-amzn-trace-id`,
/// `transfer-encoding`) come on top.
const UNSIGNED_HEADERS: &[&str] = &[
    "connection",
    "transfer-encoding",
    "content-length",
    "accept-encoding",
    "te",
    "trailer",
    "upgrade",
    "keep-alive",
    "proxy-connection",
];

/// Why a request could not be signed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SignError {
    #[error("{0}")]
    Sign(#[from] aws_sigv4::http_request::SigningError),
    #[error("signing parameters: {0}")]
    Params(String),
    #[error("signed header: {0}")]
    Header(#[from] roxy_http::ParseError),
}

/// Whether the query carries a presigned URL's signature, in which case
/// the request already authenticates itself and is forwarded untouched.
pub(crate) fn is_presigned(query: Option<&Query>) -> bool {
    query.is_some_and(|q| {
        q.pairs()
            .any(|(k, _)| k.eq_ignore_ascii_case("X-Amz-Signature"))
    })
}

/// Signs `req` in place. `host` is the `Host` field as forwarded, which is
/// always signed; `body` is the payload hash input. The client's own
/// signature fields are removed first, then `authorization`, `x-amz-date`
/// and (with a session token) `x-amz-security-token` are set; S3 also gets
/// `x-amz-content-sha256`.
pub(crate) fn sign_request(
    req: &mut CanonicalRequest,
    host: &str,
    body: SignableBody<'_>,
    spec: &AwsSigV4,
    now: SystemTime,
) -> Result<(), SignError> {
    for name in CLIENT_SIGNATURE_HEADERS {
        req.headers.remove(name);
    }
    let identity = Identity::new(
        Credentials::new(
            spec.access_key_id.as_str(),
            spec.secret_access_key.as_str(),
            spec.session_token.as_ref().map(|t| t.as_str().to_owned()),
            None,
            "roxy",
        ),
        None,
    );
    let mut settings = SigningSettings::default();
    settings
        .excluded_headers
        .get_or_insert_default()
        .extend(UNSIGNED_HEADERS.iter().map(|h| Cow::Borrowed(*h)));
    if spec.is_s3() {
        // S3 verifies against the path as sent, encoded once, and wants the
        // payload hash as a header as well as in the canonical request.
        settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
        settings.percent_encoding_mode = PercentEncodingMode::Single;
        settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
    }
    let params = v4::SigningParams::builder()
        .identity(&identity)
        .region(&spec.region)
        .name(&spec.service)
        .time(now)
        .settings(settings)
        .build()
        .map_err(|e| SignError::Params(e.to_string()))?;
    let params = SigningParams::V4(params);
    let query = req
        .query
        .as_ref()
        .map_or_else(String::new, |q| format!("?{q}"));
    let uri = format!(
        "{}://{host}{}{query}",
        req.scheme,
        aws_encoded_path(req.path.as_str())
    );
    let headers = std::iter::once(("host", host)).chain(
        req.headers
            .iter()
            .filter_map(|(n, v)| Some((n.as_str(), v.to_str().ok()?))),
    );
    let signable = SignableRequest::new(req.method.as_str(), uri, headers, body)?;
    let (instructions, _) = sign(signable, &params)?.into_parts();
    let (headers, _) = instructions.into_parts();
    for h in headers {
        req.headers.insert(h.name(), h.value())?;
    }
    Ok(())
}

/// The path in the once-encoded form AWS canonicalises from: every byte
/// percent-encoded except the unreserved set and `/`. roxy's normaliser
/// leaves sub-delimiters such as `$` literal, which AWS would encode, so
/// the two must agree before the signer encodes a second time (non-S3) or
/// takes the path as is (S3). Existing escapes are kept, including `%2F`.
fn aws_encoded_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let bytes = path.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' && bytes.len() >= i + 3 {
            out.push_str(&path[i..i + 3]);
            i += 3;
            continue;
        }
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'/') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use roxy_http::url::{parse_authority, parse_origin_form};
    use roxy_http::{
        Body, Headers, HttpFlags, Limits, Method, RequestMeta, Scheme, TargetForm, Version,
    };
    use roxy_rules::Credential;

    use super::*;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sigv4");

    /// `request.txt` of the suite: a request line, `Name:value` fields, a
    /// blank line and the body.
    fn parse_request(text: &str) -> (String, String, Vec<(String, String)>, Vec<u8>) {
        let (head, body) = text.split_once("\n\n").unwrap_or((text, ""));
        let mut lines = head.lines();
        let request_line = lines.next().unwrap();
        let mut parts = request_line.split(' ');
        let method = parts.next().unwrap().to_owned();
        let target = parts.next().unwrap().to_owned();
        let headers = lines
            .map(|l| {
                let (n, v) = l.split_once(':').unwrap();
                (n.to_owned(), v.to_owned())
            })
            .collect();
        (method, target, headers, body.as_bytes().to_vec())
    }

    fn canonical(
        method: &str,
        target: &str,
        host: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> CanonicalRequest {
        let (path, query) = parse_origin_form(target.as_bytes()).unwrap();
        let raw: Vec<(&[u8], &[u8])> = headers
            .iter()
            .map(|(n, v)| (n.as_bytes(), v.as_bytes()))
            .collect();
        let headers =
            Headers::try_from_raw(raw.into_iter(), &Limits::default(), &HttpFlags::default())
                .unwrap();
        CanonicalRequest {
            method: Method::parse(method.as_bytes()).unwrap(),
            scheme: Scheme::Https,
            authority: parse_authority(host.as_bytes(), 443).unwrap(),
            path,
            query,
            headers,
            body: Body::from_bytes(body.to_vec()),
            meta: RequestMeta::new(Version::H1_1, TargetForm::Origin),
        }
    }

    fn spec(service: &str, region: &str, akid: &str, sk: &str, token: Option<&str>) -> AwsSigV4 {
        AwsSigV4 {
            service: service.into(),
            region: region.into(),
            access_key_id: Credential::new(akid),
            secret_access_key: Credential::new(sk),
            session_token: token.map(Credential::new),
            unsigned_payload: false,
        }
    }

    fn at(rfc3339: &str) -> SystemTime {
        chrono::DateTime::parse_from_rfc3339(rfc3339)
            .unwrap()
            .into()
    }

    /// The vendored AWS test-suite cases (`tests/fixtures/sigv4`): the
    /// `Authorization` and `X-Amz-*` fields roxy produces equal the
    /// suite's expected signed request.
    #[test]
    fn aws_test_suite_vectors() {
        for case in [
            "post-vanilla",
            "get-vanilla-with-session-token",
            "get-vanilla-query-order-key-case",
            "post-header-value-case",
        ] {
            let read = |f: &str| std::fs::read_to_string(format!("{FIXTURES}/{case}/{f}")).unwrap();
            let context: serde_json::Value = serde_json::from_str(&read("context.json")).unwrap();
            let (method, target, headers, body) = parse_request(&read("request.txt"));
            let host = headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case("host"))
                .map(|(_, v)| v.clone())
                .unwrap();
            let mut req = canonical(&method, &target, &host, &headers, &body);
            let creds = &context["credentials"];
            let spec = spec(
                context["service"].as_str().unwrap(),
                context["region"].as_str().unwrap(),
                creds["access_key_id"].as_str().unwrap(),
                creds["secret_access_key"].as_str().unwrap(),
                creds["token"].as_str(),
            );
            let now = at(context["timestamp"].as_str().unwrap());
            sign_request(&mut req, &host, SignableBody::Bytes(&body), &spec, now).unwrap();

            let (_, _, expected, _) = parse_request(&read("header-signed-request.txt"));
            let expected: HashMap<String, String> = expected
                .into_iter()
                .filter(|(n, _)| {
                    n.eq_ignore_ascii_case("authorization")
                        || n.to_ascii_lowercase().starts_with("x-amz-")
                })
                .map(|(n, v)| (n.to_ascii_lowercase(), v))
                .collect();
            assert!(!expected.is_empty(), "{case}: no expected signature fields");
            for (name, value) in &expected {
                assert_eq!(
                    req.headers.get(name),
                    Some(value.as_str()),
                    "{case}: {name}"
                );
            }
        }
    }

    /// The S3 examples from the AWS documentation ("Signature Calculations
    /// for the Authorization Header: Transferring Payload in a Single
    /// Chunk"): a `GET` with `Range`, and a `PUT` whose payload hash is
    /// signed and sent as `x-amz-content-sha256`. The `PUT` path carries a
    /// `$`, which the canonical request encodes once.
    #[test]
    fn s3_documentation_examples() {
        const AKID: &str = "AKIAIOSFODNN7EXAMPLE";
        const SK: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let host = "examplebucket.s3.amazonaws.com";
        let now = at("2013-05-24T00:00:00Z");
        let s3 = spec("s3", "us-east-1", AKID, SK, None);

        let headers = vec![("Range".to_owned(), "bytes=0-9".to_owned())];
        let mut req = canonical("GET", "/test.txt", host, &headers, b"");
        sign_request(&mut req, host, SignableBody::Bytes(b""), &s3, now).unwrap();
        assert_eq!(
            req.headers.get("authorization"),
            Some(
                "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
                 SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
                 Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
            )
        );
        assert_eq!(
            req.headers.get("x-amz-content-sha256"),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );

        let headers = vec![
            (
                "Date".to_owned(),
                "Fri, 24 May 2013 00:00:00 GMT".to_owned(),
            ),
            (
                "x-amz-storage-class".to_owned(),
                "REDUCED_REDUNDANCY".to_owned(),
            ),
        ];
        let body = b"Welcome to Amazon S3.";
        let mut req = canonical("PUT", "/test$file.text", host, &headers, body);
        assert_eq!(req.path.as_str(), "/test$file.text");
        sign_request(&mut req, host, SignableBody::Bytes(body), &s3, now).unwrap();
        assert_eq!(
            req.headers.get("authorization"),
            Some(
                "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
                 SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class, \
                 Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
            )
        );
        assert_eq!(
            req.headers.get("x-amz-content-sha256"),
            Some("44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072")
        );
    }

    /// The client's own signature fields go, and a framing or hop-by-hop
    /// field (which roxy keeps out of `headers` anyway) or one on the
    /// unsigned list is left out of `SignedHeaders`.
    #[test]
    fn client_signature_fields_are_replaced_and_unsigned_fields_left_out() {
        let host = "example.amazonaws.com";
        let headers = vec![
            (
                "Authorization".to_owned(),
                "AWS4-HMAC-SHA256 client".to_owned(),
            ),
            ("X-Amz-Date".to_owned(), "19990101T000000Z".to_owned()),
            ("X-Amz-Security-Token".to_owned(), "client-token".to_owned()),
            ("X-Amz-Content-Sha256".to_owned(), "deadbeef".to_owned()),
            ("Accept-Encoding".to_owned(), "gzip".to_owned()),
            ("X-Custom".to_owned(), "1".to_owned()),
        ];
        let mut req = canonical("POST", "/", host, &headers, b"");
        let spec = spec(
            "service",
            "us-east-1",
            "AKIDEXAMPLE",
            "secret",
            Some("real-token"),
        );
        sign_request(
            &mut req,
            host,
            SignableBody::Bytes(b""),
            &spec,
            at("2015-08-30T12:36:00Z"),
        )
        .unwrap();
        let auth = req.headers.get("authorization").unwrap();
        assert!(
            auth.contains("SignedHeaders=host;x-amz-date;x-amz-security-token;x-custom,"),
            "{auth}"
        );
        assert_eq!(req.headers.get("x-amz-date"), Some("20150830T123600Z"));
        assert_eq!(req.headers.get("x-amz-security-token"), Some("real-token"));
        assert_eq!(req.headers.get("x-amz-content-sha256"), None);
        assert_eq!(req.headers.get("accept-encoding"), Some("gzip"));
    }

    #[test]
    fn presigned_detection_and_path_encoding() {
        let q = |s: &str| Query::try_from(s).unwrap();
        assert!(is_presigned(Some(&q(
            "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=abc"
        ))));
        assert!(is_presigned(Some(&q("x-amz-signature=abc"))));
        assert!(!is_presigned(Some(&q("X-Amz-Algorithm=AWS4-HMAC-SHA256"))));
        assert!(!is_presigned(None));
        assert_eq!(aws_encoded_path("/a/b-c_d.e~f"), "/a/b-c_d.e~f");
        assert_eq!(aws_encoded_path("/test$file,(x)"), "/test%24file%2C%28x%29");
        assert_eq!(aws_encoded_path("/a%20b/c%2Fd"), "/a%20b/c%2Fd");
    }
}
