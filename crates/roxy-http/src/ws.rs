//! WebSocket handshake checks and, in [`frame`],
//! the frame codec used when rules read messages.

pub mod frame;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use http::{HeaderValue, StatusCode};
use sha1::{Digest, Sha1};

use crate::model::{
    CanonicalRequest, CanonicalResponse, Method, ParseError, Reason, Version, reject,
};

/// RFC 6455 §1.3 GUID.
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// A validated `Sec-WebSocket-Key`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsKey(String);

impl WsKey {
    /// The key as sent by the client.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// `Sec-WebSocket-Accept` for a key (RFC 6455 §4.2.2).
pub fn compute_accept(key: &str) -> String {
    let mut h = Sha1::new();
    h.update(key.as_bytes());
    h.update(WS_GUID.as_bytes());
    STANDARD.encode(h.finalize())
}

/// The one value of `name`. Counted over the raw values so that an
/// obs-text duplicate (`http.allow_obs_text`) is a duplicate, not an absence.
fn single<'a>(
    it: impl Iterator<Item = &'a HeaderValue>,
    name: &str,
) -> Result<&'a str, ParseError> {
    let v: Vec<&HeaderValue> = it.collect();
    match v.as_slice() {
        [one] => one
            .to_str()
            .map_err(|_| ParseError::new(Reason::WsBadHandshake, format!("{name} is not ASCII"))),
        [] => reject(Reason::WsBadHandshake, format!("missing {name}")),
        _ => reject(Reason::WsBadHandshake, format!("multiple {name}")),
    }
}

/// Validates an upgrade request: GET, HTTP/1.1, `Connection: upgrade` +
/// `Upgrade: websocket`, `Sec-WebSocket-Version: 13`, and a
/// `Sec-WebSocket-Key` that is base64 of exactly 16 bytes; no body.
pub fn validate_upgrade_request(req: &CanonicalRequest) -> Result<WsKey, ParseError> {
    if req.method != Method::Get {
        return reject(Reason::WsBadHandshake, "upgrade must be GET");
    }
    if req.meta.version != Version::H1_1 {
        return reject(Reason::WsBadHandshake, "upgrade requires HTTP/1.1");
    }
    if !req
        .meta
        .upgrade
        .as_deref()
        .is_some_and(|u| u.eq_ignore_ascii_case("websocket"))
    {
        return reject(Reason::WsBadHandshake, "not a websocket upgrade");
    }
    if req.body.known_length() != Some(0) {
        return reject(Reason::WsBadHandshake, "upgrade request with a body");
    }
    let version = single(
        req.headers.get_all_raw("sec-websocket-version"),
        "sec-websocket-version",
    )?;
    if version != "13" {
        return reject(Reason::WsBadHandshake, "sec-websocket-version must be 13");
    }
    let key = single(
        req.headers.get_all_raw("sec-websocket-key"),
        "sec-websocket-key",
    )?;
    match STANDARD.decode(key) {
        Ok(raw) if raw.len() == 16 => Ok(WsKey(key.to_owned())),
        _ => reject(
            Reason::WsBadHandshake,
            "sec-websocket-key is not 16 base64 bytes",
        ),
    }
}

/// Validates the upstream's answer: `101`, `Upgrade: websocket` nominated by
/// `Connection`, and the correct `Sec-WebSocket-Accept`.
pub fn validate_upgrade_response(res: &CanonicalResponse, key: &WsKey) -> Result<(), ParseError> {
    if res.status != StatusCode::SWITCHING_PROTOCOLS {
        return reject(
            Reason::WsBadHandshake,
            format!("upstream answered {}", res.status),
        );
    }
    if !res
        .meta
        .upgrade
        .as_deref()
        .is_some_and(|u| u.eq_ignore_ascii_case("websocket"))
    {
        return reject(Reason::WsBadHandshake, "101 without upgrade: websocket");
    }
    let accept = single(
        res.headers.get_all_raw("sec-websocket-accept"),
        "sec-websocket-accept",
    )?;
    if accept != compute_accept(key.as_str()) {
        return reject(Reason::WsBadHandshake, "wrong sec-websocket-accept");
    }
    Ok(())
}

/// For a WebSocket whose messages are checked, where no extension was
/// offered: the `101` must not accept one (RFC 6455 §9.1).
pub fn validate_no_extensions(res: &CanonicalResponse) -> Result<(), ParseError> {
    if res.headers.get("sec-websocket-extensions").is_some() {
        return reject(
            Reason::WsBadHandshake,
            "101 accepts an extension that was not offered",
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Body, Headers, HttpFlags, Limits, RequestMeta, Scheme, TargetForm};
    use crate::url::{Path, parse_authority};

    #[test]
    fn rfc6455_example() {
        assert_eq!(
            compute_accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    fn upgrade_req(headers: &[(&str, &str)]) -> CanonicalRequest {
        let mut h = Headers::new();
        for (n, v) in headers {
            h.append(n, v).unwrap();
        }
        let mut meta = RequestMeta::new(Version::H1_1, TargetForm::Origin);
        meta.upgrade = Some("websocket".into());
        CanonicalRequest {
            method: Method::Get,
            scheme: Scheme::Https,
            authority: parse_authority(b"ws.example.com", 443).unwrap(),
            path: Path::root(),
            query: None,
            headers: h,
            body: Body::empty(),
            meta,
        }
    }

    const KEY: (&str, &str) = ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");
    const V13: (&str, &str) = ("sec-websocket-version", "13");

    #[test]
    fn request_validation() {
        let key = validate_upgrade_request(&upgrade_req(&[KEY, V13])).unwrap();
        assert_eq!(key.as_str(), KEY.1);
        for bad in [
            upgrade_req(&[KEY]),
            upgrade_req(&[V13]),
            upgrade_req(&[KEY, ("sec-websocket-version", "8")]),
            upgrade_req(&[("sec-websocket-key", "c2hvcnQ="), V13]),
            upgrade_req(&[("sec-websocket-key", "!!!"), V13]),
            upgrade_req(&[KEY, KEY, V13]),
        ] {
            assert_eq!(
                validate_upgrade_request(&bad).unwrap_err().reason,
                Reason::WsBadHandshake
            );
        }
        let mut r = upgrade_req(&[KEY, V13]);
        r.method = Method::Post;
        assert!(validate_upgrade_request(&r).is_err());
        let mut r = upgrade_req(&[KEY, V13]);
        r.meta.upgrade = Some("h2c".into());
        assert!(validate_upgrade_request(&r).is_err());
        let mut r = upgrade_req(&[KEY, V13]);
        r.meta.version = Version::H2;
        assert!(validate_upgrade_request(&r).is_err());
    }

    #[test]
    fn obs_text_duplicate_key_is_a_duplicate() {
        let mut r = upgrade_req(&[KEY, V13]);
        let obs = HttpFlags {
            allow_obs_text: true,
            ..HttpFlags::default()
        };
        r.headers = Headers::try_from_raw(
            [
                (KEY.0.as_bytes(), KEY.1.as_bytes()),
                (KEY.0.as_bytes(), &b"caf\xe9"[..]),
                (V13.0.as_bytes(), V13.1.as_bytes()),
            ],
            &Limits::default(),
            &obs,
        )
        .unwrap();
        assert_eq!(r.headers.get_all("sec-websocket-key").count(), 1);
        assert_eq!(
            validate_upgrade_request(&r).unwrap_err().reason,
            Reason::WsBadHandshake
        );
    }

    #[test]
    fn request_must_have_no_body() {
        let mut r = upgrade_req(&[KEY, V13]);
        r.body = Body::from_bytes("x");
        assert_eq!(
            validate_upgrade_request(&r).unwrap_err().reason,
            Reason::WsBadHandshake
        );
        // Unknown length (chunked) is a body too, even if it turns out empty.
        let mut r = upgrade_req(&[KEY, V13]);
        let (_tx, body) = Body::channel(1 << 20, None);
        r.body = body;
        assert_eq!(
            validate_upgrade_request(&r).unwrap_err().reason,
            Reason::WsBadHandshake
        );
    }

    #[test]
    fn response_validation() {
        let key = validate_upgrade_request(&upgrade_req(&[KEY, V13])).unwrap();
        let mut res = CanonicalResponse::new(StatusCode::SWITCHING_PROTOCOLS);
        res.meta.upgrade = Some("websocket".into());
        res.headers
            .insert("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
            .unwrap();
        validate_upgrade_response(&res, &key).unwrap();

        res.headers.insert("sec-websocket-accept", "wrong").unwrap();
        assert!(validate_upgrade_response(&res, &key).is_err());

        let mut res2 = CanonicalResponse::new(StatusCode::OK);
        res2.meta.upgrade = Some("websocket".into());
        assert!(validate_upgrade_response(&res2, &key).is_err());

        validate_no_extensions(&res).unwrap();
        res.headers
            .insert("sec-websocket-extensions", "permessage-deflate")
            .unwrap();
        assert!(validate_no_extensions(&res).is_err());

        let mut res3 = CanonicalResponse::new(StatusCode::SWITCHING_PROTOCOLS);
        res3.headers
            .insert("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
            .unwrap();
        assert!(validate_upgrade_response(&res3, &key).is_err());
    }
}
