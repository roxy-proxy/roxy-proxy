//! Authenticates each request with a central auth service, and hands the
//! user it names to the layers below as a flow tag.
//!
//! The client sends its credential in `x-roxy-auth`. The layer asks the
//! `auth` endpoint who that credential belongs to, caches the answer in its
//! state store under a hash of the credential, tags the flow `user:<name>`,
//! strips the header and passes the request on. A missing or refused
//! credential is answered with a `401` here; the request never leaves.
//!
//! ```yaml
//! addons:
//!   - name: auth-gate
//!     kind: wasm
//!     path: /etc/roxy/addons/auth_gate.wasm
//!     capabilities: [endpoints, state, record]
//!     endpoints:
//!       auth: { url: "http://auth-service:9100/introspect", private_ok: true }
//!     config: { cache_ttl_secs: 30 }
//! ```

use std::fmt::Write as _;
use std::time::Duration;

use roxy_addon::prelude::*;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const HEADER: &str = "x-roxy-auth";
const ENDPOINT: &str = "auth";
const MAX_REPLY: usize = 64 * 1024;

#[derive(Deserialize)]
struct Config {
    cache_ttl_secs: u64,
}

#[derive(Deserialize)]
struct Verdict {
    user: String,
}

pub struct AuthGate {
    cache_ttl: Duration,
}

impl Layer for AuthGate {
    fn init(config: &str) -> Result<Self, String> {
        let config: Config = serde_json::from_str(config).map_err(|e| format!("config: {e}"))?;
        Ok(Self {
            cache_ttl: Duration::from_secs(config.cache_ttl_secs),
        })
    }

    fn handle(&mut self, mut req: Request, next: Next) -> Response {
        let Some(token) = req.headers.get_str(HEADER).map(str::to_owned) else {
            return unauthenticated(&format!("{HEADER} header required"));
        };
        let key = cache_key(&token);
        let (user, cached) = if let Some(json) = flow::state_get(&key) {
            (parse_user(&json), true)
        } else {
            let Some(user) = introspect(&token) else {
                flow::record("auth", r#"{"result":"refused"}"#, false);
                return unauthenticated("credential refused by the auth service");
            };
            // A full store refuses the write; the verdict still stands for
            // this exchange, it just isn't cached.
            let _ = flow::state_put(&key, &user_json(&user), Some(self.cache_ttl));
            (user, false)
        };
        flow::add_tag(&format!("user:{user}"));
        flow::record(
            "auth",
            &serde_json::json!({"result": "ok", "user": user, "cached": cached}).to_string(),
            false,
        );
        req.headers.remove(HEADER);
        next.run(req)
    }
}

roxy_addon::export!(AuthGate);

/// Asks the auth service who `token` belongs to. `None` is a refusal; any
/// other failure panics, so the exchange fails closed.
fn introspect(token: &str) -> Option<String> {
    let body = serde_json::json!({"token": token}).to_string();
    let req = Request::new("POST", "/")
        .with_header("content-type", "application/json")
        .with_body(body);
    let resp = call_endpoint(ENDPOINT, req).expect("auth service unreachable");
    match resp.status {
        200 => {
            let body = resp.body.read_to_end(MAX_REPLY).expect("auth reply");
            let verdict: Verdict = serde_json::from_slice(&body).expect("auth reply is not JSON");
            Some(validated(verdict.user))
        }
        401 | 403 => None,
        status => panic!("auth service answered {status}"),
    }
}

/// A user name safe to put in a tag: tags are `name:value` tokens in the
/// flow log and in `when` conditions, so the auth service does not get to
/// spell one however it likes.
fn validated(user: String) -> String {
    let ok = !user.is_empty()
        && user.len() <= 64
        && user
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'@'));
    assert!(ok, "auth service returned an unusable user name");
    user
}

/// The state key for a credential: its hash, so the store never holds the
/// credential itself.
fn cache_key(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    digest.iter().fold(String::with_capacity(64), |mut hex, b| {
        let _ = write!(hex, "{b:02x}");
        hex
    })
}

fn user_json(user: &str) -> String {
    serde_json::json!({"user": user}).to_string()
}

fn parse_user(json: &str) -> String {
    let v: Verdict = serde_json::from_str(json).expect("cached verdict");
    v.user
}

/// An Anthropic-shaped error, so SDK clients raise their usual exception.
fn unauthenticated(message: &str) -> Response {
    Response::json(
        401,
        serde_json::json!({
            "type": "error",
            "error": {"type": "authentication_error", "message": message},
        })
        .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_key_is_a_hash_not_the_token() {
        let key = cache_key("alice-secret");
        assert_eq!(key.len(), 64);
        assert!(!key.contains("alice"));
        assert_ne!(key, cache_key("alice-secret "));
    }

    #[test]
    fn user_names_are_tag_safe() {
        assert_eq!(validated("alice".into()), "alice");
        assert_eq!(validated("a.b-c_d@x".into()), "a.b-c_d@x");
    }

    #[test]
    #[should_panic(expected = "unusable user name")]
    fn user_name_with_colon_is_refused() {
        validated("user:admin".into());
    }

    #[test]
    #[should_panic(expected = "unusable user name")]
    fn empty_user_name_is_refused() {
        validated(String::new());
    }

    #[test]
    fn config_needs_a_ttl() {
        assert!(AuthGate::init("null").is_err());
        assert!(AuthGate::init(r#"{"cache_ttl_secs": 30}"#).is_ok());
    }
}
