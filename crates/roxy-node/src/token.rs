//! The node token as the state dir holds it. The record carries the node
//! id and expiry the server stated with the token, since nothing else on
//! the node knows them after a restart.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::protocol::EnrolResponse;

/// The longest token a server may issue.
pub const MAX_TOKEN_BYTES: usize = 512;

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("the node token record does not parse: {0}")]
    Invalid(#[from] serde_json::Error),
    #[error(
        "the node token is not 1 to {MAX_TOKEN_BYTES} bytes of bearer token text (A-Z a-z 0-9 - . _ ~ + / and trailing =)"
    )]
    Shape,
}

/// The stored record: the token and what the server said about it.
#[derive(Clone, Serialize, Deserialize)]
pub struct NodeToken {
    pub node_id: String,
    pub token: String,
    pub not_after: DateTime<Utc>,
}

/// Never prints the token.
impl std::fmt::Debug for NodeToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeToken")
            .field("node_id", &self.node_id)
            .field("not_after", &self.not_after)
            .finish_non_exhaustive()
    }
}

impl NodeToken {
    /// The record for an enrolment or renewal response.
    pub fn from_response(res: &EnrolResponse) -> Result<Self, TokenError> {
        check_shape(&res.token)?;
        Ok(Self {
            node_id: res.node_id.clone(),
            token: res.token.clone(),
            not_after: res.not_after,
        })
    }

    /// Parses a record written by [`NodeToken::record`].
    pub fn parse(record: &str) -> Result<Self, TokenError> {
        let parsed: Self = serde_json::from_str(record)?;
        check_shape(&parsed.token)?;
        Ok(parsed)
    }

    /// The record as the state dir stores it: one JSON object.
    pub fn record(&self) -> String {
        let mut text = serde_json::to_string(self).unwrap_or_default();
        text.push('\n');
        text
    }
}

/// RFC 6750's `b64token`: what every `Authorization: Bearer` parser on the
/// way to the server accepts, and text JSON never escapes.
fn check_shape(token: &str) -> Result<(), TokenError> {
    let body = token.trim_end_matches('=');
    let token68 = !body.is_empty()
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~+/".contains(&b));
    if !token68 || token.len() > MAX_TOKEN_BYTES {
        return Err(TokenError::Shape);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(token: &str) -> EnrolResponse {
        EnrolResponse {
            node_id: "n1".into(),
            token: token.into(),
            not_after: DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
            renew_after_seconds: 60,
        }
    }

    #[test]
    fn the_record_round_trips_and_never_debug_prints_the_token() {
        let stored = NodeToken::from_response(&response("tok-secret")).unwrap();
        let record = stored.record();
        assert!(record.ends_with('\n'));
        let back = NodeToken::parse(&record).unwrap();
        assert_eq!(back.node_id, "n1");
        assert_eq!(back.token, "tok-secret");
        assert_eq!(back.not_after, stored.not_after);
        let text = format!("{back:?}");
        assert!(!text.contains("tok-secret"), "{text}");
        assert!(text.contains("n1"));
    }

    #[test]
    fn a_token_the_header_cannot_carry_is_refused() {
        for bad in [
            "",
            "=",
            "with space",
            "tab\there",
            "ünïcode",
            "\u{7f}",
            "quo\"te",
            "back\\slash",
            "a,b",
            "a:b",
            "a=b",
        ] {
            assert!(
                matches!(
                    NodeToken::from_response(&response(bad)),
                    Err(TokenError::Shape)
                ),
                "{bad:?}"
            );
        }
        for good in ["a", "nt1-9f86d081", "a-._~+/Z9", "abc==", &"x".repeat(512)] {
            assert!(
                NodeToken::from_response(&response(good)).is_ok(),
                "{good:?}"
            );
        }
        assert!(NodeToken::from_response(&response(&"x".repeat(513))).is_err());
        assert!(matches!(
            NodeToken::parse(r#"{"node_id":"n1","token":"","not_after":"2026-11-05T10:12:00Z"}"#),
            Err(TokenError::Shape)
        ));
    }
}
