//! Proxy authentication (`DESIGN.md` §4.1): `Proxy-Authorization: Basic`
//! against a file of `user:bcrypt-hash` lines.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use http::HeaderValue;

/// A bcrypt hash verified against when the user is unknown, so unknown and
/// known users take roughly the same time.
fn dummy_hash() -> String {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| bcrypt::hash("roxy-unknown-user", bcrypt::DEFAULT_COST).unwrap_or_default())
        .clone()
}

/// Verified credentials kept per connection, bounded.
const CACHE_MAX: usize = 16;

/// Users allowed on a listener.
#[derive(Debug, Clone, Default)]
pub struct UserDb {
    users: HashMap<String, String>,
}

impl UserDb {
    /// Parses `user:hash` lines. Blank lines and `#` comments are ignored;
    /// a malformed line, a duplicate user or a hash that is not bcrypt is an
    /// error naming the line.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut users = HashMap::new();
        for (i, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (user, hash) = line
                .split_once(':')
                .ok_or_else(|| format!("line {}: expected `user:bcrypt-hash`", i + 1))?;
            if user.is_empty() || user.chars().any(char::is_control) {
                return Err(format!("line {}: invalid user name", i + 1));
            }
            if !(hash.starts_with("$2a$") || hash.starts_with("$2b$") || hash.starts_with("$2y$")) {
                return Err(format!("line {}: the hash is not a bcrypt hash", i + 1));
            }
            if users.insert(user.to_owned(), hash.to_owned()).is_some() {
                return Err(format!("line {}: duplicate user {user:?}", i + 1));
            }
        }
        Ok(Self { users })
    }

    /// Reads and parses a users file.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("reading users file {}: {e}", path.display()))?;
        Self::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Number of users.
    pub fn len(&self) -> usize {
        self.users.len()
    }

    /// Whether there are no users.
    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }
}

/// Credentials verified on this connection: header value → (user, hash).
/// An entry only counts while the database still has the same hash for the
/// user, so a reload that changes or removes a user takes effect at once.
#[derive(Debug, Default)]
pub(crate) struct AuthCache {
    verified: HashMap<Vec<u8>, (String, String)>,
}

fn parse_basic(v: &HeaderValue) -> Option<(String, String)> {
    let s = v.to_str().ok()?.trim();
    let (scheme, rest) = s.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let raw = STANDARD.decode(rest.trim()).ok()?;
    let text = String::from_utf8(raw).ok()?;
    let (user, pass) = text.split_once(':')?;
    Some((user.to_owned(), pass.to_owned()))
}

/// Returns the authenticated user, or `None` (→ 407).
pub(crate) async fn authenticate(
    db: &Arc<UserDb>,
    header: Option<&HeaderValue>,
    cache: &mut AuthCache,
) -> Option<String> {
    let header = header?;
    let (user, pass) = parse_basic(header)?;
    let hash = db.users.get(&user).cloned();
    if let (Some(h), Some((cu, ch))) = (&hash, cache.verified.get(header.as_bytes()))
        && *cu == user
        && ch == h
    {
        return Some(user);
    }
    let verify_against = hash.clone();
    let ok = tokio::task::spawn_blocking(move || {
        let h = verify_against.unwrap_or_else(dummy_hash);
        bcrypt::verify(pass, &h).unwrap_or(false)
    })
    .await
    .unwrap_or(false);
    let hash = hash?;
    if !ok {
        return None;
    }
    if cache.verified.len() >= CACHE_MAX {
        cache.verified.clear();
    }
    cache
        .verified
        .insert(header.as_bytes().to_vec(), (user.clone(), hash));
    Some(user)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basic(user: &str, pass: &str) -> HeaderValue {
        HeaderValue::from_str(&format!(
            "Basic {}",
            STANDARD.encode(format!("{user}:{pass}"))
        ))
        .unwrap()
    }

    #[tokio::test]
    async fn verifies_and_caches() {
        let hash = bcrypt::hash("s3cret", 4).unwrap();
        let db = Arc::new(UserDb::parse(&format!("# users\nalice:{hash}\n")).unwrap());
        assert_eq!(db.len(), 1);
        let mut cache = AuthCache::default();
        assert_eq!(
            authenticate(&db, Some(&basic("alice", "s3cret")), &mut cache).await,
            Some("alice".into())
        );
        assert_eq!(cache.verified.len(), 1);
        assert_eq!(
            authenticate(&db, Some(&basic("alice", "s3cret")), &mut cache).await,
            Some("alice".into())
        );
        assert_eq!(
            authenticate(&db, Some(&basic("alice", "wrong")), &mut cache).await,
            None
        );
        assert_eq!(
            authenticate(&db, Some(&basic("bob", "s3cret")), &mut cache).await,
            None
        );
        assert_eq!(authenticate(&db, None, &mut cache).await, None);
        // A reload that drops the user invalidates the cached entry.
        let empty = Arc::new(UserDb::default());
        assert_eq!(
            authenticate(&empty, Some(&basic("alice", "s3cret")), &mut cache).await,
            None
        );
    }

    #[test]
    fn parse_errors() {
        assert!(UserDb::parse("alice").is_err());
        assert!(UserDb::parse("alice:plaintext").is_err());
        assert!(UserDb::parse("a:$2b$04$x\na:$2b$04$y").is_err());
    }

    #[test]
    fn dummy_hash_is_valid() {
        assert!(!bcrypt::verify("x", &dummy_hash()).unwrap());
    }
}
