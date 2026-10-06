//! Secret resolution.
//!
//! Secrets are resolved at `roxy run` and on each reload. `roxy check` never
//! reads them. A missing environment variable or unreadable file is a fatal
//! startup error: a rule that injects a secret must never run with a blank
//! value. A sourceless secret (`{}`) has nothing here to resolve it from,
//! so `roxy run --config` refuses it the same way.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use crate::config::SecretSource;

/// A resolved secret value. `Debug` never prints the value.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretValue(String);

impl SecretValue {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue([REDACTED])")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("secret {name:?}: environment variable {var} is not set or not valid UTF-8")]
    MissingEnv { name: String, var: String },
    #[error("secret {name:?}: cannot read {}: {source}", path.display())]
    File {
        name: String,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("secret {name:?} resolved to an empty value")]
    Empty { name: String },
    #[error(
        "secret {name:?} has no `env` or `file` source; its value is supplied at runtime, \
         which `roxy run --config` cannot do"
    )]
    Unresolvable { name: String },
}

/// A secret file that group or world can read is most likely a deployment
/// mistake (a `chmod 644` or a checkout); the secret still loads, since the
/// permissions of a mounted secret are not always the operator's to set.
#[cfg(unix)]
fn warn_if_readable_by_others(name: &str, path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path)
        && meta.permissions().mode() & 0o077 != 0
    {
        tracing::warn!(
            secret = name,
            path = %path.display(),
            mode = format_args!("{:04o}", meta.permissions().mode() & 0o7777),
            "secret file is readable by other users"
        );
    }
}

#[cfg(not(unix))]
fn warn_if_readable_by_others(_name: &str, _path: &Path) {}

/// All resolved secrets, by name.
#[derive(Debug, Default, Clone)]
pub struct Secrets {
    values: BTreeMap<String, SecretValue>,
}

impl Secrets {
    /// Resolve every configured secret from the process environment and the
    /// filesystem.
    pub fn resolve(sources: &BTreeMap<String, SecretSource>) -> Result<Self, SecretError> {
        Self::resolve_with(sources, |var| std::env::var(var).ok())
    }

    /// Like [`Secrets::resolve`] with an injectable environment lookup.
    pub fn resolve_with(
        sources: &BTreeMap<String, SecretSource>,
        env: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, SecretError> {
        let mut values = BTreeMap::new();
        for (name, source) in sources {
            let value = match source {
                SecretSource::Runtime => {
                    return Err(SecretError::Unresolvable { name: name.clone() });
                }
                SecretSource::Env(var) => env(var).ok_or_else(|| SecretError::MissingEnv {
                    name: name.clone(),
                    var: var.clone(),
                })?,
                SecretSource::File(path) => {
                    let mut s =
                        std::fs::read_to_string(path).map_err(|source| SecretError::File {
                            name: name.clone(),
                            path: path.clone(),
                            source,
                        })?;
                    warn_if_readable_by_others(name, path);
                    // Files written by `echo` or editors end in a newline.
                    if s.ends_with('\n') {
                        s.pop();
                        if s.ends_with('\r') {
                            s.pop();
                        }
                    }
                    s
                }
            };
            if value.is_empty() {
                return Err(SecretError::Empty { name: name.clone() });
            }
            values.insert(name.clone(), SecretValue(value));
        }
        Ok(Self { values })
    }

    pub fn get(&self, name: &str) -> Option<&SecretValue> {
        self.values.get(name)
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn values(&self) -> impl Iterator<Item = &SecretValue> {
        self.values.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_env_and_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tok");
        std::fs::write(&path, "file-secret\n").unwrap();
        let mut sources = BTreeMap::new();
        sources.insert("a".to_owned(), SecretSource::Env("A_VAR".into()));
        sources.insert("b".to_owned(), SecretSource::File(path));
        let s = Secrets::resolve_with(&sources, |v| (v == "A_VAR").then(|| "env-secret".into()))
            .unwrap();
        assert_eq!(s.get("a").unwrap().expose(), "env-secret");
        assert_eq!(s.get("b").unwrap().expose(), "file-secret");
        assert_eq!(
            format!("{:?}", s.get("a").unwrap()),
            "SecretValue([REDACTED])"
        );
    }

    #[test]
    fn missing_sources_are_fatal() {
        let mut sources = BTreeMap::new();
        sources.insert("a".to_owned(), SecretSource::Env("NOPE".into()));
        assert!(matches!(
            Secrets::resolve_with(&sources, |_| None),
            Err(SecretError::MissingEnv { .. })
        ));
        assert!(matches!(
            Secrets::resolve_with(&sources, |_| Some(String::new())),
            Err(SecretError::Empty { .. })
        ));
        let mut sources = BTreeMap::new();
        sources.insert(
            "f".to_owned(),
            SecretSource::File("/nonexistent/roxy/secret".into()),
        );
        assert!(matches!(
            Secrets::resolve_with(&sources, |_| None),
            Err(SecretError::File { .. })
        ));
    }

    #[test]
    fn a_sourceless_secret_cannot_be_resolved_here() {
        let mut sources = BTreeMap::new();
        sources.insert("a".to_owned(), SecretSource::Env("A_VAR".into()));
        sources.insert("lease".to_owned(), SecretSource::Runtime);
        let err = Secrets::resolve_with(&sources, |_| Some("v".into())).unwrap_err();
        assert!(matches!(&err, SecretError::Unresolvable { name } if name == "lease"));
        assert!(err.to_string().contains("\"lease\""), "{err}");
    }
}
