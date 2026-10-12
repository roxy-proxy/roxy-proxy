//! How roxy reads YAML: config files and the rule and metric lists in them.
//!
//! YAML 1.1 spellings are refused rather than guessed at: `yes`/`no`/`on`/
//! `off` are not booleans, `<<` is not a merge key and an unknown tag is an
//! error, so a config means what it says to anyone reading it. A repeated key
//! in any mapping is an error. Errors name the YAML path they were found at.

use std::borrow::Cow;
use std::fmt;

use serde::de::DeserializeOwned;

/// Parse one YAML document.
pub fn from_str<T: DeserializeOwned>(text: &str) -> Result<T, Error> {
    let mut path = String::new();
    serde_saphyr::with_deserializer_from_str_with_options(text, options(), |de| {
        serde_path_to_error::deserialize(de).map_err(|e| {
            path = e.path().to_string();
            e.into_inner()
        })
    })
    .map_err(|inner| Error::new(&path, inner))
}

fn options() -> serde_saphyr::Options {
    serde_saphyr::options! {
        strict_booleans: true,
        merge_keys: serde_saphyr::MergeKeyPolicy::Error,
        reject_unsupported_tags: true,
        with_snippet: false,
    }
}

/// A structural YAML error: the deserialiser's message and the YAML path it
/// was found at (`rules[0].then[1].deny`), when there is one.
#[derive(Debug)]
pub struct Error {
    path: String,
    inner: Box<serde_saphyr::Error>,
}

impl Error {
    /// `path` as `serde_path_to_error` spells it. An unknown key is part of
    /// that path, and a key that failed to parse is `?`; the message names
    /// either, so the path stops at the mapping that holds them. A key that
    /// really is `?` reads the same and loses its segment too; the message's
    /// line and column still place the error. `roxy check` and the rule-id
    /// suffix rely on this spelling; `errors_name_the_path` pins it.
    fn new(path: &str, inner: serde_saphyr::Error) -> Self {
        let leaf = if let serde_saphyr::Error::SerdeUnknownField { field, .. } = &inner {
            field.as_str()
        } else {
            "?"
        };
        let path = if path == leaf {
            ""
        } else {
            path.strip_suffix(leaf)
                .and_then(|p| p.strip_suffix('.'))
                .unwrap_or(path)
        };
        // serde_path_to_error spells the root `.`.
        let path = if path == "." { "" } else { path };
        Self {
            path: path.to_owned(),
            inner: Box::new(inner),
        }
    }

    /// The YAML path of the value that failed, or empty at the root.
    pub fn path(&self) -> &str {
        &self.path
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = self.inner.render_with_formatter(&Messages);
        if self.path.is_empty() {
            f.write_str(&msg)
        } else {
            write!(f, "{}: {msg}", self.path)
        }
    }
}

impl std::error::Error for Error {}

/// serde-saphyr's user-facing messages, with a duplicate key worded as the
/// named maps word theirs (``duplicate key `gh` ``).
struct Messages;

impl serde_saphyr::MessageFormatter for Messages {
    fn format_message<'a>(&self, err: &'a serde_saphyr::Error) -> Cow<'a, str> {
        if let serde_saphyr::Error::DuplicateMappingKey { key: Some(k), .. } = err {
            Cow::Owned(format!("duplicate key `{k}`"))
        } else {
            serde_saphyr::UserMessageFormatter.format_message(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fmt::Write as _;

    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Doc {
        #[serde(default)]
        a: Option<Inner>,
        #[serde(default)]
        b: Option<Inner>,
        #[serde(default)]
        m: BTreeMap<String, String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Inner {
        on: bool,
    }

    fn err(yaml: &str) -> String {
        from_str::<Doc>(yaml).expect_err(yaml).to_string()
    }

    #[test]
    fn errors_name_the_path() {
        assert!(err("a: { on: 1 }").starts_with("a.on: "));
        // An unknown key is named by the message, not repeated in the path.
        assert!(err("a: { off: true }").starts_with("a: unknown field `off`"));
        assert!(err("bogus: 1").starts_with("unknown field `bogus`"));
        assert!(err("m: { k: a, k: b }").starts_with("m: duplicate key `k`"));
        let doc: Doc = from_str("m: { k: a }").unwrap();
        assert_eq!(doc.m["k"], "a");
    }

    #[test]
    fn yaml_1_1_forms_are_refused() {
        for (yaml, want) in [
            ("a: { on: yes }", "a.on: invalid boolean"),
            ("a: { on: off }", "a.on: invalid boolean"),
            (
                "a: &x { on: true }\nb: { <<: *x }",
                "b: merge key not allowed",
            ),
            ("a: { on: !custom true }", "unsupported tag `!custom`"),
        ] {
            let e = err(yaml);
            assert!(e.contains(want), "{yaml}: {e}");
        }
        let doc: Doc = from_str("a: &x { on: true }\nb: *x").unwrap();
        assert!(doc.a.unwrap().on && doc.b.unwrap().on);
    }

    /// A stream of documents is refused, not read up to the first one: what
    /// roxy applies is all of what a reader sees.
    #[test]
    fn one_document_only() {
        assert!(from_str::<Doc>("a: { on: true }\n---\nb: { on: true }\n").is_err());
        assert!(from_str::<Doc>("---\na: { on: true }\n...\n").is_ok());
    }

    /// Nesting is bounded, so a deep document is an error, not a stack
    /// overflow.
    #[test]
    fn deep_nesting_is_refused() {
        let yaml = format!("{}{}", "[".repeat(5000), "]".repeat(5000));
        let e = from_str::<serde::de::IgnoredAny>(&yaml).expect_err("deep nesting");
        assert!(e.to_string().contains("recursion limit exceeded"), "{e}");
    }

    /// Aliases are expanded within a budget, so a billion-laughs document
    /// is refused instead of exhausting memory.
    #[test]
    fn alias_bomb_is_refused() {
        let mut yaml = String::from("l0: &l0 [x, x, x, x, x, x, x, x, x, x]\n");
        for i in 1..=9 {
            let prev = format!("*l{}", i - 1);
            let items = [prev.as_str(); 10].join(", ");
            writeln!(yaml, "l{i}: &l{i} [{items}]").unwrap();
        }
        let e = from_str::<serde::de::IgnoredAny>(&yaml).expect_err("alias bomb");
        let e = e.to_string();
        assert!(e.contains("budget breached"), "{e}");
    }
}
