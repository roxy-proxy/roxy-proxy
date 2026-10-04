//! `${secret:name}` placeholders in configured values: `set_header` values
//! in rules and the headers of addon endpoints. One grammar, parsed here,
//! so every place that accepts a placeholder agrees on what one looks like.

use std::fmt;

/// One piece of a value with placeholders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Part {
    /// Literal text, forwarded as written.
    Lit(String),
    /// `${secret:name}`: the named secret's value.
    Secret(String),
}

/// Why a value is not a valid template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateError {
    /// `${` followed by anything other than `secret:`.
    UnknownInterpolation,
    /// `${secret:` with no closing `}`.
    Unterminated,
    /// `${secret:}`.
    EmptyName,
}

impl fmt::Display for TemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnknownInterpolation => {
                "unknown interpolation; only `${secret:name}` is supported"
            }
            Self::Unterminated => "unterminated `${secret:`",
            Self::EmptyName => "empty secret name",
        })
    }
}

impl std::error::Error for TemplateError {}

const OPEN: &str = "${";
const SECRET_OPEN: &str = "${secret:";

/// Whether `value` contains the opening of a secret placeholder, well
/// formed or not: where secrets are not allowed at all, a broken
/// placeholder is still an attempt to use one.
pub fn mentions_secret(value: &str) -> bool {
    value.contains(SECRET_OPEN)
}

/// Splits `value` into literal text and secret references. Adjacent
/// literals are merged; an empty value is no parts.
pub fn parse_template(value: &str) -> Result<Vec<Part>, TemplateError> {
    let mut parts = Vec::new();
    let mut rest = value;
    while let Some(i) = rest.find(OPEN) {
        if i > 0 {
            parts.push(Part::Lit(rest[..i].to_owned()));
        }
        let body = rest[i..]
            .strip_prefix(SECRET_OPEN)
            .ok_or(TemplateError::UnknownInterpolation)?;
        let end = body.find('}').ok_or(TemplateError::Unterminated)?;
        let name = &body[..end];
        if name.is_empty() {
            return Err(TemplateError::EmptyName);
        }
        parts.push(Part::Secret(name.to_owned()));
        rest = &body[end + 1..];
    }
    if !rest.is_empty() {
        parts.push(Part::Lit(rest.to_owned()));
    }
    Ok(parts)
}

/// The secret names a template references, in order, with repeats.
pub fn secret_names(parts: &[Part]) -> impl Iterator<Item = &str> {
    parts.iter().filter_map(|p| match p {
        Part::Secret(name) => Some(name.as_str()),
        Part::Lit(_) => None,
    })
}

/// Whether any part is a secret reference.
pub fn has_secrets(parts: &[Part]) -> bool {
    secret_names(parts).next().is_some()
}

/// Renders a template with `lookup`; `None` if a referenced secret is
/// missing, so the caller fails closed rather than sending a placeholder.
pub fn expand(parts: &[Part], mut lookup: impl FnMut(&str) -> Option<String>) -> Option<String> {
    let mut out = String::new();
    for part in parts {
        match part {
            Part::Lit(s) => out.push_str(s),
            Part::Secret(name) => out.push_str(&lookup(name)?),
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lit(s: &str) -> Part {
        Part::Lit(s.to_owned())
    }

    fn sec(s: &str) -> Part {
        Part::Secret(s.to_owned())
    }

    #[test]
    fn splits_literals_and_references() {
        assert_eq!(parse_template(""), Ok(vec![]));
        assert_eq!(parse_template("plain"), Ok(vec![lit("plain")]));
        assert_eq!(
            parse_template("Bearer ${secret:tok}"),
            Ok(vec![lit("Bearer "), sec("tok")])
        );
        assert_eq!(
            parse_template("${secret:a}:${secret:b}!"),
            Ok(vec![sec("a"), lit(":"), sec("b"), lit("!")])
        );
    }

    #[test]
    fn rejects_malformed_placeholders() {
        assert_eq!(
            parse_template("${env:HOME}"),
            Err(TemplateError::UnknownInterpolation)
        );
        assert_eq!(
            parse_template("x ${secret:a"),
            Err(TemplateError::Unterminated)
        );
        assert_eq!(parse_template("${secret:}"), Err(TemplateError::EmptyName));
        // A lone `$` or `{` is literal text.
        assert_eq!(parse_template("$5 {x}"), Ok(vec![lit("$5 {x}")]));
    }

    #[test]
    fn expands_or_fails_closed() {
        let parts = parse_template("Bearer ${secret:tok}").unwrap();
        let found = |n: &str| (n == "tok").then(|| "s3cr3t".to_owned());
        assert_eq!(expand(&parts, found).as_deref(), Some("Bearer s3cr3t"));
        assert_eq!(expand(&parts, |_| None), None);
        assert_eq!(secret_names(&parts).collect::<Vec<_>>(), ["tok"]);
        assert!(has_secrets(&parts));
        assert!(!has_secrets(&parse_template("plain").unwrap()));
    }
}
