//! Rule ids, source spans and compile diagnostics.

use std::borrow::Borrow;
use std::fmt;
use std::sync::Arc;

/// A byte range `[start, end)` within one expression's source text.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Span {
    pub start: u32,
    pub end: u32,
}

impl Span {
    pub(crate) fn new(start: usize, end: usize) -> Self {
        // Expressions longer than 4 GiB are rejected by the lexer long before
        // this could truncate.
        let clamp = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
        Self {
            start: clamp(start),
            end: clamp(end),
        }
    }

    /// The smallest span covering both.
    pub(crate) fn to(self, other: Span) -> Span {
        Span {
            start: self.start.min(other.start),
            end: self.end.max(other.end),
        }
    }
}

/// A problem found while lexing, parsing or type-checking one expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExprError {
    pub span: Span,
    pub message: String,
}

impl ExprError {
    pub(crate) fn new(span: Span, message: impl Into<String>) -> Self {
        Self {
            span,
            message: message.into(),
        }
    }
}

/// A rule's id. Cheap to clone (shared string), so it can be recorded in
/// every [`crate::Outcome`] without copying.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RuleId(Arc<str>);

impl RuleId {
    /// The id reported when a chain is exhausted without a terminal action.
    pub const DEFAULT: &'static str = "_default";
    /// The id reported when evaluation failed closed because a policy input
    /// (metric, address list, secret) was unavailable.
    pub const FAIL_CLOSED: &'static str = "_fail_closed";

    pub fn new(id: &str) -> Self {
        Self(Arc::from(id))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this is the reserved `_default` id.
    pub fn is_default(&self) -> bool {
        &*self.0 == Self::DEFAULT
    }
}

impl fmt::Debug for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&*self.0, f)
    }
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Borrow<str> for RuleId {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for RuleId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for RuleId {
    fn eq(&self, other: &str) -> bool {
        &*self.0 == other
    }
}

impl PartialEq<&str> for RuleId {
    fn eq(&self, other: &&str) -> bool {
        &*self.0 == *other
    }
}

/// One problem found while compiling a policy.
///
/// `path` locates the YAML node (`rules[3].when`, `rules[0].then[1]`,
/// `metrics[2].key[0]`). For expression errors `line`/`col` are the 1-based
/// position *within the expression text* and `snippet` shows the offending
/// line with a caret underline; for other errors `line` and `col` are 0 and
/// `snippet` is `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub rule: Option<RuleId>,
    pub path: String,
    pub line: u32,
    pub col: u32,
    pub message: String,
    pub snippet: Option<String>,
}

impl Diagnostic {
    /// A diagnostic without a source position.
    pub fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            rule: None,
            path: path.into(),
            line: 0,
            col: 0,
            message: message.into(),
            snippet: None,
        }
    }

    /// Attach the rule the diagnostic belongs to.
    #[must_use]
    pub fn with_rule(mut self, rule: Option<RuleId>) -> Self {
        self.rule = rule;
        self
    }

    /// A diagnostic for an expression error, with position and snippet.
    pub(crate) fn from_expr(path: impl Into<String>, src: &str, err: ExprError) -> Self {
        let (line, col, snippet) = locate(src, err.span);
        Self {
            rule: None,
            path: path.into(),
            line,
            col,
            message: err.message,
            snippet: Some(snippet),
        }
    }

    /// Whether `line`/`col` carry a position.
    pub fn has_position(&self) -> bool {
        self.line > 0
    }
}

impl fmt::Display for Diagnostic {
    /// `path: message`, or `path:line:col: message` for expression errors.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.has_position() {
            write!(
                f,
                "{}:{}:{}: {}",
                self.path, self.line, self.col, self.message
            )
        } else {
            write!(f, "{}: {}", self.path, self.message)
        }
    }
}

/// 1-based line and column (in characters) of `span.start`, plus a two-line
/// snippet: the source line and a caret underline of the span (clipped to
/// that line, at least one caret).
fn locate(src: &str, span: Span) -> (u32, u32, String) {
    let start = (span.start as usize).min(src.len());
    let start = floor_char_boundary(src, start);
    let line_start = src[..start].rfind('\n').map_or(0, |i| i + 1);
    let line_end = src[start..].find('\n').map_or(src.len(), |i| start + i);
    let line_no = src[..line_start].matches('\n').count() + 1;
    let line_text = &src[line_start..line_end];
    let prefix = &src[line_start..start];
    let col = prefix.chars().count() + 1;
    let end = floor_char_boundary(src, (span.end as usize).clamp(start, line_end));
    let width = src[start..end].chars().count().max(1);
    // Keep tabs in the padding so the caret lines up under tab-indented text.
    let pad: String = prefix
        .chars()
        .map(|c| if c == '\t' { '\t' } else { ' ' })
        .collect();
    let snippet = format!("{line_text}\n{pad}{}", "^".repeat(width));
    let clamp = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
    (clamp(line_no), clamp(col), snippet)
}

fn floor_char_boundary(s: &str, mut i: usize) -> usize {
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locate_multiline() {
        let src = "host == \"a\"\n  and port == \"x\"";
        let (line, col, snip) = locate(src, Span::new(26, 29));
        assert_eq!((line, col), (2, 15));
        assert_eq!(snip, "  and port == \"x\"\n              ^^^");
    }

    #[test]
    fn locate_eof() {
        let (line, col, snip) = locate("host ==", Span::new(7, 7));
        assert_eq!((line, col), (1, 8));
        assert_eq!(snip, "host ==\n       ^");
    }

    #[test]
    fn display() {
        let d = Diagnostic::new("rules[0].then[1]", "boom");
        assert_eq!(d.to_string(), "rules[0].then[1]: boom");
        let d = Diagnostic::from_expr("rules[0].when", "x", ExprError::new(Span::new(0, 1), "bad"));
        assert_eq!(d.to_string(), "rules[0].when:1:1: bad");
    }
}
