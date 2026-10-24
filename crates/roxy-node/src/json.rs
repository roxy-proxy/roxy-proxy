//! Diagnostics for JSON the node parses, kept free of the document's text.

use serde_json::error::Category;

/// Where a JSON document stopped deserialising, without any of its text.
/// serde's own message quotes the value it rejected, and in what the node
/// reads from its state dir or the control plane that value may be a token
/// or a lease secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonFault {
    pub category: Category,
    pub line: usize,
    pub column: usize,
}

impl From<serde_json::Error> for JsonFault {
    fn from(e: serde_json::Error) -> Self {
        Self {
            category: e.classify(),
            line: e.line(),
            column: e.column(),
        }
    }
}

impl std::fmt::Display for JsonFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let what = match self.category {
            Category::Io => "read error",
            Category::Syntax => "syntax error",
            Category::Data => "missing or unexpected value",
            Category::Eof => "unexpected end of input",
        };
        write!(f, "{what} at line {} column {}", self.line, self.column)
    }
}
