//! Hand-written lexer for the expression DSL (§6.2).
//!
//! Produces the whole token vector up front; the first error aborts.

use std::net::{IpAddr, Ipv6Addr};

use ipnet::IpNet;

use crate::ast::Unit;
use crate::diag::{ExprError, Span};

/// Longest expression accepted, in bytes. Generous for hand-written rules;
/// keeps spans in `u32` and bounds compile work.
pub(crate) const MAX_EXPR_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Tok {
    /// Field path segment (`host`, `client`, `ip`, metric ids).
    Ident(String),
    /// Bare `[A-Z][A-Z_]*` identifier: an HTTP method literal.
    Upper(String),
    Str(String),
    /// Integer as written plus its unit; the scaled value is checked to fit.
    Int(i64, Option<Unit>),
    Ip(IpAddr),
    Cidr(IpNet),
    /// `@name`: a named address list (§7.1).
    ListRef(String),
    True,
    False,
    And,
    Or,
    Not,
    In,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    StartsWith,
    EndsWith,
    Contains,
    Like,
    Matches,
    Under,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
    Dot,
    Eof,
}

impl Tok {
    /// How the token is shown in "found ..." messages.
    pub(crate) fn describe(&self) -> String {
        match self {
            Tok::Ident(s) | Tok::Upper(s) => format!("`{s}`"),
            Tok::Str(_) => "a string".into(),
            Tok::Int(..) => "a number".into(),
            Tok::Ip(_) => "an IP address".into(),
            Tok::Cidr(_) => "a CIDR".into(),
            Tok::ListRef(n) => format!("`@{n}`"),
            Tok::Eof => "end of expression".into(),
            other => format!("`{}`", other.symbol()),
        }
    }

    fn symbol(&self) -> &'static str {
        match self {
            Tok::True => "true",
            Tok::False => "false",
            Tok::And => "and",
            Tok::Or => "or",
            Tok::Not => "not",
            Tok::In => "in",
            Tok::Eq => "==",
            Tok::Ne => "!=",
            Tok::Lt => "<",
            Tok::Le => "<=",
            Tok::Gt => ">",
            Tok::Ge => ">=",
            Tok::StartsWith => "starts_with",
            Tok::EndsWith => "ends_with",
            Tok::Contains => "contains",
            Tok::Like => "like",
            Tok::Matches => "matches",
            Tok::Under => "under",
            Tok::LParen => "(",
            Tok::RParen => ")",
            Tok::LBracket => "[",
            Tok::RBracket => "]",
            Tok::Comma => ",",
            Tok::Dot => ".",
            _ => "?",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Token {
    pub tok: Tok,
    pub span: Span,
}

pub(crate) fn lex(src: &str) -> Result<Vec<Token>, ExprError> {
    if src.len() > MAX_EXPR_BYTES {
        return Err(ExprError::new(
            Span::new(0, 0),
            format!("expression is longer than {MAX_EXPR_BYTES} bytes"),
        ));
    }
    Lexer {
        src,
        bytes: src.as_bytes(),
        pos: 0,
        out: Vec::new(),
    }
    .run()
}

struct Lexer<'a> {
    src: &'a str,
    bytes: &'a [u8],
    pos: usize,
    out: Vec<Token>,
}

fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

impl Lexer<'_> {
    fn run(mut self) -> Result<Vec<Token>, ExprError> {
        loop {
            self.skip_trivia();
            let start = self.pos;
            let Some(&b) = self.bytes.get(self.pos) else {
                self.push(Tok::Eof, start);
                return Ok(self.out);
            };
            let tok = match b {
                b'(' => self.single(Tok::LParen),
                b')' => self.single(Tok::RParen),
                b'[' => self.single(Tok::LBracket),
                b']' => self.single(Tok::RBracket),
                b',' => self.single(Tok::Comma),
                b'.' => self.single(Tok::Dot),
                b'"' => self.string()?,
                b'@' => self.list_ref()?,
                b'=' | b'!' | b'<' | b'>' | b'&' | b'|' => self.operator()?,
                b':' => self.ipv6()?,
                b'0'..=b'9' if self.looks_like_ipv6() => self.ipv6()?,
                b'0'..=b'9' => self.number()?,
                b if b.is_ascii_hexdigit() && self.looks_like_ipv6() => self.ipv6()?,
                b if is_ident_start(b) => self.word(),
                _ => {
                    let c = self.src[start..].chars().next().unwrap_or('?');
                    return Err(ExprError::new(
                        Span::new(start, start + c.len_utf8()),
                        format!("unexpected character {c:?}"),
                    ));
                }
            };
            self.push(tok, start);
        }
    }

    fn push(&mut self, tok: Tok, start: usize) {
        self.out.push(Token {
            tok,
            span: Span::new(start, self.pos),
        });
    }

    fn single(&mut self, tok: Tok) -> Tok {
        self.pos += 1;
        tok
    }

    fn skip_trivia(&mut self) {
        while let Some(&b) = self.bytes.get(self.pos) {
            if b.is_ascii_whitespace() {
                self.pos += 1;
            } else if b == b'#' {
                while self.bytes.get(self.pos).is_some_and(|&b| b != b'\n') {
                    self.pos += 1;
                }
            } else {
                break;
            }
        }
    }

    #[allow(clippy::unused_self)] // method form reads better at call sites
    fn err<T>(&self, start: usize, end: usize, msg: impl Into<String>) -> Result<T, ExprError> {
        Err(ExprError::new(Span::new(start, end), msg))
    }

    fn operator(&mut self) -> Result<Tok, ExprError> {
        let start = self.pos;
        let two = self.bytes.get(start..start + 2).unwrap_or(&[]);
        let (tok, len) = match two {
            b"==" => (Tok::Eq, 2),
            b"!=" => (Tok::Ne, 2),
            b"<=" => (Tok::Le, 2),
            b">=" => (Tok::Ge, 2),
            b"&&" => return self.err(start, start + 2, "unexpected `&&`; use `and`"),
            b"||" => return self.err(start, start + 2, "unexpected `||`; use `or`"),
            _ => match self.bytes[start] {
                b'<' => (Tok::Lt, 1),
                b'>' => (Tok::Gt, 1),
                b'=' => return self.err(start, start + 1, "unexpected `=`; use `==`"),
                b'!' => {
                    return self.err(start, start + 1, "unexpected `!`; use `not` or `!=`");
                }
                _ => return self.err(start, start + 1, "unexpected character"),
            },
        };
        self.pos += len;
        Ok(tok)
    }

    fn string(&mut self) -> Result<Tok, ExprError> {
        let start = self.pos;
        self.pos += 1;
        let mut out = String::new();
        loop {
            let rest = &self.src[self.pos..];
            let Some(c) = rest.chars().next() else {
                return self.err(start, self.pos, "unterminated string");
            };
            match c {
                '"' => {
                    self.pos += 1;
                    return Ok(Tok::Str(out));
                }
                '\n' | '\r' => return self.err(start, self.pos, "unterminated string"),
                '\\' => {
                    let esc = rest[1..].chars().next();
                    match esc {
                        Some(e @ ('"' | '\\')) => {
                            out.push(e);
                            self.pos += 2;
                        }
                        None | Some('\n' | '\r') => {
                            return self.err(start, self.pos + 1, "unterminated string");
                        }
                        Some(e) => {
                            return self.err(
                                self.pos,
                                self.pos + 1 + e.len_utf8(),
                                format!(
                                    "unknown escape `\\{e}`; only `\\\"` and `\\\\` are \
                                     allowed (write `\\\\{e}` for a literal backslash, e.g. in \
                                     a regex)"
                                ),
                            );
                        }
                    }
                }
                c => {
                    out.push(c);
                    self.pos += c.len_utf8();
                }
            }
        }
    }

    /// `@name` with name `[A-Za-z_][A-Za-z0-9_-]*`.
    fn list_ref(&mut self) -> Result<Tok, ExprError> {
        let start = self.pos;
        self.pos += 1;
        if !self
            .bytes
            .get(self.pos)
            .copied()
            .is_some_and(is_ident_start)
        {
            return self.err(
                start,
                self.pos,
                "expected an address list name after `@`, e.g. @internal",
            );
        }
        while self
            .bytes
            .get(self.pos)
            .is_some_and(|&b| is_ident_char(b) || b == b'-')
        {
            self.pos += 1;
        }
        Ok(Tok::ListRef(self.src[start + 1..self.pos].to_owned()))
    }

    fn word(&mut self) -> Tok {
        let start = self.pos;
        while self.bytes.get(self.pos).copied().is_some_and(is_ident_char) {
            self.pos += 1;
        }
        let w = &self.src[start..self.pos];
        // After a `.` every word is a path segment, so `metric.in` works.
        if self.out.last().is_some_and(|t| t.tok == Tok::Dot) {
            return Tok::Ident(w.to_owned());
        }
        match w {
            "true" => Tok::True,
            "false" => Tok::False,
            "and" => Tok::And,
            "or" => Tok::Or,
            "not" => Tok::Not,
            "in" => Tok::In,
            "starts_with" => Tok::StartsWith,
            "ends_with" => Tok::EndsWith,
            "contains" => Tok::Contains,
            "like" => Tok::Like,
            "matches" => Tok::Matches,
            "under" => Tok::Under,
            _ if w.as_bytes()[0].is_ascii_uppercase()
                && w.bytes().all(|b| b.is_ascii_uppercase() || b == b'_') =>
            {
                Tok::Upper(w.to_owned())
            }
            _ => Tok::Ident(w.to_owned()),
        }
    }

    /// The run of characters that could form an IP literal, from `pos`.
    fn ip_run_end(&self) -> usize {
        let mut end = self.pos;
        while self
            .bytes
            .get(end)
            .is_some_and(|&b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
        {
            end += 1;
        }
        end
    }

    /// `:` never appears in the grammar except inside IPv6 literals, so a
    /// hex/colon run containing one is lexed as IPv6. A run followed by an
    /// identifier character (`fd00::x`) is not.
    fn looks_like_ipv6(&self) -> bool {
        let end = self.ip_run_end();
        self.bytes[self.pos..end].contains(&b':')
    }

    /// Optional `/<prefix>` after an address.
    fn prefix(&mut self) -> Result<Option<u8>, ExprError> {
        if self.bytes.get(self.pos) != Some(&b'/') {
            return Ok(None);
        }
        let slash = self.pos;
        self.pos += 1;
        let digits_start = self.pos;
        while self.bytes.get(self.pos).is_some_and(u8::is_ascii_digit) {
            self.pos += 1;
        }
        let digits = &self.src[digits_start..self.pos];
        if digits.is_empty() || digits.len() > 3 {
            return self.err(slash, self.pos, "expected a prefix length after `/`");
        }
        // At most three digits, so this always fits.
        let n: u16 = digits.parse().unwrap_or(u16::MAX);
        u8::try_from(n)
            .map(Some)
            .or_else(|_| self.err(slash, self.pos, format!("prefix length /{n} is too long")))
    }

    fn finish_ip(&mut self, start: usize, addr: IpAddr) -> Result<Tok, ExprError> {
        let Some(prefix) = self.prefix()? else {
            self.reject_trailing_ident(start)?;
            return Ok(Tok::Ip(addr));
        };
        self.reject_trailing_ident(start)?;
        let text = &self.src[start..self.pos];
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let net = IpNet::new(addr, prefix).or_else(|_| {
            self.err(
                start,
                self.pos,
                format!("invalid CIDR `{text}`: prefix length must be at most /{max}"),
            )
        })?;
        if net.trunc() != net {
            return self.err(
                start,
                self.pos,
                format!(
                    "invalid CIDR `{text}`: host bits are set; did you mean `{}`?",
                    net.trunc()
                ),
            );
        }
        Ok(Tok::Cidr(net))
    }

    fn reject_trailing_ident(&self, start: usize) -> Result<(), ExprError> {
        if self.bytes.get(self.pos).copied().is_some_and(is_ident_char) {
            let mut end = self.pos;
            while self.bytes.get(end).copied().is_some_and(is_ident_char) {
                end += 1;
            }
            return self.err(
                start,
                end,
                format!("invalid IP address `{}`", &self.src[start..end]),
            );
        }
        Ok(())
    }

    fn ipv6(&mut self) -> Result<Tok, ExprError> {
        let start = self.pos;
        self.pos = self.ip_run_end();
        let text = &self.src[start..self.pos];
        let addr: Ipv6Addr = text
            .parse()
            .or_else(|_| self.err(start, self.pos, format!("invalid IPv6 address `{text}`")))?;
        self.finish_ip(start, IpAddr::V6(addr))
    }

    fn number(&mut self) -> Result<Tok, ExprError> {
        let start = self.pos;
        while self.bytes.get(self.pos).is_some_and(u8::is_ascii_digit) {
            self.pos += 1;
        }
        if self.bytes.get(self.pos) == Some(&b'.')
            && self.bytes.get(self.pos + 1).is_some_and(u8::is_ascii_digit)
        {
            while self
                .bytes
                .get(self.pos)
                .is_some_and(|&b| b.is_ascii_digit() || b == b'.')
            {
                self.pos += 1;
            }
            let text = &self.src[start..self.pos];
            let addr: std::net::Ipv4Addr = text.parse().or_else(|_| {
                let hint = if text.matches('.').count() == 1 {
                    " (numbers must be whole; use a smaller unit, e.g. 1536kb)"
                } else {
                    ""
                };
                self.err(
                    start,
                    self.pos,
                    format!("invalid number or IPv4 address `{text}`{hint}"),
                )
            })?;
            return self.finish_ip(start, IpAddr::V4(addr));
        }
        let digits_end = self.pos;
        let digits = &self.src[start..digits_end];
        let value: i64 = digits
            .parse()
            .or_else(|_| self.err(start, digits_end, format!("number `{digits}` is too large")))?;
        while self.bytes.get(self.pos).copied().is_some_and(is_ident_char) {
            self.pos += 1;
        }
        let suffix = &self.src[digits_end..self.pos];
        let unit = if suffix.is_empty() {
            None
        } else {
            Some(Unit::from_suffix(suffix).ok_or_else(|| {
                ExprError::new(
                    Span::new(digits_end, self.pos),
                    format!(
                        "unknown unit `{suffix}`; expected kb, mb, gb (1024-based sizes) or \
                         ms, s, m, h (durations, in milliseconds)"
                    ),
                )
            })?)
        };
        if let Some(u) = unit
            && value.checked_mul(u.multiplier()).is_none()
        {
            return self.err(
                start,
                self.pos,
                format!("`{}` is too large", &self.src[start..self.pos]),
            );
        }
        Ok(Tok::Int(value, unit))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(src: &str) -> Vec<Tok> {
        lex(src).unwrap().into_iter().map(|t| t.tok).collect()
    }

    fn err(src: &str) -> String {
        lex(src).unwrap_err().message
    }

    #[test]
    fn basic_tokens() {
        assert_eq!(
            toks("host == \"a\\\"b\\\\\" and not x.y in [GET, 1] # c\n or"),
            vec![
                Tok::Ident("host".into()),
                Tok::Eq,
                Tok::Str("a\"b\\".into()),
                Tok::And,
                Tok::Not,
                Tok::Ident("x".into()),
                Tok::Dot,
                Tok::Ident("y".into()),
                Tok::In,
                Tok::LBracket,
                Tok::Upper("GET".into()),
                Tok::Comma,
                Tok::Int(1, None),
                Tok::RBracket,
                Tok::Or,
                Tok::Eof,
            ]
        );
    }

    #[test]
    fn operators() {
        assert_eq!(
            toks("== != < <= > >= starts_with ends_with contains like matches under"),
            vec![
                Tok::Eq,
                Tok::Ne,
                Tok::Lt,
                Tok::Le,
                Tok::Gt,
                Tok::Ge,
                Tok::StartsWith,
                Tok::EndsWith,
                Tok::Contains,
                Tok::Like,
                Tok::Matches,
                Tok::Under,
                Tok::Eof
            ]
        );
    }

    #[test]
    fn numbers_and_units() {
        assert_eq!(
            toks("5 500mb 1kb 2gb 10ms 3s 1m 2h"),
            vec![
                Tok::Int(5, None),
                Tok::Int(500, Some(Unit::Mb)),
                Tok::Int(1, Some(Unit::Kb)),
                Tok::Int(2, Some(Unit::Gb)),
                Tok::Int(10, Some(Unit::Ms)),
                Tok::Int(3, Some(Unit::S)),
                Tok::Int(1, Some(Unit::M)),
                Tok::Int(2, Some(Unit::H)),
                Tok::Eof
            ]
        );
        assert!(err("5parsecs").contains("unknown unit `parsecs`"));
        assert!(err("1.5mb").contains("whole"));
        assert!(err("99999999999999999999").contains("too large"));
        assert!(err("9999999999999gb").contains("too large"));
    }

    #[test]
    fn ips_and_cidrs() {
        assert_eq!(
            toks("10.0.0.0/8 fd00::/8 ::1 1.2.3.4 2001:db8::1"),
            vec![
                Tok::Cidr("10.0.0.0/8".parse().unwrap()),
                Tok::Cidr("fd00::/8".parse().unwrap()),
                Tok::Ip("::1".parse().unwrap()),
                Tok::Ip("1.2.3.4".parse().unwrap()),
                Tok::Ip("2001:db8::1".parse().unwrap()),
                Tok::Eof
            ]
        );
        assert!(err("10.0.0.0/33").contains("at most /32"));
        assert!(err("10.0.0.1/8").contains("did you mean `10.0.0.0/8`"));
        assert!(err("10.0.0/8").contains("invalid number or IPv4"));
        assert!(err("fd00::zz").contains("invalid IP address"));
        assert!(err("1::2::3").contains("invalid IPv6"));
        assert!(err("10.0.0.0/").contains("prefix length"));
        // Hex-looking identifiers are still identifiers.
        assert_eq!(toks("add"), vec![Tok::Ident("add".into()), Tok::Eof]);
    }

    #[test]
    fn words() {
        assert_eq!(
            toks("GET X_Y Host metric.in"),
            vec![
                Tok::Upper("GET".into()),
                Tok::Upper("X_Y".into()),
                Tok::Ident("Host".into()),
                Tok::Ident("metric".into()),
                Tok::Dot,
                Tok::Ident("in".into()),
                Tok::Eof
            ]
        );
    }

    #[test]
    fn list_refs() {
        assert_eq!(
            toks("client.ip in @internal-v4_2"),
            vec![
                Tok::Ident("client".into()),
                Tok::Dot,
                Tok::Ident("ip".into()),
                Tok::In,
                Tok::ListRef("internal-v4_2".into()),
                Tok::Eof
            ]
        );
        assert!(err("x in @").contains("address list name"));
        assert!(err("x in @1x").contains("address list name"));
    }

    #[test]
    fn string_errors() {
        assert_eq!(err("\"abc"), "unterminated string");
        assert_eq!(err("\"abc\ndef\""), "unterminated string");
        assert!(err(r#""\d+""#).contains("unknown escape `\\d`"));
        assert!(err("a = b").contains("use `==`"));
        assert!(err("a && b").contains("use `and`"));
        assert!(err("a $ b").contains("unexpected character '$'"));
    }

    #[test]
    fn spans() {
        let t = lex("  host\n == \"x\"").unwrap();
        assert_eq!(t[0].span, Span::new(2, 6));
        assert_eq!(t[1].span, Span::new(8, 10));
        assert_eq!(t[2].span, Span::new(11, 14));
    }
}
