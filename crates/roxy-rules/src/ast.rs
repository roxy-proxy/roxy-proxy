//! Expression syntax tree, pretty-printer and S-expression dump.
//!
//! The pretty-printer ([`fmt::Display`] on [`Node`]) emits canonical source
//! that parses back to the same tree (modulo spans): `parse(print(e)) == e`.

use std::fmt::{self, Write as _};
use std::net::IpAddr;

use ipnet::IpNet;

use crate::diag::Span;

/// Unit suffix on an integer literal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unit {
    Kb,
    Mb,
    Gb,
    Ms,
    S,
    M,
    H,
}

impl Unit {
    pub(crate) fn from_suffix(s: &str) -> Option<Self> {
        Some(match s {
            "kb" => Self::Kb,
            "mb" => Self::Mb,
            "gb" => Self::Gb,
            "ms" => Self::Ms,
            "s" => Self::S,
            "m" => Self::M,
            "h" => Self::H,
            _ => return None,
        })
    }

    pub fn suffix(self) -> &'static str {
        match self {
            Self::Kb => "kb",
            Self::Mb => "mb",
            Self::Gb => "gb",
            Self::Ms => "ms",
            Self::S => "s",
            Self::M => "m",
            Self::H => "h",
        }
    }

    /// Sizes are 1024-based bytes; durations are milliseconds.
    pub fn multiplier(self) -> i64 {
        match self {
            Self::Kb => 1 << 10,
            Self::Mb => 1 << 20,
            Self::Gb => 1 << 30,
            Self::Ms => 1,
            Self::S => 1_000,
            Self::M => 60_000,
            Self::H => 3_600_000,
        }
    }
}

/// Comparison operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    In,
    NotIn,
    StartsWith,
    EndsWith,
    Contains,
    Like,
    Matches,
    Under,
}

impl Op {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Gt => ">",
            Self::Ge => ">=",
            Self::In => "in",
            Self::NotIn => "not in",
            Self::StartsWith => "starts_with",
            Self::EndsWith => "ends_with",
            Self::Contains => "contains",
            Self::Like => "like",
            Self::Matches => "matches",
            Self::Under => "under",
        }
    }
}

/// A literal value as written.
#[derive(Debug, Clone, PartialEq)]
pub enum Lit {
    Str(String),
    /// The number as written and its unit; see [`Lit::int_value`].
    Int(i64, Option<Unit>),
    Bool(bool),
    List(Vec<LitNode>),
    Ip(IpAddr),
    Cidr(IpNet),
    /// `@name`: a named address list, only valid after `in` / `not in`
    /// with an ip operand (docs/upstream.md#address-lists).
    AddressList(String),
    /// Bare uppercase identifier: an HTTP method.
    Method(String),
    /// `null`: compared with `==` / `!=` to test whether a value is present.
    Null,
}

impl Lit {
    /// Scaled integer value (the lexer guarantees it does not overflow).
    pub fn int_value(raw: i64, unit: Option<Unit>) -> i64 {
        unit.map_or(raw, |u| raw.saturating_mul(u.multiplier()))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LitNode {
    pub lit: Lit,
    pub span: Span,
}

/// A field reference: dotted path plus optional `["index"]`.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldRef {
    pub path: Vec<String>,
    pub index: Option<String>,
    pub span: Span,
}

impl FieldRef {
    /// `a.b.c` without the index.
    pub fn dotted(&self) -> String {
        self.path.join(".")
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Operand {
    Field(FieldRef),
    Lit(LitNode),
}

impl Operand {
    pub fn span(&self) -> Span {
        match self {
            Self::Field(f) => f.span,
            Self::Lit(l) => l.span,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Or(Box<Node>, Box<Node>),
    And(Box<Node>, Box<Node>),
    Not(Box<Node>),
    Cmp {
        lhs: Operand,
        op: Op,
        rhs: Operand,
    },
    /// A bare operand used as a condition (`tag["x"]`, `true`).
    Pred(Operand),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Node {
    pub expr: Expr,
    pub span: Span,
}

impl Node {
    /// A copy with every span zeroed, for structural comparison.
    #[must_use]
    pub fn strip_spans(&self) -> Node {
        fn lit(l: &LitNode) -> LitNode {
            LitNode {
                lit: match &l.lit {
                    Lit::List(items) => Lit::List(items.iter().map(lit).collect()),
                    other => other.clone(),
                },
                span: Span::default(),
            }
        }
        fn operand(o: &Operand) -> Operand {
            match o {
                Operand::Field(f) => Operand::Field(FieldRef {
                    span: Span::default(),
                    ..f.clone()
                }),
                Operand::Lit(l) => Operand::Lit(lit(l)),
            }
        }
        let expr = match &self.expr {
            Expr::Or(a, b) => Expr::Or(Box::new(a.strip_spans()), Box::new(b.strip_spans())),
            Expr::And(a, b) => Expr::And(Box::new(a.strip_spans()), Box::new(b.strip_spans())),
            Expr::Not(a) => Expr::Not(Box::new(a.strip_spans())),
            Expr::Cmp { lhs, op, rhs } => Expr::Cmp {
                lhs: operand(lhs),
                op: *op,
                rhs: operand(rhs),
            },
            Expr::Pred(o) => Expr::Pred(operand(o)),
        };
        Node {
            expr,
            span: Span::default(),
        }
    }

    /// Compact S-expression form used by golden tests.
    pub fn sexpr(&self) -> String {
        let mut out = String::new();
        write_sexpr(self, &mut out);
        out
    }

    fn precedence(&self) -> u8 {
        match self.expr {
            Expr::Or(..) => 1,
            Expr::And(..) => 2,
            Expr::Not(_) => 3,
            Expr::Cmp { .. } | Expr::Pred(_) => 4,
        }
    }

    fn write_prec(&self, min: u8, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let paren = self.precedence() < min;
        if paren {
            f.write_char('(')?;
        }
        match &self.expr {
            // Left-associative: the right child of `a or b` needs parens if
            // it is itself an `or`, so the tree shape survives a round trip.
            Expr::Or(a, b) => {
                a.write_prec(1, f)?;
                f.write_str(" or ")?;
                b.write_prec(2, f)?;
            }
            Expr::And(a, b) => {
                a.write_prec(2, f)?;
                f.write_str(" and ")?;
                b.write_prec(3, f)?;
            }
            Expr::Not(a) => {
                f.write_str("not ")?;
                // `not (a in [..])` rather than `not a in [..]`, which reads
                // like `not in`. Both parse to the same tree.
                let min = if matches!(a.expr, Expr::Cmp { .. }) {
                    5
                } else {
                    3
                };
                a.write_prec(min, f)?;
            }
            Expr::Cmp { lhs, op, rhs } => write!(f, "{lhs} {} {rhs}", op.as_str())?,
            Expr::Pred(o) => write!(f, "{o}")?,
        }
        if paren {
            f.write_char(')')?;
        }
        Ok(())
    }
}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_prec(0, f)
    }
}

pub(crate) fn write_str_lit(s: &str, f: &mut impl fmt::Write) -> fmt::Result {
    f.write_char('"')?;
    for c in s.chars() {
        if c == '"' || c == '\\' {
            f.write_char('\\')?;
        }
        f.write_char(c)?;
    }
    f.write_char('"')
}

impl fmt::Display for Lit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Lit::Str(s) => write_str_lit(s, f),
            Lit::Int(n, unit) => write!(f, "{n}{}", unit.map_or("", Unit::suffix)),
            Lit::Bool(b) => write!(f, "{b}"),
            Lit::List(items) => {
                f.write_char('[')?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{}", item.lit)?;
                }
                f.write_char(']')
            }
            Lit::Ip(ip) => write!(f, "{ip}"),
            Lit::Cidr(net) => write!(f, "{net}"),
            Lit::AddressList(n) => write!(f, "@{n}"),
            Lit::Method(m) => f.write_str(m),
            Lit::Null => f.write_str("null"),
        }
    }
}

impl fmt::Display for FieldRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.dotted())?;
        if let Some(index) = &self.index {
            f.write_char('[')?;
            write_str_lit(index, f)?;
            f.write_char(']')?;
        }
        Ok(())
    }
}

impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operand::Field(field) => write!(f, "{field}"),
            Operand::Lit(l) => write!(f, "{}", l.lit),
        }
    }
}

fn write_sexpr(node: &Node, out: &mut String) {
    // Writing to a String cannot fail.
    let _ = match &node.expr {
        Expr::Or(a, b) | Expr::And(a, b) => {
            let name = if matches!(node.expr, Expr::Or(..)) {
                "or"
            } else {
                "and"
            };
            let _ = write!(out, "({name} ");
            write_sexpr(a, out);
            out.push(' ');
            write_sexpr(b, out);
            write!(out, ")")
        }
        Expr::Not(a) => {
            out.push_str("(not ");
            write_sexpr(a, out);
            write!(out, ")")
        }
        Expr::Cmp { lhs, op, rhs } => {
            write!(
                out,
                "({} {} {})",
                op.as_str(),
                sexpr_operand(lhs),
                sexpr_operand(rhs)
            )
        }
        Expr::Pred(o) => write!(out, "(pred {})", sexpr_operand(o)),
    };
}

fn sexpr_operand(o: &Operand) -> String {
    match o {
        Operand::Field(f) => format!("field:{f}"),
        Operand::Lit(l) => sexpr_lit(&l.lit),
    }
}

fn sexpr_lit(l: &Lit) -> String {
    match l {
        Lit::Str(_) => format!("str:{l}"),
        Lit::Int(n, unit) => format!("int:{}", Lit::int_value(*n, *unit)),
        Lit::Bool(b) => format!("bool:{b}"),
        Lit::List(items) => format!(
            "[{}]",
            items
                .iter()
                .map(|i| sexpr_lit(&i.lit))
                .collect::<Vec<_>>()
                .join(" ")
        ),
        Lit::Ip(ip) => format!("ip:{ip}"),
        Lit::Cidr(net) => format!("cidr:{net}"),
        Lit::AddressList(n) => format!("list:@{n}"),
        Lit::Null => "null".into(),
        Lit::Method(m) => format!("method:{m}"),
    }
}
