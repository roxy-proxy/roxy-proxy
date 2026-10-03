//! Pratt parser for the expression DSL (docs/rules.md#expressions).
//!
//! ```text
//! expr        := or
//! or          := and ( "or" and )*
//! and         := not ( "and" not )*
//! not         := "not" not | primary
//! primary     := "(" expr ")" | comparison | predicate
//! comparison  := operand OP operand
//! predicate   := operand            ; must be boolean (type-checked later)
//! operand     := field | field "[" string "]" | literal
//! ```
//!
//! `and` binds tighter than `or`; `not` tighter than both; comparisons are
//! non-associative (`a == b == c` is an error).

use crate::ast::{Expr, FieldRef, Lit, LitNode, Node, Op, Operand};
use crate::diag::{ExprError, Span};
use crate::lexer::{Tok, Token, lex};

/// Maximum nesting of parentheses, `not` and lists. Hand-written rules never
/// come close; the bound keeps recursion (and the stack) small.
pub(crate) const MAX_DEPTH: usize = 64;

/// Parse one expression.
pub fn parse(src: &str) -> Result<Node, crate::Diagnostic> {
    parse_inner(src).map_err(|e| crate::Diagnostic::from_expr("<expr>", src, e))
}

pub(crate) fn parse_inner(src: &str) -> Result<Node, ExprError> {
    let tokens = lex(src)?;
    let mut p = Parser {
        tokens,
        pos: 0,
        depth: 0,
    };
    let node = p.expr(0)?;
    let t = p.peek();
    if t.tok != Tok::Eof {
        let hint = if is_cmp_start(&t.tok) {
            "; comparisons cannot be chained, combine them with `and`/`or`"
        } else {
            ""
        };
        return Err(ExprError::new(
            t.span,
            format!("unexpected {} after expression{hint}", t.tok.describe()),
        ));
    }
    Ok(node)
}

fn is_cmp_start(t: &Tok) -> bool {
    matches!(
        t,
        Tok::Eq
            | Tok::Ne
            | Tok::Lt
            | Tok::Le
            | Tok::Gt
            | Tok::Ge
            | Tok::In
            | Tok::StartsWith
            | Tok::EndsWith
            | Tok::Contains
            | Tok::Like
            | Tok::Matches
            | Tok::Under
    )
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    depth: usize,
}

impl Parser {
    fn peek(&self) -> &Token {
        // The token vector always ends with Eof and we never advance past it.
        &self.tokens[self.pos.min(self.tokens.len() - 1)]
    }

    fn peek_at(&self, n: usize) -> &Tok {
        &self.tokens[(self.pos + n).min(self.tokens.len() - 1)].tok
    }

    fn bump(&mut self) -> Token {
        let t = self.peek().clone();
        if t.tok != Tok::Eof {
            self.pos += 1;
        }
        t
    }

    fn enter(&mut self, span: Span) -> Result<(), ExprError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(ExprError::new(
                span,
                format!("expression is nested more than {MAX_DEPTH} levels deep"),
            ));
        }
        Ok(())
    }

    fn expect(&mut self, want: &Tok, what: &str) -> Result<Token, ExprError> {
        let t = self.peek();
        if &t.tok == want {
            Ok(self.bump())
        } else {
            Err(ExprError::new(
                t.span,
                format!("expected {what}, found {}", t.tok.describe()),
            ))
        }
    }

    /// Pratt loop over the binary boolean operators.
    fn expr(&mut self, min_bp: u8) -> Result<Node, ExprError> {
        let mut lhs = self.prefix()?;
        loop {
            let (l_bp, r_bp, is_or) = match self.peek().tok {
                Tok::Or => (1, 2, true),
                Tok::And => (3, 4, false),
                _ => break,
            };
            if l_bp < min_bp {
                break;
            }
            self.bump();
            let rhs = self.expr(r_bp)?;
            let span = lhs.span.to(rhs.span);
            let (a, b) = (Box::new(lhs), Box::new(rhs));
            lhs = Node {
                expr: if is_or {
                    Expr::Or(a, b)
                } else {
                    Expr::And(a, b)
                },
                span,
            };
        }
        Ok(lhs)
    }

    fn prefix(&mut self) -> Result<Node, ExprError> {
        let t = self.peek().clone();
        match t.tok {
            Tok::Not => {
                self.bump();
                self.enter(t.span)?;
                // Binding power above `and` so `not a and b` is `(not a) and b`.
                let inner = self.expr(5)?;
                self.depth -= 1;
                Ok(Node {
                    span: t.span.to(inner.span),
                    expr: Expr::Not(Box::new(inner)),
                })
            }
            Tok::LParen => {
                self.bump();
                self.enter(t.span)?;
                let inner = self.expr(0)?;
                self.expect(&Tok::RParen, "`)`")?;
                self.depth -= 1;
                Ok(inner)
            }
            _ => self.comparison(),
        }
    }

    fn comparison(&mut self) -> Result<Node, ExprError> {
        let lhs = self.operand()?;
        let Some(op) = self.cmp_op()? else {
            return Ok(Node {
                span: lhs.span(),
                expr: Expr::Pred(lhs),
            });
        };
        let rhs = self.operand()?;
        Ok(Node {
            span: lhs.span().to(rhs.span()),
            expr: Expr::Cmp { lhs, op, rhs },
        })
    }

    fn cmp_op(&mut self) -> Result<Option<Op>, ExprError> {
        let t = self.peek().clone();
        let op = match t.tok {
            Tok::Eq => Op::Eq,
            Tok::Ne => Op::Ne,
            Tok::Lt => Op::Lt,
            Tok::Le => Op::Le,
            Tok::Gt => Op::Gt,
            Tok::Ge => Op::Ge,
            Tok::In => Op::In,
            Tok::StartsWith => Op::StartsWith,
            Tok::EndsWith => Op::EndsWith,
            Tok::Contains => Op::Contains,
            Tok::Like => Op::Like,
            Tok::Matches => Op::Matches,
            Tok::Under => Op::Under,
            Tok::Not => {
                if *self.peek_at(1) == Tok::In {
                    self.bump();
                    self.bump();
                    return Ok(Some(Op::NotIn));
                }
                return Err(ExprError::new(
                    t.span,
                    "unexpected `not` after an operand; did you mean `not in`?",
                ));
            }
            _ => return Ok(None),
        };
        self.bump();
        Ok(Some(op))
    }

    fn operand(&mut self) -> Result<Operand, ExprError> {
        if let Tok::Ident(_) = self.peek().tok {
            return self.field().map(Operand::Field);
        }
        self.literal().map(Operand::Lit)
    }

    fn field(&mut self) -> Result<FieldRef, ExprError> {
        let first = self.bump();
        let Tok::Ident(name) = first.tok else {
            unreachable!("field() is only called on an identifier");
        };
        let mut path = vec![name];
        let mut span = first.span;
        while self.peek().tok == Tok::Dot {
            self.bump();
            let t = self.bump();
            match t.tok {
                Tok::Ident(seg) => {
                    path.push(seg);
                    span = span.to(t.span);
                }
                other => {
                    return Err(ExprError::new(
                        t.span,
                        format!(
                            "expected a field name after `.`, found {}",
                            other.describe()
                        ),
                    ));
                }
            }
        }
        let mut index = None;
        if self.peek().tok == Tok::LBracket {
            self.bump();
            let t = self.bump();
            let Tok::Str(key) = t.tok else {
                return Err(ExprError::new(
                    t.span,
                    format!(
                        "expected a quoted name inside `[...]`, e.g. header[\"user-agent\"], \
                         found {}",
                        t.tok.describe()
                    ),
                ));
            };
            let close = self.expect(&Tok::RBracket, "`]`")?;
            span = span.to(close.span);
            index = Some(key);
        }
        Ok(FieldRef { path, index, span })
    }

    fn literal(&mut self) -> Result<LitNode, ExprError> {
        let t = self.bump();
        let lit = match t.tok {
            Tok::Str(s) => Lit::Str(s),
            Tok::Int(n, unit) => Lit::Int(n, unit),
            Tok::True => Lit::Bool(true),
            Tok::Null => Lit::Null,
            Tok::False => Lit::Bool(false),
            Tok::Ip(ip) => Lit::Ip(ip),
            Tok::Cidr(net) => Lit::Cidr(net),
            Tok::ListRef(n) => Lit::AddressList(n),
            Tok::Upper(m) => Lit::Method(m),
            Tok::LBracket => return self.list(t.span),
            other => {
                return Err(ExprError::new(
                    t.span,
                    format!("expected a field or a value, found {}", other.describe()),
                ));
            }
        };
        Ok(LitNode { lit, span: t.span })
    }

    fn list(&mut self, open: Span) -> Result<LitNode, ExprError> {
        self.enter(open)?;
        if self.peek().tok == Tok::RBracket {
            return Err(ExprError::new(
                open.to(self.peek().span),
                "a list needs at least one element",
            ));
        }
        let mut items = Vec::new();
        loop {
            if let Tok::Ident(_) = self.peek().tok {
                let f = self.field()?;
                return Err(ExprError::new(
                    f.span,
                    format!("lists may only contain literal values, not fields like `{f}`"),
                ));
            }
            items.push(self.literal()?);
            let t = self.bump();
            match t.tok {
                Tok::Comma => {}
                Tok::RBracket => {
                    self.depth -= 1;
                    return Ok(LitNode {
                        lit: Lit::List(items),
                        span: open.to(t.span),
                    });
                }
                other => {
                    return Err(ExprError::new(
                        t.span,
                        format!("expected `,` or `]` in list, found {}", other.describe()),
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sx(src: &str) -> String {
        parse_inner(src).unwrap().sexpr()
    }

    fn err(src: &str) -> String {
        parse_inner(src).unwrap_err().message
    }

    #[test]
    fn precedence() {
        assert_eq!(
            sx("a == 1 or b == 2 and not c == 3"),
            "(or (== field:a int:1) (and (== field:b int:2) (not (== field:c int:3))))"
        );
        assert_eq!(
            sx("not a == 1 and b == 2"),
            "(and (not (== field:a int:1)) (== field:b int:2))"
        );
        assert_eq!(
            sx("(a == 1 or b == 2) and c == 3"),
            "(and (or (== field:a int:1) (== field:b int:2)) (== field:c int:3))"
        );
        assert_eq!(
            sx("a or b or c"),
            "(or (or (pred field:a) (pred field:b)) (pred field:c))"
        );
        assert_eq!(sx("not not true"), "(not (not (pred bool:true)))");
    }

    #[test]
    fn operands() {
        assert_eq!(
            sx(r#"header["X-Y"] not in ["a", "b"]"#),
            r#"(not in field:header["X-Y"] [str:"a" str:"b"])"#
        );
        assert_eq!(
            sx("metric.egress_bytes > 500mb"),
            "(> field:metric.egress_bytes int:524288000)"
        );
        assert_eq!(
            sx("client.ip in [10.0.0.0/8, ::1]"),
            "(in field:client.ip [cidr:10.0.0.0/8 ip:::1])"
        );
        assert_eq!(sx("method == GET"), "(== field:method method:GET)");
    }

    #[test]
    fn errors() {
        assert!(err("a == ").contains("found end of expression"));
        assert!(err("a == 1 == 2").contains("cannot be chained"));
        assert!(err("(a == 1").contains("expected `)`"));
        assert!(err("a not 1").contains("did you mean `not in`"));
        assert!(err("a in []").contains("at least one element"));
        assert!(err("a in [1 2]").contains("expected `,` or `]`"));
        assert!(err("a in [b]").contains("only contain literal"));
        assert!(err("header[x]").contains("quoted name"));
        assert!(err("a.==").contains("field name after `.`"));
        assert!(err("== a").contains("expected a field or a value"));
        assert!(err("a b").contains("unexpected `b` after expression"));
        let deep = format!("{}true{}", "(".repeat(100), ")".repeat(100));
        assert!(err(&deep).contains("nested more than"));
        let deep = format!("{}true", "not ".repeat(100));
        assert!(err(&deep).contains("nested more than"));
    }

    #[test]
    fn spans() {
        let n = parse_inner("  host == \"x\"").unwrap();
        assert_eq!(n.span, Span::new(2, 13));
        let n = parse_inner("header[\"a\"] == \"b\"").unwrap();
        let Expr::Cmp { lhs, .. } = n.expr else {
            panic!()
        };
        assert_eq!(lhs.span(), Span::new(0, 11));
    }

    #[test]
    fn pretty_print_round_trips() {
        for src in [
            "a == 1 or b == 2 and not c == 3",
            "(a or b) and c",
            "a or (b or c)",
            "not (a and b)",
            r#"header["x\"y\\"] like "*.example.com""#,
            "x in [1kb, 2, 3h]",
            "client.ip not in [10.0.0.0/8, fd00::/8, 1.2.3.4]",
            "tag[\"t\"] and true",
        ] {
            let ast = parse_inner(src).unwrap();
            let printed = ast.to_string();
            let again = parse_inner(&printed).unwrap();
            assert_eq!(ast.strip_spans(), again.strip_spans(), "{src} -> {printed}");
        }
        assert_eq!(
            parse_inner("a or (b or c)").unwrap().to_string(),
            "a or (b or c)"
        );
        assert_eq!(
            parse_inner("(a or b) or c").unwrap().to_string(),
            "a or b or c"
        );
    }
}
