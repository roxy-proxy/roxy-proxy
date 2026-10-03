//! Parser golden tests and property tests.

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;
use proptest::prelude::*;
use roxy_rules::Span;
use roxy_rules::ast::{Expr, FieldRef, Lit, LitNode, Node, Op, Operand, Unit};

#[test]
fn parser_golden() {
    let cases = [
        r#"host == "api.openai.com" and path starts_with "/v1/" and method == POST"#,
        r#"host under "github.com" and method in [GET, HEAD]"#,
        r#"host in ["pypi.org", "files.pythonhosted.org"] and method == GET"#,
        "metric.github_writes >= 30 and host under \"api.github.com\"",
        "metric.egress_bytes > 500mb",
        "response.status >= 500",
        "true",
        r#"header["Upgrade"] == "websocket""#,
        r#"header.all["accept"] contains "json""#,
        r#"not (client.ip in [10.0.0.0/8, fd00::/8]) or client.user == "ci""#,
        "client.ip not in [192.168.0.0/16, 127.0.0.1, ::1]",
        r#"path like "/repos/*/issues" and query["page"] != "1""#,
        r#"url matches "https://[a-z]+\\.example\\.com/.*""#,
        r#"tag["billing"] and not tag["internal"]"#,
        r#"state["mode"] == "lockdown""#,
        "ws.size <= 16kb and ws.opcode == 1",
        "a == 1 or b == 2 or c == 3 and d == 4",
        "not not tls.sni ends_with \".internal\"",
        "dst.port in [443, 8443] # trailing comment",
        "body.size < 1mb and body.text contains \"\\\"secret\\\\\"",
        "listener.name == \"proxy\"\n  and (scheme == \"https\"\n       or port == 80)",
        "response.header[\"content-type\"] starts_with \"text/\"",
        "client.ip in @internal",
        "dst.ip not in @blocked-v6 or client.ip in [10.0.0.0/8]",
    ];
    let mut out = String::new();
    for src in cases {
        let node = roxy_rules::parse(src).unwrap_or_else(|d| panic!("{src}: {d}"));
        writeln!(out, "{src}\n  sexpr:  {}\n  pretty: {node}\n", node.sexpr()).unwrap();
    }
    insta::assert_snapshot!("parser_golden", out);
}

#[test]
fn parse_error_golden() {
    let cases = [
        "",
        "host ==",
        "host == \"unterminated",
        "host = \"a\"",
        "(host == \"a\"",
        "host == \"a\" == \"b\"",
        "method in [GET HEAD]",
        "client.ip in [10.0.0.0/33]",
        "path matches \"\\d+\"",
        "port == 5parsecs",
        "a not b",
        "x\n  and y ==\n  and z",
    ];
    let mut out = String::new();
    for src in cases {
        let d = roxy_rules::parse(src).expect_err(src);
        writeln!(
            out,
            "{src:?}\n  {}:{}: {}\n{}\n",
            d.line,
            d.col,
            d.message,
            indent(d.snippet.as_deref().unwrap_or(""))
        )
        .unwrap();
    }
    insta::assert_snapshot!("parse_error_golden", out);
}

fn indent(s: &str) -> String {
    s.lines()
        .map(|l| format!("  | {l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

// ----- property tests -------------------------------------------------------

const KEYWORDS: &[&str] = &[
    "and",
    "or",
    "not",
    "in",
    "true",
    "false",
    "starts_with",
    "ends_with",
    "contains",
    "like",
    "matches",
    "under",
];

fn segment() -> impl Strategy<Value = String> {
    "[a-z_][a-z0-9_]{0,6}".prop_filter("keyword", |s| !KEYWORDS.contains(&s.as_str()))
}

fn string() -> impl Strategy<Value = String> {
    "[^\n\r]{0,8}"
}

fn field() -> impl Strategy<Value = Operand> {
    (
        prop::collection::vec(segment(), 1..4),
        prop::option::of(string()),
    )
        .prop_map(|(path, index)| {
            Operand::Field(FieldRef {
                path,
                index,
                span: Span::default(),
            })
        })
}

fn unit() -> impl Strategy<Value = Option<Unit>> {
    prop_oneof![
        Just(None),
        Just(Some(Unit::Kb)),
        Just(Some(Unit::Mb)),
        Just(Some(Unit::Gb)),
        Just(Some(Unit::Ms)),
        Just(Some(Unit::S)),
        Just(Some(Unit::M)),
        Just(Some(Unit::H)),
    ]
}

fn scalar_lit() -> impl Strategy<Value = Lit> {
    prop_oneof![
        string().prop_map(Lit::Str),
        (0..i64::MAX >> 31, unit()).prop_map(|(n, u)| Lit::Int(n, u)),
        any::<bool>().prop_map(Lit::Bool),
        any::<Ipv4Addr>().prop_map(|ip| Lit::Ip(IpAddr::V4(ip))),
        any::<Ipv6Addr>().prop_map(|ip| Lit::Ip(IpAddr::V6(ip))),
        (any::<Ipv4Addr>(), 0u8..=32)
            .prop_map(|(ip, p)| Lit::Cidr(IpNet::new(IpAddr::V4(ip), p).unwrap().trunc())),
        (any::<Ipv6Addr>(), 0u8..=128)
            .prop_map(|(ip, p)| Lit::Cidr(IpNet::new(IpAddr::V6(ip), p).unwrap().trunc())),
        "[A-Z][A-Z_]{0,6}".prop_map(Lit::Method),
        "[a-z_][a-z0-9_-]{0,6}".prop_map(Lit::AddressList),
    ]
}

fn lit_node(lit: Lit) -> LitNode {
    LitNode {
        lit,
        span: Span::default(),
    }
}

fn literal() -> impl Strategy<Value = Operand> {
    prop_oneof![
        3 => scalar_lit(),
        1 => prop::collection::vec(scalar_lit().prop_map(lit_node), 1..4).prop_map(Lit::List),
    ]
    .prop_map(|l| Operand::Lit(lit_node(l)))
}

fn operand() -> impl Strategy<Value = Operand> {
    prop_oneof![field(), literal()]
}

fn op() -> impl Strategy<Value = Op> {
    prop::sample::select(vec![
        Op::Eq,
        Op::Ne,
        Op::Lt,
        Op::Le,
        Op::Gt,
        Op::Ge,
        Op::In,
        Op::NotIn,
        Op::StartsWith,
        Op::EndsWith,
        Op::Contains,
        Op::Like,
        Op::Matches,
        Op::Under,
    ])
}

fn node(expr: Expr) -> Node {
    Node {
        expr,
        span: Span::default(),
    }
}

fn expr() -> impl Strategy<Value = Node> {
    let leaf = prop_oneof![
        (operand(), op(), operand()).prop_map(|(lhs, op, rhs)| node(Expr::Cmp { lhs, op, rhs })),
        operand().prop_map(|o| node(Expr::Pred(o))),
    ];
    leaf.prop_recursive(5, 32, 2, |inner| {
        prop_oneof![
            (inner.clone(), inner.clone())
                .prop_map(|(a, b)| node(Expr::Or(Box::new(a), Box::new(b)))),
            (inner.clone(), inner.clone())
                .prop_map(|(a, b)| node(Expr::And(Box::new(a), Box::new(b)))),
            inner.prop_map(|a| node(Expr::Not(Box::new(a)))),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// Any printable input either parses or yields a positioned diagnostic.
    #[test]
    fn never_panics(src in "[ -~\t\n]{0,80}") {
        match roxy_rules::parse(&src) {
            Ok(_) => {}
            Err(d) => {
                prop_assert!(d.line >= 1 && d.col >= 1);
                prop_assert!(d.snippet.is_some());
            }
        }
    }

    /// Arbitrary unicode, including control characters.
    #[test]
    fn never_panics_unicode(src in "\\PC{0,40}") {
        let _ = roxy_rules::parse(&src);
    }

    /// Token soup built from the DSL's own vocabulary reaches deeper paths.
    #[test]
    fn never_panics_tokens(toks in prop::collection::vec(prop::sample::select(vec![
        "host", "header", "[", "]", "\"x\"", "(", ")", "==", "!=", "<", "in", "not", "and",
        "or", "10.0.0.0/8", "fd00::/8", "5mb", "GET", ",", ".", "all", "true", "under",
        "matches", "#c\n", "\"", "::", "1.2", "/", "@internal", "@", "@-",
    ]), 0..20)) {
        let src = toks.join(" ");
        let _ = roxy_rules::parse(&src);
        let _ = roxy_rules::parse(&toks.concat());
    }

    /// pretty-print -> parse yields the same tree.
    #[test]
    fn round_trip(ast in expr()) {
        let printed = ast.to_string();
        let parsed = roxy_rules::parse(&printed)
            .map_err(|d| TestCaseError::fail(format!("{printed:?}: {d}")))?;
        prop_assert_eq!(parsed.strip_spans(), ast, "printed: {}", printed);
    }
}
