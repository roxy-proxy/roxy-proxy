//! Evaluation of compiled policies against arbitrary flows.
//!
//! Policies are generated from the rule language's own vocabulary (fields,
//! operators, literals, `and`/`or`/`not`), so most of them compile and the
//! fuzzer spends its time in the evaluator.
//!
//! Invariants, for the head decision:
//! - a fail-closed outcome (`_fail_closed`, with a reason) is never an
//!   allow, and the reason is set exactly when the terminal rule is
//!   `_fail_closed`;
//! - **unavailable inputs only ever fail closed.** Take a flow where every
//!   input is available, then make one unavailable (a metric, the request
//!   body text, the address list). The outcome is either exactly the same
//!   (the input was not reached) or a fail-closed deny. It is never a
//!   different decision, in particular never an allow that the available
//!   flow did not get.
#![no_main]

use std::net::Ipv4Addr;

use arbitrary::{Arbitrary, Result, Unstructured};
use ipnet::{IpNet, Ipv4Net};
use libfuzzer_sys::fuzz_target;
use roxy_rules::{Decision, EvalContext, Field, MapView, Outcome};
use serde_json::json;

const STR_FIELDS: &[&str] = &[
    "host",
    "method",
    "path",
    "url",
    "scheme",
    "query.raw",
    "tls.sni",
    "client.user",
    "header[\"x-a\"]",
    "query[\"q\"]",
    "state[\"k\"]",
    "body.text",
];
const INT_FIELDS: &[&str] = &["port", "client.port", "body.size", "metric.m0", "metric.m1"];
const STR_OPS: &[&str] = &[
    "==",
    "!=",
    "starts_with",
    "ends_with",
    "contains",
    "like",
    "matches",
    "under",
];
const INT_OPS: &[&str] = &["==", "!=", "<", "<=", ">", ">="];
const STRS: &[&str] = &[
    "\"example.com\"",
    "\"a\"",
    "\"\"",
    "\"*.com\"",
    "\"^/a.*\"",
    "\"GET\"",
    "\"/a/b\"",
    "null",
];
const INTS: &[&str] = &["0", "1", "30", "443", "-1", "1kb", "null"];

fn pick<'a>(u: &mut Unstructured<'_>, xs: &[&'a str]) -> Result<&'a str> {
    u.choose(xs).copied()
}

fn expr(u: &mut Unstructured<'_>, depth: u8) -> Result<String> {
    let max = if depth == 0 { 6 } else { 10 };
    Ok(match u.int_in_range(0..=max)? {
        0..=2 => format!(
            "{} {} {}",
            pick(u, STR_FIELDS)?,
            pick(u, STR_OPS)?,
            pick(u, STRS)?
        ),
        3 | 4 => format!(
            "{} {} {}",
            pick(u, INT_FIELDS)?,
            pick(u, INT_OPS)?,
            pick(u, INTS)?
        ),
        5 => format!(
            "{} in [{}, {}]",
            pick(u, STR_FIELDS)?,
            pick(u, STRS)?,
            pick(u, STRS)?
        ),
        6 => match u.int_in_range(0..=3)? {
            0 => "client.ip in @l0".to_owned(),
            1 => "client.ip in 10.0.0.0/8".to_owned(),
            2 => "tag[\"t0\"]".to_owned(),
            _ => "true".to_owned(),
        },
        7 => format!("not ({})", expr(u, depth - 1)?),
        8 => format!("({}) and ({})", expr(u, depth - 1)?, expr(u, depth - 1)?),
        _ => format!("({}) or ({})", expr(u, depth - 1)?, expr(u, depth - 1)?),
    })
}

fn then(u: &mut Unstructured<'_>) -> Result<serde_json::Value> {
    Ok(match u.int_in_range(0..=4)? {
        0 => json!("allow"),
        1 => json!("deny"),
        2 => json!({ "deny": { "status": 429 } }),
        3 => json!([{ "tag": "t0" }]),
        _ => json!([{ "tag": "t0" }, "allow"]),
    })
}

#[derive(Debug, Arbitrary)]
struct Flow<'a> {
    host: &'a str,
    method: u8,
    path: &'a str,
    port: u16,
    client_ip: u32,
    header: Option<&'a str>,
    query: Option<&'a str>,
    state: Option<&'a str>,
    m0: i64,
    m1: i64,
    body: &'a str,
    in_list: bool,
}

fn view(f: &Flow<'_>) -> MapView {
    let ip = Ipv4Addr::from(f.client_ip);
    let mut v = MapView::new()
        .with_str(Field::Host, f.host)
        .with_str(
            Field::Method,
            ["GET", "POST", "HEAD", "PUT"][usize::from(f.method % 4)],
        )
        .with_str(Field::Path, f.path)
        .with_str(Field::Scheme, "https")
        .with_int(Field::Port, i64::from(f.port))
        .with(Field::ClientIp, roxy_rules::Value::Ip(ip.into()))
        .with_metric("m0", f.m0)
        .with_metric("m1", f.m1)
        .with_body(f.body);
    if let Some(h) = f.header {
        v = v.with_header("x-a", h);
    }
    if let Some(q) = f.query {
        v = v.with_query("q", q);
    }
    if let Some(s) = f.state {
        v = v.with_state("k", s);
    }
    let net = if f.in_list {
        Ipv4Net::new(ip, 32).expect("valid /32")
    } else {
        Ipv4Net::new(Ipv4Addr::new(192, 0, 2, 0), 24).expect("valid /24")
    };
    v.with_address_list("l0", vec![IpNet::V4(net)])
}

fn check(out: &Outcome) {
    assert_eq!(
        out.fail_closed_reason.is_some(),
        out.terminal_rule.as_str() == "_fail_closed",
        "{out:?}"
    );
    if out.fail_closed_reason.is_some() {
        assert_eq!(out.decision, Decision::fail_closed(), "{out:?}");
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(n) = u.int_in_range(1..=5u8) else {
        return;
    };
    let mut rules = Vec::new();
    for i in 0..n {
        let (Ok(when), Ok(then)) = (expr(&mut u, 3), then(&mut u)) else {
            return;
        };
        rules.push(json!({ "id": format!("r{i}"), "when": when, "then": then }));
    }
    let Ok(default_allow) = u.arbitrary::<bool>() else {
        return;
    };
    let Ok(flow) = Flow::arbitrary(&mut u) else {
        return;
    };
    let Some(policy) = roxy_fuzz::rules::compile(json!(rules), default_allow) else {
        return;
    };
    let ctx = EvalContext::empty();
    let full = view(&flow);
    let base = policy.evaluate_head(&full, &ctx);
    check(&base);

    let mut degraded = Vec::new();
    for metric in ["m0", "m1"] {
        let mut v = full.clone();
        v.metrics.remove(metric);
        degraded.push((format!("metric {metric} unavailable"), v));
    }
    let mut v = full.clone();
    v.body = None;
    degraded.push(("body text unavailable".to_owned(), v));
    degraded.push((
        "body too large".to_owned(),
        full.clone().with_body_too_large(false),
    ));
    let mut v = full.clone();
    v.address_lists.clear();
    degraded.push(("address list unavailable".to_owned(), v));

    for (what, v) in &degraded {
        let out = policy.evaluate_head(v, &ctx);
        check(&out);
        assert!(
            out == base || out.fail_closed_reason.is_some(),
            "{what} changed the outcome without failing closed\nrules: {rules:#?}\nflow: {flow:?}\navailable: {base:?}\ndegraded: {out:?}"
        );
    }
});
