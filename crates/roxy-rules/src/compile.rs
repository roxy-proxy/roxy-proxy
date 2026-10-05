//! Static type checking and compilation of expressions into [`Pred`] plans.
//!
//! Semantics fixed here (documented in the crate docs):
//!
//! * Strings compare byte-exact, except operands involving `host`,
//!   `tls.sni` and `scheme`, which compare ASCII case-insensitively (header
//!   names are lower-cased at compile time). `method` is byte-exact: `get`
//!   is not `GET`.
//! * Compiling also records what an expression *reads* beyond the request
//!   head ([`Needs::reads`]), which decides whether its rule is a head rule
//!   or a watching rule.
//! * `like` is a full-match glob where only `*` (any run, including `/`)
//!   and `?` (one character) are special; it compiles to a `globset`
//!   matcher.
//! * `matches` is a full-match regex: the pattern is compiled as
//!   `^(?:pattern)$` with bounded program and DFA sizes.
//! * `under "x"` is `host == "x" or host ends_with ".x"`, ASCII
//!   case-insensitive, ignoring a trailing dot on either side.
//! * A list-valued operand (`header.all["x"]`) satisfies `==`, `in`,
//!   `starts_with`, `ends_with`, `contains`, `like` and `matches` if *any*
//!   element does; `!=` and `not in` on a list are rejected as ambiguous.

use std::net::IpAddr;
use std::sync::Arc;

use globset::{GlobBuilder, GlobMatcher};
use ipnet::{IpNet, Ipv4Net};
use regex::{Regex, RegexBuilder};

use crate::ast::{Expr, Lit, LitNode, Node, Op, Operand};
use crate::diag::{ExprError, Span};
use crate::types::{Access, Field, Reads, Type, resolve};

/// Compiled-program size limit for one regex (bytes). A hostile or careless
/// pattern such as `\w{1000}{1000}` fails to compile instead of using
/// unbounded memory.
pub const REGEX_SIZE_LIMIT: usize = 1 << 20;
/// Lazy-DFA cache limit per regex (bytes).
pub const REGEX_DFA_SIZE_LIMIT: usize = 2 << 20;
const REGEX_NEST_LIMIT: u32 = 64;

/// Compilation environment for one expression.
pub(crate) struct Env<'a> {
    /// `Some(reads)` for a defined metric: the watched bits a read of it
    /// carries ([`Reads::METRIC_REQUEST_BYTES`] / `..._RESPONSE_BYTES` for
    /// byte metrics, empty otherwise). `None` = undefined.
    pub metric: &'a dyn Fn(&str) -> Option<Reads>,
    pub list_exists: &'a dyn Fn(&str) -> bool,
}

/// What an expression needs beyond its plan: body buffering, and the
/// values it reads that are not known at the request head.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Needs {
    pub request_body: bool,
    pub response_body: bool,
    /// Watched fields and byte metrics read.
    pub reads: Reads,
    /// The watched values read, each with the bit it carries and its name
    /// as written (`body.bytes`, `metric.egress (request_bytes)`), in order
    /// of first appearance.
    watched: Vec<(Reads, String)>,
    /// The tags read (`tag["x"]`), in order of first appearance.
    pub tags: Vec<Box<str>>,
}

impl Needs {
    fn add_watched(&mut self, reads: Reads, name: String) {
        self.reads |= reads;
        if !self.watched.iter().any(|(_, n)| *n == name) {
            self.watched.push((reads, name));
        }
    }

    /// Names of the watched values whose bits intersect `mask`, as written,
    /// for messages and `roxy check`.
    pub(crate) fn watched_names(&self, mask: Reads) -> Vec<String> {
        self.watched
            .iter()
            .filter(|(r, _)| r.intersects(mask))
            .map(|(_, n)| n.clone())
            .collect()
    }
}

/// A compile-time constant operand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Const {
    Str(Box<str>),
    Int(i64),
    Bool(bool),
    Ip(IpAddr),
}

/// A runtime operand: a constant or a field read.
#[derive(Debug, Clone)]
pub(crate) enum ROperand {
    Const(Const),
    Get(Access),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StrOp {
    StartsWith,
    EndsWith,
    Contains,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OrdOp {
    Lt,
    Le,
    Gt,
    Ge,
}

/// A compiled boolean expression.
#[derive(Debug, Clone)]
pub(crate) enum Pred {
    Const(bool),
    All(Box<[Pred]>),
    Any(Box<[Pred]>),
    Not(Box<Pred>),
    /// A bool-typed operand (`tag["x"]`).
    Truthy(ROperand),
    Eq {
        lhs: ROperand,
        rhs: ROperand,
        ci: bool,
        negate: bool,
    },
    Ord {
        lhs: ROperand,
        rhs: ROperand,
        op: OrdOp,
    },
    Str {
        lhs: ROperand,
        rhs: ROperand,
        op: StrOp,
        ci: bool,
    },
    Glob {
        lhs: ROperand,
        glob: GlobMatcher,
    },
    Regex {
        lhs: ROperand,
        re: Regex,
    },
    Under {
        lhs: ROperand,
        suffix: Box<str>,
    },
    InStr {
        lhs: ROperand,
        set: Box<[Box<str>]>,
        ci: bool,
        negate: bool,
    },
    InInt {
        lhs: ROperand,
        set: Box<[i64]>,
        negate: bool,
    },
    InNet {
        lhs: ROperand,
        nets: Box<[IpNet]>,
        negate: bool,
    },
    /// `ip in @list`: membership is answered by the view
    /// ([`crate::FlowView::in_address_list`]); the engine holds only the name.
    InList {
        lhs: ROperand,
        list: Arc<str>,
        negate: bool,
    },
    /// `x == null` (or `x != null` with `negate`): is the value missing?
    IsNull {
        op: ROperand,
        negate: bool,
    },
}

fn list_misuse(span: Span, name: &str) -> ExprError {
    ExprError::new(
        span,
        format!("address list @{name} can only be used with `in`/`not in` on an ip field"),
    )
}

/// Reject `@list` anywhere except directly on the right of `in`/`not in`.
fn reject_list(t: &Typed<'_>) -> Result<(), ExprError> {
    fn walk(l: &LitNode) -> Result<(), ExprError> {
        match &l.lit {
            Lit::AddressList(n) => Err(list_misuse(l.span, n)),
            Lit::List(items) => items.iter().try_for_each(walk),
            _ => Ok(()),
        }
    }
    match t {
        Typed::Lit(l) => walk(l),
        Typed::Field(..) => Ok(()),
    }
}

fn is_null(t: &Typed<'_>) -> bool {
    matches!(t, Typed::Lit(LitNode { lit: Lit::Null, .. }))
}

/// `x == null` / `x != null` (either side). `None` if neither side is
/// `null`; an error for any other use of `null`.
fn null_comparison(
    l: &Typed<'_>,
    op: Op,
    r: &Typed<'_>,
    span: Span,
) -> Result<Option<Pred>, ExprError> {
    let (field, other) = match (is_null(l), is_null(r)) {
        (false, false) => return Ok(None),
        (true, true) => {
            return Err(ExprError::new(
                span,
                "comparing `null` with `null` is always the same answer; remove it",
            ));
        }
        (true, false) => (r, l),
        (false, true) => (l, r),
    };
    if !matches!(op, Op::Eq | Op::Ne) {
        return Err(ExprError::new(
            other.span(),
            "`null` can only be used with `==` or `!=` (e.g. `x != null and x > 10`)",
        ));
    }
    match field {
        Typed::Field(a, _) => Ok(Some(Pred::IsNull {
            op: ROperand::Get(a.clone()),
            negate: op == Op::Ne,
        })),
        Typed::Lit(lit) => Err(ExprError::new(
            lit.span,
            format!(
                "{} is never null; compare a field with `null`",
                describe_lit(&lit.lit)
            ),
        )),
    }
}

/// Reject `null` anywhere other than `x == null` / `x != null`, including
/// inside a list literal.
fn reject_null(t: &Typed<'_>) -> Result<(), ExprError> {
    fn walk(l: &LitNode) -> Result<(), ExprError> {
        match &l.lit {
            Lit::Null => Err(ExprError::new(
                l.span,
                "`null` can only be used with `==` or `!=` (e.g. `x != null and x > 10`)",
            )),
            Lit::List(items) => items.iter().try_for_each(walk),
            _ => Ok(()),
        }
    }
    match t {
        Typed::Lit(l) => walk(l),
        Typed::Field(..) => Ok(()),
    }
}

/// Parse and compile one expression.
pub(crate) fn compile(src: &str, env: &Env<'_>) -> Result<(Pred, Needs), ExprError> {
    let node = crate::parser::parse_inner(src)?;
    let mut needs = Needs::default();
    let pred = Compiler {
        env,
        needs: &mut needs,
    }
    .node(&node)?;
    Ok((pred, needs))
}

/// Build a full-match regex with resource limits.
fn anchored_regex(pattern: &str, case_insensitive: bool) -> Result<Regex, regex::Error> {
    let build = |p: &str| {
        RegexBuilder::new(p)
            .size_limit(REGEX_SIZE_LIMIT)
            .dfa_size_limit(REGEX_DFA_SIZE_LIMIT)
            .nest_limit(REGEX_NEST_LIMIT)
            .case_insensitive(case_insensitive)
            .build()
    };
    // Compile the pattern on its own first: a valid pattern has balanced
    // groups, so wrapping it cannot change its meaning (`a)|(b` must not
    // escape the anchors).
    build(pattern)?;
    build(&format!("^(?:{pattern})$"))
}

/// The regex behind `matches`, written at `span`.
fn build_regex(span: Span, pattern: &str, case_insensitive: bool) -> Result<Regex, ExprError> {
    anchored_regex(pattern, case_insensitive).map_err(|e| ExprError::new(span, regex_error(&e)))
}

/// Shared compiled regex, for `rewrite_path`, whose pattern is a YAML
/// string without a span.
pub(crate) fn build_shared_regex(pattern: &str) -> Result<Arc<Regex>, String> {
    anchored_regex(pattern, false)
        .map(Arc::new)
        .map_err(|e| regex_error(&e))
}

fn regex_error(e: &regex::Error) -> String {
    match e {
        regex::Error::CompiledTooBig(limit) => {
            format!("regex is too large to compile (limit {limit} bytes); simplify it")
        }
        other => {
            // The syntax error renders as a multi-line diagram; keep the
            // final "error: ..." line, which carries the reason.
            let text = other.to_string();
            let reason = text
                .lines()
                .rev()
                .find_map(|l| l.trim().strip_prefix("error: "))
                .unwrap_or(text.trim());
            format!("invalid regex: {reason}")
        }
    }
}

/// Build a full-match glob in which only `*` and `?` are special.
fn build_glob(span: Span, pattern: &str, case_insensitive: bool) -> Result<GlobMatcher, ExprError> {
    let mut glob = String::with_capacity(pattern.len() + 8);
    let mut prev_star = false;
    let mut buf = [0u8; 4];
    for c in pattern.chars() {
        match c {
            // `**` has path-component meaning in globset; `*` already spans
            // `/` here, so runs of stars collapse to one.
            '*' if prev_star => {}
            '*' | '?' => glob.push(c),
            _ => glob.push_str(&globset::escape(c.encode_utf8(&mut buf))),
        }
        prev_star = c == '*';
    }
    GlobBuilder::new(&glob)
        .literal_separator(false)
        .backslash_escape(false)
        .case_insensitive(case_insensitive)
        .build()
        .map(|g| g.compile_matcher())
        .map_err(|e| ExprError::new(span, format!("invalid pattern: {e}")))
}

/// An operand after field resolution, before lowering.
enum Typed<'n> {
    Field(Access, Span),
    Lit(&'n LitNode),
}

impl Typed<'_> {
    fn span(&self) -> Span {
        match self {
            Typed::Field(_, s) => *s,
            Typed::Lit(l) => l.span,
        }
    }

    /// Scalar type, or `None` for list / CIDR literals.
    fn ty(&self) -> Option<Type> {
        match self {
            Typed::Field(a, _) => Some(a.ty()),
            Typed::Lit(l) => match l.lit {
                Lit::Str(_) | Lit::Method(_) => Some(Type::Str),
                Lit::Int(..) => Some(Type::Int),
                Lit::Bool(_) => Some(Type::Bool),
                Lit::Ip(_) => Some(Type::Ip),
                Lit::List(_) | Lit::Cidr(_) | Lit::AddressList(_) | Lit::Null => None,
            },
        }
    }

    fn ci(&self) -> bool {
        matches!(self, Typed::Field(a, _) if a.case_insensitive())
    }

    fn is_method_field(&self) -> bool {
        matches!(self, Typed::Field(Access::Scalar(Field::Method), _))
    }

    /// For messages: "`port` (int)", "the string \"x\"", "the list [...]".
    fn describe(&self, src_field: Option<&Operand>) -> String {
        match (self, src_field) {
            (Typed::Field(a, _), Some(o)) => format!("`{o}` ({})", a.ty()),
            (Typed::Field(a, _), None) => format!("a {} field", a.ty()),
            (Typed::Lit(l), _) => describe_lit(&l.lit),
        }
    }
}

fn describe_lit(l: &Lit) -> String {
    match l {
        Lit::Str(_) => format!("the string {l}"),
        Lit::Int(..) => format!("the number {l}"),
        Lit::Bool(_) => format!("the bool {l}"),
        Lit::List(_) => format!("the list {l}"),
        Lit::Ip(_) => format!("the IP address {l}"),
        Lit::Cidr(_) => format!("the CIDR {l}"),
        Lit::AddressList(_) => format!("the address list {l}"),
        Lit::Method(_) => format!("the method {l}"),
        Lit::Null => "null".into(),
    }
}

struct Compiler<'a, 'e> {
    env: &'a Env<'e>,
    needs: &'a mut Needs,
}

impl Compiler<'_, '_> {
    fn node(&mut self, node: &Node) -> Result<Pred, ExprError> {
        Ok(match &node.expr {
            Expr::Or(..) => {
                let mut out = Vec::new();
                self.flatten(node, true, &mut out)?;
                Pred::Any(out.into())
            }
            Expr::And(..) => {
                let mut out = Vec::new();
                self.flatten(node, false, &mut out)?;
                Pred::All(out.into())
            }
            Expr::Not(inner) => Pred::Not(Box::new(self.node(inner)?)),
            Expr::Pred(o) => self.predicate(o)?,
            Expr::Cmp { lhs, op, rhs } => self.comparison(lhs, *op, rhs, node.span)?,
        })
    }

    fn flatten(&mut self, node: &Node, or: bool, out: &mut Vec<Pred>) -> Result<(), ExprError> {
        match &node.expr {
            Expr::Or(a, b) if or => {
                self.flatten(a, or, out)?;
                self.flatten(b, or, out)
            }
            Expr::And(a, b) if !or => {
                self.flatten(a, or, out)?;
                self.flatten(b, or, out)
            }
            _ => {
                out.push(self.node(node)?);
                Ok(())
            }
        }
    }

    fn operand<'n>(&mut self, o: &'n Operand) -> Result<Typed<'n>, ExprError> {
        match o {
            Operand::Lit(l) => Ok(Typed::Lit(l)),
            Operand::Field(f) => {
                let metric = self.env.metric;
                let access = resolve(f, &|id| metric(id).is_some())?;
                match &access {
                    Access::BodyText => self.needs.request_body = true,
                    Access::RespBodyText => self.needs.response_body = true,
                    Access::Tag(t) if !self.needs.tags.contains(t) => {
                        self.needs.tags.push(t.clone());
                    }
                    _ => {}
                }
                let (reads, name) = match &access {
                    Access::Metric(id) => {
                        let r = metric(id).unwrap_or_default();
                        let what = if r == Reads::METRIC_REQUEST_BYTES {
                            "request_bytes"
                        } else {
                            "response_bytes"
                        };
                        (r, format!("metric.{id} ({what})"))
                    }
                    a => (a.reads(), a.display_name()),
                };
                if !reads.is_empty() {
                    self.needs.add_watched(reads, name);
                }
                Ok(Typed::Field(access, f.span))
            }
        }
    }

    fn predicate(&mut self, o: &Operand) -> Result<Pred, ExprError> {
        let t = self.operand(o)?;
        reject_list(&t)?;
        match t {
            Typed::Lit(LitNode {
                lit: Lit::Bool(b), ..
            }) => Ok(Pred::Const(*b)),
            Typed::Field(access, _) if access.ty() == Type::Bool => {
                Ok(Pred::Truthy(ROperand::Get(access)))
            }
            Typed::Field(access, span) => Err(ExprError::new(
                span,
                format!(
                    "`{o}` is a {}, not a condition; compare it with a value, e.g. `{o} == ...`",
                    access.ty()
                ),
            )),
            Typed::Lit(l) => Err(ExprError::new(
                l.span,
                format!("{} is not a condition", describe_lit(&l.lit)),
            )),
        }
    }

    fn comparison(
        &mut self,
        lo: &Operand,
        op: Op,
        ro: &Operand,
        span: Span,
    ) -> Result<Pred, ExprError> {
        let l = self.operand(lo)?;
        let r = self.operand(ro)?;
        check_method_literal(&l, &r)?;
        check_method_literal(&r, &l)?;
        reject_list(&l)?;
        let rhs_is_list_ref = matches!(
            r,
            Typed::Lit(LitNode {
                lit: Lit::AddressList(_),
                ..
            })
        );
        if !(rhs_is_list_ref && matches!(op, Op::In | Op::NotIn)) {
            reject_list(&r)?;
        }
        if let Some(p) = null_comparison(&l, op, &r, span)? {
            return Ok(p);
        }
        reject_null(&l)?;
        reject_null(&r)?;
        match op {
            Op::Eq | Op::Ne => equality(l, lo, op, r, ro, span),
            Op::Lt | Op::Le | Op::Gt | Op::Ge => ordering(l, lo, op, r, ro),
            Op::In | Op::NotIn => self.membership(l, lo, op, &r, span),
            Op::StartsWith | Op::EndsWith | Op::Contains => string_op(l, lo, op, r, ro),
            Op::Like | Op::Matches | Op::Under => pattern(l, lo, op, &r, ro),
        }
    }

    /// `in` / `not in`: an address list, or a literal list (or CIDR) of
    /// the left operand's type.
    fn membership(
        &mut self,
        l: Typed<'_>,
        lo: &Operand,
        op: Op,
        r: &Typed<'_>,
        span: Span,
    ) -> Result<Pred, ExprError> {
        let negate = op == Op::NotIn;
        let Typed::Lit(rl) = r else {
            return Err(ExprError::new(
                r.span(),
                format!(
                    "`{}` needs a literal list (or a CIDR) on the right, e.g. [\"a\", \"b\"]",
                    op.as_str()
                ),
            ));
        };
        if let Lit::AddressList(name) = &rl.lit {
            if l.ty() != Some(Type::Ip) {
                return Err(list_misuse(rl.span, name));
            }
            if !(self.env.list_exists)(name) {
                return Err(ExprError::new(
                    rl.span,
                    format!(
                        "reference to undefined address list `@{name}` (define it under \
                         `address_lists`)"
                    ),
                ));
            }
            return Ok(Pred::InList {
                lhs: lower(l),
                list: Arc::from(name.as_str()),
                negate,
            });
        }
        let items: &[LitNode] = match &rl.lit {
            Lit::List(items) => items,
            Lit::Cidr(_) => std::slice::from_ref(*rl),
            other => {
                return Err(ExprError::new(
                    rl.span,
                    format!(
                        "`{}` needs a list (or a CIDR) on the right, found {}",
                        op.as_str(),
                        describe_lit(other)
                    ),
                ));
            }
        };
        literal_set(l, lo, op, items, span)
    }
}

/// A literal list (or CIDR) of the left operand's type.
fn literal_set(
    l: Typed<'_>,
    lo: &Operand,
    op: Op,
    items: &[LitNode],
    span: Span,
) -> Result<Pred, ExprError> {
    let negate = op == Op::NotIn;
    let lt = scalar(&l, op)?;
    let mismatch = |item: &LitNode, want: &str| {
        ExprError::new(
            item.span,
            format!(
                "type mismatch: `{lo}` is {}, so the list must contain {want}, but this is {}",
                article(lt),
                describe_lit(&item.lit)
            ),
        )
    };
    match lt {
        Type::Ip => {
            let nets = items
                .iter()
                .map(|item| match item.lit {
                    Lit::Cidr(n) => Ok(canonical_net(n)),
                    Lit::Ip(ip) => Ok(IpNet::from(ip.to_canonical())),
                    _ => Err(mismatch(item, "IP addresses or CIDRs")),
                })
                .collect::<Result<_, _>>()?;
            Ok(Pred::InNet {
                lhs: lower(l),
                nets,
                negate,
            })
        }
        Type::Str | Type::StrList => {
            if lt == Type::StrList && negate {
                return Err(ExprError::new(
                    span,
                    "`not in` on a list (`header.all[...]`) is ambiguous; write \
                     `not (... in [...])` instead",
                ));
            }
            let method = l.is_method_field();
            let set = items
                .iter()
                .map(|item| match &item.lit {
                    Lit::Str(s) => Ok(s.as_str().into()),
                    Lit::Method(m) if method => Ok(m.as_str().into()),
                    Lit::Method(m) => Err(method_literal_error(item.span, m)),
                    _ => Err(mismatch(item, "strings")),
                })
                .collect::<Result<_, _>>()?;
            Ok(Pred::InStr {
                ci: l.ci(),
                lhs: lower(l),
                set,
                negate,
            })
        }
        Type::Int => {
            let set = items
                .iter()
                .map(|item| match item.lit {
                    Lit::Int(n, u) => Ok(Lit::int_value(n, u)),
                    _ => Err(mismatch(item, "numbers")),
                })
                .collect::<Result<_, _>>()?;
            Ok(Pred::InInt {
                lhs: lower(l),
                set,
                negate,
            })
        }
        Type::Bool => Err(ExprError::new(
            l.span(),
            format!("`{}` does not apply to booleans; use `==`", op.as_str()),
        )),
    }
}

/// The IPv4 network an IPv4-mapped IPv6 CIDR (`::ffff:10.0.0.0/104`)
/// denotes. Flow addresses are canonicalised to IPv4 before matching, so a
/// mapped network left in IPv6 form would never match. A mapped address
/// has `ffff` in bits 80..96, so a prefix shorter than /96 sets host bits
/// and the lexer has already rejected it.
fn canonical_net(net: IpNet) -> IpNet {
    match (net.addr().to_canonical(), net.prefix_len().checked_sub(96)) {
        (IpAddr::V4(v4), Some(prefix)) => Ipv4Net::new(v4, prefix).map_or(net, IpNet::V4),
        _ => net,
    }
}

/// `==` / `!=`.
fn equality(
    l: Typed<'_>,
    lo: &Operand,
    op: Op,
    r: Typed<'_>,
    ro: &Operand,
    span: Span,
) -> Result<Pred, ExprError> {
    let (lt, rt) = (scalar(&l, op)?, scalar(&r, op)?);
    let list = lt == Type::StrList || rt == Type::StrList;
    if list && op == Op::Ne {
        return Err(ExprError::new(
            span,
            "`!=` on a list (`header.all[...]`) is ambiguous; write `not (... == ...)` instead",
        ));
    }
    let compatible = lt == rt
        || (lt == Type::StrList && rt == Type::Str)
        || (lt == Type::Str && rt == Type::StrList);
    if !compatible || (lt == Type::StrList && rt == Type::StrList) {
        return Err(ExprError::new(
            span,
            format!(
                "type mismatch: cannot compare {} with {}",
                l.describe(Some(lo)),
                r.describe(Some(ro))
            ),
        ));
    }
    Ok(Pred::Eq {
        ci: l.ci() || r.ci(),
        lhs: lower(l),
        rhs: lower(r),
        negate: op == Op::Ne,
    })
}

/// `<`, `<=`, `>`, `>=`: ints only.
fn ordering(
    l: Typed<'_>,
    lo: &Operand,
    op: Op,
    r: Typed<'_>,
    ro: &Operand,
) -> Result<Pred, ExprError> {
    for (t, o) in [(&l, lo), (&r, ro)] {
        if t.ty() != Some(Type::Int) {
            return Err(ExprError::new(
                t.span(),
                format!(
                    "`{}` compares numbers, but this is {}",
                    op.as_str(),
                    t.describe(Some(o))
                ),
            ));
        }
    }
    let op = match op {
        Op::Lt => OrdOp::Lt,
        Op::Le => OrdOp::Le,
        Op::Gt => OrdOp::Gt,
        _ => OrdOp::Ge,
    };
    Ok(Pred::Ord {
        lhs: lower(l),
        rhs: lower(r),
        op,
    })
}

/// `starts_with`, `ends_with`, `contains`.
fn string_op(
    l: Typed<'_>,
    lo: &Operand,
    op: Op,
    r: Typed<'_>,
    ro: &Operand,
) -> Result<Pred, ExprError> {
    string_lhs(&l, lo, op)?;
    if r.ty() != Some(Type::Str) {
        return Err(ExprError::new(
            r.span(),
            format!(
                "`{}` needs a string on the right, found {}",
                op.as_str(),
                r.describe(Some(ro))
            ),
        ));
    }
    let sop = match op {
        Op::StartsWith => StrOp::StartsWith,
        Op::EndsWith => StrOp::EndsWith,
        _ => StrOp::Contains,
    };
    Ok(Pred::Str {
        ci: l.ci() || r.ci(),
        lhs: lower(l),
        rhs: lower(r),
        op: sop,
    })
}

/// `like`, `matches`, `under`: a string field against a quoted literal.
fn pattern(
    l: Typed<'_>,
    lo: &Operand,
    op: Op,
    r: &Typed<'_>,
    ro: &Operand,
) -> Result<Pred, ExprError> {
    string_lhs(&l, lo, op)?;
    let Typed::Lit(LitNode {
        lit: Lit::Str(pattern),
        span: rspan,
    }) = r
    else {
        let what = match op {
            Op::Like => "a quoted glob pattern",
            Op::Matches => "a quoted regex",
            _ => "a quoted domain",
        };
        return Err(ExprError::new(
            r.span(),
            format!(
                "`{}` needs {what} on the right, found {}",
                op.as_str(),
                r.describe(Some(ro))
            ),
        ));
    };
    let ci = l.ci();
    match op {
        Op::Like => Ok(Pred::Glob {
            glob: build_glob(*rspan, pattern, ci)?,
            lhs: lower(l),
        }),
        Op::Matches => Ok(Pred::Regex {
            re: build_regex(*rspan, pattern, ci)?,
            lhs: lower(l),
        }),
        _ => {
            if l.ty() == Some(Type::StrList) {
                return Err(ExprError::new(
                    l.span(),
                    "`under` needs a single host name on the left, not a list",
                ));
            }
            Ok(Pred::Under {
                suffix: under_suffix(*rspan, pattern)?,
                lhs: lower(l),
            })
        }
    }
}

fn article(t: Type) -> String {
    match t {
        Type::Int | Type::Ip => format!("an {t}"),
        _ => format!("a {t}"),
    }
}

/// The scalar type of an operand of `op`; list and CIDR literals are only
/// valid on the right of `in`.
fn scalar(t: &Typed<'_>, op: Op) -> Result<Type, ExprError> {
    t.ty().ok_or_else(|| {
        let Typed::Lit(l) = t else {
            unreachable!("fields always have a scalar type")
        };
        let hint = if matches!(op, Op::Eq | Op::Ne) {
            "; use `in` to test membership"
        } else {
            ""
        };
        ExprError::new(
            l.span,
            format!(
                "{} cannot be used with `{}`{hint}",
                describe_lit(&l.lit),
                op.as_str()
            ),
        )
    })
}

fn string_lhs(l: &Typed<'_>, lo: &Operand, op: Op) -> Result<(), ExprError> {
    match l.ty() {
        Some(Type::Str | Type::StrList) => Ok(()),
        _ => Err(ExprError::new(
            l.span(),
            format!(
                "`{}` needs a string on the left, found {}",
                op.as_str(),
                l.describe(Some(lo))
            ),
        )),
    }
}

fn method_literal_error(span: Span, m: &str) -> ExprError {
    ExprError::new(
        span,
        format!(
            "bare identifier `{m}` is only valid as an HTTP method compared with `method`; \
             quote it if you meant the string \"{m}\""
        ),
    )
}

/// Bare uppercase identifiers are only valid against the `method` field.
fn check_method_literal(this: &Typed<'_>, other: &Typed<'_>) -> Result<(), ExprError> {
    if let Typed::Lit(LitNode {
        lit: Lit::Method(m),
        span,
    }) = this
        && !other.is_method_field()
    {
        return Err(method_literal_error(*span, m));
    }
    Ok(())
}

/// The suffix `under` tests, from the domain written at `span`.
fn under_suffix(span: Span, domain: &str) -> Result<Box<str>, ExprError> {
    let d = domain.strip_suffix('.').unwrap_or(domain);
    if d.is_empty() {
        return Err(ExprError::new(span, "`under` needs a non-empty domain"));
    }
    if d.starts_with('.') {
        return Err(ExprError::new(
            span,
            format!(
                "write the domain without a leading dot: `under {:?}`",
                d.trim_start_matches('.')
            ),
        ));
    }
    Ok(d.to_ascii_lowercase().into())
}

fn lower(t: Typed<'_>) -> ROperand {
    match t {
        Typed::Field(a, _) => ROperand::Get(a),
        Typed::Lit(l) => ROperand::Const(match &l.lit {
            Lit::Str(s) | Lit::Method(s) => Const::Str(s.as_str().into()),
            Lit::Int(n, u) => Const::Int(Lit::int_value(*n, *u)),
            Lit::Bool(b) => Const::Bool(*b),
            Lit::Ip(ip) => Const::Ip(ip.to_canonical()),
            // Rejected by the type checks before lowering.
            Lit::List(_) | Lit::Cidr(_) | Lit::AddressList(_) | Lit::Null => Const::Bool(false),
        }),
    }
}
