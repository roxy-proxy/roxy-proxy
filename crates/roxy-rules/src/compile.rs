//! Static type checking and compilation of expressions into [`Pred`] plans.
//!
//! Semantics fixed here (documented in the crate docs):
//!
//! * Strings compare byte-exact, except operands involving `host`,
//!   `tls.sni` and `scheme`, which compare ASCII case-insensitively (header
//!   names are lower-cased at compile time). `method` is byte-exact: `get`
//!   is not `GET`.
//! * Compiling also records what an expression *reads* that is not known
//!   at admission ([`Needs::reads`]), which decides whether its rule is an
//!   admission rule or an in-flight rule.
//! * `like` is a full-match glob where only `*` (any run, including `/`)
//!   and `?` (one character) are special; it compiles to a regex with the
//!   same limits as `matches`.
//! * `matches` is a full-match regex: the pattern is compiled as
//!   `^(?:pattern)$` with bounded program and DFA sizes.
//! * `under "x"` is `host == "x" or host ends_with ".x"`, ASCII
//!   case-insensitive, ignoring a trailing dot on either side.
//! * A list-valued operand (`header.all["x"]`) satisfies `==`, `in`,
//!   `starts_with`, `ends_with`, `contains`, `like` and `matches` if *any*
//!   element does; `!=` and `not in` on a list are rejected as ambiguous.
//! * `body.text` and `response.body.text` are compared only with quoted
//!   strings, by the operators that can be decided as the body streams
//!   (`contains`, `starts_with`, `ends_with`, `==`, `!=`, `in`, `not in`).
//!   Each comparison becomes a [`TextTest`], answered by the proxy's scan
//!   of the body ([`crate::text`]).

use std::net::IpAddr;
use std::sync::Arc;

use ipnet::{IpNet, Ipv4Net};
use regex::{Regex, RegexBuilder};

use crate::ast::{Expr, Lit, LitNode, Node, Op, Operand};
use crate::config::MetricCount;
use crate::diag::{ExprError, Span};
use crate::text::{BodySide, TextOp, TextTest, Want};
use crate::types::{Access, Field, InFlightValue, Reads, Type, resolve};

/// Compiled-program size limit for one regex (bytes). A hostile or careless
/// pattern such as `\w{1000}{1000}` fails to compile instead of using
/// unbounded memory.
pub const REGEX_SIZE_LIMIT: usize = 1 << 20;
/// Lazy-DFA cache limit per regex (bytes).
pub const REGEX_DFA_SIZE_LIMIT: usize = 2 << 20;
const REGEX_NEST_LIMIT: u32 = 64;
/// Longest `like` pattern, in bytes: far longer than any host or path glob,
/// and small enough that every pattern fits [`REGEX_SIZE_LIMIT`] (`?` and
/// `*` each cost about 1 KiB of compiled regex).
pub const MAX_GLOB_BYTES: usize = 1024;

/// Compilation environment for one expression.
pub(crate) struct Env<'a> {
    /// What a defined metric counts; `None` = undefined.
    pub metric: &'a dyn Fn(&str) -> Option<&'a MetricCount>,
    pub list_exists: &'a dyn Fn(&str) -> bool,
}

/// What an expression needs beyond its plan: the values it reads that are
/// not known at admission, and its body text tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Needs {
    /// In-flight fields and byte metrics read.
    pub reads: Reads,
    /// The in-flight values read, each with its name as written (`body.bytes`,
    /// `metric.egress (request_bytes)`), in order of first appearance.
    in_flight: Vec<(InFlightValue, String)>,
    /// The tags read (`tag["x"]`), in order of first appearance.
    pub tags: Vec<Box<str>>,
    /// The body text tests, in the order of the plan's [`Pred::Text`]
    /// indices, with the answer on which each can make the expression true.
    pub texts: Vec<(BodySide, TextTest, Want)>,
}

impl Needs {
    fn add_in_flight(&mut self, w: InFlightValue, name: String) {
        self.reads |= Reads::of(w);
        if !self.in_flight.iter().any(|(_, n)| *n == name) {
            self.in_flight.push((w, name));
        }
    }

    /// Names of the in-flight values in `mask`, as written, for messages and
    /// `roxy check`.
    pub(crate) fn in_flight_names(&self, mask: Reads) -> Vec<String> {
        self.in_flight
            .iter()
            .filter(|(w, _)| mask.contains(*w))
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

impl StrOp {
    fn as_str(self) -> &'static str {
        match self {
            Self::StartsWith => "starts_with",
            Self::EndsWith => "ends_with",
            Self::Contains => "contains",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OrdOp {
    Lt,
    Le,
    Gt,
    Ge,
}

impl OrdOp {
    fn as_str(self) -> &'static str {
        match self {
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Gt => ">",
            Self::Ge => ">=",
        }
    }
}

/// The operators that take a quoted pattern on the right.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PatternOp {
    Like,
    Matches,
    Under,
}

impl PatternOp {
    fn as_str(self) -> &'static str {
        match self {
            Self::Like => "like",
            Self::Matches => "matches",
            Self::Under => "under",
        }
    }
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
        glob: Regex,
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
    /// A body text test, true when its answer differs from `negate`. The
    /// index is the test's in the policy's [`crate::TextTests`] for `side`
    /// (in [`Needs::texts`] until the policy is assembled). `pending` is
    /// the value while the test is undecided: whichever cannot make the
    /// whole expression true, so an undecided test never fires a rule.
    Text {
        side: BodySide,
        index: usize,
        test: Arc<TextTest>,
        negate: bool,
        pending: bool,
    },
}

impl Pred {
    /// Renumbers the body text tests through `index`.
    pub(crate) fn renumber_texts(&mut self, index: &mut dyn FnMut(BodySide, usize) -> usize) {
        match self {
            Pred::All(ps) | Pred::Any(ps) => {
                for p in ps {
                    p.renumber_texts(index);
                }
            }
            Pred::Not(p) => p.renumber_texts(index),
            Pred::Text { side, index: i, .. } => *i = index(*side, *i),
            Pred::Const(_)
            | Pred::Truthy(_)
            | Pred::Eq { .. }
            | Pred::Ord { .. }
            | Pred::Str { .. }
            | Pred::Glob { .. }
            | Pred::Regex { .. }
            | Pred::Under { .. }
            | Pred::InStr { .. }
            | Pred::InInt { .. }
            | Pred::InNet { .. }
            | Pred::InList { .. }
            | Pred::IsNull { .. } => {}
        }
    }
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
            Lit::Str(_)
            | Lit::Int(..)
            | Lit::Bool(_)
            | Lit::Ip(_)
            | Lit::Cidr(_)
            | Lit::Method(_)
            | Lit::Null => Ok(()),
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
        Typed::Field(a, span) => {
            if let Some(why) = a.never_null() {
                return Err(ExprError::new(
                    *span,
                    format!(
                        "`{}` is never null ({why}), so comparing it with `null` is always the \
                         same answer; remove it",
                        a.display_name()
                    ),
                ));
            }
            Ok(Some(Pred::IsNull {
                op: ROperand::Get(a.clone()),
                negate: op == Op::Ne,
            }))
        }
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
            Lit::Str(_)
            | Lit::Int(..)
            | Lit::Bool(_)
            | Lit::Ip(_)
            | Lit::Cidr(_)
            | Lit::AddressList(_)
            | Lit::Method(_) => Ok(()),
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
        negated: false,
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

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "regex::Error is non_exhaustive"
)]
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
fn build_glob(span: Span, pattern: &str, case_insensitive: bool) -> Result<Regex, ExprError> {
    if pattern.len() > MAX_GLOB_BYTES {
        return Err(ExprError::new(
            span,
            format!("pattern is longer than {MAX_GLOB_BYTES} bytes"),
        ));
    }
    // `(?s)` so `*` and `?` span every character, newline included.
    let mut re = String::with_capacity(pattern.len() + 8);
    re.push_str("(?s)");
    let mut prev_star = false;
    let mut buf = [0u8; 4];
    for c in pattern.chars() {
        match c {
            '*' if prev_star => {}
            '*' => re.push_str(".*"),
            '?' => re.push('.'),
            _ => re.push_str(&regex::escape(c.encode_utf8(&mut buf))),
        }
        prev_star = c == '*';
    }
    anchored_regex(&re, case_insensitive).map_err(|e| ExprError::new(span, regex_error(&e)))
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
    /// Inside an odd number of `not`s: a predicate here makes the
    /// expression true by being false.
    negated: bool,
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
            Expr::Not(inner) => {
                self.negated = !self.negated;
                let inner = self.node(inner);
                self.negated = !self.negated;
                Pred::Not(Box::new(inner?))
            }
            Expr::Pred(o) => self.predicate(o)?,
            Expr::Cmp { lhs, op, rhs } => self.comparison(lhs, *op, rhs, node.span)?,
        })
    }

    /// Collect the operands of an `or` (`and`) chain, left to right. The
    /// parser builds a chain left-deep and does not count its links against
    /// `MAX_DEPTH`, so the left spine is walked iteratively; a right child
    /// of the same kind only arises from parentheses, which are counted.
    fn flatten(&mut self, node: &Node, or: bool, out: &mut Vec<Pred>) -> Result<(), ExprError> {
        let mut rights = Vec::new();
        let mut node = node;
        loop {
            match &node.expr {
                Expr::Or(a, b) if or => {
                    rights.push(b);
                    node = a;
                }
                Expr::And(a, b) if !or => {
                    rights.push(b);
                    node = a;
                }
                Expr::Or(..) | Expr::And(..) | Expr::Not(_) | Expr::Cmp { .. } | Expr::Pred(_) => {
                    break;
                }
            }
        }
        out.push(self.node(node)?);
        rights
            .into_iter()
            .rev()
            .try_for_each(|b| self.flatten(b, or, out))
    }

    fn operand<'n>(&mut self, o: &'n Operand) -> Result<Typed<'n>, ExprError> {
        match o {
            Operand::Lit(l) => Ok(Typed::Lit(l)),
            Operand::Field(f) => {
                let metric = self.env.metric;
                let access = resolve(f, &|id| metric(id).is_some())?;
                if let Access::Tag(t) = &access
                    && !self.needs.tags.contains(t)
                {
                    self.needs.tags.push(t.clone());
                }
                let in_flight = match &access {
                    Access::Metric(id) => metric(id).and_then(|count| {
                        Some((count.in_flight()?, format!("metric.{id} ({count})")))
                    }),
                    a @ (Access::Scalar(_)
                    | Access::Header(_)
                    | Access::HeaderAll(_)
                    | Access::RespHeader(_)
                    | Access::RespHeaderAll(_)
                    | Access::Query(_)
                    | Access::State(_)
                    | Access::Tag(_)
                    | Access::BodyText
                    | Access::RespBodyText) => a.in_flight().map(|w| (w, a.display_name())),
                };
                if let Some((w, name)) = in_flight {
                    self.needs.add_in_flight(w, name);
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
        if let Some(side) = body_side(&l).or_else(|| body_side(&r)) {
            return self.text_comparison(side, l, op, r, ro, span);
        }
        match op {
            Op::Eq | Op::Ne => equality(l, lo, op, r, ro, span),
            Op::Lt => ordering(l, lo, OrdOp::Lt, r, ro),
            Op::Le => ordering(l, lo, OrdOp::Le, r, ro),
            Op::Gt => ordering(l, lo, OrdOp::Gt, r, ro),
            Op::Ge => ordering(l, lo, OrdOp::Ge, r, ro),
            Op::In | Op::NotIn => self.membership(l, lo, op, &r, span),
            Op::StartsWith => string_op(l, lo, StrOp::StartsWith, r, ro),
            Op::EndsWith => string_op(l, lo, StrOp::EndsWith, r, ro),
            Op::Contains => string_op(l, lo, StrOp::Contains, r, ro),
            Op::Like => pattern(l, lo, PatternOp::Like, &r, ro),
            Op::Matches => pattern(l, lo, PatternOp::Matches, &r, ro),
            Op::Under => pattern(l, lo, PatternOp::Under, &r, ro),
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
            other @ (Lit::Str(_)
            | Lit::Int(..)
            | Lit::Bool(_)
            | Lit::Ip(_)
            | Lit::AddressList(_)
            | Lit::Method(_)
            | Lit::Null) => {
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

impl Compiler<'_, '_> {
    /// A comparison of a body's text: with quoted strings only, by an
    /// operator that can be decided as the body streams.
    fn text_comparison(
        &mut self,
        side: BodySide,
        l: Typed<'_>,
        op: Op,
        r: Typed<'_>,
        ro: &Operand,
        span: Span,
    ) -> Result<Pred, ExprError> {
        let field = side.field();
        let text_op = match op {
            Op::Eq | Op::Ne | Op::In | Op::NotIn => TextOp::Equals,
            Op::Contains => TextOp::Contains,
            Op::StartsWith => TextOp::StartsWith,
            Op::EndsWith => TextOp::EndsWith,
            Op::Lt | Op::Le | Op::Gt | Op::Ge | Op::Like | Op::Matches | Op::Under => {
                return Err(ExprError::new(
                    span,
                    format!(
                        "`{field}` is checked as the body streams past, which `{}` cannot be; \
                         use `contains`, `starts_with`, `ends_with`, `==`, `!=`, `in` or `not in`",
                        op.as_str()
                    ),
                ));
            }
        };
        // `==` and `!=` read the same either way round.
        let other = match (body_side(&l), op) {
            (Some(_), _) => r,
            (None, Op::Eq | Op::Ne) => l,
            (None, _) => {
                return Err(ExprError::new(
                    r.span(),
                    format!("put `{field}` on the left of `{}`", op.as_str()),
                ));
            }
        };
        let needles: Vec<&str> = match (&other, op) {
            (
                Typed::Lit(LitNode {
                    lit: Lit::List(items),
                    ..
                }),
                Op::In | Op::NotIn,
            ) => items
                .iter()
                .map(|item| match &item.lit {
                    Lit::Str(s) => Ok(s.as_str()),
                    lit @ (Lit::Int(..)
                    | Lit::Bool(_)
                    | Lit::List(_)
                    | Lit::Ip(_)
                    | Lit::Cidr(_)
                    | Lit::AddressList(_)
                    | Lit::Method(_)
                    | Lit::Null) => Err(ExprError::new(
                        item.span,
                        format!(
                            "`{field}` is compared with quoted strings, but this is {}",
                            describe_lit(lit)
                        ),
                    )),
                })
                .collect::<Result<_, _>>()?,
            (
                Typed::Lit(LitNode {
                    lit: Lit::Str(s), ..
                }),
                Op::Eq | Op::Ne | Op::Contains | Op::StartsWith | Op::EndsWith,
            ) => vec![s.as_str()],
            (other, _) => {
                let want = if matches!(op, Op::In | Op::NotIn) {
                    "a list of quoted strings"
                } else {
                    "a quoted string"
                };
                return Err(ExprError::new(
                    other.span(),
                    format!(
                        "`{field}` can only be compared with {want}, found {}",
                        other.describe(Some(ro))
                    ),
                ));
            }
        };
        // The body is compared byte for byte, not decoded, so a U+FFFD
        // would match only its own bytes, never the invalid UTF-8 a
        // decoder would have replaced with it.
        if needles.iter().any(|n| n.contains('\u{FFFD}')) {
            return Err(ExprError::new(
                other.span(),
                format!(
                    "`{field}` is compared byte for byte, so U+FFFD matches only its own bytes, \
                     not invalid UTF-8"
                ),
            ));
        }
        let negate = matches!(op, Op::Ne | Op::NotIn);
        let mut atoms: Vec<Pred> = needles
            .into_iter()
            .map(|needle| self.text_test(side, TextTest::new(text_op, needle), negate))
            .collect();
        Ok(match (op, atoms.pop()) {
            (Op::In, last) => Pred::Any(atoms.into_iter().chain(last).collect()),
            (Op::NotIn, last) => Pred::All(atoms.into_iter().chain(last).collect()),
            (_, Some(one)) => one,
            (_, None) => unreachable!("one needle"),
        })
    }

    /// One text test, true when its answer differs from `negate`.
    fn text_test(&mut self, side: BodySide, test: TextTest, negate: bool) -> Pred {
        // The answer that can make the expression true: `true` for a test
        // that reads as itself, `false` under a negation or a `not`.
        let wanted = negate == self.negated;
        let want = Want {
            on_true: wanted,
            on_false: !wanted,
        };
        let index = self.needs.texts.len();
        self.needs.texts.push((side, test.clone(), want));
        Pred::Text {
            side,
            index,
            test: Arc::new(test),
            negate,
            pending: self.negated,
        }
    }
}

/// The body whose text `t` is, if it is one.
fn body_side(t: &Typed<'_>) -> Option<BodySide> {
    match t {
        Typed::Field(Access::BodyText, _) => Some(BodySide::Request),
        Typed::Field(Access::RespBodyText, _) => Some(BodySide::Response),
        Typed::Field(..) | Typed::Lit(_) => None,
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
                    Lit::Str(_)
                    | Lit::Int(..)
                    | Lit::Bool(_)
                    | Lit::List(_)
                    | Lit::AddressList(_)
                    | Lit::Method(_)
                    | Lit::Null => Err(mismatch(item, "IP addresses or CIDRs")),
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
                    Lit::Str(s) => {
                        check_host_literal(&l, s, item.span, HostPos::Whole)?;
                        Ok(s.as_str().into())
                    }
                    Lit::Method(m) if method => Ok(m.as_str().into()),
                    Lit::Method(m) => Err(method_literal_error(item.span, m)),
                    Lit::Int(..)
                    | Lit::Bool(_)
                    | Lit::List(_)
                    | Lit::Ip(_)
                    | Lit::Cidr(_)
                    | Lit::AddressList(_)
                    | Lit::Null => Err(mismatch(item, "strings")),
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
                    Lit::Str(_)
                    | Lit::Bool(_)
                    | Lit::List(_)
                    | Lit::Ip(_)
                    | Lit::Cidr(_)
                    | Lit::AddressList(_)
                    | Lit::Method(_)
                    | Lit::Null => Err(mismatch(item, "numbers")),
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
/// and the lexer has already rejected it. roxy-proxy's address lists do the
/// same in `addrlist::normalise_net`; this crate cannot depend on it.
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
    for (field, lit) in [(&l, &r), (&r, &l)] {
        if let Typed::Lit(LitNode {
            lit: Lit::Str(s),
            span,
        }) = lit
        {
            check_host_literal(field, s, *span, HostPos::Whole)?;
        }
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
    op: OrdOp,
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
    op: StrOp,
    r: Typed<'_>,
    ro: &Operand,
) -> Result<Pred, ExprError> {
    string_lhs(&l, lo, op.as_str())?;
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
    if let Typed::Lit(LitNode {
        lit: Lit::Str(s),
        span,
    }) = &r
    {
        let pos = match op {
            StrOp::EndsWith => HostPos::Tail,
            StrOp::StartsWith => HostPos::Head,
            StrOp::Contains => HostPos::Inside,
        };
        check_host_literal(&l, s, *span, pos)?;
    }
    Ok(Pred::Str {
        ci: l.ci() || r.ci(),
        lhs: lower(l),
        rhs: lower(r),
        op,
    })
}

/// `like`, `matches`, `under`: a string field against a quoted literal.
fn pattern(
    l: Typed<'_>,
    lo: &Operand,
    op: PatternOp,
    r: &Typed<'_>,
    ro: &Operand,
) -> Result<Pred, ExprError> {
    string_lhs(&l, lo, op.as_str())?;
    let Typed::Lit(LitNode {
        lit: Lit::Str(pattern),
        span: rspan,
    }) = r
    else {
        let what = match op {
            PatternOp::Like => "a quoted glob pattern",
            PatternOp::Matches => "a quoted regex",
            PatternOp::Under => "a quoted domain",
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
        PatternOp::Like => {
            check_host_literal(&l, pattern, *rspan, HostPos::Glob)?;
            Ok(Pred::Glob {
                glob: build_glob(*rspan, pattern, ci)?,
                lhs: lower(l),
            })
        }
        PatternOp::Matches => Ok(Pred::Regex {
            re: build_regex(*rspan, pattern, ci)?,
            lhs: lower(l),
        }),
        PatternOp::Under => {
            if l.ty() == Some(Type::StrList) {
                return Err(ExprError::new(
                    l.span(),
                    "`under` needs a single host name on the left, not a list",
                ));
            }
            check_host_literal(&l, pattern, *rspan, HostPos::Inside)?;
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
        Type::Bool | Type::Str | Type::StrList => format!("a {t}"),
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

fn string_lhs(l: &Typed<'_>, lo: &Operand, op: &str) -> Result<(), ExprError> {
    match l.ty() {
        Some(Type::Str | Type::StrList) => Ok(()),
        _ => Err(ExprError::new(
            l.span(),
            format!(
                "`{op}` needs a string on the left, found {}",
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

/// Where a string literal sits against the host it is compared with.
/// `Whole` (`==`, `in`), `Tail` (`ends_with`) and `Glob` (`like`) end the
/// host, so a trailing dot there never matches; `Head` (`starts_with`)
/// and `Inside` (`contains`, `under`) may legitimately end with a dot.
/// `Whole`, `Head` and `Glob` start the host, so an IPv4-mapped prefix
/// there never matches.
#[derive(Clone, Copy, PartialEq, Eq)]
enum HostPos {
    Whole,
    Head,
    Tail,
    Glob,
    Inside,
}

/// Rejects a literal that no `host` or `tls.sni` can match: hosts arrive
/// as ASCII A-labels, without a trailing dot, IPv6 without brackets, and
/// an IPv4-mapped IPv6 address as the IPv4 address it embeds. Case is not
/// checked, as host comparisons are case-insensitive. Regexes (`matches`)
/// are not checked: dots and brackets are syntax there.
fn check_host_literal(
    field: &Typed<'_>,
    lit: &str,
    span: Span,
    pos: HostPos,
) -> Result<(), ExprError> {
    let Typed::Field(access @ Access::Scalar(Field::Host | Field::TlsSni), _) = field else {
        return Ok(());
    };
    let name = access.display_name();
    if !lit.is_ascii() {
        return Err(ExprError::new(
            span,
            format!(
                "`{name}` is ASCII (internationalised labels arrive as A-labels), so {lit:?} \
                 never matches; write the `xn--` form"
            ),
        ));
    }
    if lit.contains(['[', ']']) {
        // The bare form is the remedy, unless it is itself an IPv4-mapped
        // address, which arrives as the IPv4 address.
        let hint = lit
            .strip_prefix('[')
            .and_then(|l| l.strip_suffix(']'))
            .map_or_else(String::new, |bare| {
                let bare = mapped_v4(bare).map_or_else(|| bare.to_owned(), |v4| v4.to_string());
                format!("; write {bare:?}")
            });
        return Err(ExprError::new(
            span,
            format!(
                "`{name}` never has brackets (an IPv6 host is bare), so {lit:?} never matches{hint}"
            ),
        ));
    }
    if matches!(pos, HostPos::Whole | HostPos::Tail | HostPos::Glob) && lit.ends_with('.') {
        return Err(ExprError::new(
            span,
            format!(
                "`{name}` never has a trailing dot, so {lit:?} never matches; write {:?}",
                lit.trim_end_matches('.')
            ),
        ));
    }
    // A mapped address arrives as the IPv4 address it embeds, so neither
    // the whole literal nor a prefix of it in mapped form ever matches. A
    // host never starts with `::ffff:` in any other case: that spelling
    // is the mapped block. Elsewhere in a host (`1::ffff:2`) it is plain
    // IPv6 and no claim is made.
    let anchored = matches!(pos, HostPos::Whole | HostPos::Head | HostPos::Glob);
    let whole = mapped_v4(lit);
    let prefixed = lit
        .get(..MAPPED_PREFIX.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(MAPPED_PREFIX));
    if anchored && (whole.is_some() || prefixed) {
        // A complete address, in any spelling, has an IPv4 form to write;
        // a partial prefix only has the rest of itself.
        let hint = whole.map_or_else(
            || lit[MAPPED_PREFIX.len()..].to_owned(),
            |v4| v4.to_string(),
        );
        return Err(ExprError::new(
            span,
            format!(
                "`{name}` carries an IPv4-mapped address as the IPv4 address it embeds, so \
                 {lit:?} never matches; write {hint:?}"
            ),
        ));
    }
    Ok(())
}

/// How an IPv4-mapped IPv6 address starts when written out.
const MAPPED_PREFIX: &str = "::ffff:";

/// The IPv4 address an IPv4-mapped IPv6 literal embeds, in any spelling.
fn mapped_v4(s: &str) -> Option<std::net::Ipv4Addr> {
    match s.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(v6)) => v6.to_ipv4_mapped(),
        _ => None,
    }
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
    // Hosts arrive without empty labels, so a domain with one never matches.
    if d.split('.').any(str::is_empty) {
        return Err(ExprError::new(
            span,
            format!("domain {domain:?} has an empty label (`..`), which no host has"),
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
            Lit::List(_) | Lit::Cidr(_) | Lit::AddressList(_) | Lit::Null => {
                unreachable!(
                    "list, CIDR, address list and null literals are rejected before lowering"
                )
            }
        }),
    }
}
