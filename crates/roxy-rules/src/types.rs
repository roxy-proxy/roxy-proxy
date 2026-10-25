//! Field catalogue, static types, and which values are *admission* values
//! (known when the forwarding decision is made) or *in-flight* values (known
//! later).

use std::fmt::{self, Write as _};

use crate::ast::FieldRef;
use crate::diag::ExprError;

/// Static type of an operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    Bool,
    Int,
    Str,
    Ip,
    /// `header.all["x"]`: every value of a header.
    StrList,
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Type::Bool => "bool",
            Type::Int => "int",
            Type::Str => "string",
            Type::Ip => "ip",
            Type::StrList => "list of strings",
        })
    }
}

/// Every scalar field a [`crate::FlowView`] provides through
/// [`crate::FlowView::field`]. Map-indexed fields (`header["x"]`,
/// `query["k"]`, `state["k"]`, …), `metric.<id>`, `tag["t"]` and the body
/// texts have their own `FlowView` methods.
///
/// Normalisation contract for implementors: `Host` and `TlsSni`
/// are lower-case without a trailing dot (comparisons against them and
/// `scheme` are ASCII case-insensitive anyway); `Method` is the request
/// method as sent, and like everything else is compared byte-exact (HTTP
/// methods are case-sensitive: `get` is not `GET`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Field {
    /// `client.ip` (ip): the client as the proxy establishes it
    ClientIp,
    /// `listener.name` (string)
    ListenerName,
    /// `tls.sni` (string)
    TlsSni,
    /// `tls.alpn` (string)
    TlsAlpn,
    /// `tls.version` (string, e.g. `1.3`)
    TlsVersion,
    /// `method` (string)
    Method,
    /// `scheme` (string: `http` / `https`)
    Scheme,
    /// `host` (string)
    Host,
    /// `port` (int)
    Port,
    /// `path` (string, normalised)
    Path,
    /// `url` (string)
    Url,
    /// `query.raw` (string)
    QueryRaw,
    /// `body.size` (int: declared length; `null` if undeclared)
    BodySize,
    /// `body.bytes` (int: request body bytes so far; in flight)
    BodyBytes,
    /// `response.status` (int; in flight)
    ResponseStatus,
    /// `response.body.size` (int: declared length, `null` if undeclared;
    /// in flight)
    ResponseBodySize,
    /// `response.body.bytes` (int: response body bytes so far; in flight)
    ResponseBodyBytes,
    /// `ws.direction` (string: `c2s` / `s2c`)
    WsDirection,
    /// `ws.opcode` (int)
    WsOpcode,
    /// `ws.size` (int)
    WsSize,
    /// `ws.text` (string)
    WsText,
}

/// One value that becomes known (or changes) after the forwarding
/// decision. Each variant answers what it is (a field of the flow or a
/// byte metric) and when it is fixed; the [`Reads`] groups and names derive
/// from those answers, so a new in-flight value is declared here and
/// nowhere else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InFlightValue {
    /// `body.bytes`.
    BodyBytes,
    /// `body.text` (decided as the request body streams).
    BodyText,
    /// `response.status`, `response.header[...]`, `response.body.size`.
    ResponseHead,
    /// `response.body.bytes`.
    ResponseBodyBytes,
    /// `response.body.text` (decided as the response body streams).
    ResponseBodyText,
    /// `ws.*` (per WebSocket message).
    Ws,
    /// A metric counting `request_bytes`, which this exchange adds to as
    /// the request body (or WebSocket client bytes) stream.
    MetricRequestBytes,
    /// A metric counting `response_bytes`.
    MetricResponseBytes,
}

impl InFlightValue {
    pub const ALL: [InFlightValue; 8] = [
        Self::BodyBytes,
        Self::BodyText,
        Self::ResponseHead,
        Self::ResponseBodyBytes,
        Self::ResponseBodyText,
        Self::Ws,
        Self::MetricRequestBytes,
        Self::MetricResponseBytes,
    ];

    /// The name used in messages and `roxy check`.
    pub const fn name(self) -> &'static str {
        match self {
            Self::BodyBytes => "body.bytes",
            Self::BodyText => "body.text",
            Self::ResponseHead => "response head",
            Self::ResponseBodyBytes => "response.body.bytes",
            Self::ResponseBodyText => "response.body.text",
            Self::Ws => "ws.*",
            Self::MetricRequestBytes => "request_bytes metric",
            Self::MetricResponseBytes => "response_bytes metric",
        }
    }

    /// A field of the flow, as opposed to a byte metric. A byte metric's
    /// value is known at admission, so only a field makes the rule reading
    /// it an in-flight rule.
    pub const fn is_field(self) -> bool {
        !matches!(self, Self::MetricRequestBytes | Self::MetricResponseBytes)
    }

    /// Known before the response head is sent to the client, so a rule
    /// reading only such values can still change the response head.
    pub const fn before_response_sent(self) -> bool {
        matches!(self, Self::ResponseHead)
    }

    const fn bit(self) -> u16 {
        1 << (self as u16)
    }
}

impl fmt::Display for InFlightValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A set of [`InFlightValue`] values: what a rule reads that is not known at
/// admission, or what an event during an exchange changed. A bit mask, so the
/// per-chunk test "does any in-flight rule care about this?" is one `and`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Reads(u16);

/// The set of every [`InFlightValue`] value for which `$pred` holds.
macro_rules! derived {
    (|$w:ident| $pred:expr) => {{
        let mut bits = 0;
        let mut i = 0;
        while i < InFlightValue::ALL.len() {
            let $w = InFlightValue::ALL[i];
            if $pred {
                bits |= $w.bit();
            }
            i += 1;
        }
        Reads(bits)
    }};
}

impl Reads {
    pub const NONE: Reads = Reads(0);
    pub const BODY_BYTES: Reads = Reads::of(InFlightValue::BodyBytes);
    pub const BODY_TEXT: Reads = Reads::of(InFlightValue::BodyText);
    pub const RESPONSE_HEAD: Reads = Reads::of(InFlightValue::ResponseHead);
    pub const RESPONSE_BODY_BYTES: Reads = Reads::of(InFlightValue::ResponseBodyBytes);
    pub const RESPONSE_BODY_TEXT: Reads = Reads::of(InFlightValue::ResponseBodyText);
    pub const WS: Reads = Reads::of(InFlightValue::Ws);
    pub const METRIC_REQUEST_BYTES: Reads = Reads::of(InFlightValue::MetricRequestBytes);
    pub const METRIC_RESPONSE_BYTES: Reads = Reads::of(InFlightValue::MetricResponseBytes);

    /// Every in-flight *field* (not metrics).
    pub const IN_FLIGHT_FIELDS: Reads = derived!(|w| w.is_field());
    /// Both byte metrics.
    pub const METRICS: Reads = derived!(|w| !w.is_field());
    /// Everything: every in-flight field and both byte metrics.
    pub const ALL: Reads = derived!(|_w| true);
    /// Values known before the response head is sent to the client.
    pub const BEFORE_RESPONSE_SENT: Reads = derived!(|w| w.before_response_sent());

    pub const fn of(w: InFlightValue) -> Reads {
        Reads(w.bit())
    }

    pub const fn contains(self, w: InFlightValue) -> bool {
        self.0 & w.bit() != 0
    }

    #[must_use]
    pub const fn union(self, other: Reads) -> Reads {
        Reads(self.0 | other.0)
    }

    pub const fn intersects(self, other: Reads) -> bool {
        self.0 & other.0 != 0
    }

    /// Every bit of `self` is in `other`.
    pub const fn is_subset(self, other: Reads) -> bool {
        self.0 & !other.0 == 0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    #[must_use]
    pub const fn minus(self, other: Reads) -> Reads {
        Reads(self.0 & !other.0)
    }

    /// The members of `self` for which `keep` holds.
    #[must_use]
    pub fn retain(self, keep: impl Fn(InFlightValue) -> bool) -> Reads {
        self.iter().filter(|w| keep(*w)).collect()
    }

    /// The members, in [`InFlightValue::ALL`] order.
    pub fn iter(self) -> impl Iterator<Item = InFlightValue> {
        InFlightValue::ALL
            .into_iter()
            .filter(move |w| self.contains(*w))
    }

    /// Names of the members, for messages and `roxy check`.
    pub fn names(self) -> Vec<&'static str> {
        self.iter().map(InFlightValue::name).collect()
    }
}

impl From<InFlightValue> for Reads {
    fn from(w: InFlightValue) -> Reads {
        Reads::of(w)
    }
}

impl From<Option<InFlightValue>> for Reads {
    fn from(w: Option<InFlightValue>) -> Reads {
        w.map_or(Reads::NONE, Reads::of)
    }
}

impl FromIterator<InFlightValue> for Reads {
    fn from_iter<I: IntoIterator<Item = InFlightValue>>(iter: I) -> Reads {
        iter.into_iter()
            .fold(Reads::NONE, |acc, w| acc | Reads::of(w))
    }
}

impl std::ops::BitOr for Reads {
    type Output = Reads;
    fn bitor(self, rhs: Reads) -> Reads {
        self.union(rhs)
    }
}

impl std::ops::BitOrAssign for Reads {
    fn bitor_assign(&mut self, rhs: Reads) {
        *self = self.union(rhs);
    }
}

impl Field {
    pub const ALL: [Field; 21] = [
        Self::ClientIp,
        Self::ListenerName,
        Self::TlsSni,
        Self::TlsAlpn,
        Self::TlsVersion,
        Self::Method,
        Self::Scheme,
        Self::Host,
        Self::Port,
        Self::Path,
        Self::Url,
        Self::QueryRaw,
        Self::BodySize,
        Self::BodyBytes,
        Self::ResponseStatus,
        Self::ResponseBodySize,
        Self::ResponseBodyBytes,
        Self::WsDirection,
        Self::WsOpcode,
        Self::WsSize,
        Self::WsText,
    ];

    /// The DSL name, e.g. `client.ip`.
    pub fn name(self) -> &'static str {
        match self {
            Self::ClientIp => "client.ip",
            Self::ListenerName => "listener.name",
            Self::TlsSni => "tls.sni",
            Self::TlsAlpn => "tls.alpn",
            Self::TlsVersion => "tls.version",
            Self::Method => "method",
            Self::Scheme => "scheme",
            Self::Host => "host",
            Self::Port => "port",
            Self::Path => "path",
            Self::Url => "url",
            Self::QueryRaw => "query.raw",
            Self::BodySize => "body.size",
            Self::BodyBytes => "body.bytes",
            Self::ResponseStatus => "response.status",
            Self::ResponseBodySize => "response.body.size",
            Self::ResponseBodyBytes => "response.body.bytes",
            Self::WsDirection => "ws.direction",
            Self::WsOpcode => "ws.opcode",
            Self::WsSize => "ws.size",
            Self::WsText => "ws.text",
        }
    }

    pub fn from_name(name: &str) -> Option<Field> {
        Self::ALL.into_iter().find(|f| f.name() == name)
    }

    pub fn ty(self) -> Type {
        match self {
            Self::ClientIp => Type::Ip,
            Self::Port
            | Self::BodySize
            | Self::BodyBytes
            | Self::ResponseStatus
            | Self::ResponseBodySize
            | Self::ResponseBodyBytes
            | Self::WsOpcode
            | Self::WsSize => Type::Int,
            Self::ListenerName
            | Self::TlsSni
            | Self::TlsAlpn
            | Self::TlsVersion
            | Self::Method
            | Self::Scheme
            | Self::Host
            | Self::Path
            | Self::Url
            | Self::QueryRaw
            | Self::WsDirection
            | Self::WsText => Type::Str,
        }
    }

    /// Fields that can be `null` on an ordinary flow: the `tls.*` values on
    /// a plaintext connection, `query.raw` without a query, a declared
    /// length when the body is chunked.
    pub fn nullable(self) -> bool {
        matches!(
            self,
            Self::TlsSni
                | Self::TlsAlpn
                | Self::TlsVersion
                | Self::QueryRaw
                | Self::BodySize
                | Self::ResponseBodySize
        )
    }

    /// Fields compared ASCII case-insensitively (DNS names and the scheme).
    /// `method` is not one: HTTP methods are case-sensitive, and the proxy
    /// treats `get` as an extension method, not as `GET`.
    pub fn case_insensitive(self) -> bool {
        matches!(self, Self::Host | Self::TlsSni | Self::Scheme)
    }

    /// The in-flight value this field reads; `None` for an admission field.
    pub fn in_flight(self) -> Option<InFlightValue> {
        match self {
            Self::BodyBytes => Some(InFlightValue::BodyBytes),
            Self::ResponseStatus | Self::ResponseBodySize => Some(InFlightValue::ResponseHead),
            Self::ResponseBodyBytes => Some(InFlightValue::ResponseBodyBytes),
            Self::WsDirection | Self::WsOpcode | Self::WsSize | Self::WsText => {
                Some(InFlightValue::Ws)
            }
            Self::ClientIp
            | Self::ListenerName
            | Self::TlsSni
            | Self::TlsAlpn
            | Self::TlsVersion
            | Self::Method
            | Self::Scheme
            | Self::Host
            | Self::Port
            | Self::Path
            | Self::Url
            | Self::QueryRaw
            | Self::BodySize => None,
        }
    }

    /// Whether the field is known when the forwarding decision is made.
    pub fn is_admission(self) -> bool {
        self.in_flight().is_none()
    }
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A resolved field reference: how the evaluator obtains the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Access {
    Scalar(Field),
    /// Lower-cased header name.
    Header(Box<str>),
    HeaderAll(Box<str>),
    RespHeader(Box<str>),
    RespHeaderAll(Box<str>),
    Query(Box<str>),
    State(Box<str>),
    Tag(Box<str>),
    Metric(Box<str>),
    BodyText,
    RespBodyText,
}

impl Access {
    /// The field as written in a rule, for messages: `body.size`,
    /// `header["x"]`.
    pub(crate) fn display_name(&self) -> String {
        match self {
            Self::Scalar(f) => f.to_string(),
            Self::Header(n) => format!("header[{n:?}]"),
            Self::HeaderAll(n) => format!("header.all[{n:?}]"),
            Self::RespHeader(n) => format!("response.header[{n:?}]"),
            Self::RespHeaderAll(n) => format!("response.header.all[{n:?}]"),
            Self::Query(k) => format!("query[{k:?}]"),
            Self::State(k) => format!("state[{k:?}]"),
            Self::Tag(t) => format!("tag[{t:?}]"),
            Self::Metric(m) => format!("metric.{m}"),
            Self::BodyText => "body.text".into(),
            Self::RespBodyText => "response.body.text".into(),
        }
    }

    pub(crate) fn ty(&self) -> Type {
        match self {
            Self::Scalar(f) => f.ty(),
            Self::HeaderAll(_) | Self::RespHeaderAll(_) => Type::StrList,
            Self::Tag(_) => Type::Bool,
            Self::Metric(_) => Type::Int,
            Self::Header(_)
            | Self::RespHeader(_)
            | Self::Query(_)
            | Self::State(_)
            | Self::BodyText
            | Self::RespBodyText => Type::Str,
        }
    }

    pub(crate) fn case_insensitive(&self) -> bool {
        matches!(self, Self::Scalar(f) if f.case_insensitive())
    }

    /// Why this value is never `null`, for an access that always has one:
    /// the view answers, or the flow fails closed. `None` where `null` is a
    /// possible value (an unsent header, an unset state key, a scalar field
    /// the flow does not have).
    pub(crate) fn never_null(&self) -> Option<&'static str> {
        match self {
            Self::Tag(_) => Some("false until set"),
            Self::Metric(_) => Some("an unavailable metric fails the flow closed"),
            Self::BodyText | Self::RespBodyText => Some("an empty body is the empty string"),
            Self::Scalar(_)
            | Self::Header(_)
            | Self::HeaderAll(_)
            | Self::RespHeader(_)
            | Self::RespHeaderAll(_)
            | Self::Query(_)
            | Self::State(_) => None,
        }
    }

    /// The in-flight value this access reads; `None` for an admission
    /// value. A metric's depends on what it counts
    /// ([`MetricCount::in_flight`]), which the compiler looks up.
    ///
    /// [`MetricCount::in_flight`]: crate::config::MetricCount::in_flight
    pub(crate) fn in_flight(&self) -> Option<InFlightValue> {
        match self {
            Self::Scalar(f) => f.in_flight(),
            Self::RespHeader(_) | Self::RespHeaderAll(_) => Some(InFlightValue::ResponseHead),
            Self::BodyText => Some(InFlightValue::BodyText),
            Self::RespBodyText => Some(InFlightValue::ResponseBodyText),
            Self::Header(_)
            | Self::HeaderAll(_)
            | Self::Query(_)
            | Self::State(_)
            | Self::Tag(_)
            | Self::Metric(_) => None,
        }
    }
}

/// Names accepted by [`resolve`], for "did you mean" suggestions.
fn known_names() -> impl Iterator<Item = &'static str> {
    Field::ALL.iter().map(|f| f.name()).chain([
        "header[\"name\"]",
        "header.all[\"name\"]",
        "response.header[\"name\"]",
        "response.header.all[\"name\"]",
        "query[\"key\"]",
        "state[\"key\"]",
        "tag[\"name\"]",
        "metric.<id>",
        "body.text",
        "response.body.text",
    ])
}

/// HTTP `token` characters (RFC 9110 §5.6.2).
pub(crate) fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// Resolve a syntactic field reference, checking it exists and is indexed
/// correctly. `metric_exists` decides `metric.<id>` references.
pub(crate) fn resolve(
    f: &FieldRef,
    metric_exists: &dyn Fn(&str) -> bool,
) -> Result<Access, ExprError> {
    let dotted = f.dotted();
    let path: Vec<&str> = f.path.iter().map(String::as_str).collect();
    let index = f.index.as_deref();
    let header = |name: &str| -> Result<Box<str>, ExprError> {
        if is_token(name) {
            Ok(name.to_ascii_lowercase().into())
        } else {
            Err(ExprError::new(
                f.span,
                format!("invalid header name {name:?}"),
            ))
        }
    };
    let keyed = |what: &str, key: &str| -> Result<Box<str>, ExprError> {
        if key.is_empty() {
            Err(ExprError::new(f.span, format!("{what} must not be empty")))
        } else {
            Ok(key.into())
        }
    };
    let access = match (path.as_slice(), index) {
        (["header"], Some(n)) => Access::Header(header(n)?),
        (["header", "all"], Some(n)) => Access::HeaderAll(header(n)?),
        (["response", "header"], Some(n)) => Access::RespHeader(header(n)?),
        (["response", "header", "all"], Some(n)) => Access::RespHeaderAll(header(n)?),
        (["query"], Some(k)) => Access::Query(keyed("query key", k)?),
        (["state"], Some(k)) => Access::State(keyed("state key", k)?),
        (["tag"], Some(t)) => Access::Tag(keyed("tag name", t)?),
        (
            ["header" | "query" | "state" | "tag"]
            | ["header", "all"]
            | ["response", "header"]
            | ["response", "header", "all"],
            None,
        ) => {
            let example = match path[0] {
                "query" | "state" => "\"key\"",
                "tag" => "\"name\"",
                _ => "\"user-agent\"",
            };
            return Err(ExprError::new(
                f.span,
                format!("`{dotted}` needs a name in brackets, e.g. {dotted}[{example}]"),
            ));
        }
        (["metric", id], None) => {
            if !metric_exists(id) {
                return Err(ExprError::new(
                    f.span,
                    format!(
                        "reference to undefined metric `metric.{id}` (define it under `metrics`)"
                    ),
                ));
            }
            Access::Metric((*id).into())
        }
        (["metric"], _) => {
            return Err(ExprError::new(
                f.span,
                "`metric` needs an id, e.g. metric.github_writes",
            ));
        }
        (["body", "text"], None) => Access::BodyText,
        (["response", "body", "text"], None) => Access::RespBodyText,
        (_, idx) => {
            let Some(field) = Field::from_name(&dotted) else {
                return Err(unknown_field(f, &dotted));
            };
            if idx.is_some() {
                return Err(ExprError::new(
                    f.span,
                    format!("`{dotted}` cannot be indexed with [...]"),
                ));
            }
            Access::Scalar(field)
        }
    };
    Ok(access)
}

fn unknown_field(f: &FieldRef, dotted: &str) -> ExprError {
    let best = known_names()
        .map(|n| (edit_distance(dotted, n.split('[').next().unwrap_or(n)), n))
        .min_by_key(|(d, _)| *d)
        .filter(|(d, _)| *d <= 2);
    let mut msg = format!("unknown field `{dotted}`");
    if let Some((_, name)) = best {
        let _ = write!(msg, "; did you mean `{name}`?");
    } else if f.path.len() == 1 && f.index.is_none() {
        msg.push_str("; strings must be double-quoted");
    }
    ExprError::new(f.span, msg)
}

fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = vec![i + 1; b.len() + 1];
        for (j, cb) in b.iter().enumerate() {
            let sub = prev[j] + usize::from(ca != *cb);
            cur[j + 1] = sub.min(prev[j + 1] + 1).min(cur[j] + 1);
        }
        prev = cur;
    }
    prev[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_inner;

    fn res(src: &str) -> Result<Access, String> {
        let node = parse_inner(src).unwrap();
        let crate::ast::Expr::Pred(crate::ast::Operand::Field(f)) = node.expr else {
            panic!("{src}")
        };
        resolve(&f, &|id| id == "m").map_err(|e| e.message)
    }

    #[test]
    fn names_round_trip() {
        for f in Field::ALL {
            assert_eq!(Field::from_name(f.name()), Some(f));
        }
    }

    #[test]
    fn resolution() {
        assert_eq!(res("host"), Ok(Access::Scalar(Field::Host)));
        assert_eq!(
            res("header[\"User-Agent\"]"),
            Ok(Access::Header("user-agent".into()))
        );
        assert_eq!(res("header.all[\"x\"]"), Ok(Access::HeaderAll("x".into())));
        assert_eq!(res("metric.m"), Ok(Access::Metric("m".into())));
        assert_eq!(res("tag[\"t\"]"), Ok(Access::Tag("t".into())));
        assert_eq!(
            res("response.header[\"x\"]"),
            Ok(Access::RespHeader("x".into()))
        );
        assert_eq!(res("body.text"), Ok(Access::BodyText));
        assert_eq!(res("body.bytes"), Ok(Access::Scalar(Field::BodyBytes)));
    }

    #[test]
    fn admission_and_in_flight() {
        assert!(Field::Host.is_admission());
        assert!(Field::BodySize.is_admission());
        assert_eq!(Field::BodyBytes.in_flight(), Some(InFlightValue::BodyBytes));
        assert_eq!(
            Field::ResponseStatus.in_flight(),
            Some(InFlightValue::ResponseHead)
        );
        assert_eq!(
            Field::ResponseBodyBytes.in_flight(),
            Some(InFlightValue::ResponseBodyBytes)
        );
        assert_eq!(Field::WsText.in_flight(), Some(InFlightValue::Ws));
        assert_eq!(
            Access::RespBodyText.in_flight(),
            Some(InFlightValue::ResponseBodyText)
        );
        assert_eq!(Access::BodyText.in_flight(), Some(InFlightValue::BodyText));
        let r = Reads::BODY_BYTES | Reads::METRIC_REQUEST_BYTES;
        assert!(r.intersects(Reads::METRICS));
        assert!(Reads::BODY_BYTES.is_subset(r));
        assert_eq!(r.names(), ["body.bytes", "request_bytes metric"]);
        assert_eq!(r.retain(InFlightValue::is_field), Reads::BODY_BYTES);
    }

    /// The groups partition `InFlightValue::ALL` by its own predicates, and
    /// every member has a distinct bit and name.
    #[test]
    fn groups_derive_from_in_flight() {
        assert_eq!(Reads::IN_FLIGHT_FIELDS | Reads::METRICS, Reads::ALL);
        assert!(!Reads::IN_FLIGHT_FIELDS.intersects(Reads::METRICS));
        assert!(Reads::BEFORE_RESPONSE_SENT.is_subset(Reads::IN_FLIGHT_FIELDS));
        assert_eq!(Reads::ALL.iter().count(), InFlightValue::ALL.len());
        let names: std::collections::HashSet<&str> = Reads::ALL.names().into_iter().collect();
        assert_eq!(names.len(), InFlightValue::ALL.len());
    }

    #[test]
    fn resolution_errors() {
        assert!(res("hots").unwrap_err().contains("did you mean `host`"));
        assert!(res("github").unwrap_err().contains("double-quoted"));
        assert!(res("metric.x").unwrap_err().contains("undefined metric"));
        assert!(res("header").unwrap_err().contains("needs a name"));
        assert!(
            res("host[\"x\"]")
                .unwrap_err()
                .contains("cannot be indexed")
        );
        assert!(
            res("header[\"a b\"]")
                .unwrap_err()
                .contains("invalid header name")
        );
        // There are no connect-time fields.
        assert!(res("dst.host").unwrap_err().contains("unknown field"));
        assert!(res("dst.ip").unwrap_err().contains("unknown field"));
    }
}
