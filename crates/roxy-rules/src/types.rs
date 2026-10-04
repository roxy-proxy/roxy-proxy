//! Field catalogue, static types, and which values are *head* values
//! (known when the forwarding decision is made) or *watched* values (known
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
    /// `client.ip` (ip)
    ClientIp,
    /// `client.port` (int)
    ClientPort,
    /// `client.user` (string; absent without proxy auth)
    ClientUser,
    /// `listener.name` (string)
    ListenerName,
    /// `listener.mode` (string: `explicit`)
    ListenerMode,
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
    /// `body.bytes` (int: request body bytes so far; watched)
    BodyBytes,
    /// `response.status` (int; watched)
    ResponseStatus,
    /// `response.body.size` (int: declared length, `null` if undeclared;
    /// watched)
    ResponseBodySize,
    /// `response.body.bytes` (int: response body bytes so far; watched)
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

/// A set of values that become known (or change) after the forwarding
/// decision: what a rule reads beyond the request head, and
/// what an event during an exchange changed. A bit mask, so the per-chunk
/// test "does any watching rule care about this?" is one `and`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Reads(u16);

impl Reads {
    pub const NONE: Reads = Reads(0);
    /// `body.bytes`.
    pub const BODY_BYTES: Reads = Reads(1);
    /// `response.status`, `response.header[...]`, `response.body.size`.
    pub const RESPONSE_HEAD: Reads = Reads(1 << 1);
    /// `response.body.bytes`.
    pub const RESPONSE_BODY_BYTES: Reads = Reads(1 << 2);
    /// `response.body.text` (buffered before the response head is sent).
    pub const RESPONSE_BODY_TEXT: Reads = Reads(1 << 3);
    /// `ws.*` (per WebSocket message).
    pub const WS: Reads = Reads(1 << 4);
    /// A metric counting `request_bytes`, which this exchange adds to as
    /// the request body (or WebSocket client bytes) stream.
    pub const METRIC_REQUEST_BYTES: Reads = Reads(1 << 5);
    /// A metric counting `response_bytes`.
    pub const METRIC_RESPONSE_BYTES: Reads = Reads(1 << 6);

    /// Every watched *field* (not metrics).
    pub const WATCHED_FIELDS: Reads = Reads(0b1_1111);
    /// Both byte-metric bits.
    pub const METRICS: Reads = Reads(0b110_0000);
    /// Everything: every watched field and both byte metrics.
    pub const ALL: Reads = Reads(0b111_1111);
    /// Values known before the response head is sent to the client.
    pub const BEFORE_RESPONSE_SENT: Reads = Reads(0b1010);

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

    /// Names of the set bits, for messages and `roxy check`.
    pub fn names(self) -> Vec<&'static str> {
        [
            (Self::BODY_BYTES, "body.bytes"),
            (Self::RESPONSE_HEAD, "response head"),
            (Self::RESPONSE_BODY_BYTES, "response.body.bytes"),
            (Self::RESPONSE_BODY_TEXT, "response.body.text"),
            (Self::WS, "ws.*"),
            (Self::METRIC_REQUEST_BYTES, "request_bytes metric"),
            (Self::METRIC_RESPONSE_BYTES, "response_bytes metric"),
        ]
        .into_iter()
        .filter(|(b, _)| self.intersects(*b))
        .map(|(_, n)| n)
        .collect()
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
    pub const ALL: [Field; 24] = [
        Self::ClientIp,
        Self::ClientPort,
        Self::ClientUser,
        Self::ListenerName,
        Self::ListenerMode,
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
            Self::ClientPort => "client.port",
            Self::ClientUser => "client.user",
            Self::ListenerName => "listener.name",
            Self::ListenerMode => "listener.mode",
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
            Self::ClientPort
            | Self::Port
            | Self::BodySize
            | Self::BodyBytes
            | Self::ResponseStatus
            | Self::ResponseBodySize
            | Self::ResponseBodyBytes
            | Self::WsOpcode
            | Self::WsSize => Type::Int,
            _ => Type::Str,
        }
    }

    /// Fields compared ASCII case-insensitively (DNS names and the scheme).
    /// `method` is not one: HTTP methods are case-sensitive, and the proxy
    /// treats `get` as an extension method, not as `GET`.
    pub fn case_insensitive(self) -> bool {
        matches!(self, Self::Host | Self::TlsSni | Self::Scheme)
    }

    /// The watched values this field reads; empty for a head field.
    pub fn reads(self) -> Reads {
        match self {
            Self::BodyBytes => Reads::BODY_BYTES,
            Self::ResponseStatus | Self::ResponseBodySize => Reads::RESPONSE_HEAD,
            Self::ResponseBodyBytes => Reads::RESPONSE_BODY_BYTES,
            Self::WsDirection | Self::WsOpcode | Self::WsSize | Self::WsText => Reads::WS,
            _ => Reads::NONE,
        }
    }

    /// Whether the field is known when the forwarding decision is made.
    pub fn is_head(self) -> bool {
        self.reads().is_empty()
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
            _ => Type::Str,
        }
    }

    pub(crate) fn case_insensitive(&self) -> bool {
        matches!(self, Self::Scalar(f) if f.case_insensitive())
    }

    /// Watched values read by this access. Metrics are classified by the
    /// policy compiler (it knows what each metric counts), so they read
    /// [`Reads::NONE`] here.
    pub(crate) fn reads(&self) -> Reads {
        match self {
            Self::Scalar(f) => f.reads(),
            Self::RespHeader(_) | Self::RespHeaderAll(_) => Reads::RESPONSE_HEAD,
            Self::RespBodyText => Reads::RESPONSE_BODY_TEXT,
            Self::Header(_)
            | Self::HeaderAll(_)
            | Self::BodyText
            | Self::Query(_)
            | Self::State(_)
            | Self::Tag(_)
            | Self::Metric(_) => Reads::NONE,
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
    fn head_and_watched() {
        assert!(Field::Host.is_head());
        assert!(Field::BodySize.is_head());
        assert_eq!(Field::BodyBytes.reads(), Reads::BODY_BYTES);
        assert_eq!(Field::ResponseStatus.reads(), Reads::RESPONSE_HEAD);
        assert_eq!(Field::ResponseBodyBytes.reads(), Reads::RESPONSE_BODY_BYTES);
        assert_eq!(Field::WsText.reads(), Reads::WS);
        assert_eq!(Access::RespBodyText.reads(), Reads::RESPONSE_BODY_TEXT);
        assert!(Access::BodyText.reads().is_empty());
        let r = Reads::BODY_BYTES | Reads::METRIC_REQUEST_BYTES;
        assert!(r.intersects(Reads::METRICS));
        assert!(Reads::BODY_BYTES.is_subset(r));
        assert_eq!(r.names(), ["body.bytes", "request_bytes metric"]);
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
        // Connect-time fields are gone (they return with transparent mode).
        assert!(res("dst.host").unwrap_err().contains("unknown field"));
        assert!(res("dst.ip").unwrap_err().contains("unknown field"));
    }
}
