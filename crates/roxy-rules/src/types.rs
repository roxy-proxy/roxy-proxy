//! Field catalogue, static types and phase availability (§6.2 table).

use std::fmt::{self, Write as _};

use crate::ast::FieldRef;
use crate::config::Phase;
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
/// Normalisation contract for implementors: `Host`, `DstHost` and `TlsSni`
/// are lower-case without a trailing dot; `Method` is the request method as
/// sent (comparisons against `method`, `scheme` and the host fields are
/// ASCII case-insensitive anyway); everything else is compared byte-exact.
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
    /// `dst.host` (string; connect phase)
    DstHost,
    /// `dst.port` (int; connect phase)
    DstPort,
    /// `dst.ip` (ip; connect phase; absent until resolved)
    DstIp,
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
    /// `path` (string, normalised per §5.4)
    Path,
    /// `url` (string)
    Url,
    /// `query.raw` (string)
    QueryRaw,
    /// `body.size` (int)
    BodySize,
    /// `response.status` (int)
    ResponseStatus,
    /// `response.body.size` (int)
    ResponseBodySize,
    /// `ws.direction` (string: `c2s` / `s2c`)
    WsDirection,
    /// `ws.opcode` (int)
    WsOpcode,
    /// `ws.size` (int)
    WsSize,
    /// `ws.text` (string)
    WsText,
}

/// Bit set of phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Phases(u8);

impl Phases {
    const fn of(phases: &[Phase]) -> Self {
        let mut bits = 0;
        let mut i = 0;
        while i < phases.len() {
            bits |= 1 << phases[i] as u8;
            i += 1;
        }
        Self(bits)
    }
    const ALL: Phases = Phases::of(&Phase::ALL);
    const CONNECT: Phases = Phases::of(&[Phase::Connect]);
    const HTTP: Phases = Phases::of(&[Phase::Request, Phase::Response, Phase::Ws]);
    const MESSAGE: Phases = Phases::of(&[Phase::Request, Phase::Response]);
    const RESPONSE: Phases = Phases::of(&[Phase::Response]);
    const WS: Phases = Phases::of(&[Phase::Ws]);

    pub(crate) fn contains(self, p: Phase) -> bool {
        self.0 & (1 << p as u8) != 0
    }

    pub(crate) fn names(self) -> String {
        Phase::ALL
            .iter()
            .filter(|p| self.contains(**p))
            .map(|p| p.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl Field {
    pub const ALL: [Field; 25] = [
        Self::ClientIp,
        Self::ClientPort,
        Self::ClientUser,
        Self::ListenerName,
        Self::ListenerMode,
        Self::DstHost,
        Self::DstPort,
        Self::DstIp,
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
        Self::ResponseStatus,
        Self::ResponseBodySize,
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
            Self::DstHost => "dst.host",
            Self::DstPort => "dst.port",
            Self::DstIp => "dst.ip",
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
            Self::ResponseStatus => "response.status",
            Self::ResponseBodySize => "response.body.size",
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
            Self::ClientIp | Self::DstIp => Type::Ip,
            Self::ClientPort
            | Self::DstPort
            | Self::Port
            | Self::BodySize
            | Self::ResponseStatus
            | Self::ResponseBodySize
            | Self::WsOpcode
            | Self::WsSize => Type::Int,
            _ => Type::Str,
        }
    }

    /// Fields compared ASCII case-insensitively (DNS names, method, scheme).
    pub fn case_insensitive(self) -> bool {
        matches!(
            self,
            Self::Host | Self::DstHost | Self::TlsSni | Self::Method | Self::Scheme
        )
    }

    pub(crate) fn phases(self) -> Phases {
        match self {
            Self::DstHost | Self::DstPort | Self::DstIp => Phases::CONNECT,
            Self::Method | Self::Scheme | Self::Host | Self::Port | Self::Path | Self::Url => {
                Phases::HTTP
            }
            Self::QueryRaw => Phases::HTTP,
            Self::BodySize => Phases::MESSAGE,
            Self::ResponseStatus | Self::ResponseBodySize => Phases::RESPONSE,
            Self::WsDirection | Self::WsOpcode | Self::WsSize | Self::WsText => Phases::WS,
            _ => Phases::ALL,
        }
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

    fn phases(&self) -> Phases {
        match self {
            Self::Scalar(f) => f.phases(),
            Self::Header(_) | Self::HeaderAll(_) | Self::BodyText => Phases::MESSAGE,
            Self::RespHeader(_) | Self::RespHeaderAll(_) | Self::RespBodyText => Phases::RESPONSE,
            Self::Query(_) => Phases::HTTP,
            Self::State(_) | Self::Tag(_) | Self::Metric(_) => Phases::ALL,
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

/// Resolve a syntactic field reference, checking it exists, is indexed
/// correctly, and is available in `phase`. `metric_exists` decides
/// `metric.<id>` references.
pub(crate) fn resolve(
    f: &FieldRef,
    phase: Phase,
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
    let phases = access.phases();
    if !phases.contains(phase) {
        return Err(ExprError::new(
            f.span,
            format!(
                "`{f}` is not available in the {phase} phase (available in: {})",
                phases.names()
            ),
        ));
    }
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

    fn res(src: &str, phase: Phase) -> Result<Access, String> {
        let node = parse_inner(src).unwrap();
        let crate::ast::Expr::Pred(crate::ast::Operand::Field(f)) = node.expr else {
            panic!("{src}")
        };
        resolve(&f, phase, &|id| id == "m").map_err(|e| e.message)
    }

    #[test]
    fn names_round_trip() {
        for f in Field::ALL {
            assert_eq!(Field::from_name(f.name()), Some(f));
        }
    }

    #[test]
    fn resolution() {
        let r = Phase::Request;
        assert_eq!(res("host", r), Ok(Access::Scalar(Field::Host)));
        assert_eq!(
            res("header[\"User-Agent\"]", r),
            Ok(Access::Header("user-agent".into()))
        );
        assert_eq!(
            res("header.all[\"x\"]", r),
            Ok(Access::HeaderAll("x".into()))
        );
        assert_eq!(res("metric.m", r), Ok(Access::Metric("m".into())));
        assert_eq!(res("tag[\"t\"]", Phase::Ws), Ok(Access::Tag("t".into())));
        assert_eq!(
            res("response.header[\"x\"]", Phase::Response),
            Ok(Access::RespHeader("x".into()))
        );
        assert_eq!(res("body.text", r), Ok(Access::BodyText));
    }

    #[test]
    fn resolution_errors() {
        let r = Phase::Request;
        assert!(res("hots", r).unwrap_err().contains("did you mean `host`"));
        assert!(res("github", r).unwrap_err().contains("double-quoted"));
        assert!(res("metric.x", r).unwrap_err().contains("undefined metric"));
        assert!(res("header", r).unwrap_err().contains("needs a name"));
        assert!(
            res("host[\"x\"]", r)
                .unwrap_err()
                .contains("cannot be indexed")
        );
        assert!(
            res("header[\"a b\"]", r)
                .unwrap_err()
                .contains("invalid header name")
        );
        let e = res("response.status", r).unwrap_err();
        assert_eq!(
            e,
            "`response.status` is not available in the request phase (available in: response)"
        );
        assert!(res("dst.host", r).unwrap_err().contains("connect"));
        assert!(
            res("host", Phase::Connect)
                .unwrap_err()
                .contains("connect phase")
        );
    }
}
