//! The interface between the proxy's flow model and the evaluator.

use std::borrow::Cow;
use std::collections::HashMap;
use std::net::IpAddr;

use ipnet::IpNet;

use crate::types::Field;

/// A runtime value. Borrowed wherever the view can lend its own storage, so
/// evaluation does not copy strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value<'a> {
    Str(Cow<'a, str>),
    Int(i64),
    Bool(bool),
    Ip(IpAddr),
    List(Vec<Cow<'a, str>>),
    /// Not known for this flow (no proxy auth, body not buffered, …). Every
    /// comparison with an absent operand is false — including `!=` and
    /// `not in`. `not (x == "a")` is true when `x` is absent.
    Absent,
}

impl Value<'_> {
    /// A `Value` borrowing from `self` (no string copies).
    pub fn reborrow(&self) -> Value<'_> {
        match self {
            Value::Str(s) => Value::Str(Cow::Borrowed(s)),
            Value::Int(n) => Value::Int(*n),
            Value::Bool(b) => Value::Bool(*b),
            Value::Ip(ip) => Value::Ip(*ip),
            Value::List(items) => Value::List(items.iter().map(|s| Cow::Borrowed(&**s)).collect()),
            Value::Absent => Value::Absent,
        }
    }

    /// An owned string value.
    pub fn str(s: impl Into<String>) -> Value<'static> {
        Value::Str(Cow::Owned(s.into()))
    }
}

/// A body as seen by `body.text` / `response.body.text`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyText<'a> {
    /// The buffered body as text. Bodies that are not valid UTF-8 should be
    /// passed lossily decoded rather than withheld.
    Available(Cow<'a, str>),
    /// Larger than `limits.max_inspect_body_bytes`: cannot be checked, so
    /// the flow fails closed. Scope large uploads out first with
    /// `body.size < 1mb and body.text contains ...` (`and` short-circuits,
    /// so the body is never inspected when the size test is false).
    TooLarge,
    /// Not buffered or could not be read (e.g. decompression failed).
    Unavailable,
}

/// Read-only access to one flow, implemented by the proxy.
///
/// Header names passed in are lower-case. Methods return `None` / `Absent` /
/// an empty vector for anything unknown, which the evaluator treats as absent
/// (predicate false) — except `metric` and `in_address_list`, see below.
pub trait FlowView {
    /// A scalar field. Normalisation contract: see [`Field`].
    fn field(&self, f: Field) -> Value<'_>;
    /// First value of a request header.
    fn header(&self, name: &str) -> Option<Cow<'_, str>>;
    /// Every value of a request header, in order.
    fn header_all(&self, name: &str) -> Vec<Cow<'_, str>>;
    /// First value of a response header (response phase).
    fn response_header(&self, name: &str) -> Option<Cow<'_, str>>;
    /// Every value of a response header.
    fn response_header_all(&self, name: &str) -> Vec<Cow<'_, str>>;
    /// First value of a query parameter.
    fn query(&self, key: &str) -> Option<Cow<'_, str>>;
    /// Current value of metric `id` for this flow's series key; `Some(0)` for a
    /// series with no data yet. `None` = unavailable, which fails the flow closed.
    fn metric(&self, id: &str) -> Option<i64>;
    /// A state-store entry.
    fn state(&self, key: &str) -> Option<Cow<'_, str>>;
    /// The buffered request body as text (§6.2). Only called when a rule
    /// reaches a `body.text` predicate. `TooLarge` and `Unavailable` both
    /// fail the flow closed; an empty body is `Available("")`.
    fn body_text(&self) -> BodyText<'_>;
    /// The buffered response body as text; same contract.
    fn response_body_text(&self) -> BodyText<'_>;
    /// Whether `ip` is in the named address list (`ip in @list`, §7.1).
    /// `None` = list unavailable (not loaded), which fails the flow closed
    /// (503, `_fail_closed`). `ip` is canonical (IPv4-mapped IPv6
    /// addresses arrive as IPv4).
    fn in_address_list(&self, list: &str, ip: IpAddr) -> Option<bool>;
}

/// A simple map-backed [`FlowView`] for tests, benchmarks and `roxy rule
/// test`.
#[derive(Debug, Clone, Default)]
pub struct MapView {
    pub fields: HashMap<Field, Value<'static>>,
    /// Lower-case name, value; repeated names allowed.
    pub headers: Vec<(String, String)>,
    pub response_headers: Vec<(String, String)>,
    pub query: Vec<(String, String)>,
    pub metrics: HashMap<String, i64>,
    pub state: HashMap<String, String>,
    /// `None` = not buffered (`BodyText::Unavailable`).
    pub body: Option<String>,
    pub response_body: Option<String>,
    /// Report the body as larger than the inspect cap.
    pub body_too_large: bool,
    pub response_body_too_large: bool,
    /// Address lists for `in @name`, scanned linearly.
    pub address_lists: HashMap<String, Vec<IpNet>>,
}

impl MapView {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with(mut self, f: Field, v: Value<'static>) -> Self {
        self.fields.insert(f, v);
        self
    }

    #[must_use]
    pub fn with_str(self, f: Field, s: &str) -> Self {
        self.with(f, Value::str(s))
    }

    #[must_use]
    pub fn with_int(self, f: Field, n: i64) -> Self {
        self.with(f, Value::Int(n))
    }

    #[must_use]
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers
            .push((name.to_ascii_lowercase(), value.to_owned()));
        self
    }

    #[must_use]
    pub fn with_response_header(mut self, name: &str, value: &str) -> Self {
        self.response_headers
            .push((name.to_ascii_lowercase(), value.to_owned()));
        self
    }

    #[must_use]
    pub fn with_query(mut self, key: &str, value: &str) -> Self {
        self.query.push((key.to_owned(), value.to_owned()));
        self
    }

    #[must_use]
    pub fn with_metric(mut self, id: &str, n: i64) -> Self {
        self.metrics.insert(id.to_owned(), n);
        self
    }

    #[must_use]
    pub fn with_state(mut self, key: &str, value: &str) -> Self {
        self.state.insert(key.to_owned(), value.to_owned());
        self
    }

    /// Define address list `name`.
    #[must_use]
    pub fn with_address_list(mut self, name: &str, nets: Vec<IpNet>) -> Self {
        self.address_lists.insert(name.to_owned(), nets);
        self
    }

    #[must_use]
    pub fn with_body(mut self, body: &str) -> Self {
        self.body = Some(body.to_owned());
        self
    }

    #[must_use]
    pub fn with_response_body(mut self, body: &str) -> Self {
        self.response_body = Some(body.to_owned());
        self
    }

    /// Report the request (or, with `response`, the response) body as over
    /// the inspect cap.
    #[must_use]
    pub fn with_body_too_large(mut self, response: bool) -> Self {
        if response {
            self.response_body_too_large = true;
        } else {
            self.body_too_large = true;
        }
        self
    }
}

fn body(text: Option<&str>, too_large: bool) -> BodyText<'_> {
    match (too_large, text) {
        (true, _) => BodyText::TooLarge,
        (false, Some(t)) => BodyText::Available(Cow::Borrowed(t)),
        (false, None) => BodyText::Unavailable,
    }
}

fn first<'a>(pairs: &'a [(String, String)], name: &str) -> Option<Cow<'a, str>> {
    pairs
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| Cow::Borrowed(v.as_str()))
}

fn all<'a>(pairs: &'a [(String, String)], name: &str) -> Vec<Cow<'a, str>> {
    pairs
        .iter()
        .filter(|(k, _)| k == name)
        .map(|(_, v)| Cow::Borrowed(v.as_str()))
        .collect()
}

impl FlowView for MapView {
    fn field(&self, f: Field) -> Value<'_> {
        self.fields.get(&f).map_or(Value::Absent, Value::reborrow)
    }
    fn header(&self, name: &str) -> Option<Cow<'_, str>> {
        first(&self.headers, name)
    }
    fn header_all(&self, name: &str) -> Vec<Cow<'_, str>> {
        all(&self.headers, name)
    }
    fn response_header(&self, name: &str) -> Option<Cow<'_, str>> {
        first(&self.response_headers, name)
    }
    fn response_header_all(&self, name: &str) -> Vec<Cow<'_, str>> {
        all(&self.response_headers, name)
    }
    fn query(&self, key: &str) -> Option<Cow<'_, str>> {
        first(&self.query, key)
    }
    fn metric(&self, id: &str) -> Option<i64> {
        self.metrics.get(id).copied()
    }
    fn state(&self, key: &str) -> Option<Cow<'_, str>> {
        self.state.get(key).map(|v| Cow::Borrowed(v.as_str()))
    }
    fn body_text(&self) -> BodyText<'_> {
        body(self.body.as_deref(), self.body_too_large)
    }
    fn response_body_text(&self) -> BodyText<'_> {
        body(self.response_body.as_deref(), self.response_body_too_large)
    }
    fn in_address_list(&self, list: &str, ip: IpAddr) -> Option<bool> {
        self.address_lists
            .get(list)
            .map(|nets| nets.iter().any(|n| n.contains(&ip)))
    }
}
