//! The flow as the rule engine sees it ([`FlowView`]).
//!
//! [`FlowFacts`] is an owned summary of the flow (the request head is
//! cloned, never the body), so the same view can be used for the request
//! decision, the response decision, metric recording after the body has
//! streamed, and the flow log.
//!
//! Field contract (`roxy_rules::Field`): hosts lower-case without a
//! trailing dot (IPv6 without brackets); `header["host"]` is the canonical
//! authority in `Host` form; `header["content-length"]` is the declared
//! length; `header["upgrade"]` is the requested upgrade (the hop-by-hop
//! header itself is consumed by the codec); `body.size` is the declared or
//! buffered length (absent for an unbuffered chunked body).

use std::borrow::Cow;
use std::net::IpAddr;
use std::sync::{Mutex, PoisonError};

use roxy_http::{Headers, Host, Query, Scheme};
use roxy_rules::{BodyText, Field, FlowView, Value};

use crate::addrlist::AddressLists;
use crate::flowlog::TlsInfo;
use crate::listener::ClientConn;
use crate::sources::{MetricSource, MetricSourceError, StateSource};

/// An inspected (buffered) body.
#[derive(Debug, Clone, Default)]
pub(crate) enum Inspected {
    /// No rule needs the body; it streams untouched.
    #[default]
    NotBuffered,
    /// Buffered (lossy UTF-8).
    Text(String),
    /// Larger than `limits.max_inspect_body_bytes`.
    TooLarge,
}

impl Inspected {
    fn as_body_text(&self) -> BodyText<'_> {
        match self {
            Self::NotBuffered => BodyText::Unavailable,
            Self::Text(t) => BodyText::Available(Cow::Borrowed(t)),
            Self::TooLarge => BodyText::TooLarge,
        }
    }
}

/// Connect-phase destination.
#[derive(Debug, Clone)]
pub(crate) struct DstFacts {
    pub host: Host,
    pub port: u16,
}

/// The request head.
#[derive(Debug, Clone)]
pub(crate) struct RequestFacts {
    pub method: String,
    pub scheme: Scheme,
    pub host: Host,
    pub port: u16,
    pub path: String,
    pub query: Option<Query>,
    pub headers: Headers,
    pub upgrade: Option<String>,
    pub body_size: Option<u64>,
    pub body: Inspected,
    pub head_bytes: usize,
}

/// The response head.
#[derive(Debug, Clone)]
pub(crate) struct ResponseFacts {
    pub status: u16,
    pub headers: Headers,
    pub body_size: Option<u64>,
    pub body: Inspected,
}

/// Everything a rule can see about a flow.
#[derive(Debug, Clone)]
pub(crate) struct FlowFacts {
    pub client: ClientConn,
    pub tls: Option<TlsInfo>,
    pub dst: Option<DstFacts>,
    pub request: Option<RequestFacts>,
    pub response: Option<ResponseFacts>,
}

/// Lower-case host text without brackets.
pub(crate) fn host_text(h: &Host) -> String {
    match h {
        Host::Dns(n) => n.clone(),
        Host::Ipv4(ip) => ip.to_string(),
        Host::Ipv6(ip) => ip.to_string(),
    }
}

fn host_ip(h: &Host) -> Option<IpAddr> {
    match h {
        Host::Dns(_) => None,
        Host::Ipv4(ip) => Some(IpAddr::V4(*ip)),
        Host::Ipv6(ip) => Some(IpAddr::V6(*ip)),
    }
}

enum Synthetic {
    Value(Option<String>),
    NotSynthetic,
}

fn s(v: Option<&String>) -> Value<'_> {
    v.map_or(Value::Absent, |s| Value::Str(Cow::Borrowed(s)))
}

fn all_values<'h>(h: &'h Headers, name: &str) -> Vec<Cow<'h, str>> {
    h.iter()
        .filter(|(n, _)| n.as_str() == name)
        .filter_map(|(_, v)| v.to_str().ok())
        .map(Cow::Borrowed)
        .collect()
}

fn int(n: u64) -> Value<'static> {
    Value::Int(i64::try_from(n).unwrap_or(i64::MAX))
}

impl RequestFacts {
    fn authority_header(&self) -> String {
        roxy_http::Authority::new(self.host.clone(), self.port).to_host_header(self.scheme)
    }

    pub(crate) fn url(&self) -> String {
        let q = self
            .query
            .as_ref()
            .map(|q| format!("?{q}"))
            .unwrap_or_default();
        format!(
            "{}://{}{}{}",
            self.scheme,
            self.authority_header(),
            self.path,
            q
        )
    }

    /// Headers the codec consumed or regenerates, served from the model.
    fn synthetic_header(&self, name: &str) -> Synthetic {
        match name {
            "host" => Synthetic::Value(Some(self.authority_header())),
            "content-length" => Synthetic::Value(self.body_size.map(|n| n.to_string())),
            "upgrade" => Synthetic::Value(self.upgrade.clone()),
            _ => Synthetic::NotSynthetic,
        }
    }
}

/// A [`FlowView`] over [`FlowFacts`] plus the metric and state stores.
pub(crate) struct ProxyView<'a> {
    pub facts: &'a FlowFacts,
    metrics: &'a dyn MetricSource,
    state: &'a dyn StateSource,
    /// The snapshot's address lists, for `ip in @name`.
    lists: &'a AddressLists,
    /// The first metric error met during evaluation, so a fail-closed
    /// outcome can say *why* (`metric_table_full` vs unavailable).
    metric_error: Mutex<Option<MetricSourceError>>,
}

impl<'a> ProxyView<'a> {
    pub(crate) fn new(
        facts: &'a FlowFacts,
        metrics: &'a dyn MetricSource,
        state: &'a dyn StateSource,
        lists: &'a AddressLists,
    ) -> Self {
        Self {
            facts,
            metrics,
            state,
            lists,
            metric_error: Mutex::new(None),
        }
    }

    pub(crate) fn take_metric_error(&self) -> Option<MetricSourceError> {
        self.metric_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }
}

impl FlowView for ProxyView<'_> {
    fn field(&self, f: Field) -> Value<'_> {
        let fa = self.facts;
        let req = fa.request.as_ref();
        let res = fa.response.as_ref();
        let tls = fa.tls.as_ref();
        match f {
            Field::ClientIp => Value::Ip(fa.client.peer.ip()),
            Field::ClientPort => Value::Int(i64::from(fa.client.peer.port())),
            Field::ClientUser => s(fa.client.user.as_ref()),
            Field::ListenerName => Value::Str(Cow::Borrowed(&fa.client.listener.name)),
            Field::ListenerMode => Value::Str(Cow::Borrowed(fa.client.listener.mode.as_str())),
            Field::DstHost => fa
                .dst
                .as_ref()
                .map_or(Value::Absent, |d| Value::str(host_text(&d.host))),
            Field::DstPort => fa
                .dst
                .as_ref()
                .map_or(Value::Absent, |d| Value::Int(i64::from(d.port))),
            Field::DstIp => fa
                .dst
                .as_ref()
                .and_then(|d| host_ip(&d.host))
                .map_or(Value::Absent, Value::Ip),
            Field::TlsSni => s(tls.and_then(|t| t.sni.as_ref())),
            Field::TlsAlpn => s(tls.and_then(|t| t.alpn.as_ref())),
            Field::TlsVersion => s(tls.and_then(|t| t.version.as_ref())),
            Field::Method => req.map_or(Value::Absent, |r| Value::Str(Cow::Borrowed(&r.method))),
            Field::Scheme => req.map_or(Value::Absent, |r| {
                Value::Str(Cow::Borrowed(r.scheme.as_str()))
            }),
            Field::Host => req.map_or(Value::Absent, |r| Value::str(host_text(&r.host))),
            Field::Port => req.map_or(Value::Absent, |r| Value::Int(i64::from(r.port))),
            Field::Path => req.map_or(Value::Absent, |r| Value::Str(Cow::Borrowed(&r.path))),
            Field::Url => req.map_or(Value::Absent, |r| Value::str(r.url())),
            Field::QueryRaw => req
                .and_then(|r| r.query.as_ref())
                .map_or(Value::Absent, |q| Value::Str(Cow::Borrowed(q.as_str()))),
            Field::BodySize => req.and_then(|r| r.body_size).map_or(Value::Absent, int),
            Field::ResponseStatus => res.map_or(Value::Absent, |r| Value::Int(i64::from(r.status))),
            Field::ResponseBodySize => res.and_then(|r| r.body_size).map_or(Value::Absent, int),
            // WebSocket inspect tier (M3): not available in this build.
            Field::WsDirection | Field::WsOpcode | Field::WsSize | Field::WsText => Value::Absent,
        }
    }

    fn header(&self, name: &str) -> Option<Cow<'_, str>> {
        let r = self.facts.request.as_ref()?;
        if let Synthetic::Value(v) = r.synthetic_header(name) {
            return v.map(Cow::Owned);
        }
        r.headers.get(name).map(Cow::Borrowed)
    }

    fn header_all(&self, name: &str) -> Vec<Cow<'_, str>> {
        let Some(r) = self.facts.request.as_ref() else {
            return Vec::new();
        };
        if let Synthetic::Value(v) = r.synthetic_header(name) {
            return v.into_iter().map(Cow::Owned).collect();
        }
        all_values(&r.headers, name)
    }

    fn response_header(&self, name: &str) -> Option<Cow<'_, str>> {
        let r = self.facts.response.as_ref()?;
        if name == "content-length" {
            return r.body_size.map(|n| Cow::Owned(n.to_string()));
        }
        r.headers.get(name).map(Cow::Borrowed)
    }

    fn response_header_all(&self, name: &str) -> Vec<Cow<'_, str>> {
        let Some(r) = self.facts.response.as_ref() else {
            return Vec::new();
        };
        if name == "content-length" {
            return r
                .body_size
                .map(|n| Cow::Owned(n.to_string()))
                .into_iter()
                .collect();
        }
        all_values(&r.headers, name)
    }

    fn query(&self, key: &str) -> Option<Cow<'_, str>> {
        self.facts
            .request
            .as_ref()?
            .query
            .as_ref()?
            .get(key)
            .map(Cow::Owned)
    }

    fn metric(&self, id: &str) -> Option<i64> {
        match self.metrics.get(id, self) {
            Ok(v) => Some(v),
            Err(e) => {
                let mut slot = self
                    .metric_error
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                if slot.is_none() {
                    *slot = Some(e);
                }
                None
            }
        }
    }

    fn state(&self, key: &str) -> Option<Cow<'_, str>> {
        self.state.get(key).map(Cow::Owned)
    }

    fn body_text(&self) -> BodyText<'_> {
        self.facts
            .request
            .as_ref()
            .map_or(BodyText::Unavailable, |r| r.body.as_body_text())
    }

    fn response_body_text(&self) -> BodyText<'_> {
        self.facts
            .response
            .as_ref()
            .map_or(BodyText::Unavailable, |r| r.body.as_body_text())
    }

    fn in_address_list(&self, list: &str, ip: IpAddr) -> Option<bool> {
        // The compiler only accepts names defined under `address_lists`, and
        // every defined list is loaded into the snapshot or the snapshot is
        // refused; `None` (fail closed) is the "cannot happen" answer.
        self.lists.get(list).map(|l| l.contains(ip))
    }
}
