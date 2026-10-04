//! `roxy rule test`: evaluate a synthetic flow against the
//! compiled policy without any network I/O.

use std::borrow::Cow;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::sync::Arc;

use roxy_proxy::Redactor;
use roxy_proxy::addr::AddressDenied;
use roxy_proxy::addrlist::AddressLists;
use roxy_rules::{
    BodyText, Decision, EvalContext, Field, FlowView, MapView, Outcome, Policy, Reads, RuleId,
    RuleKind, Value, WatchOutcome,
};

use crate::config::{Config, ListenerMode};

/// The dry-run flow: a [`MapView`] whose address lists are the same
/// compiled [`roxy_proxy::AddressList`]s `roxy run` uses.
#[derive(Debug, Clone, Default)]
pub struct DryRunView {
    pub map: MapView,
    /// Loaded lists; a list missing here (failed to load) answers `None`,
    /// which fails the flow closed, as it would at run time.
    pub lists: AddressLists,
}

impl FlowView for DryRunView {
    fn field(&self, f: Field) -> Value<'_> {
        self.map.field(f)
    }
    fn header(&self, name: &str) -> Option<Cow<'_, str>> {
        self.map.header(name)
    }
    fn header_all(&self, name: &str) -> Vec<Cow<'_, str>> {
        self.map.header_all(name)
    }
    fn response_header(&self, name: &str) -> Option<Cow<'_, str>> {
        self.map.response_header(name)
    }
    fn response_header_all(&self, name: &str) -> Vec<Cow<'_, str>> {
        self.map.response_header_all(name)
    }
    fn query(&self, key: &str) -> Option<Cow<'_, str>> {
        self.map.query(key)
    }
    fn metric(&self, id: &str) -> Option<i64> {
        self.map.metric(id)
    }
    fn state(&self, key: &str) -> Option<Cow<'_, str>> {
        self.map.state(key)
    }
    fn body_text(&self) -> BodyText<'_> {
        self.map.body_text()
    }
    fn response_body_text(&self) -> BodyText<'_> {
        self.map.response_body_text()
    }
    fn in_address_list(&self, list: &str, ip: IpAddr) -> Option<bool> {
        self.lists.get(list).map(|l| l.contains_exact(ip))
    }
}

/// A dry-run request described on the command line.
#[derive(Debug, Clone)]
pub struct TestRequest {
    pub method: String,
    pub url: String,
    /// `name: value` pairs.
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub client_ip: IpAddr,
    pub user: Option<String>,
    /// `body.bytes`: request body bytes streamed so far (watching rules).
    pub body_bytes: Option<u64>,
    /// `response.status`; with it, rules reading the response head run.
    pub response_status: Option<u16>,
    /// `response.body.bytes` (watching rules).
    pub response_body_bytes: Option<u64>,
    pub response_headers: Vec<(String, String)>,
    /// A WebSocket message (`ws.*`); with it, rules reading `ws.*` run.
    pub ws: Option<WsMessage>,
    /// `--metric id=N` (`Some(N)`) or `--metric id=unavailable` (`None`).
    /// Defined metrics not listed here evaluate as 0, a fresh series.
    pub metrics: Vec<(String, Option<i64>)>,
    pub state: Vec<(String, String)>,
    pub tags: Vec<String>,
}

/// How a metric is presented to the rules in a dry run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricValue {
    /// Given with `--metric id=N`.
    Given(i64),
    /// Not given: a fresh series, 0.
    Default,
    /// `--metric id=unavailable`: the view returns `None`, exercising the
    /// engine's fail-closed path.
    Unavailable,
}

/// The value of every defined metric, plus any extra ones given on the
/// command line, in config order.
pub fn metric_values(config: &Config, req: &TestRequest) -> Vec<(String, MetricValue)> {
    let given = |id: &str| {
        req.metrics
            .iter()
            .rev()
            .find(|(k, _)| k == id)
            .map(|(_, v)| v.map_or(MetricValue::Unavailable, MetricValue::Given))
    };
    let mut out: Vec<(String, MetricValue)> = config
        .metrics
        .iter()
        .map(|m| (m.id.clone(), given(&m.id).unwrap_or(MetricValue::Default)))
        .collect();
    for (id, _) in &req.metrics {
        if !out.iter().any(|(k, _)| k == id) {
            out.push((id.clone(), given(id).unwrap_or(MetricValue::Default)));
        }
    }
    out
}

/// `github_writes=0 (default), egress_bytes=12, x=unavailable`, or `None`
/// when there are no metrics.
pub fn metric_note(values: &[(String, MetricValue)]) -> Option<String> {
    if values.is_empty() {
        return None;
    }
    Some(
        values
            .iter()
            .map(|(id, v)| match v {
                MetricValue::Given(n) => format!("{id}={n}"),
                MetricValue::Default => format!("{id}=0 (default)"),
                MetricValue::Unavailable => format!("{id}=unavailable"),
            })
            .collect::<Vec<_>>()
            .join(", "),
    )
}

/// Parse a `--metric` argument: `id=N` or `id=unavailable`.
pub fn parse_metric(s: &str) -> Result<(String, Option<i64>), String> {
    let (k, v) = parse_pair(s)?;
    if v == "unavailable" {
        return Ok((k, None));
    }
    let n = v
        .parse::<i64>()
        .map_err(|_| format!("metric {k:?}: {v:?} is not an integer or `unavailable`"))?;
    Ok((k, Some(n)))
}

impl TestRequest {
    /// A request with defaults: client 127.0.0.1, no headers or body.
    pub fn new(method: &str, url: &str) -> Self {
        Self {
            method: method.to_owned(),
            url: url.to_owned(),
            headers: Vec::new(),
            body: None,
            client_ip: IpAddr::from([127, 0, 0, 1]),
            user: None,
            body_bytes: None,
            response_status: None,
            response_body_bytes: None,
            response_headers: Vec::new(),
            ws: None,
            metrics: Vec::new(),
            state: Vec::new(),
            tags: Vec::new(),
        }
    }
}

/// A dry-run WebSocket message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsMessage {
    /// `c2s` or `s2c`.
    pub direction: String,
    pub opcode: u8,
    pub size: u64,
    /// `ws.text`: set for a text message only.
    pub text: Option<String>,
}

/// The message described by `--ws-direction`, `--ws-opcode`, `--ws-text`
/// and `--ws-size`; `None` when none is given. A text message (opcode 1,
/// the default with `--ws-text`) takes its size from its text; any other
/// message has no text and is binary (2) by default.
pub fn ws_message(
    direction: Option<&str>,
    opcode: Option<u8>,
    text: Option<&str>,
    size: Option<u64>,
) -> Result<Option<WsMessage>, String> {
    if direction.is_none() && opcode.is_none() && text.is_none() && size.is_none() {
        return Ok(None);
    }
    let direction = match direction.unwrap_or("c2s") {
        d @ ("c2s" | "s2c") => d.to_owned(),
        d => return Err(format!("--ws-direction {d:?}: expected `c2s` or `s2c`")),
    };
    let opcode = opcode.unwrap_or(if text.is_some() { 1 } else { 2 });
    if ![1, 2, 8, 9, 10].contains(&opcode) {
        return Err(format!(
            "--ws-opcode {opcode}: expected 1 (text), 2 (binary), 8 (close), 9 (ping) or 10 (pong)"
        ));
    }
    if opcode == 1 {
        if size.is_some() {
            return Err("--ws-size: a text message's size is the length of --ws-text".into());
        }
        let text = text.unwrap_or("").to_owned();
        return Ok(Some(WsMessage {
            direction,
            opcode,
            size: text.len() as u64,
            text: Some(text),
        }));
    }
    if text.is_some() {
        return Err(format!(
            "--ws-text needs a text message (--ws-opcode 1), not {opcode}"
        ));
    }
    let size = size.unwrap_or(0);
    if opcode >= 8 && size > 125 {
        return Err(format!(
            "--ws-size {size}: a control message is at most 125 bytes"
        ));
    }
    Ok(Some(WsMessage {
        direction,
        opcode,
        size,
        text: None,
    }))
}

/// The parts of an absolute URL that rules see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedUrl {
    pub scheme: String,
    /// Lower-case, trailing dot removed, IPv6 without brackets.
    pub host: String,
    pub port: u16,
    pub path: String,
    pub query: Option<String>,
}

impl ParsedUrl {
    /// `scheme://host[:port]/path[?query]`, port shown only if non-default.
    pub(crate) fn url(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let default = matches!(
            (self.scheme.as_str(), self.port),
            ("http", 80) | ("https", 443)
        );
        let port = if default {
            String::new()
        } else {
            format!(":{}", self.port)
        };
        let query = self
            .query
            .as_ref()
            .map_or_else(String::new, |q| format!("?{q}"));
        format!("{}://{host}{port}{}{query}", self.scheme, self.path)
    }

    fn authority(&self) -> String {
        let u = self.url();
        let rest = &u[self.scheme.len() + 3..];
        rest.split('/').next().unwrap_or(rest).to_owned()
    }
}

/// Parse an absolute `http`/`https` URL. Deliberately small: roxy-http owns
/// real normalisation; this only splits the parts.
pub(crate) fn parse_url(url: &str) -> Result<ParsedUrl, String> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| format!("{url:?} is not an absolute URL (expected http(s)://host/...)"))?;
    let scheme = scheme.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "http" => 80,
        "https" => 443,
        other => return Err(format!("unsupported scheme {other:?}")),
    };
    if rest.contains('#') {
        return Err("fragments are not valid in request targets".into());
    }
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    if authority.contains('@') {
        return Err("userinfo in URLs is not supported".into());
    }
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (h, after) = v6
            .split_once(']')
            .ok_or("unterminated IPv6 literal in URL")?;
        (h, after.strip_prefix(':'))
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    if host.is_empty() {
        return Err(format!("{url:?} has no host"));
    }
    let port = match port {
        Some(p) => p
            .parse::<u16>()
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| format!("invalid port {p:?}"))?,
        None => default_port,
    };
    let (path, query) = match tail.split_once('?') {
        Some((p, q)) => (p, Some(q.to_owned())),
        None => (tail, None),
    };
    let path = if path.is_empty() { "/" } else { path };
    Ok(ParsedUrl {
        scheme,
        host,
        port,
        path: path.to_owned(),
        query,
    })
}

/// Split `name: value`.
pub fn parse_header(h: &str) -> Result<(String, String), String> {
    let (name, value) = h
        .split_once(':')
        .ok_or_else(|| format!("header {h:?} must look like `name: value`"))?;
    let name = name.trim();
    if name.is_empty() {
        return Err(format!("header {h:?} has an empty name"));
    }
    Ok((name.to_ascii_lowercase(), value.trim().to_owned()))
}

/// Split `key=value`.
pub fn parse_pair(s: &str) -> Result<(String, String), String> {
    s.split_once('=')
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .filter(|(k, _)| !k.is_empty())
        .ok_or_else(|| format!("{s:?} must look like `key=value`"))
}

/// Build the flow the rules see. Address lists are loaded exactly as at run
/// time; if any fails to load, a warning is returned and every list stays
/// unloaded, so `in @list` fails closed (at run time the config would not
/// start at all).
pub fn build_view(config: &Config, req: &TestRequest) -> Result<(DryRunView, Vec<String>), String> {
    let url = parse_url(&req.url)?;
    let mut warnings = Vec::new();
    let host_ip = url.host.parse::<IpAddr>().ok();
    // The request is taken to arrive on the first listener.
    let listener = config.listeners.first();
    let mode = match listener.map(|l| l.mode) {
        Some(ListenerMode::Direct) => "direct",
        _ => "explicit",
    };
    let mut v = MapView::new()
        .with(Field::ClientIp, Value::Ip(req.client_ip))
        .with_str(
            Field::ListenerName,
            listener.map_or("proxy", |l| l.name.as_str()),
        )
        .with_str(Field::ListenerMode, mode)
        .with_str(Field::Method, &req.method)
        .with_str(Field::Scheme, &url.scheme)
        .with_str(Field::Host, &url.host)
        .with_int(Field::Port, i64::from(url.port))
        .with_str(Field::Path, &url.path)
        .with_str(Field::Url, &url.url())
        .with_int(
            Field::BodySize,
            req.body
                .as_ref()
                .map_or(0, |b| i64::try_from(b.len()).unwrap_or(i64::MAX)),
        );
    if url.scheme == "https" && host_ip.is_none() {
        v = v.with_str(Field::TlsSni, &url.host);
    }
    if let Some(user) = &req.user {
        v = v.with_str(Field::ClientUser, user);
    }
    if let Some(q) = &url.query {
        v = v.with_str(Field::QueryRaw, q);
        for pair in q.split('&').filter(|p| !p.is_empty()) {
            let (k, val) = pair.split_once('=').unwrap_or((pair, ""));
            v = v.with_query(k, val);
        }
    }
    if !req.headers.iter().any(|(n, _)| n == "host") {
        v = v.with_header("host", &url.authority());
    }
    for (n, val) in &req.headers {
        v = v.with_header(n, val);
    }
    // No --body means an empty (and therefore inspectable) body; the dry run
    // has no response body, so `response.body.text` is empty too.
    v = v
        .with_body(req.body.as_deref().unwrap_or(""))
        .with_response_body("");
    let int = |n: u64| i64::try_from(n).unwrap_or(i64::MAX);
    if let Some(n) = req.body_bytes {
        v = v.with_int(Field::BodyBytes, int(n));
    }
    if let Some(status) = req.response_status {
        v = v.with_int(Field::ResponseStatus, i64::from(status));
    }
    if let Some(n) = req.response_body_bytes {
        v = v.with_int(Field::ResponseBodyBytes, int(n));
    }
    for (n, val) in &req.response_headers {
        v = v.with_response_header(n, val);
    }
    if let Some(m) = &req.ws {
        v = v
            .with_str(Field::WsDirection, &m.direction)
            .with_int(Field::WsOpcode, i64::from(m.opcode))
            .with_int(Field::WsSize, int(m.size));
        if let Some(t) = &m.text {
            v = v.with_str(Field::WsText, t);
        }
    }
    // Unavailable metrics are simply not inserted: MapView then returns
    // `None`, which the engine treats as fail-closed.
    for (id, value) in metric_values(config, req) {
        match value {
            MetricValue::Given(n) => v = v.with_metric(&id, n),
            MetricValue::Default => v = v.with_metric(&id, 0),
            MetricValue::Unavailable => {}
        }
    }
    for (k, val) in &req.state {
        v = v.with_state(k, val);
    }
    let lists = match crate::lists::load_all(config) {
        Ok(l) => l,
        Err(errs) => {
            for e in errs {
                warnings.push(format!("{e}; treating address lists as unavailable"));
            }
            AddressLists::new()
        }
    };
    Ok((DryRunView { map: v, lists }, warnings))
}

/// The upstream address floor for an IP-literal URL, as the
/// connector would apply it: private ranges (unless `private_ok`),
/// `deny_cidrs` and every `upstream.deny_lists` list. `None` when the host
/// is a name (it is not resolved in a dry run) or the decision is not an
/// allow.
pub fn address_check(
    config: &Config,
    view: &DryRunView,
    out: &Outcome,
) -> Option<Result<IpAddr, AddressDenied>> {
    let Decision::Allow(opts) = &out.decision else {
        return None;
    };
    let Value::Str(host) = view.map.field(Field::Host) else {
        return None;
    };
    let ip = host.parse::<IpAddr>().ok()?;
    let mut policy = roxy_proxy::UpstreamSettings::from(config).address_policy;
    policy.deny_lists = config
        .upstream
        .deny_lists
        .iter()
        .map(|n| view.lists.get(n).cloned())
        .collect::<Option<Vec<Arc<_>>>>()
        .unwrap_or_default();
    if policy.deny_lists.len() != config.upstream.deny_lists.len() {
        // A deny list failed to load: `roxy run` would refuse the config.
        return Some(Err(AddressDenied {
            ip,
            reason: "deny list unavailable".into(),
            matched_cidr: None,
            list: None,
        }));
    }
    Some(policy.check(ip, opts.private_ok).map(|()| ip))
}

/// Applies an address-policy denial to the outcome: `403 _address_policy`.
pub fn apply_address_denial(out: &mut Outcome) {
    out.decision = Decision::Deny {
        status: 403,
        message: roxy_rules::DEFAULT_DENY_MESSAGE.to_owned(),
        close: true,
    };
    out.terminal_rule = RuleId::new("_address_policy");
}

/// The watched values a dry run supplies, from the command line: which
/// watching rules can run.
pub fn known(req: &TestRequest) -> Reads {
    let mut k = Reads::NONE;
    if req.body_bytes.is_some() {
        k |= Reads::BODY_BYTES;
    }
    if req.response_status.is_some() {
        // The dry run has no response body: `response.body.text` is "".
        k |= Reads::RESPONSE_HEAD | Reads::RESPONSE_BODY_TEXT;
    }
    if req.response_body_bytes.is_some() {
        k |= Reads::RESPONSE_BODY_BYTES;
    }
    if req.ws.is_some() {
        k |= Reads::WS;
    }
    k
}

/// What a dry run decided.
#[derive(Debug, Clone)]
pub struct DryRun {
    /// The head decision.
    pub head: Outcome,
    /// The watching rules, re-checked once with the supplied watched values
    /// (and the given metric values), when the head allowed.
    pub watching: Option<WatchOutcome>,
}

impl DryRun {
    /// The final decision: a watching stop overrides the head's allow.
    pub fn decision(&self) -> &Decision {
        self.watching
            .as_ref()
            .and_then(|w| w.stop.as_ref())
            .unwrap_or(&self.head.decision)
    }

    pub(crate) fn terminal_rule(&self) -> &RuleId {
        self.watching
            .as_ref()
            .and_then(|w| w.terminal_rule.as_ref())
            .unwrap_or(&self.head.terminal_rule)
    }
}

/// Evaluate `req`: the head decision, then, if allowed, the watching rules
/// whose values are `known` (plus deny rules on byte metrics, at the given
/// metric values). Secrets are not resolved: each `${secret:name}` becomes
/// the placeholder `[secret:name]`.
pub fn run(policy: &Policy, view: &DryRunView, tags: &[String], known: Reads) -> DryRun {
    let placeholder = |name: &str| Some(format!("[secret:{name}]"));
    let ctx = EvalContext {
        secrets: &placeholder,
        initial_tags: tags,
    };
    let head = policy.evaluate_head(view, &ctx);
    let watching = head.decision.is_allow().then(|| {
        let mut st = policy.watch_state(&head.tags);
        let changed = known | Reads::METRICS;
        policy
            .evaluate_watching(changed, known, &mut st, view, &ctx)
            .unwrap_or_default()
    });
    DryRun { head, watching }
}

/// Every rule, whether it is decided at the request head or watches, and
/// what it watches. Shared by `roxy check` and `roxy rule test`.
pub fn classification(policy: &Policy) -> String {
    let info = policy.rule_info();
    let width = info.iter().map(|r| r.id.as_str().len()).max().unwrap_or(0);
    let mut s = String::new();
    for r in &info {
        let kind = match r.kind {
            RuleKind::Head => "head".to_owned(),
            RuleKind::Watching => format!("watching: {}", r.watches.join(", ")),
            RuleKind::HeadAndWatching => {
                format!("head, then watching: {}", r.watches.join(", "))
            }
        };
        let _ = writeln!(s, "  {:width$}  {kind}", r.id.as_str());
    }
    s
}

/// Human-readable report. Effect text passes through `redactor`.
/// `address` is the result of [`address_check`], when it ran.
pub fn report(
    policy: &Policy,
    metrics: Option<&str>,
    address: Option<&Result<IpAddr, AddressDenied>>,
    run: &DryRun,
    redactor: &Redactor,
) -> String {
    let mut s = String::new();
    let list = |items: Vec<String>| {
        if items.is_empty() {
            "(none)".to_owned()
        } else {
            items.join(", ")
        }
    };
    let _ = write!(s, "rules:\n{}", classification(policy));
    if let Some(m) = metrics {
        let _ = writeln!(s, "metrics:  {m}");
    }
    let out = &run.head;
    let _ = writeln!(
        s,
        "matched:  {}",
        list(out.matched.iter().map(ToString::to_string).collect())
    );
    let effects = |s: &mut String, effects: &[roxy_rules::Effect]| {
        if effects.is_empty() {
            let _ = writeln!(s, "effects:  (none)");
        } else {
            let _ = writeln!(s, "effects:");
            for e in effects {
                let _ = writeln!(s, "  - {}", redactor.redact_str(&e.to_string()));
            }
        }
    };
    effects(&mut s, &out.effects);
    let _ = writeln!(s, "tags:     {}", list(out.tags.clone()));
    match address {
        Some(Ok(ip)) => {
            let _ = writeln!(s, "address:  {ip} allowed by the upstream address policy");
        }
        Some(Err(d)) => {
            let _ = write!(
                s,
                "address:  {} denied by the upstream address policy ({}",
                d.ip, d.reason
            );
            if let Some(net) = d.matched_cidr {
                let _ = write!(s, ", matched {net}");
            }
            let _ = writeln!(s, ")");
        }
        None => {}
    }
    if let Some(w) = &run.watching {
        let _ = writeln!(s, "watching:");
        let _ = writeln!(
            s,
            "  matched:  {}",
            list(w.matched.iter().map(ToString::to_string).collect())
        );
        for e in &w.effects {
            let _ = writeln!(s, "  - {}", redactor.redact_str(&e.to_string()));
        }
        match (&w.stop, &w.terminal_rule) {
            (Some(d), Some(r)) => {
                let _ = writeln!(s, "  stops:    {d} (rule {r})");
            }
            _ => {
                let _ = writeln!(s, "  stops:    no");
            }
        }
    }
    let _ = writeln!(s, "decision: {}", run.decision());
    let _ = writeln!(s, "rule:     {}", run.terminal_rule());
    let reason = run
        .watching
        .as_ref()
        .and_then(|w| w.fail_closed_reason.as_ref())
        .or(out.fail_closed_reason.as_ref());
    if let Some(reason) = reason {
        let _ = writeln!(s, "reason:   {reason} (fail closed)");
    }
    s
}

/// Process exit code for a decision: 0 allow/passthrough, 3 deny.
pub fn exit_code(d: &Decision) -> u8 {
    if d.is_deny() { 3 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        let u = parse_url("https://API.GitHub.com./repos/a/b?x=1&y").unwrap();
        assert_eq!(u.scheme, "https");
        assert_eq!(u.host, "api.github.com");
        assert_eq!(u.port, 443);
        assert_eq!(u.path, "/repos/a/b");
        assert_eq!(u.query.as_deref(), Some("x=1&y"));
        assert_eq!(u.url(), "https://api.github.com/repos/a/b?x=1&y");

        let u = parse_url("http://[::1]:8080").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.path.as_str()),
            ("::1", 8080, "/")
        );
        assert_eq!(u.authority(), "[::1]:8080");

        for bad in [
            "example.com/x",
            "ftp://x/",
            "http:///x",
            "http://x:0/",
            "http://x:99999/",
            "http://u@x/",
            "http://x/#f",
        ] {
            assert!(parse_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn headers_and_pairs() {
        assert_eq!(
            parse_header("Content-Type:  application/json ").unwrap(),
            ("content-type".into(), "application/json".into())
        );
        assert!(parse_header("nocolon").is_err());
        assert_eq!(parse_pair("a=1").unwrap(), ("a".into(), "1".into()));
        assert!(parse_pair("=1").is_err());
    }

    #[test]
    fn ws_messages() {
        assert_eq!(ws_message(None, None, None, None), Ok(None));
        let m = ws_message(None, None, Some("héllo"), None)
            .unwrap()
            .unwrap();
        assert_eq!(
            (m.direction.as_str(), m.opcode, m.size, m.text.as_deref()),
            ("c2s", 1, 6, Some("héllo"))
        );
        let m = ws_message(Some("s2c"), None, None, Some(4096))
            .unwrap()
            .unwrap();
        assert_eq!((m.opcode, m.size, m.text), (2, 4096, None));
        let m = ws_message(None, Some(9), None, None).unwrap().unwrap();
        assert_eq!((m.opcode, m.size), (9, 0));
        for bad in [
            ws_message(Some("up"), None, None, None),
            ws_message(None, Some(3), None, None),
            ws_message(None, Some(2), Some("x"), None),
            ws_message(None, None, Some("x"), Some(1)),
            ws_message(None, Some(9), None, Some(126)),
        ] {
            assert!(bad.is_err(), "{bad:?}");
        }
    }

    #[test]
    fn ws_rules_run_with_a_message() {
        let config = Config::from_yaml(
            "version: 1\nlisteners: [{ name: p, bind: 127.0.0.1:3128 }]\nrules:\n  \
             - { id: ws, when: 'host == \"ws.test\"', then: { allow: { upgrade: websocket } } }\n  \
             - { id: no-secrets, when: 'ws.opcode == 1 and ws.text contains \"secret\"', then: deny }\n",
        )
        .unwrap();
        let policy = config.validate().unwrap().policy;
        let dry = |ws| {
            let mut req = TestRequest::new("GET", "https://ws.test/");
            req.ws = ws;
            let (view, _) = build_view(&config, &req).unwrap();
            run(&policy, &view, &[], known(&req))
        };
        assert!(dry(None).decision().is_allow());
        let hello = ws_message(None, None, Some("hello"), None).unwrap();
        assert!(dry(hello).decision().is_allow());
        let secret = ws_message(None, None, Some("my secret"), None).unwrap();
        let r = dry(secret);
        assert!(r.decision().is_deny());
        assert_eq!(r.terminal_rule().as_str(), "no-secrets");
    }

    #[test]
    fn the_first_listener_gives_the_mode() {
        let config = Config::from_yaml(
            "version: 1\nlisteners: [{ name: d, mode: direct, bind: 127.0.0.1:443 }]\nrules:\n  \
             - { id: direct, when: 'listener.mode == \"direct\" and listener.name == \"d\"', then: allow }\n",
        )
        .unwrap();
        let policy = config.validate().unwrap().policy;
        let req = TestRequest::new("GET", "https://example.com/");
        let (view, _) = build_view(&config, &req).unwrap();
        let r = run(&policy, &view, &[], known(&req));
        assert!(r.decision().is_allow());
        assert_eq!(r.terminal_rule().as_str(), "direct");
    }
}
