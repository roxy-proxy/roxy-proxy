//! `roxy rule test`: evaluate a synthetic flow against the
//! compiled policy without any network I/O.

use std::borrow::Cow;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::sync::Arc;

use roxy_http::url::{self, Path, Query};
use roxy_http::{Authority, Headers, Host, HttpFlags, Limits, ParseError, Reason, Scheme};
use roxy_proxy::Redactor;
use roxy_proxy::addr::{AddressDenied, PrivateAddrs};
use roxy_proxy::addrlist::AddressLists;
use roxy_rules::{
    BodyText, Decision, Effect, EvalContext, Field, FlowView, MapView, Outcome, Policy, Reads,
    RuleId, RuleKind, Value, WatchOutcome,
};

use crate::config::Config;

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
    /// A chunked body: `body.size` and `header["content-length"]` are
    /// absent, as they are until a chunked body is buffered.
    pub chunked: bool,
    pub client_ip: IpAddr,
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
            chunked: false,
            client_ip: IpAddr::from([127, 0, 0, 1]),
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

/// The request head as the proxy hands it to the rules: canonical URL
/// parts and the header fields that survive parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Head {
    pub scheme: Scheme,
    pub authority: Authority,
    pub path: Path,
    pub query: Option<Query>,
    /// Without the hop-by-hop and framing fields; `host`,
    /// `content-length` and `upgrade` are served from the model instead.
    pub headers: Headers,
    /// The protocols `Upgrade` names, when `Connection` nominates it.
    pub upgrade: Option<String>,
}

impl Head {
    /// The `Host` header value: the authority with a non-default port only.
    pub(crate) fn host_header(&self) -> String {
        self.authority.to_host_header(self.scheme)
    }

    /// `scheme://host[:port]/path[?query]`.
    pub(crate) fn url(&self) -> String {
        let query = self
            .query
            .as_ref()
            .map_or_else(String::new, |q| format!("?{q}"));
        format!(
            "{}://{}{}{query}",
            self.scheme,
            self.host_header(),
            self.path
        )
    }
}

/// `host` as the rules see it: lower-case, no trailing dot, IPv6 without
/// brackets.
fn host_text(h: &Host) -> String {
    match h {
        Host::Dns(n) => n.clone(),
        Host::Ipv4(ip) => ip.to_string(),
        Host::Ipv6(ip) => ip.to_string(),
    }
}

/// Parse the URL and headers with the proxy's own parser, so the dry run
/// sees the canonical request and refuses what the proxy would refuse,
/// naming the same reason code.
pub(crate) fn parse_head(config: &Config, req: &TestRequest) -> Result<Head, String> {
    let (scheme, authority, path, query) = url::parse_absolute_form(req.url.as_bytes())
        .map_err(|e| format!("{:?} is not an absolute URL roxy accepts ({e})", req.url))?;
    let raw: Vec<(&[u8], &[u8])> = req
        .headers
        .iter()
        .map(|(n, v)| (n.as_bytes(), v.as_bytes()))
        .collect();
    let rejected = |e: ParseError| format!("roxy would reject these headers ({e})");
    let headers = Headers::try_from_raw(
        raw.iter().copied(),
        &Limits::from(config),
        &HttpFlags::from(config),
    )
    .map_err(rejected)?;
    let all = |name: &str| -> Vec<&[u8]> {
        raw.iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name.as_bytes()))
            .map(|(_, v)| *v)
            .collect()
    };
    let hosts = all("host");
    if hosts.len() > 1 {
        return Err(rejected(ParseError::new(
            Reason::MultipleHost,
            "multiple host fields",
        )));
    }
    if let Some(h) = hosts.first() {
        let given = url::parse_authority(h, scheme.default_port()).map_err(rejected)?;
        if given != authority {
            return Err(rejected(ParseError::new(
                Reason::HostMismatch,
                "host does not match the URL",
            )));
        }
    }
    let connection = roxy_http::connection_tokens(all("connection")).map_err(rejected)?;
    let upgrade = roxy_http::requested_upgrade(&connection, all("upgrade"));
    Ok(Head {
        scheme,
        authority,
        path,
        query,
        headers,
        upgrade,
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
    let head = parse_head(config, req)?;
    let mut warnings = Vec::new();
    let host = host_text(&head.authority.host);
    // The request is taken to arrive on the first listener.
    let listener = config.listeners.first();
    let mut v = MapView::new()
        .with(Field::ClientIp, Value::Ip(req.client_ip))
        .with_str(
            Field::ListenerName,
            listener.map_or("proxy", |l| l.name.as_str()),
        )
        .with_str(Field::ListenerMode, "explicit")
        .with_str(Field::Method, &req.method)
        .with_str(Field::Scheme, head.scheme.as_str())
        .with_str(Field::Host, &host)
        .with_int(Field::Port, i64::from(head.authority.port))
        .with_str(Field::Path, head.path.as_str())
        .with_str(Field::Url, &head.url())
        .with_header("host", &head.host_header());
    let int = |n: u64| i64::try_from(n).unwrap_or(i64::MAX);
    // No --body means an empty body with a declared length of 0; a chunked
    // body has no declared length.
    if !req.chunked {
        let size = req.body.as_ref().map_or(0, |b| b.len() as u64);
        v = v
            .with_int(Field::BodySize, int(size))
            .with_header("content-length", &size.to_string());
    }
    if let Some(u) = &head.upgrade {
        v = v.with_header("upgrade", u);
    }
    if head.scheme == Scheme::Https
        && let Some(name) = head.authority.host.dns_name()
    {
        v = v.with_str(Field::TlsSni, name);
    }
    if let Some(q) = &head.query {
        v = v.with_str(Field::QueryRaw, q.as_str());
        for (k, val) in q.pairs() {
            v = v.with_query(&k, &val);
        }
    }
    for (n, val) in head.headers.iter() {
        if let Ok(val) = val.to_str() {
            v = v.with_header(n.as_str(), val);
        }
    }
    // The body text is inspectable whether or not it is chunked; the dry
    // run has no response body, so `response.body.text` is empty too.
    v = v
        .with_body(req.body.as_deref().unwrap_or(""))
        .with_response_body("");
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
    for (id, _) in &req.metrics {
        if !config.metrics.iter().any(|m| &m.id == id) {
            warnings.push(format!(
                "--metric {id}: no metric {id:?} is defined, so no rule can read it"
            ));
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
    Some(
        policy
            .check(ip, PrivateAddrs::from_private_ok(opts.private_ok))
            .map(|()| ip),
    )
}

/// Applies an address-policy denial to the outcome: `403 _address_policy`.
pub fn apply_address_denial(out: &mut Outcome) {
    out.decision = Decision::default_deny();
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
    pub fn decision(&self) -> Decision {
        self.watching
            .as_ref()
            .and_then(|w| w.stop.clone())
            .map_or_else(|| self.head.decision.clone(), Decision::Deny)
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
            .evaluate_watching(changed, known, &mut st, view)
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
    let effects = |s: &mut String, effects: &[Effect]| {
        if effects.is_empty() {
            let _ = writeln!(s, "effects:  (none)");
        } else {
            let _ = writeln!(s, "effects:");
            for e in effects {
                // A dry run resolves secrets to `[secret:name]` placeholders,
                // which the report shows rather than the redacted form.
                let text = if let Effect::SetHeader { name, value } = e {
                    format!("set_header {name}: {}", value.as_str())
                } else {
                    e.to_string()
                };
                let _ = writeln!(s, "  - {}", redactor.redact_str(&text));
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

/// Process exit code for a decision: 0 allow, 3 deny.
pub fn exit_code(d: &Decision) -> u8 {
    if d.is_deny() { 3 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config::from_yaml("version: 1\nlisteners: [{ name: p, bind: 127.0.0.1:3128 }]\nrules: []\n")
            .unwrap()
    }

    #[test]
    fn urls_are_canonical() {
        let config = config();
        let req = TestRequest::new(
            "GET",
            "HTTPS://API.GitHub.com.:443/repos/%7ea/./b/../c%2e?x=%2f&y",
        );
        let h = parse_head(&config, &req).unwrap();
        assert_eq!(h.scheme, Scheme::Https);
        assert_eq!(host_text(&h.authority.host), "api.github.com");
        assert_eq!(h.authority.port, 443);
        assert_eq!(h.path.as_str(), "/repos/~a/c.");
        assert_eq!(h.query.as_ref().unwrap().as_str(), "x=%2F&y");
        assert_eq!(h.url(), "https://api.github.com/repos/~a/c.?x=%2F&y");
        assert_eq!(h.host_header(), "api.github.com");

        let req = TestRequest::new("GET", "http://[::1]:8080");
        let h = parse_head(&config, &req).unwrap();
        assert_eq!(host_text(&h.authority.host), "::1");
        assert_eq!((h.authority.port, h.path.as_str()), (8080, "/"));
        assert_eq!(h.host_header(), "[::1]:8080");

        for (bad, reason) in [
            ("example.com/x", "bad_request_target"),
            ("ftp://x/", "bad_request_target"),
            ("http:///x", "bad_authority"),
            ("http://x:0/", "bad_authority"),
            ("http://u@x/", "bad_authority"),
            ("http://x/#f", "fragment_in_target"),
            ("http://x/../a", "path_climbs_above_root"),
            ("http://b\u{fc}cher.example/", "non_ascii"),
            ("http://127.1/", "bad_authority"),
        ] {
            let err = parse_head(&config, &TestRequest::new("GET", bad)).unwrap_err();
            assert!(err.contains(reason), "{bad}: {err}");
        }
    }

    #[test]
    fn headers_are_canonical() {
        let config = config();
        let mut req = TestRequest::new("GET", "https://h.example/");
        req.headers = vec![
            ("connection".into(), "close, x-hop".into()),
            ("x-hop".into(), "1".into()),
            ("transfer-encoding".into(), "chunked".into()),
            ("content-length".into(), "99".into()),
            ("upgrade".into(), "websocket".into()),
            ("x-keep".into(), "yes".into()),
        ];
        let h = parse_head(&config, &req).unwrap();
        let names: Vec<_> = h.headers.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["x-keep"]);
        // `Upgrade` without `Connection: upgrade` is not a request to switch.
        assert_eq!(h.upgrade, None);

        req.headers = vec![
            ("connection".into(), "Upgrade".into()),
            ("upgrade".into(), "WebSocket".into()),
        ];
        let h = parse_head(&config, &req).unwrap();
        assert_eq!(h.upgrade.as_deref(), Some("websocket"));

        req.headers = vec![("connection".into(), "(bad)".into())];
        let err = parse_head(&config, &req).unwrap_err();
        assert!(err.contains("bad_connection_header"), "{err}");
        req.headers = vec![("bad name".into(), "x".into())];
        let err = parse_head(&config, &req).unwrap_err();
        assert!(err.contains("invalid_header_name"), "{err}");
        req.headers = vec![("x".into(), "a\u{7f}b".into())];
        let err = parse_head(&config, &req).unwrap_err();
        assert!(err.contains("invalid_header_value"), "{err}");
    }

    #[test]
    fn host_header_must_name_the_url_authority() {
        let config = config();
        let mut req = TestRequest::new("GET", "https://h.example/");
        req.headers = vec![("host".into(), "H.EXAMPLE.:443".into())];
        assert_eq!(
            parse_head(&config, &req).unwrap().host_header(),
            "h.example"
        );
        req.headers = vec![("host".into(), "other.example".into())];
        let err = parse_head(&config, &req).unwrap_err();
        assert!(err.contains("host_mismatch"), "{err}");
        req.headers = vec![("host".into(), "h.example:8443".into())];
        let err = parse_head(&config, &req).unwrap_err();
        assert!(err.contains("host_mismatch"), "{err}");
        req.headers = vec![
            ("host".into(), "h.example".into()),
            ("host".into(), "h.example".into()),
        ];
        let err = parse_head(&config, &req).unwrap_err();
        assert!(err.contains("multiple_host"), "{err}");
    }

    #[test]
    fn body_size_follows_the_framing() {
        let config = config();
        let mut req = TestRequest::new("POST", "https://h.example/");
        req.body = Some("hello".into());
        let (view, _) = build_view(&config, &req).unwrap();
        assert_eq!(view.field(Field::BodySize), Value::Int(5));
        assert_eq!(view.header("content-length").as_deref(), Some("5"));
        req.chunked = true;
        let (view, _) = build_view(&config, &req).unwrap();
        assert_eq!(view.field(Field::BodySize), Value::Absent);
        assert_eq!(view.header("content-length"), None);
        assert_eq!(
            view.body_text(),
            BodyText::Available(std::borrow::Cow::Borrowed("hello"))
        );
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
}
