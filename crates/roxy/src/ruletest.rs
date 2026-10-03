//! `roxy rule test` (DESIGN.md §6.6): evaluate a synthetic flow against the
//! compiled policy without any network I/O.

use std::fmt::Write as _;
use std::net::IpAddr;

use ipnet::IpNet;
use roxy_proxy::Redactor;
use roxy_rules::{Decision, EvalContext, Field, MapView, Outcome, Phase, Policy, Value};

use crate::config::{AddressListSource, Config};

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
    /// Response phase only.
    pub status: Option<u16>,
    pub response_headers: Vec<(String, String)>,
    pub metrics: Vec<(String, i64)>,
    pub state: Vec<(String, String)>,
    pub tags: Vec<String>,
    /// Give every metric not set in `metrics` the value 0 (a fresh series).
    /// Otherwise an unset metric is unavailable and the flow fails closed.
    pub fresh_metrics: bool,
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
            status: None,
            response_headers: Vec::new(),
            metrics: Vec::new(),
            state: Vec::new(),
            tags: Vec::new(),
            fresh_metrics: false,
        }
    }
}

/// The parts of an absolute URL that rules see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUrl {
    pub scheme: String,
    /// Lower-case, trailing dot removed, IPv6 without brackets.
    pub host: String,
    pub port: u16,
    pub path: String,
    pub query: Option<String>,
}

impl ParsedUrl {
    /// `scheme://host[:port]/path[?query]`, port shown only if non-default.
    pub fn url(&self) -> String {
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
pub fn parse_url(url: &str) -> Result<ParsedUrl, String> {
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

/// Build the flow the rules see. Address lists are backed by the config's
/// inline entries and readable files (unreadable files stay unloaded, which
/// makes `in @list` false, as at run time); warnings are returned.
pub fn build_view(config: &Config, req: &TestRequest) -> Result<(MapView, Vec<String>), String> {
    let url = parse_url(&req.url)?;
    let mut warnings = Vec::new();
    let host_ip = url.host.parse::<IpAddr>().ok();
    let mut v = MapView::new()
        .with(Field::ClientIp, Value::Ip(req.client_ip))
        .with_str(
            Field::ListenerName,
            config
                .listeners
                .first()
                .map_or("proxy", |l| l.name.as_str()),
        )
        .with_str(Field::ListenerMode, "explicit")
        .with_str(Field::DstHost, &url.host)
        .with_int(Field::DstPort, i64::from(url.port))
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
    if let Some(ip) = host_ip {
        v = v.with(Field::DstIp, Value::Ip(ip));
    }
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
    if let Some(body) = &req.body {
        v = v.with_body(body);
    }
    if let Some(status) = req.status {
        v = v.with_int(Field::ResponseStatus, i64::from(status));
    }
    for (n, val) in &req.response_headers {
        v = v.with_response_header(n, val);
    }
    if req.fresh_metrics {
        for m in &config.metrics {
            v = v.with_metric(&m.id, 0);
        }
    }
    for (id, n) in &req.metrics {
        v = v.with_metric(id, *n);
    }
    for (k, val) in &req.state {
        v = v.with_state(k, val);
    }
    for list in &config.address_lists {
        let entries: Vec<String> = match &list.source {
            AddressListSource::Inline(e) => e.clone(),
            AddressListSource::File(path) => match std::fs::read_to_string(path) {
                Ok(text) => text
                    .lines()
                    .map(|l| l.split('#').next().unwrap_or("").trim().to_owned())
                    .filter(|l| !l.is_empty())
                    .collect(),
                Err(e) => {
                    warnings.push(format!(
                        "address list @{}: cannot read {}: {e}; treating it as unavailable",
                        list.name,
                        path.display()
                    ));
                    continue;
                }
            },
        };
        let nets: Vec<IpNet> = entries
            .iter()
            .filter_map(|e| {
                e.parse::<IpNet>()
                    .ok()
                    .or_else(|| e.parse::<IpAddr>().ok().map(IpNet::from))
            })
            .collect();
        v = v.with_address_list(&list.name, nets);
    }
    Ok((v, warnings))
}

/// Evaluate `req` in `phase`. Secrets are not resolved: each
/// `${secret:name}` becomes the placeholder `[secret:name]`.
pub fn run(policy: &Policy, phase: Phase, view: &MapView, tags: &[String]) -> Outcome {
    let placeholder = |name: &str| Some(format!("[secret:{name}]"));
    let ctx = EvalContext {
        secrets: &placeholder,
        initial_tags: tags,
    };
    policy.evaluate(phase, view, &ctx)
}

/// Human-readable report. Effect text passes through `redactor`.
pub fn report(phase: Phase, out: &Outcome, redactor: &Redactor) -> String {
    let mut s = String::new();
    let list = |items: Vec<String>| {
        if items.is_empty() {
            "(none)".to_owned()
        } else {
            items.join(", ")
        }
    };
    let _ = writeln!(s, "phase:    {phase}");
    let _ = writeln!(
        s,
        "matched:  {}",
        list(out.matched.iter().map(ToString::to_string).collect())
    );
    if out.effects.is_empty() {
        let _ = writeln!(s, "effects:  (none)");
    } else {
        let _ = writeln!(s, "effects:");
        for e in &out.effects {
            let _ = writeln!(s, "  - {}", redactor.redact_str(&e.to_string()));
        }
    }
    let _ = writeln!(s, "tags:     {}", list(out.tags.clone()));
    let _ = writeln!(s, "decision: {}", out.decision);
    let _ = writeln!(s, "rule:     {}", out.terminal_rule);
    if let Some(reason) = &out.fail_closed_reason {
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
}
