//! Semantic validation that serde cannot express.
//!
//! Rules and metrics are compiled by [`roxy_rules::Policy::compile`]; its
//! diagnostics (with line/column within an expression) are merged with the
//! checks here.

use roxy_rules::{Condition, Policy, PolicyInput};
use std::collections::{HashMap, HashSet};

use super::{AddressListSource, CONFIG_VERSION, Config, ListenerMode, UpstreamVerify};

/// One problem found in a config, located by a YAML path such as
/// `rules[2].when`. Displays as `path: message`, or `path:line:col: message`
/// for expression errors (see [`roxy_rules::Diagnostic`]).
pub use roxy_rules::Diagnostic;

impl Config {
    /// Check cross-references and constraints and compile the policy.
    /// Returns every problem found, not just the first.
    pub fn validate(&self) -> Result<(), Vec<Diagnostic>> {
        let mut d = Vec::new();

        if self.version != CONFIG_VERSION {
            d.push(Diagnostic::new(
                "version",
                format!(
                    "unsupported config version {} (expected {CONFIG_VERSION})",
                    self.version
                ),
            ));
        }

        self.validate_listeners(&mut d);
        self.validate_dns(&mut d);
        self.validate_tls(&mut d);
        self.validate_secrets(&mut d);
        self.validate_address_lists(&mut d);
        self.validate_addons(&mut d);
        self.validate_upstream(&mut d);
        self.validate_log(&mut d);

        if let Err(policy) = self.compile_policy() {
            d.extend(policy);
        }
        if let Err(conditions) = self.compile_addon_conditions() {
            d.extend(conditions);
        }

        if d.is_empty() { Ok(()) } else { Err(d) }
    }

    /// Compile the rules and metrics. `validate` calls this; the run
    /// path and `roxy rule test` use the result.
    pub fn compile_policy(&self) -> Result<Policy, Vec<Diagnostic>> {
        self.with_policy_input(Policy::compile)
    }

    /// Compile each addon's `when` (`None` where it has none), against the
    /// same metrics and address lists as the rules.
    pub fn compile_addon_conditions(&self) -> Result<Vec<Option<Condition>>, Vec<Diagnostic>> {
        self.with_policy_input(|input| {
            let mut out = Vec::with_capacity(self.addons.len());
            let mut d = Vec::new();
            for (i, a) in self.addons.iter().enumerate() {
                let Some(when) = &a.when else {
                    out.push(None);
                    continue;
                };
                match Condition::compile(input, &format!("addons[{i}].when"), when.as_str()) {
                    Ok(c) => out.push(Some(c)),
                    Err(e) => d.extend(e),
                }
            }
            if d.is_empty() { Ok(out) } else { Err(d) }
        })
    }

    fn with_policy_input<R>(&self, f: impl FnOnce(&PolicyInput<'_>) -> R) -> R {
        let secret_names: HashSet<String> = self.secrets.keys().cloned().collect();
        let address_lists: HashSet<String> =
            self.address_lists.iter().map(|l| l.name.clone()).collect();
        f(&PolicyInput {
            rules: &self.rules,
            metrics: &self.metrics,
            secret_names: &secret_names,
            address_lists: &address_lists,
            transparent_listeners: self
                .listeners
                .iter()
                .any(|l| l.mode == ListenerMode::Transparent),
            default: self.default,
        })
    }

    fn validate_listeners(&self, d: &mut Vec<Diagnostic>) {
        if self.listeners.is_empty() {
            d.push(Diagnostic::new(
                "listeners",
                "at least one listener is required",
            ));
        }
        let mut names: HashMap<&str, usize> = HashMap::new();
        let mut binds = HashMap::new();
        for (i, l) in self.listeners.iter().enumerate() {
            let path = format!("listeners[{i}]");
            if l.name.trim().is_empty() {
                d.push(Diagnostic::new(
                    format!("{path}.name"),
                    "listener name must not be empty",
                ));
            } else if let Some(first) = names.insert(l.name.as_str(), i) {
                d.push(Diagnostic::new(
                    format!("{path}.name"),
                    format!(
                        "duplicate listener name {:?} (first defined at listeners[{first}])",
                        l.name
                    ),
                ));
            }
            // Port 0 asks the OS for a free port, so it never conflicts.
            if l.bind.port() != 0
                && let Some(first) = binds.insert(l.bind, path.clone())
            {
                d.push(Diagnostic::new(
                    format!("{path}.bind"),
                    format!("bind address {} is already used by {first}", l.bind),
                ));
            }
            validate_listener_mode(l, &path, d);
        }
        if let Some(ca) = &self.ca_server
            && ca.bind.port() != 0
            && let Some(first) = binds.get(&ca.bind)
        {
            d.push(Diagnostic::new(
                "ca_server.bind",
                format!("bind address {} is already used by {first}", ca.bind),
            ));
        }
        // The DNS listener's TCP side shares the TCP port space.
        if let Some(dns) = &self.dns
            && dns.bind.port() != 0
            && let Some(first) = binds.get(&dns.bind)
        {
            d.push(Diagnostic::new(
                "dns.bind",
                format!("bind address {} is already used by {first}", dns.bind),
            ));
        }
    }

    fn validate_dns(&self, d: &mut Vec<Diagnostic>) {
        let Some(dns) = &self.dns else {
            return;
        };
        if dns.answer.ipv4.is_none() && dns.answer.ipv6.is_none() {
            d.push(Diagnostic::new(
                "dns.answer",
                "set ipv4, ipv6 or both: roxy's address as the clients reach it",
            ));
        }
        if dns.ttl.as_secs() > u64::from(u32::MAX) {
            d.push(Diagnostic::new("dns.ttl", "must fit in 32 bits of seconds"));
        }
    }

    fn validate_tls(&self, d: &mut Vec<Diagnostic>) {
        let up = &self.tls.upstream;
        match up.verify {
            UpstreamVerify::Strict if !up.extra_roots.is_empty() => d.push(Diagnostic::new(
                "tls.upstream.extra_roots",
                "extra_roots is set but verify is `strict`; use `strict+extra_roots` to trust them",
            )),
            UpstreamVerify::StrictExtraRoots if up.extra_roots.is_empty() => {
                d.push(Diagnostic::new(
                    "tls.upstream.verify",
                    "`strict+extra_roots` requires at least one entry in extra_roots",
                ));
            }
            _ => {}
        }
        match (&self.tls.ca_cert, &self.tls.ca_key) {
            (Some(_), None) => d.push(Diagnostic::new(
                "tls.ca_key",
                "ca_cert is set but ca_key is not; a provided CA needs both",
            )),
            (None, Some(_)) => d.push(Diagnostic::new(
                "tls.ca_cert",
                "ca_key is set but ca_cert is not; a provided CA needs both",
            )),
            _ => {}
        }
        if self.tls.leaf_cache_size == 0 {
            d.push(Diagnostic::new("tls.leaf_cache_size", "must be at least 1"));
        }
    }

    fn validate_secrets(&self, d: &mut Vec<Diagnostic>) {
        for (name, source) in &self.secrets {
            if name.trim().is_empty() || name.contains('}') {
                d.push(Diagnostic::new(
                    format!("secrets.{name}"),
                    "secret names must be non-empty and must not contain `}`",
                ));
            }
            let empty = match source {
                super::SecretSource::Env(var) => var.trim().is_empty(),
                super::SecretSource::File(path) => path.as_os_str().is_empty(),
            };
            if empty {
                d.push(Diagnostic::new(
                    format!("secrets.{name}"),
                    "secret source must not be empty",
                ));
            }
        }
    }

    fn validate_addons(&self, d: &mut Vec<Diagnostic>) {
        let mut names: HashMap<&str, usize> = HashMap::new();
        for (i, a) in self.addons.iter().enumerate() {
            let path = format!("addons[{i}]");
            if a.name.trim().is_empty() {
                d.push(Diagnostic::new(
                    format!("{path}.name"),
                    "addon name must not be empty",
                ));
            } else if let Some(first) = names.insert(a.name.as_str(), i) {
                d.push(Diagnostic::new(
                    format!("{path}.name"),
                    format!(
                        "duplicate addon name {:?} (first defined at addons[{first}])",
                        a.name
                    ),
                ));
            }
            match a.kind {
                super::AddonKind::Wasm => {
                    if a.path.is_none() {
                        d.push(Diagnostic::new(
                            format!("{path}.path"),
                            "a `kind: wasm` addon needs `path`",
                        ));
                    }
                    if a.endpoint.is_some() {
                        d.push(Diagnostic::new(
                            format!("{path}.endpoint"),
                            "`endpoint` is for `kind: service` addons",
                        ));
                    }
                    for (field, set) in [
                        ("first_byte_timeout", a.limits.first_byte_timeout.is_some()),
                        ("max_connections", a.limits.max_connections.is_some()),
                        ("max_streams", a.limits.max_streams.is_some()),
                    ] {
                        if set {
                            d.push(Diagnostic::new(
                                format!("{path}.limits.{field}"),
                                format!("`{field}` is for `kind: service` addons"),
                            ));
                        }
                    }
                }
                super::AddonKind::Service => Self::validate_service(&path, a, d),
            }
            if let Some(i) = a
                .capabilities
                .iter()
                .position(|c| *c == super::Capability::Secrets)
            {
                d.push(Diagnostic::new(
                    format!("{path}.capabilities[{i}]"),
                    "the `secrets` capability is not provided: put credentials on an \
                     endpoint's `headers`, which roxy attaches without the addon seeing them",
                ));
            }
            if let Some(s) = a.sample {
                if !(s > 0.0 && s <= 1.0) {
                    d.push(Diagnostic::new(
                        format!("{path}.sample"),
                        "must be greater than 0 and at most 1",
                    ));
                }
                if a.mode != super::AddonMode::Observe {
                    d.push(Diagnostic::new(
                        format!("{path}.sample"),
                        "`sample` needs `mode: observe`: skipping an enforcing addon at random \
                         would let traffic past it",
                    ));
                }
            }
            if a.limits.max_instances == Some(0) {
                d.push(Diagnostic::new(
                    format!("{path}.limits.max_instances"),
                    "must be at least 1",
                ));
            }
            for (name, e) in &a.endpoints {
                self.validate_endpoint(&format!("{path}.endpoints.{name}"), name, e, d);
            }
            if let Some(n) = &a.audit_endpoint
                && !a.endpoints.contains_key(n)
            {
                d.push(Diagnostic::new(
                    format!("{path}.audit_endpoint"),
                    format!("{n:?} is not one of this addon's `endpoints`"),
                ));
            }
        }
    }

    /// What only makes sense for, or is refused on, a `kind: service`
    /// addon: it streams through one of its own endpoints, and gets
    /// no host services and no WASM limits.
    fn validate_service(path: &str, a: &super::Addon, d: &mut Vec<Diagnostic>) {
        match &a.endpoint {
            None => d.push(Diagnostic::new(
                format!("{path}.endpoint"),
                "a `kind: service` addon needs `endpoint`",
            )),
            Some(n) if !a.endpoints.contains_key(n) => d.push(Diagnostic::new(
                format!("{path}.endpoint"),
                format!("{n:?} is not one of this addon's `endpoints`"),
            )),
            Some(_) => {}
        }
        let mut refuse = |field: &str, why: &str| {
            d.push(Diagnostic::new(format!("{path}.{field}"), why.to_owned()));
        };
        if a.path.is_some() {
            refuse("path", "`path` is for `kind: wasm` addons");
        }
        if !a.capabilities.is_empty() {
            refuse(
                "capabilities",
                "a service layer gets no host services: it calls what it needs itself",
            );
        }
        if !a.config.is_null() {
            refuse(
                "config",
                "`config` is passed to WASM addons; configure the service itself",
            );
        }
        if a.audit_endpoint.is_some() {
            refuse(
                "audit_endpoint",
                "`audit_endpoint` is for `kind: wasm` addons",
            );
        }
        let l = &a.limits;
        for (field, set) in [
            ("max_memory", l.max_memory.is_some()),
            (
                "max_buffered_body_bytes",
                l.max_buffered_body_bytes.is_some(),
            ),
            ("step_cpu", l.step_cpu.is_some()),
            ("fuel_per_step", l.fuel_per_step.is_some()),
            (
                "recycle_after_exchanges",
                l.recycle_after_exchanges.is_some(),
            ),
            ("recycle_above_memory", l.recycle_above_memory.is_some()),
            ("max_instances", l.max_instances.is_some()),
        ] {
            if set {
                refuse(
                    &format!("limits.{field}"),
                    "a WASM limit; a service layer takes `first_byte_timeout`, \
                     `max_exchange_time`, `max_connections` and `max_streams`",
                );
            }
        }
        for (field, n) in [
            ("max_connections", l.max_connections),
            ("max_streams", l.max_streams),
        ] {
            if n == Some(0) {
                refuse(&format!("limits.{field}"), "must be at least 1");
            }
        }
    }

    fn validate_endpoint(
        &self,
        path: &str,
        name: &str,
        e: &super::Endpoint,
        d: &mut Vec<Diagnostic>,
    ) {
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        {
            d.push(Diagnostic::new(
                path.to_owned(),
                "endpoint names use letters, digits, `-`, `_` and `.`",
            ));
        }
        match e.url.parse::<http::Uri>() {
            Ok(u)
                if matches!(u.scheme_str(), Some("http" | "https"))
                    && u.authority().is_some()
                    && u.query().is_none() => {}
            _ => d.push(Diagnostic::new(
                format!("{path}.url"),
                format!(
                    "{:?} must be an http(s) URL with a host and no query",
                    e.url
                ),
            )),
        }
        for (h, v) in &e.headers {
            if http::HeaderName::from_bytes(h.as_bytes()).is_err() {
                d.push(Diagnostic::new(
                    format!("{path}.headers.{h}"),
                    "invalid header name",
                ));
            }
            for secret in secret_refs(v) {
                if !self.secrets.contains_key(secret) {
                    d.push(Diagnostic::new(
                        format!("{path}.headers.{h}"),
                        format!("unknown secret {secret:?}"),
                    ));
                }
            }
        }
    }

    /// Names unique and usable as `@name`; inline entries parse; files exist
    /// (their contents are parsed by `roxy check`, at startup and on reload,
    /// see [`crate::lists`]). `upstream.deny_lists` must name defined lists.
    fn validate_address_lists(&self, d: &mut Vec<Diagnostic>) {
        let mut names: HashMap<&str, usize> = HashMap::new();
        for (i, list) in self.address_lists.iter().enumerate() {
            let path = format!("address_lists[{i}]");
            if !is_list_name(&list.name) {
                d.push(Diagnostic::new(
                    format!("{path}.name"),
                    format!(
                        "invalid address list name {:?}: must match [A-Za-z_][A-Za-z0-9_-]* so \
                         it can be used as @name",
                        list.name
                    ),
                ));
            }
            if let Some(first) = names.insert(list.name.as_str(), i) {
                d.push(Diagnostic::new(
                    format!("{path}.name"),
                    format!(
                        "duplicate address list name {:?} (first defined at address_lists[{first}])",
                        list.name
                    ),
                ));
            }
            match &list.source {
                AddressListSource::Inline(entries) => {
                    if entries.is_empty() {
                        d.push(Diagnostic::new(
                            format!("{path}.inline"),
                            "inline address list must not be empty",
                        ));
                    }
                    for (j, e) in entries.iter().enumerate() {
                        if let Err(reason) = roxy_proxy::addrlist::parse_entry(e) {
                            d.push(Diagnostic::new(
                                format!("{path}.inline[{j}]"),
                                format!("{:?} {reason}", e.trim()),
                            ));
                        }
                    }
                }
                AddressListSource::File(file) => {
                    if !file.exists() {
                        d.push(Diagnostic::new(
                            format!("{path}.file"),
                            format!("{} does not exist", file.display()),
                        ));
                    }
                }
            }
        }
        for (i, name) in self.upstream.deny_lists.iter().enumerate() {
            if !names.contains_key(name.as_str()) {
                d.push(Diagnostic::new(
                    format!("upstream.deny_lists[{i}]"),
                    format!("undefined address list {name:?} (define it under `address_lists`)"),
                ));
            }
        }
    }
}

impl Config {
    fn validate_upstream(&self, d: &mut Vec<Diagnostic>) {
        for name in self.upstream.dns.static_hosts.keys() {
            let norm = name.trim_end_matches('.').to_ascii_lowercase();
            if !matches!(
                roxy_http::url::parse_host(norm.as_bytes()),
                Ok(roxy_http::Host::Dns(_))
            ) {
                d.push(Diagnostic::new(
                    format!("upstream.dns.static_hosts.{name}"),
                    "must be a DNS host name (A-labels)",
                ));
            }
        }
        if self.limits.max_connections == 0 {
            d.push(Diagnostic::new(
                "limits.max_connections",
                "must be at least 1",
            ));
        }
        if self.limits.max_connections_per_client == 0 {
            d.push(Diagnostic::new(
                "limits.max_connections_per_client",
                "must be at least 1",
            ));
        }
        let metric_bytes = self.limits.max_metric_bytes.as_u64();
        if metric_bytes == 0 {
            d.push(Diagnostic::new(
                "limits.max_metric_bytes",
                "must be at least 1 byte",
            ));
        } else if metric_bytes > MAX_METRIC_BYTES_CEILING || usize::try_from(metric_bytes).is_err()
        {
            d.push(Diagnostic::new(
                "limits.max_metric_bytes",
                "must be at most 64gb",
            ));
        }
    }
}

impl Config {
    fn validate_log(&self, d: &mut Vec<Diagnostic>) {
        let f = &self.log.flow;
        if f.high_water.as_u64() < 64 * 1024 {
            d.push(Diagnostic::new(
                "log.flow.high_water",
                "must be at least 64kb (traffic is held back whenever this much log is unwritten)",
            ));
        }
        let rotating = f.max_file_bytes.is_some() || f.max_files.is_some() || f.compress;
        if rotating && f.path.is_none() {
            d.push(Diagnostic::new(
                "log.flow",
                "max_file_bytes, max_files and compress need `path` (stdout cannot rotate)",
            ));
        }
        if f.max_file_bytes.is_none() && (f.max_files.is_some() || f.compress) {
            d.push(Diagnostic::new(
                "log.flow.max_file_bytes",
                "max_files and compress apply to rotated files; set max_file_bytes to rotate",
            ));
        }
        if f.max_file_bytes.is_some_and(|b| b.as_u64() < 4096) {
            d.push(Diagnostic::new(
                "log.flow.max_file_bytes",
                "must be at least 4kb",
            ));
        }
        if f.max_files == Some(0) {
            d.push(Diagnostic::new(
                "log.flow.max_files",
                "must be at least 1 (omit it to keep every rotated file)",
            ));
        }
        let c = &self.log.capture;
        if self.uses_capture() && self.capture_dir.is_none() {
            d.push(Diagnostic::new(
                "capture_dir",
                "capture (a `capture` action or log.capture.all) needs `capture_dir`",
            ));
        }
        if c.high_water.as_u64() < 64 * 1024 {
            d.push(Diagnostic::new(
                "log.capture.high_water",
                "must be at least 64kb",
            ));
        }
        if c.max_file_bytes.is_none() && (c.max_files.is_some() || c.compress) {
            d.push(Diagnostic::new(
                "log.capture.max_file_bytes",
                "max_files and compress apply to rotated files; set max_file_bytes to rotate",
            ));
        }
        if c.max_file_bytes.is_some_and(|b| b.as_u64() < 4096) {
            d.push(Diagnostic::new(
                "log.capture.max_file_bytes",
                "must be at least 4kb",
            ));
        }
        if c.max_files == Some(0) {
            d.push(Diagnostic::new(
                "log.capture.max_files",
                "must be at least 1 (omit it to keep every rotated file)",
            ));
        }
    }
}

/// Upper bound on `limits.max_metric_bytes`: well past any sensible
/// budget, so a unit typo (`256gb` for `256mb`) is caught at load.
const MAX_METRIC_BYTES_CEILING: u64 = 64 << 30;

fn is_list_name(s: &str) -> bool {
    let mut b = s.bytes();
    b.next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
        && b.all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

/// The names in `${secret:name}` references.
pub(crate) fn secret_refs(v: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = v;
    while let Some(i) = rest.find("${secret:") {
        let after = &rest[i + "${secret:".len()..];
        let Some(end) = after.find('}') else { break };
        out.push(&after[..end]);
        rest = &after[end + 1..];
    }
    out
}

/// The checks that depend on a listener's mode.
fn validate_listener_mode(l: &super::Listener, path: &str, d: &mut Vec<Diagnostic>) {
    if l.mode != ListenerMode::Direct && l.target_port.is_some() {
        d.push(Diagnostic::new(
            format!("{path}.target_port"),
            "only valid on direct listeners",
        ));
    }
    if l.mode != ListenerMode::Transparent {
        for (field, set) in [
            ("allow_passthrough", l.allow_passthrough.is_some()),
            ("upstream_target", l.upstream_target.is_some()),
        ] {
            if set {
                d.push(Diagnostic::new(
                    format!("{path}.{field}"),
                    "only valid on transparent listeners",
                ));
            }
        }
    }
    match l.mode {
        ListenerMode::Explicit => {}
        ListenerMode::Direct => {
            if l.auth.is_some() {
                d.push(Diagnostic::new(
                    format!("{path}.auth"),
                    "not valid on direct listeners: their clients do not know they \
                     are talking to a proxy, so they send no Proxy-Authorization",
                ));
            }
            if l.target_port == Some(0) {
                d.push(Diagnostic::new(
                    format!("{path}.target_port"),
                    "must not be 0",
                ));
            }
        }
        ListenerMode::Transparent => d.push(Diagnostic::new(
            format!("{path}.mode"),
            "transparent mode is deferred and not yet supported (issue #15); use `explicit` or `direct`",
        )),
    }
}
