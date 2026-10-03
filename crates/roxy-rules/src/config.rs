//! Serde types for the rule-related parts of the config (`DESIGN.md` §6.1,
//! §6.3, §6.4).
//!
//! These are the *uncompiled* shapes. [`crate::Policy::compile`] turns them
//! into an evaluable policy and reports every semantic problem as a
//! [`crate::Diagnostic`]. Deserialisation only checks shape; its error
//! messages name the offending action, and the caller (which knows the YAML
//! path) attaches the rule id.

use std::fmt;
use std::time::Duration;

use serde::Deserialize;
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};

// ----- default decision ---------------------------------------------------

/// What the request head gets when no head rule decides (§6.1): the
/// top-level `default:` key.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultDecision {
    /// Deny 403 with `terminal_rule = "_default"`. The default.
    #[default]
    Deny,
    /// Allow with `terminal_rule = "_default"`, granting no allow options
    /// (no WebSocket upgrade, no private destinations).
    Allow,
}

impl DefaultDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::Allow => "allow",
        }
    }
}

impl fmt::Display for DefaultDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ----- expressions ----------------------------------------------------------

/// An uncompiled DSL expression (§6.2).
///
/// YAML turns `where: true` into a boolean, so booleans are accepted and
/// stored as their literal text (a bool literal is a valid expression).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expr(pub String);

impl Expr {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Expr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = Expr;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an expression string")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Expr, E> {
                Ok(Expr(v.to_string()))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Expr, E> {
                if v.trim().is_empty() {
                    return Err(E::custom(
                        "expression must not be empty (omit the key to match everything)",
                    ));
                }
                Ok(Expr(v.to_owned()))
            }
        }
        d.deserialize_any(V)
    }
}

// ----- rules ----------------------------------------------------------------

/// One entry of `rules:`. Rules form one ordered list; when a rule runs
/// follows from what it reads (§6.1), so there is no `phase` key.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(try_from = "RawRule")]
pub struct RuleConfig {
    pub id: String,
    /// Match expression; absent = always matches.
    pub when: Option<Expr>,
    /// Required: one action or a list of actions.
    pub then: Then,
}

/// Message for a rule that still sets the removed `phase` key.
pub const PHASE_REMOVED: &str = "`phase` was removed: rules no longer have phases; each rule runs \
     when the values it reads are known (head rules at the request head; rules that read \
     body.bytes, response.* or ws.* watch the rest of the exchange; see DESIGN.md §6.1). Delete \
     the `phase` key";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    id: String,
    #[serde(default)]
    phase: Option<de::IgnoredAny>,
    #[serde(default)]
    when: Option<Expr>,
    then: Then,
}

impl TryFrom<RawRule> for RuleConfig {
    type Error = String;
    fn try_from(r: RawRule) -> Result<Self, String> {
        if r.phase.is_some() {
            return Err(format!("rule {:?}: {PHASE_REMOVED}", r.id));
        }
        Ok(Self {
            id: r.id,
            when: r.when,
            then: r.then,
        })
    }
}

/// A rule's `then`: one action or a list, normalised to a non-empty list.
#[derive(Debug, Clone, PartialEq)]
pub struct Then(pub Vec<Action>);

/// One action (§6.3). A closed enum, deliberately.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// Terminal. Bare `allow` or `allow: { upgrade, private_ok }`.
    Allow(AllowArgs),
    /// Terminal. Bare `deny` or `deny: { status, message, close }`.
    Deny(DenyArgs),
    /// Terminal; reserved for transparent listeners (deferred), rejected by
    /// the compiler.
    Passthrough,
    /// `set_header: { name: value, ... }`, in YAML order.
    SetHeader(Vec<(String, String)>),
    /// `remove_header: [names]`
    RemoveHeader(Vec<String>),
    /// `rewrite_path: { match, to }`
    RewritePath(RewritePathArgs),
    /// `set_query: { key: value, ... }`
    SetQuery(Vec<(String, String)>),
    /// `remove_query: [keys]`
    RemoveQuery(Vec<String>),
    /// `redirect: { host, port, scheme?, rewrite_host? }`
    Redirect(RedirectArgs),
    /// `tag: name`
    Tag(String),
    /// `log: { level, message }`
    Log(LogArgs),
    /// `set_state: { key, value, ttl? }`
    SetState(SetStateArgs),
    /// `capture: request | response | both`
    Capture(CaptureTarget),
    /// `call: addon_name`
    Call(String),
}

impl Action {
    /// Every action name, for error messages.
    pub const NAMES: &'static [&'static str] = &[
        "allow",
        "deny",
        "passthrough",
        "set_header",
        "remove_header",
        "rewrite_path",
        "set_query",
        "remove_query",
        "redirect",
        "tag",
        "log",
        "set_state",
        "capture",
        "call",
    ];

    /// The action's YAML name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Allow(_) => "allow",
            Self::Deny(_) => "deny",
            Self::Passthrough => "passthrough",
            Self::SetHeader(_) => "set_header",
            Self::RemoveHeader(_) => "remove_header",
            Self::RewritePath(_) => "rewrite_path",
            Self::SetQuery(_) => "set_query",
            Self::RemoveQuery(_) => "remove_query",
            Self::Redirect(_) => "redirect",
            Self::Tag(_) => "tag",
            Self::Log(_) => "log",
            Self::SetState(_) => "set_state",
            Self::Capture(_) => "capture",
            Self::Call(_) => "call",
        }
    }

    /// Whether this action is terminal (decides the rule's outcome).
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Allow(_) | Self::Deny(_) | Self::Passthrough)
    }
}

/// Arguments of `allow`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowArgs {
    /// Permit an Upgrade (§8). Only `websocket` exists.
    #[serde(default)]
    pub upgrade: Option<Upgrade>,
    /// Permit private / loopback upstream addresses for this flow (§7).
    #[serde(default)]
    pub private_ok: bool,
}

/// `allow: { upgrade: ... }` protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Upgrade {
    Websocket,
}

/// Arguments of `deny`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenyArgs {
    /// Response status; default 403. Must be 4xx or 5xx.
    #[serde(default)]
    pub status: Option<u16>,
    /// Response message; default `blocked by roxy`.
    #[serde(default)]
    pub message: Option<String>,
    /// Close the connection after the deny response (default `true`). A
    /// deny that stops an exchange whose response has started always closes
    /// the connection (h1) or resets the stream (h2).
    #[serde(default)]
    pub close: Option<bool>,
}

/// Arguments of `rewrite_path`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RewritePathArgs {
    /// Regex; implicitly anchored (`^(?:…)$`) like `matches`.
    #[serde(rename = "match")]
    pub pattern: String,
    /// Replacement with `$1` / `${name}` group references.
    pub to: String,
}

/// Arguments of `redirect`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedirectArgs {
    pub host: String,
    pub port: u16,
    /// Absent = keep the request's scheme.
    #[serde(default)]
    pub scheme: Option<Scheme>,
    /// Also rewrite the `Host` header to the new target.
    #[serde(default)]
    pub rewrite_host: bool,
}

/// URL scheme for `redirect`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

/// Arguments of `log`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogArgs {
    #[serde(default)]
    pub level: LogLevel,
    pub message: String,
}

/// `log` levels.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

/// Arguments of `set_state`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetStateArgs {
    pub key: String,
    pub value: String,
    /// Absent = the store's default TTL.
    #[serde(default, with = "humantime_serde")]
    pub ttl: Option<Duration>,
}

/// What `capture` writes (§10.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureTarget {
    Request,
    Response,
    Both,
}

impl CaptureTarget {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
            Self::Both => "both",
        }
    }
}

// ----- `then` deserialisation -------------------------------------------------

fn unknown_action(name: &str) -> String {
    format!(
        "unknown action `{name}`; expected one of {}",
        Action::NAMES
            .iter()
            .map(|n| format!("`{n}`"))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

impl Action {
    /// A bare-word action (`allow`, `deny`, `passthrough`).
    fn from_word<E: de::Error>(word: &str) -> Result<Self, E> {
        match word {
            "allow" => Ok(Self::Allow(AllowArgs::default())),
            "deny" => Ok(Self::Deny(DenyArgs::default())),
            "passthrough" => Ok(Self::Passthrough),
            other if Action::NAMES.contains(&other) => Err(E::custom(format!(
                "action `{other}` needs an argument (write `{other}: ...`); only `allow`, \
                 `deny` and `passthrough` may be bare words"
            ))),
            other => Err(E::custom(unknown_action(other))),
        }
    }

    /// A single-key map action. Rejects maps with zero or several keys.
    fn from_map<'de, A: MapAccess<'de>>(mut map: A) -> Result<Self, A::Error> {
        let Some(name) = map.next_key::<String>()? else {
            return Err(de::Error::custom(
                "an empty map is not an action; write e.g. `allow` or `deny: { status: 403 }`",
            ));
        };
        // Argument errors are not re-wrapped: the YAML deserialiser already
        // prefixes them with a path ending in the action name
        // (`rules[2].then[1].deny: unknown field ...`).
        macro_rules! arg {
            ($t:ty) => {
                map.next_value::<$t>()?
            };
        }
        let action = match name.as_str() {
            "allow" => Self::Allow(arg!(Option<AllowArgs>).unwrap_or_default()),
            "deny" => Self::Deny(arg!(Option<DenyArgs>).unwrap_or_default()),
            "passthrough" => {
                arg!(Option<de::IgnoredAny>).map_or(Ok(()), |_| {
                    Err(de::Error::custom("`passthrough` takes no argument"))
                })?;
                Self::Passthrough
            }
            "set_header" => Self::SetHeader(arg!(StringPairs).0),
            "remove_header" => Self::RemoveHeader(arg!(StringList).0),
            "rewrite_path" => Self::RewritePath(arg!(RewritePathArgs)),
            "set_query" => Self::SetQuery(arg!(StringPairs).0),
            "remove_query" => Self::RemoveQuery(arg!(StringList).0),
            "redirect" => Self::Redirect(arg!(RedirectArgs)),
            "tag" => Self::Tag(arg!(String)),
            "log" => Self::Log(arg!(LogArgs)),
            "set_state" => Self::SetState(arg!(SetStateArgs)),
            "capture" => Self::Capture(arg!(CaptureTarget)),
            "call" => Self::Call(arg!(String)),
            other => {
                return Err(de::Error::custom(unknown_action(other)));
            }
        };
        if let Some(extra) = map.next_key::<String>()? {
            return Err(de::Error::custom(format!(
                "an action is a map with exactly one key, but this one has `{name}` and \
                 `{extra}`; write each action as its own list item"
            )));
        }
        Ok(action)
    }
}

impl<'de> Deserialize<'de> for Action {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Action;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an action: a bare word (`allow`, `deny`) or a single-key map")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Action, E> {
                Action::from_word(v)
            }
            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Action, A::Error> {
                Action::from_map(map)
            }
        }
        d.deserialize_any(V)
    }
}

impl<'de> Deserialize<'de> for Then {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Then;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an action or a list of actions")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Then, E> {
                Ok(Then(vec![Action::from_word(v)?]))
            }
            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Then, A::Error> {
                Ok(Then(vec![Action::from_map(map)?]))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Then, A::Error> {
                let mut actions = Vec::new();
                while let Some(a) = seq.next_element::<Action>()? {
                    actions.push(a);
                }
                if actions.is_empty() {
                    return Err(de::Error::custom("`then` must name at least one action"));
                }
                Ok(Then(actions))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Then, E> {
                Err(E::custom("`then` must name at least one action"))
            }
        }
        d.deserialize_any(V)
    }
}

/// A YAML map of string to string, in document order.
struct StringPairs(Vec<(String, String)>);

impl<'de> Deserialize<'de> for StringPairs {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = StringPairs;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a map of name to string value, e.g. `{ x-env: prod }`")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<StringPairs, A::Error> {
                let mut out: Vec<(String, String)> = Vec::new();
                while let Some(k) = map.next_key::<String>()? {
                    let v = map.next_value::<String>()?;
                    out.push((k, v));
                }
                if out.is_empty() {
                    return Err(de::Error::custom("must name at least one entry"));
                }
                Ok(StringPairs(out))
            }
        }
        d.deserialize_map(V)
    }
}

/// A list of strings; a single string is accepted as a one-element list.
struct StringList(Vec<String>);

impl<'de> Deserialize<'de> for StringList {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = StringList;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a list of names")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<StringList, E> {
                Ok(StringList(vec![v.to_owned()]))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<StringList, A::Error> {
                let mut out = Vec::new();
                while let Some(s) = seq.next_element::<String>()? {
                    out.push(s);
                }
                if out.is_empty() {
                    return Err(de::Error::custom("must name at least one entry"));
                }
                Ok(StringList(out))
            }
        }
        d.deserialize_any(V)
    }
}

// ----- metrics --------------------------------------------------------------

/// One entry of `metrics:` (§6.4).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricConfig {
    pub id: String,
    pub count: MetricCount,
    /// Filter expression; absent = every flow.
    #[serde(default, rename = "where")]
    pub where_: Option<Expr>,
    /// Series key fields; empty = one global series.
    #[serde(default)]
    pub key: Vec<String>,
    /// Sliding window; absent = cumulative since start.
    #[serde(default, with = "humantime_serde")]
    pub window: Option<Duration>,
}

/// What a metric counts (§6.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetricCount {
    Requests,
    RequestBytes,
    ResponseBytes,
    Errors,
    Denied,
    /// `unique(<field>)`: distinct values of a field (`HyperLogLog`).
    Unique(String),
}

impl MetricCount {
    /// Whether this metric grows as bytes stream (and so is *watched* by deny
    /// rules that read it, §6.4).
    pub fn counts_bytes(&self) -> bool {
        matches!(self, Self::RequestBytes | Self::ResponseBytes)
    }
}

impl<'de> Deserialize<'de> for MetricCount {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let s = s.trim();
        Ok(match s {
            "requests" => Self::Requests,
            "request_bytes" => Self::RequestBytes,
            "response_bytes" => Self::ResponseBytes,
            "errors" => Self::Errors,
            "denied" => Self::Denied,
            _ => {
                let field = s
                    .strip_prefix("unique(")
                    .and_then(|r| r.strip_suffix(')'))
                    .map(str::trim)
                    .filter(|f| !f.is_empty())
                    .ok_or_else(|| {
                        de::Error::custom(format!(
                            "unknown metric count {s:?}: expected requests, request_bytes, \
                             response_bytes, errors, denied or unique(<field>)"
                        ))
                    })?;
                Self::Unique(field.to_owned())
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct Wrapper {
        then: Then,
    }

    fn then(yaml: &str) -> Result<Vec<Action>, String> {
        let yaml = format!("then: {}", yaml.replace('\n', "\n  "));
        serde_yaml_ng::from_str::<Wrapper>(&yaml)
            .map(|w| w.then.0)
            .map_err(|e| e.to_string())
    }

    #[test]
    fn bare_words() {
        assert_eq!(
            then("allow").unwrap(),
            [Action::Allow(AllowArgs::default())]
        );
        assert_eq!(then("deny").unwrap(), [Action::Deny(DenyArgs::default())]);
        assert_eq!(then("passthrough").unwrap(), [Action::Passthrough]);
        assert_eq!(
            then("[tag: x, allow]").unwrap(),
            [Action::Tag("x".into()), Action::Allow(AllowArgs::default())]
        );
    }

    #[test]
    fn every_map_action_parses() {
        let actions = then(
            r#"
- allow: { upgrade: websocket, private_ok: true }
- deny: { status: 451, message: "no", close: true }
- set_header: { authorization: "Bearer ${secret:x}", x-b: "2" }
- remove_header: [x-debug, x-other]
- remove_header: x-single
- rewrite_path: { match: "/old/(.*)", to: "/new/$1" }
- set_query: { a: "1" }
- remove_query: [b]
- redirect: { host: example.org, port: 8443, scheme: https, rewrite_host: true }
- tag: billing
- log: { level: warn, message: hi }
- log: { message: default-level }
- set_state: { key: k, value: v, ttl: 5m }
- capture: both
- call: pii-scan
- allow:
- passthrough:
"#,
        )
        .unwrap();
        let names: Vec<&str> = actions.iter().map(Action::name).collect();
        assert_eq!(
            names,
            [
                "allow",
                "deny",
                "set_header",
                "remove_header",
                "remove_header",
                "rewrite_path",
                "set_query",
                "remove_query",
                "redirect",
                "tag",
                "log",
                "log",
                "set_state",
                "capture",
                "call",
                "allow",
                "passthrough"
            ]
        );
        assert_eq!(
            actions[2],
            Action::SetHeader(vec![
                ("authorization".into(), "Bearer ${secret:x}".into()),
                ("x-b".into(), "2".into())
            ])
        );
        assert_eq!(actions[4], Action::RemoveHeader(vec!["x-single".into()]));
        assert_eq!(
            actions[12],
            Action::SetState(SetStateArgs {
                key: "k".into(),
                value: "v".into(),
                ttl: Some(Duration::from_secs(300))
            })
        );
        assert_eq!(
            actions[11],
            Action::Log(LogArgs {
                level: LogLevel::Info,
                message: "default-level".into()
            })
        );
    }

    #[test]
    fn errors_name_the_action() {
        let cases = [
            ("bogus", "unknown action `bogus`"),
            ("{ bogus: 1 }", "unknown action `bogus`"),
            ("tag", "action `tag` needs an argument"),
            ("{ deny: { stauts: 1 } }", "then.deny"),
            ("{ deny: {}, allow: {} }", "has `deny` and `allow`"),
            ("{}", "empty map is not an action"),
            ("[]", "at least one action"),
            ("~", "at least one action"),
            ("{ set_header: [a] }", "then.set_header"),
            ("{ capture: everything }", "then.capture"),
            ("{ passthrough: 1 }", "takes no argument"),
            ("{ allow: { upgrade: h2c } }", "then.allow"),
            ("{ allow: { inspect: true } }", "then.allow"),
            (
                "[allow, { log: { level: loud, message: x } }]",
                "then[1].log",
            ),
        ];
        for (yaml, want) in cases {
            let err = then(yaml).expect_err(yaml);
            assert!(err.contains(want), "{yaml}: {err}");
        }
    }

    #[test]
    fn phase_key_is_rejected_with_a_pointer() {
        let err =
            serde_yaml_ng::from_str::<Vec<RuleConfig>>("- { id: r, phase: response, then: deny }")
                .unwrap_err()
                .to_string();
        assert!(err.contains("`phase` was removed"), "{err}");
        assert!(err.contains("§6.1"), "{err}");
        let ok: Vec<RuleConfig> =
            serde_yaml_ng::from_str("- { id: r, when: 'body.bytes > 1', then: deny }").unwrap();
        assert_eq!(ok[0].id, "r");
        let unknown =
            serde_yaml_ng::from_str::<Vec<RuleConfig>>("- { id: r, bogus: 1, then: deny }")
                .unwrap_err()
                .to_string();
        assert!(unknown.contains("bogus"), "{unknown}");
    }

    #[test]
    fn metric_count() {
        let c: MetricCount = serde_yaml_ng::from_str("unique(host)").unwrap();
        assert_eq!(c, MetricCount::Unique("host".into()));
        assert!(serde_yaml_ng::from_str::<MetricCount>("unique()").is_err());
        assert!(MetricCount::ResponseBytes.counts_bytes());
        assert!(!MetricCount::Requests.counts_bytes());
    }
}
