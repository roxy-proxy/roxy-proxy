//! Helpers shared by the fuzz targets.

use roxy_http::h1::{Head, Role};
use roxy_http::url::parse_authority;
use roxy_http::{HttpFlags, Limits, Scheme, TargetForm, Version};

/// Parser flags from one fuzz byte (bits 0..=4).
pub fn flags(cfg: u8) -> HttpFlags {
    HttpFlags {
        allow_http10: cfg & 1 != 0,
        allow_trailers: cfg & 2 != 0,
        allow_chunk_extensions: cfg & 4 != 0,
        allow_obs_text: cfg & 8 != 0,
        allow_body_on_get: cfg & 16 != 0,
    }
}

/// The connection role from one fuzz byte (bits 5..=6): the proxy port, a
/// plaintext direct listener on port 80, or a tunnel (https or plaintext
/// http) to `example.com`.
pub fn role(cfg: u8) -> Role {
    match (cfg >> 5) & 3 {
        0 => Role::ProxyPort,
        1 => Role::Direct { port: 80 },
        2 => Role::Tunnel {
            authority: parse_authority(b"example.com", 443).expect("valid authority"),
            scheme: Scheme::Https,
        },
        _ => Role::Tunnel {
            authority: parse_authority(b"example.com", 80).expect("valid authority"),
            scheme: Scheme::Http,
        },
    }
}

/// Small limits, so the fuzzer reaches every limit check.
pub fn tight_limits() -> Limits {
    Limits {
        max_header_bytes: 4096,
        max_url_bytes: 1024,
        max_headers: 32,
        ..Limits::default()
    }
}

/// Limits that never reject a re-serialised head for its size alone (the
/// canonical form can be longer than the input: it always carries `Host`).
pub fn roomy_limits() -> Limits {
    Limits {
        max_header_bytes: 1 << 20,
        max_url_bytes: 1 << 20,
        max_headers: 1 << 12,
        ..Limits::default()
    }
}

fn version(v: Version) -> &'static str {
    match v {
        Version::H1_0 => "HTTP/1.0",
        _ => "HTTP/1.1",
    }
}

/// Writes a parsed head back out as an HTTP/1.x head that means the same
/// thing: the request line in the form it arrived in, `Host` from the
/// authority, the framing field, the hop-by-hop facts kept in the metadata
/// (`Expect`, `Connection`, `Upgrade`, `Proxy-Authorization`), then the
/// canonical header fields in order.
pub fn serialise(head: &Head) -> Vec<u8> {
    let mut out = Vec::new();
    let (meta, headers, authority) = match head {
        Head::Request(r) => {
            let q = r
                .query
                .as_ref()
                .map(|q| format!("?{q}"))
                .unwrap_or_default();
            let target = match r.meta.target_form {
                TargetForm::Absolute => format!("{}://{}{}{q}", r.scheme, r.authority, r.path),
                _ => format!("{}{q}", r.path),
            };
            out.extend_from_slice(
                format!("{} {target} {}\r\n", r.method, version(r.meta.version)).as_bytes(),
            );
            match r.framing {
                roxy_http::h1::Framing::None => {}
                roxy_http::h1::Framing::Length(n) => {
                    out.extend_from_slice(format!("Content-Length: {n}\r\n").as_bytes());
                }
                roxy_http::h1::Framing::Chunked => {
                    out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
                }
            }
            (&r.meta, &r.headers, &r.authority)
        }
        Head::Connect {
            authority,
            headers,
            meta,
        } => {
            out.extend_from_slice(
                format!("CONNECT {authority} {}\r\n", version(meta.version)).as_bytes(),
            );
            (meta, headers, authority)
        }
    };
    out.extend_from_slice(format!("Host: {authority}\r\n").as_bytes());
    if meta.expect_continue {
        out.extend_from_slice(b"Expect: 100-continue\r\n");
    }
    let mut connection = Vec::new();
    match meta.version {
        Version::H1_0 if !meta.close => connection.push("keep-alive"),
        Version::H1_1 if meta.close => connection.push("close"),
        _ => {}
    }
    if let Some(up) = &meta.upgrade {
        connection.push("upgrade");
        out.extend_from_slice(format!("Upgrade: {up}\r\n").as_bytes());
    }
    if !connection.is_empty() {
        out.extend_from_slice(format!("Connection: {}\r\n", connection.join(", ")).as_bytes());
    }
    for (name, value) in headers {
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// Metric, address-list and secret names the rule targets define, so
/// expressions that use them can compile.
pub mod rules {
    use std::collections::HashSet;

    use roxy_rules::{MetricConfig, Policy, PolicyInput, RuleConfig};

    /// `m0` counts requests per client IP; `m1` counts request bytes (a
    /// byte metric, so a deny reading it is also a watching rule).
    pub fn metrics() -> Vec<MetricConfig> {
        serde_json::from_value(serde_json::json!([
            { "id": "m0", "count": "requests", "key": ["client.ip"] },
            { "id": "m1", "count": "request_bytes" },
        ]))
        .expect("valid metric configs")
    }

    /// Compiles `rules` (as JSON) against the fixed metrics, address list
    /// `l0` and secret `s0`. `None` if the JSON or the policy is rejected.
    pub fn compile(rules: serde_json::Value) -> Option<Policy> {
        let rules: Vec<RuleConfig> = serde_json::from_value(rules).ok()?;
        let metrics = metrics();
        let secrets: HashSet<String> = ["s0".to_owned()].into();
        let lists: HashSet<String> = ["l0".to_owned()].into();
        Policy::compile(&PolicyInput {
            rules: &rules,
            metrics: &metrics,
            secret_names: &secrets,
            address_lists: &lists,
        })
        .ok()
    }
}
