//! Custom deserialisers for config scalars.

use std::fmt;
use std::net::SocketAddr;

use bytesize::ByteSize;
use serde::Deserialize;
use serde::de::{self, Deserializer, SeqAccess, Visitor};

// ----- sizes ----------------------------------------------------------------

/// Parse a size such as `64kb`, `1 GiB`, `512` (bytes). Units are
/// case-insensitive and **1024-based** (`kb` == `kib`, §16 #5).
pub fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (digits, unit) = s.split_at(split);
    if digits.is_empty() {
        return Err(format!(
            "invalid size {s:?}: expected a number with optional unit, e.g. 64kb"
        ));
    }
    let n: u64 = digits
        .parse()
        .map_err(|_| format!("invalid size {s:?}: number too large"))?;
    let shift = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 0,
        "k" | "kb" | "kib" => 10,
        "m" | "mb" | "mib" => 20,
        "g" | "gb" | "gib" => 30,
        "t" | "tb" | "tib" => 40,
        other => {
            return Err(format!(
                "invalid size unit {other:?} in {s:?}: expected b, kb, mb, gb or tb (1024-based)"
            ));
        }
    };
    n.checked_mul(1u64 << shift)
        .ok_or_else(|| format!("invalid size {s:?}: overflows 64 bits"))
}

/// `deserialize_with` for [`ByteSize`] fields: accepts an integer number of
/// bytes or a string with a 1024-based unit.
pub fn size<'de, D: Deserializer<'de>>(d: D) -> Result<ByteSize, D::Error> {
    struct V;
    impl Visitor<'_> for V {
        type Value = ByteSize;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a size such as 64kb, 1mb, 1gb, or a number of bytes")
        }
        fn visit_u64<E: de::Error>(self, v: u64) -> Result<ByteSize, E> {
            Ok(ByteSize::b(v))
        }
        fn visit_i64<E: de::Error>(self, v: i64) -> Result<ByteSize, E> {
            u64::try_from(v)
                .map(ByteSize::b)
                .map_err(|_| E::custom("size must not be negative"))
        }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<ByteSize, E> {
            parse_size(v).map(ByteSize::b).map_err(E::custom)
        }
    }
    d.deserialize_any(V)
}

// ----- expressions ----------------------------------------------------------

/// An uncompiled DSL expression (§6.2). Compiled by `roxy-rules` in M1.
///
/// YAML turns `where: true` into a boolean, so booleans are accepted and
/// stored as their literal text.
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

// ----- actions --------------------------------------------------------------

/// A rule's `then`: a single action or a list, normalised to a list.
///
/// TODO(M1): actions are untyped YAML values in M0. `roxy-rules` owns the
/// typed, closed action enum (§6.3) and replaces this with it.
#[derive(Debug, Clone, PartialEq)]
pub struct Actions(pub Vec<serde_yaml_ng::Value>);

impl<'de> Deserialize<'de> for Actions {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde_yaml_ng::Value;
        match Value::deserialize(d)? {
            Value::Null => Err(de::Error::custom("`then` must name at least one action")),
            Value::Sequence(items) if items.is_empty() => {
                Err(de::Error::custom("`then` must name at least one action"))
            }
            Value::Sequence(items) => Ok(Actions(items)),
            single => Ok(Actions(vec![single])),
        }
    }
}

// ----- metric count ---------------------------------------------------------

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

// ----- resolver -------------------------------------------------------------

/// `upstream.dns.resolver`: `system` or a list of nameserver socket addresses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Resolver {
    #[default]
    System,
    Servers(Vec<SocketAddr>),
}

impl<'de> Deserialize<'de> for Resolver {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Resolver;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("`system` or a list of nameserver addresses like \"1.1.1.1:53\"")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Resolver, E> {
                if v == "system" {
                    Ok(Resolver::System)
                } else {
                    Err(E::custom(format!(
                        "unknown resolver {v:?}: expected `system` or a list of addresses"
                    )))
                }
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Resolver, A::Error> {
                let mut servers = Vec::new();
                while let Some(addr) = seq.next_element::<SocketAddr>()? {
                    servers.push(addr);
                }
                if servers.is_empty() {
                    return Err(de::Error::custom("resolver list must not be empty"));
                }
                Ok(Resolver::Servers(servers))
            }
        }
        d.deserialize_any(V)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_are_1024_based() {
        assert_eq!(parse_size("512"), Ok(512));
        assert_eq!(parse_size("64kb"), Ok(64 * 1024));
        assert_eq!(parse_size("64KiB"), Ok(64 * 1024));
        assert_eq!(parse_size("8 kb"), Ok(8 * 1024));
        assert_eq!(parse_size("1mb"), Ok(1024 * 1024));
        assert_eq!(parse_size("1gb"), Ok(1024 * 1024 * 1024));
        assert_eq!(parse_size("2TB"), Ok(2 << 40));
    }

    #[test]
    fn bad_sizes_rejected() {
        for s in [
            "",
            "kb",
            "-1kb",
            "1.5mb",
            "10 parsecs",
            "99999999999999999999",
            "20000000tb",
        ] {
            assert!(parse_size(s).is_err(), "{s:?} should be rejected");
        }
    }
}
