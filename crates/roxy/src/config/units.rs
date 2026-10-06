//! Custom deserialisers for config scalars and maps.

use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;
use std::net::SocketAddr;

use bytesize::ByteSize;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};

// ----- sizes ----------------------------------------------------------------

/// Parse a size such as `64kb`, `1 GiB`, `512` (bytes). Units are
/// case-insensitive and **1024-based** (`kb` == `kib`).
pub(crate) fn parse_size(s: &str) -> Result<u64, String> {
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
pub(crate) fn size<'de, D: Deserializer<'de>>(d: D) -> Result<ByteSize, D::Error> {
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

/// `deserialize_with` for optional [`ByteSize`] fields (use with
/// `#[serde(default)]`).
pub(crate) fn opt_size<'de, D: Deserializer<'de>>(d: D) -> Result<Option<ByteSize>, D::Error> {
    size(d).map(Some)
}

// ----- timestamps -----------------------------------------------------------

/// `deserialize_with` for the optional `valid_until` (use with
/// `#[serde(default)]`): an RFC 3339 date-time with a `Z` or numeric
/// offset, nothing else. The field is named in the error because a custom
/// error loses the YAML path.
pub(crate) fn opt_rfc3339<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<DateTime<Utc>>, D::Error> {
    let s = String::deserialize(d)?;
    DateTime::parse_from_rfc3339(&s)
        .map(|t| Some(t.with_timezone(&Utc)))
        .map_err(|e| {
            de::Error::custom(format!(
                "valid_until: invalid timestamp {s:?}: expected RFC 3339, e.g. 2026-10-06T12:00:00Z ({e})"
            ))
        })
}

// ----- counts ---------------------------------------------------------------

/// Parse a count such as `100000` or `100_000_000` (underscores as digit
/// separators, as in the documented examples).
pub(crate) fn parse_count(s: &str) -> Result<u64, String> {
    let t = s.trim();
    if t.is_empty()
        || t.starts_with('_')
        || t.ends_with('_')
        || !t.bytes().all(|b| b.is_ascii_digit() || b == b'_')
    {
        return Err(format!(
            "invalid count {s:?}: expected digits, e.g. 100_000_000"
        ));
    }
    t.replace('_', "")
        .parse()
        .map_err(|_| format!("invalid count {s:?}: too large"))
}

/// `deserialize_with` for optional counts: an integer or a string with `_`
/// separators (use with `#[serde(default)]`).
pub(crate) fn opt_count<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
    struct V;
    impl Visitor<'_> for V {
        type Value = u64;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a non-negative integer such as 100_000_000")
        }
        fn visit_u64<E: de::Error>(self, v: u64) -> Result<u64, E> {
            Ok(v)
        }
        fn visit_i64<E: de::Error>(self, v: i64) -> Result<u64, E> {
            u64::try_from(v).map_err(|_| E::custom("count must not be negative"))
        }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<u64, E> {
            parse_count(v).map_err(E::custom)
        }
    }
    d.deserialize_any(V).map(Some)
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

// ----- maps -----------------------------------------------------------------

/// Deserialise a `name: value` map, refusing a repeated name. serde only
/// detects duplicate keys for struct fields; a plain map is last-wins, which
/// would let the second of two `secrets.gh` entries silently replace the
/// first.
pub(super) fn unique_map<'de, D, V>(d: D) -> Result<BTreeMap<String, V>, D::Error>
where
    D: Deserializer<'de>,
    V: Deserialize<'de>,
{
    struct Vis<V>(PhantomData<V>);
    impl<'de, V: Deserialize<'de>> Visitor<'de> for Vis<V> {
        type Value = BTreeMap<String, V>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a map of unique names to values")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut out = BTreeMap::new();
            while let Some(k) = map.next_key::<String>()? {
                if out.contains_key(&k) {
                    return Err(de::Error::custom(format!("duplicate key `{k}`")));
                }
                let v = map.next_value::<V>()?;
                out.insert(k, v);
            }
            Ok(out)
        }
    }
    d.deserialize_map(Vis(PhantomData))
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
    fn counts() {
        assert_eq!(parse_count("100_000_000"), Ok(100_000_000));
        assert_eq!(parse_count("42"), Ok(42));
        for bad in [
            "",
            "_1",
            "1_",
            "1e6",
            "-1",
            "1.0",
            "99999999999999999999999",
        ] {
            assert!(parse_count(bad).is_err(), "{bad:?}");
        }
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
