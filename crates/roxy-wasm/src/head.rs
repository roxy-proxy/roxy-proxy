//! Heads crossing the boundary: records in the WIT, `http` parts here.
//!
//! A head from the guest is validated as it arrives: no more header fields
//! than `limits.max_headers`, names and values parse, no reserved name
//! (hop-by-hop, framing, `host`, `content-length`: the body carries its
//! length) and the whole record under [`MAX_FIELDS_BYTES`]. What passes is
//! still re-validated by the canonical model where it enters the stack.

use http::uri::{Authority, PathAndQuery, Scheme};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use roxy_http::model::is_reserved;

use crate::bindings::roxy::addon::types::{Headers, RequestHead, ResponseHead};

/// Most bytes in a head the guest hands the host (`next`, `respond`,
/// `call`): the method, scheme, authority and path, and every header name
/// and value. Twice the default `max_header_bytes`, so a head roxy accepts
/// can be copied and added to.
pub const MAX_FIELDS_BYTES: usize = 128 * 1024;

/// Why a guest head was refused.
pub(crate) enum HeadError {
    /// It does not parse, or states a field a layer may not.
    Invalid(String),
    /// Its path and query do not parse.
    InvalidPath(String),
    /// It has more header fields than `max_headers`.
    TooMany(String),
    /// It is over [`MAX_FIELDS_BYTES`].
    TooLarge,
}

fn headers_into_guest(map: &HeaderMap) -> Headers {
    map.iter()
        .map(|(n, v)| (n.as_str().to_owned(), v.as_bytes().to_vec()))
        .collect()
}

pub(crate) fn request_into_guest(parts: &http::request::Parts) -> RequestHead {
    RequestHead {
        method: parts.method.as_str().to_owned(),
        scheme: parts.uri.scheme_str().map(str::to_owned),
        authority: parts.uri.authority().map(|a| a.as_str().to_owned()),
        path_with_query: parts
            .uri
            .path_and_query()
            .map_or("/", PathAndQuery::as_str)
            .to_owned(),
        headers: headers_into_guest(&parts.headers),
    }
}

pub(crate) fn response_into_guest(parts: &http::response::Parts) -> ResponseHead {
    ResponseHead {
        status: parts.status.as_u16(),
        headers: headers_into_guest(&parts.headers),
    }
}

/// Parses the guest's header list, counting its bytes into `size`. The
/// count is checked before anything is allocated for the list: the map's
/// capacity is otherwise the guest's to choose.
fn headers_from_guest(
    list: Headers,
    size: &mut usize,
    max_headers: usize,
) -> Result<HeaderMap, HeadError> {
    let count = list.len();
    if count > max_headers {
        return Err(HeadError::TooMany(format!(
            "{count} header fields, more than max_headers ({max_headers})"
        )));
    }
    let too_many = |_| HeadError::TooMany(format!("{count} header fields, more than a head holds"));
    let mut map = HeaderMap::try_with_capacity(count).map_err(too_many)?;
    for (name, value) in list {
        *size = size.saturating_add(name.len()).saturating_add(value.len());
        if *size > MAX_FIELDS_BYTES {
            return Err(HeadError::TooLarge);
        }
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| HeadError::Invalid(format!("invalid header name {name:?}")))?;
        if is_reserved(name.as_str()) {
            return Err(HeadError::Invalid(format!("{name} set by a layer")));
        }
        let value = HeaderValue::from_bytes(&value)
            .map_err(|_| HeadError::Invalid(format!("invalid value for header {name}")))?;
        map.try_append(name, value).map_err(too_many)?;
    }
    Ok(map)
}

fn path_from_guest(path: &str) -> Result<PathAndQuery, HeadError> {
    if path.is_empty() {
        return Ok(PathAndQuery::from_static("/"));
    }
    path.parse::<PathAndQuery>()
        .map_err(|e| HeadError::InvalidPath(format!("invalid path {path:?}: {e}")))
}

/// The guest's request head as `http` parts, with at most `max_headers`
/// header fields. With `defaults` (the exchange's scheme and authority, for
/// `next`) the URI is absolute and a missing scheme or authority is the
/// exchange's; without them (an endpoint call) the URI holds only the path
/// and query.
pub(crate) fn request_from_guest(
    head: RequestHead,
    defaults: Option<(&Scheme, &Authority)>,
    max_headers: usize,
) -> Result<(Method, Uri, HeaderMap), HeadError> {
    let mut size = head
        .method
        .len()
        .saturating_add(head.scheme.as_ref().map_or(0, String::len))
        .saturating_add(head.authority.as_ref().map_or(0, String::len))
        .saturating_add(head.path_with_query.len());
    if size > MAX_FIELDS_BYTES {
        return Err(HeadError::TooLarge);
    }
    let method = Method::from_bytes(head.method.as_bytes())
        .map_err(|_| HeadError::Invalid(format!("invalid method {:?}", head.method)))?;
    let path = path_from_guest(&head.path_with_query)?;
    let uri = match defaults {
        Some((scheme, authority)) => {
            let scheme = match head.scheme.as_deref() {
                None => scheme.clone(),
                Some("http") => Scheme::HTTP,
                Some("https") => Scheme::HTTPS,
                Some(other) => {
                    return Err(HeadError::Invalid(format!("unsupported scheme {other:?}")));
                }
            };
            let authority = match head.authority {
                None => authority.clone(),
                Some(a) => Authority::try_from(a.as_str())
                    .map_err(|e| HeadError::Invalid(format!("invalid authority {a:?}: {e}")))?,
            };
            Uri::builder()
                .scheme(scheme)
                .authority(authority)
                .path_and_query(path)
                .build()
                .map_err(|e| HeadError::Invalid(format!("invalid URI: {e}")))?
        }
        None => Uri::from(path),
    };
    let headers = headers_from_guest(head.headers, &mut size, max_headers)?;
    Ok((method, uri, headers))
}

/// The guest's response head as `http` parts, with at most `max_headers`
/// header fields.
pub(crate) fn response_from_guest(
    head: ResponseHead,
    max_headers: usize,
) -> Result<(StatusCode, HeaderMap), HeadError> {
    let status = StatusCode::from_u16(head.status)
        .map_err(|_| HeadError::Invalid(format!("invalid status {}", head.status)))?;
    let mut size = 0;
    let headers = headers_from_guest(head.headers, &mut size, max_headers)?;
    Ok((status, headers))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(headers: Vec<(&str, &[u8])>) -> RequestHead {
        head_of(
            headers
                .into_iter()
                .map(|(n, v)| (n.to_owned(), v.to_vec()))
                .collect(),
        )
    }

    fn head_of(headers: Headers) -> RequestHead {
        RequestHead {
            method: "GET".into(),
            scheme: None,
            authority: None,
            path_with_query: "/x?y=1".into(),
            headers,
        }
    }

    fn defaults() -> (Scheme, Authority) {
        (Scheme::HTTPS, Authority::from_static("api.example.com"))
    }

    const MAX: usize = 100;

    fn pairs(n: usize) -> Headers {
        (0..n).map(|_| ("a".to_owned(), Vec::new())).collect()
    }

    #[test]
    fn defaults_fill_a_relative_head_and_names_are_lower_cased() {
        let (scheme, authority) = defaults();
        let (method, uri, headers) =
            request_from_guest(head(vec![("X-Mixed", b"v")]), Some((&scheme, &authority)), MAX)
                .ok()
                .unwrap();
        assert_eq!(method, Method::GET);
        assert_eq!(uri.to_string(), "https://api.example.com/x?y=1");
        assert_eq!(headers["x-mixed"], "v");
    }

    #[test]
    fn reserved_and_malformed_fields_are_refused() {
        let (scheme, authority) = defaults();
        for name in [
            "host",
            "content-length",
            "connection",
            "upgrade",
            "transfer-encoding",
        ] {
            let err = request_from_guest(head(vec![(name, b"v")]), Some((&scheme, &authority)), MAX)
                .err()
                .unwrap();
            assert!(
                matches!(err, HeadError::Invalid(m) if m.contains(name)),
                "{name}"
            );
        }
        let bad = [
            head(vec![("bad name", b"v")]),
            head(vec![("x", b"line\nbreak")]),
            RequestHead {
                scheme: Some("ftp".into()),
                ..head(vec![])
            },
            RequestHead {
                method: "NO SPACES".into(),
                ..head(vec![])
            },
            RequestHead {
                authority: Some("a b".into()),
                ..head(vec![])
            },
        ];
        for h in bad {
            assert!(matches!(
                request_from_guest(h, Some((&scheme, &authority)), MAX),
                Err(HeadError::Invalid(_))
            ));
        }
        assert!(matches!(
            response_from_guest(
                ResponseHead {
                    status: 99,
                    headers: vec![]
                },
                MAX
            ),
            Err(HeadError::Invalid(_))
        ));
    }

    #[test]
    fn the_whole_head_is_capped() {
        let big = vec![b'a'; MAX_FIELDS_BYTES];
        let err = response_from_guest(
            ResponseHead {
                status: 200,
                headers: vec![("x-big".into(), big)],
            },
            MAX,
        )
        .err()
        .unwrap();
        assert!(matches!(err, HeadError::TooLarge));
        let long_path = RequestHead {
            path_with_query: format!("/{}", "p".repeat(MAX_FIELDS_BYTES)),
            ..head(vec![])
        };
        assert!(matches!(
            request_from_guest(long_path, None, MAX),
            Err(HeadError::TooLarge)
        ));
    }

    /// The count is checked before the list is lowered, so a list past
    /// what `http` can hold is an error whatever `max_headers` allows.
    #[test]
    fn too_many_fields_are_refused_without_building_the_map() {
        let (scheme, authority) = defaults();
        let ok = request_from_guest(head_of(pairs(MAX)), Some((&scheme, &authority)), MAX);
        assert_eq!(ok.ok().unwrap().2.len(), MAX);
        let over = request_from_guest(head_of(pairs(MAX + 1)), None, MAX);
        assert!(matches!(over, Err(HeadError::TooMany(m)) if m.contains("101 header fields")));
        let response = ResponseHead {
            status: 200,
            headers: pairs(MAX + 1),
        };
        assert!(matches!(
            response_from_guest(response, MAX),
            Err(HeadError::TooMany(_))
        ));
        let huge = ResponseHead {
            status: 200,
            headers: pairs(1 << 16),
        };
        assert!(matches!(
            response_from_guest(huge, usize::MAX),
            Err(HeadError::TooMany(_))
        ));
    }

    #[test]
    fn an_endpoint_head_keeps_only_the_path() {
        let h = RequestHead {
            scheme: Some("https".into()),
            authority: Some("elsewhere".into()),
            path_with_query: String::new(),
            ..head(vec![])
        };
        let (_, uri, _) = request_from_guest(h, None, MAX).ok().unwrap();
        assert_eq!(uri.to_string(), "/");
    }
}
