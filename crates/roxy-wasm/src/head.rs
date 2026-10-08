//! Heads crossing the boundary: records in the WIT, `http` parts here.
//!
//! A head from the guest is validated as it arrives: names and values
//! parse, no reserved name (hop-by-hop, framing, `host`, `content-length`:
//! the body carries its length) and the whole record under
//! [`MAX_FIELDS_BYTES`]. What passes is still re-validated by the canonical
//! model where it enters the stack.

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

/// Parses the guest's header list, counting its bytes into `size`.
fn headers_from_guest(list: Headers, size: &mut usize) -> Result<HeaderMap, HeadError> {
    let mut map = HeaderMap::with_capacity(list.len());
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
        map.append(name, value);
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

/// The guest's request head as `http` parts. With `defaults` (the
/// exchange's scheme and authority, for `next`) the URI is absolute and a
/// missing scheme or authority is the exchange's; without them (an
/// endpoint call) the URI holds only the path and query.
pub(crate) fn request_from_guest(
    head: RequestHead,
    defaults: Option<(&Scheme, &Authority)>,
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
    let headers = headers_from_guest(head.headers, &mut size)?;
    Ok((method, uri, headers))
}

/// The guest's response head as `http` parts.
pub(crate) fn response_from_guest(
    head: ResponseHead,
) -> Result<(StatusCode, HeaderMap), HeadError> {
    let status = StatusCode::from_u16(head.status)
        .map_err(|_| HeadError::Invalid(format!("invalid status {}", head.status)))?;
    let mut size = 0;
    let headers = headers_from_guest(head.headers, &mut size)?;
    Ok((status, headers))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(headers: Vec<(&str, &[u8])>) -> RequestHead {
        RequestHead {
            method: "GET".into(),
            scheme: None,
            authority: None,
            path_with_query: "/x?y=1".into(),
            headers: headers
                .into_iter()
                .map(|(n, v)| (n.to_owned(), v.to_vec()))
                .collect(),
        }
    }

    fn defaults() -> (Scheme, Authority) {
        (Scheme::HTTPS, Authority::from_static("api.example.com"))
    }

    #[test]
    fn defaults_fill_a_relative_head_and_names_are_lower_cased() {
        let (scheme, authority) = defaults();
        let (method, uri, headers) =
            request_from_guest(head(vec![("X-Mixed", b"v")]), Some((&scheme, &authority)))
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
            let err = request_from_guest(head(vec![(name, b"v")]), Some((&scheme, &authority)))
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
                request_from_guest(h, Some((&scheme, &authority))),
                Err(HeadError::Invalid(_))
            ));
        }
        assert!(matches!(
            response_from_guest(ResponseHead {
                status: 99,
                headers: vec![]
            }),
            Err(HeadError::Invalid(_))
        ));
    }

    #[test]
    fn the_whole_head_is_capped() {
        let big = vec![b'a'; MAX_FIELDS_BYTES];
        let err = response_from_guest(ResponseHead {
            status: 200,
            headers: vec![("x-big".into(), big)],
        })
        .err()
        .unwrap();
        assert!(matches!(err, HeadError::TooLarge));
        let long_path = RequestHead {
            path_with_query: format!("/{}", "p".repeat(MAX_FIELDS_BYTES)),
            ..head(vec![])
        };
        assert!(matches!(
            request_from_guest(long_path, None),
            Err(HeadError::TooLarge)
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
        let (_, uri, _) = request_from_guest(h, None).ok().unwrap();
        assert_eq!(uri.to_string(), "/");
    }
}
