//! Request-head parsing: raw pre-checks, `httparse` tokenisation, and the
//! semantic validation of the rejection rules. Pure functions over bytes (fuzz target).

use crate::chars::trim_ows;
use crate::model::{
    Authority, Headers, HttpFlags, Limits, Method, ParseError, Reason, RequestMeta, Scheme,
    TargetForm, Version, connection_tokens, parse_content_length, parse_field_line, reject,
    requested_upgrade,
};
use crate::url::{self, Path, Query};

/// The context a connection runs in; decides which request-target forms are
/// legal and what `Host` must equal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Role {
    /// The explicit proxy port: absolute-form and CONNECT (origin-form is
    /// surfaced separately for the `roxy.internal` special case).
    ProxyPort,
    /// Inside a CONNECT tunnel (after TLS termination, or plaintext with
    /// `http.allow_plain_in_connect`): origin-form only, `Host` must equal
    /// `authority`.
    Tunnel {
        /// The CONNECT / SNI authority.
        authority: Authority,
        /// `https` after TLS termination, `http` for plaintext tunnels.
        scheme: Scheme,
    },
    /// A plaintext connection the client addressed to the origin itself (a
    /// `direct` listener): origin-form only,
    /// `Host` names the authority, and its port must be `port`, the port the
    /// client connected to.
    Direct {
        /// The listener's `target_port`.
        port: u16,
    },
}

/// How the request body is framed on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// No body.
    None,
    /// `Content-Length: n` (n > 0).
    Length(u64),
    /// `Transfer-Encoding: chunked`.
    Chunked,
}

/// A validated request head (everything except the body).
#[derive(Debug)]
pub struct RequestHead {
    /// Method.
    pub method: Method,
    /// Scheme.
    pub scheme: Scheme,
    /// Target authority.
    pub authority: Authority,
    /// Normalised path.
    pub path: Path,
    /// Query.
    pub query: Option<Query>,
    /// Canonical headers.
    pub headers: Headers,
    /// Metadata.
    pub meta: RequestMeta,
    /// Body framing.
    pub framing: Framing,
}

/// A validated head: a normal request or a CONNECT.
#[derive(Debug)]
pub enum Head {
    /// Any non-CONNECT request.
    Request(RequestHead),
    /// `CONNECT host:port` on the proxy port.
    Connect {
        /// Target authority (port always explicit in the request).
        authority: Authority,
        /// Canonical headers.
        headers: Headers,
        /// Metadata (`proxy_authorization` is here).
        meta: RequestMeta,
    },
}

/// Outcome of scanning a buffer for the end of a head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadScan {
    /// The head ends at this offset (just past the blank line).
    Complete(usize),
    /// More bytes needed; resume scanning from this offset.
    Partial(usize),
}

/// Scans `buf[from..]` for the end of the head (`CRLF CRLF`), rejecting bare
/// CR and bare LF as soon as they are seen, and enforcing the head and
/// request-line size limits on partial input.
pub fn scan_head(buf: &[u8], from: usize, limits: &Limits) -> Result<HeadScan, ParseError> {
    match scan_section(buf, from) {
        Err(Bare::Lf(i)) => return reject(Reason::BareLf, format!("bare LF at offset {i}")),
        Err(Bare::Cr(i)) => return reject(Reason::BareCr, format!("bare CR at offset {i}")),
        Ok(Some(end)) => {
            if end > limits.max_header_bytes {
                return reject(Reason::HeadTooLarge, format!("head is {end} bytes"));
            }
            return Ok(HeadScan::Complete(end));
        }
        Ok(None) => {}
    }
    if buf.len() > limits.max_header_bytes {
        return reject(
            Reason::HeadTooLarge,
            format!("head exceeds {} bytes", limits.max_header_bytes),
        );
    }
    // Request line still incomplete and already longer than any legal one.
    if !buf.contains(&b'\n') && buf.len() > limits.max_url_bytes.saturating_add(64) {
        return reject(Reason::UrlTooLong, "request line too long");
    }
    // Re-examine a trailing CR once its successor arrives.
    Ok(HeadScan::Partial(buf.len().saturating_sub(1)))
}

/// A line ending the head and trailer scanners refuse, with its offset.
pub(crate) enum Bare {
    /// A CR not followed by LF.
    Cr(usize),
    /// A LF not preceded by CR.
    Lf(usize),
}

/// Looks from `from` for the CRLF CRLF that ends a head or trailer
/// section: the offset just past it, or `None` while it has not arrived.
/// Any bare CR or LF before it is a fault. A CR as the last byte is left
/// undecided until its successor arrives.
pub(crate) fn scan_section(buf: &[u8], from: usize) -> Result<Option<usize>, Bare> {
    for (i, &b) in buf.iter().enumerate().skip(from) {
        match b {
            b'\n' => {
                if i.checked_sub(1).is_none_or(|p| buf[p] != b'\r') {
                    return Err(Bare::Lf(i));
                }
                if i.checked_sub(3).is_some_and(|s| &buf[s..=i] == b"\r\n\r\n") {
                    // `i` indexes `buf`, so the end offset fits.
                    return Ok(Some(i.saturating_add(1)));
                }
            }
            b'\r' if buf[i..].get(1).is_some_and(|&next| next != b'\n') => {
                return Err(Bare::Cr(i));
            }
            _ => {}
        }
    }
    Ok(None)
}

/// Splits a head (ending in CRLF CRLF, already scanned) into lines.
fn lines(head: &[u8]) -> Vec<&[u8]> {
    let body = head.strip_suffix(b"\r\n\r\n").unwrap_or(head);
    let mut out = Vec::new();
    let mut rest = body;
    loop {
        if let Some(i) = rest.windows(2).position(|w| w == b"\r\n") {
            out.push(&rest[..i]);
            rest = &rest[i..][2..];
        } else {
            out.push(rest);
            return out;
        }
    }
}

fn check_request_line(
    line: &[u8],
    limits: &Limits,
    flags: &HttpFlags,
) -> Result<Version, ParseError> {
    if line.iter().any(|&b| b >= 0x80) {
        return reject(Reason::NonAscii, "non-ASCII byte in request line");
    }
    if line.iter().any(|&b| b < 0x20 || b == 0x7f) {
        return reject(Reason::BadRequestLine, "control character in request line");
    }
    let parts: Vec<&[u8]> = line.split(|&b| b == b' ').collect();
    if parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty() {
        return reject(Reason::UnsupportedVersion, "HTTP/0.9 request line");
    }
    if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
        return reject(
            Reason::BadRequestLine,
            "request line is not 'method SP target SP version'",
        );
    }
    Method::parse(parts[0])?;
    if parts[1].len() > limits.max_url_bytes {
        return reject(
            Reason::UrlTooLong,
            format!("target is {} bytes", parts[1].len()),
        );
    }
    match parts[2] {
        b"HTTP/1.1" => Ok(Version::H1_1),
        b"HTTP/1.0" if flags.allow_http10 => Ok(Version::H1_0),
        [b'H', b'T', b'T', b'P', b'/', maj, b'.', min]
            if maj.is_ascii_digit() && min.is_ascii_digit() =>
        {
            reject(
                Reason::UnsupportedVersion,
                format!("version {}", String::from_utf8_lossy(parts[2])),
            )
        }
        _ => reject(Reason::BadRequestLine, "malformed HTTP version"),
    }
}

fn map_httparse(e: httparse::Error) -> ParseError {
    let reason = match e {
        httparse::Error::HeaderName => Reason::InvalidHeaderName,
        httparse::Error::HeaderValue => Reason::InvalidHeaderValue,
        httparse::Error::NewLine => Reason::BareLf,
        httparse::Error::TooManyHeaders => Reason::TooManyHeaders,
        httparse::Error::Version => Reason::UnsupportedVersion,
        httparse::Error::Token => Reason::InvalidMethod,
        httparse::Error::Status => Reason::BadRequestLine,
    };
    ParseError::new(reason, format!("httparse: {e}"))
}

/// Raw pre-checks, stricter than httparse: head termination and size, the
/// request line, then every field line in order. Returns the version.
fn check_raw_head(head: &[u8], limits: &Limits, flags: &HttpFlags) -> Result<Version, ParseError> {
    if head.len() > limits.max_header_bytes {
        return reject(
            Reason::HeadTooLarge,
            format!("head is {} bytes", head.len()),
        );
    }
    match scan_head(head, 0, limits)? {
        HeadScan::Complete(n) if n == head.len() => {}
        HeadScan::Complete(_) | HeadScan::Partial(_) => {
            return reject(
                Reason::BadRequestLine,
                "head is not terminated by CRLF CRLF",
            );
        }
    }
    let lines = lines(head);
    let version = check_request_line(lines[0], limits, flags)?;
    let header_lines = &lines[1..];
    if header_lines.len() > limits.max_headers {
        return reject(
            Reason::TooManyHeaders,
            format!("{} header fields", header_lines.len()),
        );
    }
    for line in header_lines {
        parse_field_line(line, flags.allow_obs_text)?;
    }
    Ok(version)
}

/// Tokenises a pre-checked head with httparse (defence in depth: it must
/// agree with the raw checks). Returns the method, the target and the raw
/// `(name, OWS-trimmed value)` pairs.
#[allow(clippy::type_complexity)]
fn tokenise(head: &[u8]) -> Result<(Method, &[u8], Vec<(&[u8], &[u8])>), ParseError> {
    // The request line is always there.
    let field_count = lines(head).len().saturating_sub(1);
    let mut storage = vec![httparse::EMPTY_HEADER; field_count];
    let mut req = httparse::Request::new(&mut storage);
    match req.parse(head) {
        Ok(httparse::Status::Complete(n)) if n == head.len() => {}
        Ok(_) => return reject(Reason::BadRequestLine, "httparse disagrees on head length"),
        Err(e) => return Err(map_httparse(e)),
    }
    let method = Method::parse(req.method.unwrap_or("").as_bytes())?;
    let target = req.path.unwrap_or("").as_bytes();
    let raw = req
        .headers
        .iter()
        .map(|h| (h.name.as_bytes(), trim_ows(h.value)))
        .collect();
    Ok((method, target, raw))
}

/// Values of every field named `name`, in order.
fn all<'a>(raw: &[(&'a [u8], &'a [u8])], name: &str) -> Vec<&'a [u8]> {
    raw.iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case(name.as_bytes()))
        .map(|(_, v)| *v)
        .collect()
}

/// Body framing from `Content-Length` / `Transfer-Encoding`, with the body
/// policy applied: one `Content-Length` or exactly `chunked`, never both;
/// no body on a bodiless method; a declared length within the cap.
fn request_framing(
    raw: &[(&[u8], &[u8])],
    method: &Method,
    version: Version,
    limits: &Limits,
    flags: &HttpFlags,
) -> Result<Framing, ParseError> {
    let cls = all(raw, "content-length");
    let tes = all(raw, "transfer-encoding");
    if !cls.is_empty() && !tes.is_empty() {
        return reject(Reason::ClAndTe, "both content-length and transfer-encoding");
    }
    if cls.len() > 1 {
        return reject(
            Reason::DuplicateContentLength,
            "multiple content-length fields",
        );
    }
    let framing = if let Some(cl) = cls.first() {
        match parse_content_length(cl)? {
            0 => Framing::None,
            n => Framing::Length(n),
        }
    } else if let Some(te) = tes.first() {
        if tes.len() > 1 || !te.eq_ignore_ascii_case(b"chunked") {
            return reject(
                Reason::BadTransferEncoding,
                format!(
                    "transfer-encoding {:?}",
                    tes.iter()
                        .map(|t| String::from_utf8_lossy(t))
                        .collect::<Vec<_>>()
                ),
            );
        }
        if version == Version::H1_0 {
            return reject(
                Reason::BadTransferEncoding,
                "chunked in an HTTP/1.0 request",
            );
        }
        Framing::Chunked
    } else {
        Framing::None
    };
    if framing != Framing::None && !method.allows_body(flags.allow_body_on_get) {
        return reject(Reason::BodyOnBodiless, format!("body on {method} request"));
    }
    if let Framing::Length(n) = framing
        && n > limits.max_request_body_bytes
    {
        return reject(Reason::BodyTooLarge, format!("content-length {n}"));
    }
    Ok(framing)
}

/// Metadata from the hop-by-hop fields: `Expect`, `Connection` and
/// `Upgrade`.
fn hop_by_hop_meta(
    raw: &[(&[u8], &[u8])],
    version: Version,
    framing: Framing,
    head_bytes: usize,
) -> Result<RequestMeta, ParseError> {
    let mut meta = RequestMeta::new(version, TargetForm::Origin);
    meta.head_bytes = head_bytes;
    let expects = all(raw, "expect");
    if !expects.is_empty() {
        if expects.len() > 1 || !expects[0].eq_ignore_ascii_case(b"100-continue") {
            return reject(Reason::BadExpect, "unsupported expectation");
        }
        meta.expect_continue = version == Version::H1_1 && framing != Framing::None;
    }
    let conn = connection_tokens(all(raw, "connection"))?;
    // roxy never keeps an HTTP/1.0 connection alive, whatever `Connection`
    // says, so the flag is simply true for every 1.0 request.
    meta.close = version == Version::H1_0 || conn.iter().any(|t| t == "close");
    meta.upgrade = requested_upgrade(&conn, all(raw, "upgrade"));
    Ok(meta)
}

/// The single `Host` value, if any.
fn single_host<'a>(raw: &[(&'a [u8], &'a [u8])]) -> Result<Option<&'a [u8]>, ParseError> {
    let hosts = all(raw, "host");
    if hosts.len() > 1 {
        return reject(Reason::MultipleHost, "multiple host fields");
    }
    Ok(hosts.first().copied())
}

/// `Host` must name `authority` (with `default_port` implied) when present.
fn check_host(
    host: &[u8],
    authority: &Authority,
    default_port: u16,
    what: &str,
) -> Result<(), ParseError> {
    let ha = url::parse_authority(host, default_port)?;
    if ha != *authority {
        return reject(Reason::HostMismatch, format!("host does not match {what}"));
    }
    Ok(())
}

/// The CONNECT target: authority-form on the proxy port, agreeing with
/// `Host` when one is sent.
fn connect_target(
    target: &[u8],
    host: Option<&[u8]>,
    role: &Role,
) -> Result<Authority, ParseError> {
    if *role != Role::ProxyPort {
        return reject(
            Reason::TargetFormMismatch,
            "CONNECT is only accepted on the proxy port",
        );
    }
    if target.contains(&b'/') {
        return reject(
            Reason::BadRequestTarget,
            "CONNECT target must be authority-form",
        );
    }
    let authority = url::parse_authority_opt(target, None)?;
    if let Some(h) = host {
        check_host(h, &authority, authority.port, "CONNECT authority")?;
    }
    Ok(authority)
}

/// Where a non-CONNECT request goes, from its target form, `Host` and the
/// connection's role.
type Target = (Scheme, Authority, Path, Option<Query>, TargetForm);

fn resolve_target(
    target: &[u8],
    host: Option<&[u8]>,
    role: &Role,
    version: Version,
) -> Result<Target, ParseError> {
    if target == b"*" {
        return reject(Reason::BadRequestTarget, "asterisk-form is not supported");
    }
    if !target.starts_with(b"/") {
        return match role {
            Role::ProxyPort => {
                let (scheme, authority, path, query) = url::parse_absolute_form(target)?;
                match host {
                    Some(h) => {
                        check_host(h, &authority, scheme.default_port(), "target authority")?;
                    }
                    None if version == Version::H1_1 => {
                        return reject(Reason::MissingHost, "no host field");
                    }
                    None => {}
                }
                Ok((scheme, authority, path, query, TargetForm::Absolute))
            }
            Role::Tunnel { .. } => reject(
                Reason::TargetFormMismatch,
                "only origin-form is accepted inside a tunnel",
            ),
            Role::Direct { .. } => reject(
                Reason::TargetFormMismatch,
                "only origin-form is accepted on a direct listener",
            ),
        };
    }
    // Origin-form: `Host` names the target, or must agree with the tunnel.
    let Some(h) = host else {
        return reject(Reason::MissingHost, "no host field");
    };
    let (path, query) = url::parse_origin_form(target)?;
    let (scheme, authority) = match role {
        Role::ProxyPort => (
            Scheme::Http,
            url::parse_authority(h, Scheme::Http.default_port())?,
        ),
        Role::Direct { port } => {
            let authority = url::parse_authority(h, Scheme::Http.default_port())?;
            if authority.port != *port {
                return reject(
                    Reason::HostMismatch,
                    "host port does not match the listener's port",
                );
            }
            (Scheme::Http, authority)
        }
        Role::Tunnel { authority, scheme } => {
            check_host(h, authority, scheme.default_port(), "tunnel authority")?;
            (*scheme, authority.clone())
        }
    };
    Ok((scheme, authority, path, query, TargetForm::Origin))
}

/// Parses and validates a complete head (as delimited by [`scan_head`]).
pub fn parse_head(
    head: &[u8],
    role: &Role,
    limits: &Limits,
    flags: &HttpFlags,
) -> Result<Head, ParseError> {
    let version = check_raw_head(head, limits, flags)?;
    let (method, target, raw) = tokenise(head)?;
    let framing = request_framing(&raw, &method, version, limits, flags)?;
    let mut meta = hop_by_hop_meta(&raw, version, framing, head.len())?;
    let host = single_host(&raw)?;
    let headers = Headers::try_from_raw(raw.iter().copied(), limits, flags)?;

    if method == Method::Connect {
        let authority = connect_target(target, host, role)?;
        meta.target_form = TargetForm::Authority;
        return Ok(Head::Connect {
            authority,
            headers,
            meta,
        });
    }
    let (scheme, authority, path, query, form) = resolve_target(target, host, role, version)?;
    meta.target_form = form;
    Ok(Head::Request(RequestHead {
        method,
        scheme,
        authority,
        path,
        query,
        headers,
        meta,
        framing,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(raw: &str) -> Result<Head, Reason> {
        parse_head(
            raw.as_bytes(),
            &Role::ProxyPort,
            &Limits::default(),
            &HttpFlags::default(),
        )
        .map_err(|e| e.reason)
    }

    #[test]
    fn scan() {
        let l = Limits::default();
        assert_eq!(
            scan_head(b"GET / HTTP/1.1\r\n", 0, &l).unwrap(),
            HeadScan::Partial(15)
        );
        assert_eq!(
            scan_head(b"GET / HTTP/1.1\r\n\r\nXX", 0, &l).unwrap(),
            HeadScan::Complete(18)
        );
        assert_eq!(
            scan_head(b"GET / HTTP/1.1\r", 0, &l).unwrap(),
            HeadScan::Partial(14)
        );
        assert_eq!(
            scan_head(b"GET / HTTP/1.1\rX", 0, &l).unwrap_err().reason,
            Reason::BareCr
        );
        assert_eq!(
            scan_head(b"GET / HTTP/1.1\n", 0, &l).unwrap_err().reason,
            Reason::BareLf
        );
    }

    #[test]
    fn absolute_form_ok() {
        let Head::Request(h) =
            parse("GET http://Example.com/a/./b?x=1 HTTP/1.1\r\nHost: example.com:80\r\nAccept: */*\r\n\r\n")
                .unwrap()
        else {
            panic!()
        };
        assert_eq!(h.authority.to_string(), "example.com:80");
        assert_eq!(h.path.as_str(), "/a/b");
        assert_eq!(h.query.unwrap().as_str(), "x=1");
        assert_eq!(h.framing, Framing::None);
        assert_eq!(h.meta.target_form, TargetForm::Absolute);
        assert_eq!(h.headers.get("accept"), Some("*/*"));
        assert!(!h.headers.contains("host"));
    }

    #[test]
    fn connect_ok() {
        let Head::Connect { authority, .. } =
            parse("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n").unwrap()
        else {
            panic!()
        };
        assert_eq!(authority.to_string(), "example.com:443");
        assert_eq!(
            parse("CONNECT example.com HTTP/1.1\r\n\r\n").unwrap_err(),
            Reason::BadAuthority
        );
        assert_eq!(
            parse("CONNECT http://example.com/ HTTP/1.1\r\n\r\n").unwrap_err(),
            Reason::BadRequestTarget
        );
    }

    #[test]
    fn http10_always_closes() {
        let flags = HttpFlags {
            allow_http10: true,
            ..HttpFlags::default()
        };
        let Head::Request(h) = parse_head(
            b"GET http://example.com/ HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
            &Role::ProxyPort,
            &Limits::default(),
            &flags,
        )
        .unwrap() else {
            panic!()
        };
        assert!(h.meta.close);
    }
}
