//! Request-head parsing: raw pre-checks, `httparse` tokenisation, and the
//! semantic validation of the rejection rules. Pure functions over bytes (fuzz target).

use http::HeaderValue;

use crate::chars::{is_field_value_byte, is_tchar, split_list, trim_ows};
use crate::model::{
    Authority, Headers, HttpFlags, Limits, Method, ParseError, Reason, RequestMeta, Scheme,
    TargetForm, Version, connection_tokens, reject,
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
    let mut i = from;
    while i < buf.len() {
        match buf[i] {
            b'\n' => {
                if i == 0 || buf[i - 1] != b'\r' {
                    return reject(Reason::BareLf, format!("bare LF at offset {i}"));
                }
                if i >= 3 && &buf[i - 3..=i] == b"\r\n\r\n" {
                    let end = i + 1;
                    if end > limits.max_header_bytes {
                        return reject(Reason::HeadTooLarge, format!("head is {end} bytes"));
                    }
                    return Ok(HeadScan::Complete(end));
                }
            }
            b'\r' => {
                if let Some(&next) = buf.get(i + 1)
                    && next != b'\n'
                {
                    return reject(Reason::BareCr, format!("bare CR at offset {i}"));
                }
            }
            _ => {}
        }
        i += 1;
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

/// Splits a head (ending in CRLF CRLF, already scanned) into lines.
fn lines(head: &[u8]) -> Vec<&[u8]> {
    let body = head.strip_suffix(b"\r\n\r\n").unwrap_or(head);
    let mut out = Vec::new();
    let mut rest = body;
    loop {
        if let Some(i) = rest.windows(2).position(|w| w == b"\r\n") {
            out.push(&rest[..i]);
            rest = &rest[i + 2..];
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

fn check_header_line(line: &[u8], flags: &HttpFlags) -> Result<(), ParseError> {
    if matches!(line.first(), Some(b' ' | b'\t')) {
        return reject(Reason::ObsFold, "obsolete line folding");
    }
    let Some(colon) = line.iter().position(|&b| b == b':') else {
        return reject(Reason::InvalidHeaderName, "header line without colon");
    };
    let name = &line[..colon];
    if name.is_empty() {
        return reject(Reason::InvalidHeaderName, "empty header name");
    }
    if matches!(name.last(), Some(b' ' | b'\t')) {
        return reject(Reason::WhitespaceBeforeColon, "whitespace before colon");
    }
    if name.iter().any(|&b| b >= 0x80) {
        return reject(Reason::NonAscii, "non-ASCII header name");
    }
    if !name.iter().all(|&b| is_tchar(b)) {
        return reject(
            Reason::InvalidHeaderName,
            format!("invalid header name {:?}", String::from_utf8_lossy(name)),
        );
    }
    let value = &line[colon + 1..];
    if let Some(&b) = value
        .iter()
        .find(|&&b| !is_field_value_byte(b, flags.allow_obs_text))
    {
        if b >= 0x80 {
            return reject(Reason::NonAscii, "non-ASCII header value");
        }
        return reject(
            Reason::InvalidHeaderValue,
            format!("byte 0x{b:02x} in header value"),
        );
    }
    Ok(())
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

fn parse_content_length(v: &[u8]) -> Result<u64, ParseError> {
    if v.is_empty() || v.len() > 19 || !v.iter().all(u8::is_ascii_digit) {
        return reject(
            Reason::BadContentLength,
            format!("content-length {:?}", String::from_utf8_lossy(v)),
        );
    }
    // 19 digits always fit in a u64.
    Ok(v.iter()
        .fold(0u64, |acc, &d| acc * 10 + u64::from(d - b'0')))
}

/// Parses and validates a complete head (as delimited by [`scan_head`]).
#[allow(clippy::too_many_lines)] // one linear pass over the rejection rules; splitting obscures the order of checks
pub fn parse_head(
    head: &[u8],
    role: &Role,
    limits: &Limits,
    flags: &HttpFlags,
) -> Result<Head, ParseError> {
    // ----- raw pre-checks (stricter than httparse) -----
    if head.len() > limits.max_header_bytes {
        return reject(
            Reason::HeadTooLarge,
            format!("head is {} bytes", head.len()),
        );
    }
    match scan_head(head, 0, limits)? {
        HeadScan::Complete(n) if n == head.len() => {}
        _ => {
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
        check_header_line(line, flags)?;
    }

    // ----- tokenisation (defence in depth: httparse must agree) -----
    let mut storage = vec![httparse::EMPTY_HEADER; header_lines.len()];
    let mut req = httparse::Request::new(&mut storage);
    match req.parse(head) {
        Ok(httparse::Status::Complete(n)) if n == head.len() => {}
        Ok(_) => return reject(Reason::BadRequestLine, "httparse disagrees on head length"),
        Err(e) => return Err(map_httparse(e)),
    }
    let method = Method::parse(req.method.unwrap_or("").as_bytes())?;
    let target = req.path.unwrap_or("").as_bytes();
    let raw: Vec<(&[u8], &[u8])> = req
        .headers
        .iter()
        .map(|h| (h.name.as_bytes(), trim_ows(h.value)))
        .collect();

    // ----- semantic validation -----
    let all = |name: &str| -> Vec<&[u8]> {
        raw.iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name.as_bytes()))
            .map(|(_, v)| *v)
            .collect()
    };
    let hosts = all("host");
    let cls = all("content-length");
    let tes = all("transfer-encoding");
    let expects = all("expect");
    let conn = connection_tokens(all("connection"))?;
    let upgrades = all("upgrade");
    let proxy_auth = all("proxy-authorization");

    // Framing: Content-Length / Transfer-Encoding.
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

    // Expect.
    let mut expect_continue = false;
    if !expects.is_empty() {
        if expects.len() > 1 || !expects[0].eq_ignore_ascii_case(b"100-continue") {
            return reject(Reason::BadExpect, "unsupported expectation");
        }
        expect_continue = version == Version::H1_1 && framing != Framing::None;
    }

    // Host.
    if hosts.len() > 1 {
        return reject(Reason::MultipleHost, "multiple host fields");
    }
    let host = hosts.first().copied();

    let mut meta = RequestMeta::new(version, TargetForm::Origin);
    meta.head_bytes = head.len();
    meta.expect_continue = expect_continue;
    meta.close = conn.iter().any(|t| t == "close")
        || (version == Version::H1_0 && !conn.iter().any(|t| t == "keep-alive"));
    if conn.iter().any(|t| t == "upgrade") && !upgrades.is_empty() {
        let joined: Vec<String> = upgrades
            .iter()
            .flat_map(|u| split_list(u))
            .map(|u| String::from_utf8_lossy(u).to_ascii_lowercase())
            .collect();
        meta.upgrade = Some(joined.join(", "));
    }
    if let Some(pa) = proxy_auth.first() {
        meta.proxy_authorization = HeaderValue::from_bytes(pa).ok();
    }

    let mut headers = Headers::try_from_raw(raw.iter().copied(), limits, flags)?;
    headers.remove("expect");

    // Request target vs role.
    if method == Method::Connect {
        if *role != Role::ProxyPort {
            return reject(
                Reason::TargetFormMismatch,
                "CONNECT is only accepted on the proxy port",
            );
        }
        if target.starts_with(b"/") || target.contains(&b'/') {
            return reject(
                Reason::BadRequestTarget,
                "CONNECT target must be authority-form",
            );
        }
        let authority = url::parse_authority_opt(target, None)?;
        if let Some(h) = host {
            let ha = url::parse_authority(h, authority.port)?;
            if ha != authority {
                return reject(
                    Reason::HostMismatch,
                    "host does not match CONNECT authority",
                );
            }
        }
        meta.target_form = TargetForm::Authority;
        return Ok(Head::Connect {
            authority,
            headers,
            meta,
        });
    }
    if target == b"*" {
        return reject(Reason::BadRequestTarget, "asterisk-form is not supported");
    }
    let is_origin = target.starts_with(b"/");
    let (scheme, authority, path, query) = match (role, is_origin) {
        (Role::ProxyPort, false) => {
            let (scheme, authority, path, query) = url::parse_absolute_form(target)?;
            match host {
                Some(h) => {
                    let ha = url::parse_authority(h, scheme.default_port())?;
                    if ha != authority {
                        return reject(
                            Reason::HostMismatch,
                            "host does not match target authority",
                        );
                    }
                }
                None if version == Version::H1_1 => {
                    return reject(Reason::MissingHost, "no host field");
                }
                None => {}
            }
            meta.target_form = TargetForm::Absolute;
            (scheme, authority, path, query)
        }
        (Role::ProxyPort, true) => {
            let Some(h) = host else {
                return reject(Reason::MissingHost, "no host field");
            };
            let authority = url::parse_authority(h, Scheme::Http.default_port())?;
            let (path, query) = url::parse_origin_form(target)?;
            meta.target_form = TargetForm::Origin;
            (Scheme::Http, authority, path, query)
        }
        (Role::Tunnel { .. }, false) => {
            return reject(
                Reason::TargetFormMismatch,
                "only origin-form is accepted inside a tunnel",
            );
        }
        (Role::Direct { .. }, false) => {
            return reject(
                Reason::TargetFormMismatch,
                "only origin-form is accepted on a direct listener",
            );
        }
        (Role::Direct { port }, true) => {
            let Some(h) = host else {
                return reject(Reason::MissingHost, "no host field");
            };
            let authority = url::parse_authority(h, Scheme::Http.default_port())?;
            if authority.port != *port {
                return reject(
                    Reason::HostMismatch,
                    "host port does not match the listener's port",
                );
            }
            let (path, query) = url::parse_origin_form(target)?;
            meta.target_form = TargetForm::Origin;
            (Scheme::Http, authority, path, query)
        }
        (Role::Tunnel { authority, scheme }, true) => {
            let Some(h) = host else {
                return reject(Reason::MissingHost, "no host field");
            };
            let ha = url::parse_authority(h, scheme.default_port())?;
            if ha != *authority {
                return reject(Reason::HostMismatch, "host does not match tunnel authority");
            }
            let (path, query) = url::parse_origin_form(target)?;
            meta.target_form = TargetForm::Origin;
            (*scheme, authority.clone(), path, query)
        }
    };
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
        let Head::Connect { authority, meta, .. } = parse(
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic eA==\r\n\r\n",
        )
        .unwrap() else {
            panic!()
        };
        assert_eq!(authority.to_string(), "example.com:443");
        assert_eq!(meta.proxy_authorization.unwrap(), "Basic eA==");
        assert_eq!(
            parse("CONNECT example.com HTTP/1.1\r\n\r\n").unwrap_err(),
            Reason::BadAuthority
        );
        assert_eq!(
            parse("CONNECT http://example.com/ HTTP/1.1\r\n\r\n").unwrap_err(),
            Reason::BadRequestTarget
        );
    }
}
