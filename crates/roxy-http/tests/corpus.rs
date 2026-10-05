//! Smuggling / strictness corpus runner.
//!
//! Every file in `tests/corpus/*.txt` holds cases of the form:
//!
//! ```text
//! === case_name
//! # comment
//! role: proxy | tunnel <http|https> <host:port> | direct <port>
//! flags: allow_http10 allow_trailers ...
//! limits: max_headers=5 max_header_bytes=300 ...
//! expect: request <METHOD> <url> [body=<escaped>] [hdr:<name>=<value>] [nohdr:<name>]
//! expect: origin <METHOD> <url>          (origin-form on the proxy port)
//! expect: connect <host:port> [leftover=<escaped>]
//! expect: error <reason_code>            (from next_request)
//! expect: body-error <reason_code>       (request head ok, body rejected)
//! expect: eof                            (next_request returns None)
//! ---
//! raw request bytes, physical newlines ignored, escapes:
//! \r \n \t \s (space) \0 \\ \xNN, and \{N:text} = text repeated N times
//! ```
//!
//! `expect:` lines are checked in order against successive requests on one
//! connection; the client half-closes after sending the raw bytes. A
//! `request` line with a body expectation drains the body through
//! `ServerConn::drive`; the server then answers `200` before reading the next
//! request.

#![allow(clippy::too_many_lines, clippy::many_single_char_names)]

use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::Arc;

use roxy_http::h1::{Incoming, Role, ServerConn};
use roxy_http::url::parse_authority;
use roxy_http::{Body, CanonicalResponse, DriveError, HttpFlags, Limits, Reason, Scheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug)]
struct Case {
    file: String,
    name: String,
    role: Role,
    flags: HttpFlags,
    limits: Limits,
    expects: Vec<String>,
    raw: Vec<u8>,
}

fn unescape(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'\\' {
            out.push(b[i]);
            i += 1;
            continue;
        }
        let c = b[i + 1];
        i += 2;
        match c {
            b'r' => out.push(b'\r'),
            b'n' => out.push(b'\n'),
            b't' => out.push(b'\t'),
            b's' => out.push(b' '),
            b'0' => out.push(0),
            b'\\' => out.push(b'\\'),
            b'x' => {
                let hex = std::str::from_utf8(&b[i..i + 2]).unwrap();
                out.push(u8::from_str_radix(hex, 16).unwrap());
                i += 2;
            }
            b'{' => {
                let end = i + b[i..].iter().position(|&x| x == b'}').unwrap();
                let inner = std::str::from_utf8(&b[i..end]).unwrap();
                let (n, text) = inner.split_once(':').unwrap();
                for _ in 0..n.parse::<usize>().unwrap() {
                    out.extend_from_slice(text.as_bytes());
                }
                i = end + 1;
            }
            other => panic!("unknown escape \\{}", other as char),
        }
    }
    out
}

fn parse_cases(file: &str, text: &str) -> Vec<Case> {
    // Split into (name, meta lines, raw lines) blocks.
    let mut blocks: Vec<(String, Vec<&str>, Vec<&str>, bool)> = Vec::new();
    for line in text.lines() {
        if let Some(name) = line.strip_prefix("=== ") {
            blocks.push((name.trim().to_owned(), Vec::new(), Vec::new(), false));
            continue;
        }
        let Some(block) = blocks.last_mut() else {
            continue;
        };
        if !block.3 && line.trim() == "---" {
            block.3 = true;
        } else if block.3 {
            block.2.push(line);
        } else {
            block.1.push(line);
        }
    }
    let mut cases = Vec::new();
    for (name, meta, raw, has_raw) in blocks {
        assert!(has_raw, "{file}/{name}: case without ---");
        let mut case = Case {
            file: file.to_owned(),
            name,
            role: Role::ProxyPort,
            flags: HttpFlags::default(),
            limits: Limits::default(),
            expects: Vec::new(),
            raw: Vec::new(),
        };
        for line in meta {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (k, v) = line.split_once(':').unwrap();
            let v = v.trim();
            match k {
                "role" => {
                    let parts: Vec<_> = v.split_whitespace().collect();
                    case.role = match parts.as_slice() {
                        ["proxy"] => Role::ProxyPort,
                        ["tunnel", scheme, auth] => {
                            let scheme = if *scheme == "https" {
                                Scheme::Https
                            } else {
                                Scheme::Http
                            };
                            Role::Tunnel {
                                authority: parse_authority(auth.as_bytes(), scheme.default_port())
                                    .unwrap(),
                                scheme,
                            }
                        }
                        ["direct", port] => Role::Direct {
                            port: port.parse().unwrap(),
                        },
                        _ => panic!("bad role {v}"),
                    }
                }
                "flags" => {
                    for f in v.split_whitespace() {
                        match f {
                            "allow_http10" => case.flags.allow_http10 = true,
                            "allow_trailers" => case.flags.allow_trailers = true,
                            "allow_chunk_extensions" => case.flags.allow_chunk_extensions = true,
                            "allow_obs_text" => case.flags.allow_obs_text = true,
                            "allow_body_on_get" => case.flags.allow_body_on_get = true,
                            _ => panic!("unknown flag {f}"),
                        }
                    }
                }
                "limits" => {
                    for kv in v.split_whitespace() {
                        let (k, n) = kv.split_once('=').unwrap();
                        let n: u64 = n.parse().unwrap();
                        let u = usize::try_from(n).unwrap();
                        match k {
                            "max_headers" => case.limits.max_headers = u,
                            "max_header_bytes" => case.limits.max_header_bytes = u,
                            "max_url_bytes" => case.limits.max_url_bytes = u,
                            "max_request_body_bytes" => case.limits.max_request_body_bytes = n,
                            _ => panic!("unknown limit {k}"),
                        }
                    }
                }
                "expect" => case.expects.push(v.to_owned()),
                _ => panic!("{file}: unknown key {k}"),
            }
        }
        let joined: String = raw.iter().map(|l| l.trim_end()).collect();
        case.raw = unescape(&joined);
        assert!(
            !case.expects.is_empty(),
            "{file}/{}: no expectations",
            case.name
        );
        cases.push(case);
    }
    cases
}

fn code(r: Reason) -> &'static str {
    r.as_str()
}

/// Runs one case; returns a description of the first mismatch.
async fn run_case(case: &Case) -> Result<(), String> {
    let (mut client, server) = tokio::io::duplex(1 << 20);
    let raw = case.raw.clone();
    let writer = tokio::spawn(async move {
        let _ = client.write_all(&raw).await;
        let _ = client.shutdown().await;
        let mut sink = Vec::new();
        let _ = client.read_to_end(&mut sink).await;
        sink
    });
    let mut conn = ServerConn::new(
        server,
        case.role.clone(),
        Arc::new(case.limits.clone()),
        Arc::new(case.flags.clone()),
    );
    for (idx, exp) in case.expects.iter().enumerate() {
        let mut words = exp.split_whitespace();
        let kind = words.next().unwrap();
        let rest: Vec<&str> = words.collect();
        let got = conn.next_request().await;
        let ctx = format!("expectation #{idx} `{exp}`");
        match (kind, got) {
            ("error", Err(e)) => {
                if code(e.reason) != rest[0] {
                    return Err(format!("{ctx}: got error {} ({})", e.reason, e.detail));
                }
                return Ok(());
            }
            ("eof", Ok(None)) => {}
            ("connect", Ok(Some(Incoming::Connect { authority, .. }))) => {
                if authority.to_string() != rest[0] {
                    return Err(format!("{ctx}: got CONNECT {authority}"));
                }
                if let Some(l) = rest.iter().find_map(|w| w.strip_prefix("leftover=")) {
                    let (_, leftover) = conn.accept_connect().await.map_err(|e| e.to_string())?;
                    if leftover[..] != unescape(l)[..] {
                        return Err(format!("{ctx}: leftover {leftover:?}"));
                    }
                    return Ok(());
                }
                conn.respond(CanonicalResponse::new(http::StatusCode::FORBIDDEN))
                    .await
                    .map_err(|e| format!("{ctx}: respond: {e}"))?;
            }
            (
                "request" | "origin" | "body-error",
                Ok(Some(inc @ (Incoming::Request(_) | Incoming::OriginFormOnProxyPort(_)))),
            ) => {
                let (is_origin, mut req) = match inc {
                    Incoming::Request(r) => (false, r),
                    Incoming::OriginFormOnProxyPort(r) => (true, r),
                    Incoming::Connect { .. } => unreachable!(),
                };
                if (kind == "origin") != is_origin {
                    return Err(format!(
                        "{ctx}: origin-form mismatch (got origin={is_origin})"
                    ));
                }
                if kind == "body-error" {
                    let body = std::mem::take(&mut req.body);
                    match conn.drive(body.collect_up_to(u64::MAX)).await {
                        Err(DriveError::Client(e)) if code(e.reason) == rest[0] => return Ok(()),
                        Err(DriveError::Client(e)) => {
                            return Err(format!("{ctx}: body error {} ({})", e.reason, e.detail));
                        }
                        Err(e @ DriveError::Write(_)) => return Err(format!("{ctx}: {e}")),
                        Ok(r) => return Err(format!("{ctx}: body completed: {r:?}")),
                    }
                }
                if req.method.as_str() != rest[0] || req.url() != rest[1] {
                    return Err(format!("{ctx}: got {} {}", req.method, req.url()));
                }
                for w in &rest[2..] {
                    if let Some(b) = w.strip_prefix("body=") {
                        let body = std::mem::take(&mut req.body);
                        let got = conn
                            .drive(body.collect_up_to(u64::MAX))
                            .await
                            .map_err(|e| format!("{ctx}: body: {e}"))?
                            .map_err(|e| format!("{ctx}: body: {e}"))?;
                        if got[..] != unescape(b)[..] {
                            return Err(format!("{ctx}: body {got:?}"));
                        }
                    } else if let Some(h) = w.strip_prefix("hdr:") {
                        let (n, v) = h.split_once('=').unwrap();
                        let v = String::from_utf8(unescape(v)).unwrap();
                        if req.headers.get(n) != Some(v.as_str()) {
                            return Err(format!("{ctx}: header {n} = {:?}", req.headers.get(n)));
                        }
                    } else if let Some(n) = w.strip_prefix("nohdr:") {
                        if req.headers.contains(n) {
                            return Err(format!("{ctx}: header {n} present"));
                        }
                    } else {
                        panic!("unknown request word {w}");
                    }
                }
                drop(req);
                let mut res = CanonicalResponse::new(http::StatusCode::OK);
                res.body = Body::from_bytes("ok");
                conn.respond(res)
                    .await
                    .map_err(|e| format!("{ctx}: respond: {e}"))?;
            }
            (_, got) => {
                let desc = match got {
                    Ok(None) => "eof".to_owned(),
                    Ok(Some(Incoming::Request(r))) => format!("request {} {}", r.method, r.url()),
                    Ok(Some(Incoming::OriginFormOnProxyPort(r))) => {
                        format!("origin {} {}", r.method, r.url())
                    }
                    Ok(Some(Incoming::Connect { authority, .. })) => format!("connect {authority}"),
                    Err(e) => format!("error {} ({})", e.reason, e.detail),
                };
                return Err(format!("{ctx}: got {desc}"));
            }
        }
    }
    drop(conn);
    let _ = writer.await;
    Ok(())
}

#[tokio::test]
async fn smuggling_corpus() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "txt"))
        .collect();
    files.sort();
    let mut total = 0;
    let mut failures = String::new();
    let mut seen_codes = std::collections::BTreeSet::new();
    for f in &files {
        let text = std::fs::read_to_string(f).unwrap().replace("\r\n", "\n");
        let name = f.file_name().unwrap().to_string_lossy().into_owned();
        for case in parse_cases(&name, &text) {
            total += 1;
            for e in &case.expects {
                if let Some(c) = e
                    .strip_prefix("error ")
                    .or_else(|| e.strip_prefix("body-error "))
                {
                    assert!(
                        Reason::from_code(c.trim()).is_some(),
                        "{}/{}: unknown reason code {c}",
                        case.file,
                        case.name
                    );
                    seen_codes.insert(c.trim().to_owned());
                }
            }
            if let Err(msg) = run_case(&case).await {
                let _ = writeln!(failures, "{}/{}: {msg}", case.file, case.name);
            }
        }
    }
    assert!(total >= 80, "corpus too small: {total} cases");
    assert!(failures.is_empty(), "corpus failures:\n{failures}");
    println!("{total} corpus cases passed; reason codes covered: {seen_codes:?}");
}
