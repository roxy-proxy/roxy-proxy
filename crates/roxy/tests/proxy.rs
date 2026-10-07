//! End-to-end smoke tests of `roxy run`: a real server from a YAML config,
//! a local TLS upstream signed by a test CA, and real clients. One or two
//! per feature, plus what needs the binary's wiring (config reload, the CA
//! endpoint, connection caps, capture to disk). Exchange
//! semantics are tested in-process in `roxy-proxy`'s testkit.

mod support;

use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use serde_json::Value;
use support::{Harness, Opts, capture_body, capture_of, raw, read_to_eof};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;

const ALLOW_UPSTREAM: &str = r#"
  - id: upstream
    when: host == "upstream.test"
    then: { allow: { private_ok: true } }
"#;

fn json(b: &[u8]) -> Value {
    serde_json::from_slice(b).unwrap_or_else(|e| {
        panic!("not JSON ({e}): {}", String::from_utf8_lossy(b));
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn allow_get_end_to_end() {
    let h = Harness::start(ALLOW_UPSTREAM).await;
    let res = h
        .client()
        .get(h.https_url("/hello?x=1"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let v = json(&res.bytes().await.unwrap());
    assert_eq!(v["path"], "/hello?x=1");
    assert_eq!(v["method"], "GET");
    let ev = h.wait_events("request", 1).await;
    assert_eq!(ev.len(), 1, "{ev:#?}");
    let e = &ev[0];
    assert_eq!(e["decision"], "allow");
    assert_eq!(e["rules"], serde_json::json!(["upstream"]));
    assert_eq!(e["terminal_rule"], "upstream");
    assert_eq!(e["res"]["status"], 200);
    assert_eq!(e["tls"]["sni"], "upstream.test");
    assert_eq!(e["req"]["query"], "x=[REDACTED]");
    assert!(e["res"]["body_bytes"].as_u64().unwrap() > 0);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn websocket_relay_echo() {
    let h = Harness::start(
        r#"
  - id: ws
    when: host == "ws.test"
    then: { allow: { upgrade: websocket, private_ok: true } }
"#,
    )
    .await;
    let port = h.upstream.ws.port();
    let tls = h
        .tls_tunnel(&format!("ws.test:{port}"), "ws.test")
        .await
        .unwrap();
    let (mut ws, resp) = tokio_tungstenite::client_async(format!("wss://ws.test:{port}/echo"), tls)
        .await
        .unwrap();
    assert_eq!(resp.status(), 101);
    ws.send(Message::text("hello through roxy")).await.unwrap();
    let back = ws.next().await.unwrap().unwrap();
    assert_eq!(back.into_text().unwrap().as_str(), "hello through roxy");
    ws.send(Message::binary(vec![7u8; 100_000])).await.unwrap();
    let back = ws.next().await.unwrap().unwrap();
    assert_eq!(back.into_data().len(), 100_000);
    ws.close(None).await.unwrap();
    drop(ws);
    h.wait_events("ws_open", 1).await;
    let close = h.wait_events("ws_close", 1).await;
    assert!(close[0]["bytes_c2s"].as_u64().unwrap() > 100_000);
    assert!(close[0]["bytes_s2c"].as_u64().unwrap() > 100_000);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn ca_certificate_endpoints() {
    let h = Harness::start("").await;
    let res = h
        .client()
        .get("http://roxy.internal/roxy-ca.pem")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.headers()["content-type"], "application/x-pem-file");
    assert_eq!(res.text().await.unwrap(), h.roxy_ca_pem);
    let res = h
        .client()
        .get("http://roxy.internal/other")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);

    let ca = h.ca_server.unwrap();
    let direct = reqwest::Client::builder().no_proxy().build().unwrap();
    let res = direct
        .get(format!("http://{ca}/healthz"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.text().await.unwrap(), "ok");
    let res = direct
        .get(format!("http://{ca}/roxy-ca.pem"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.text().await.unwrap(), h.roxy_ca_pem);
    let res = direct
        .get(format!("http://{ca}/nope"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    // Origin-form for any other host on the proxy port is refused.
    let (out, eof) = raw(h.proxy, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
    assert!(eof);
    assert!(out.starts_with("HTTP/1.1 400"), "{out}");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn hot_reload_swaps_policy_and_keeps_it_on_failure() {
    let h = Harness::start(ALLOW_UPSTREAM).await;
    let c = h.client();
    let url = h.http_url("/r");
    assert_eq!(c.get(&url).send().await.unwrap().status(), 200);

    let denied = h.render(&Opts {
        rules: r#"
  - id: now-denied
    when: host == "upstream.test"
    then: { deny: { status: 403 } }
"#,
        ..Opts::default()
    });
    std::fs::write(&h.config_path, denied).unwrap();
    h.wait_events("config_reloaded", 1).await;
    let res = c.get(&url).send().await.unwrap();
    assert_eq!(res.status(), 403);
    assert_eq!(res.headers()["x-roxy-rule"], "now-denied");

    std::fs::write(&h.config_path, "version: 1\nrules: [ {").unwrap();
    let failed = h.wait_events("config_reload_failed", 1).await;
    assert_ne!(failed[0]["diagnostics"].as_array().unwrap().len(), 0);
    let res = c.get(&url).send().await.unwrap();
    assert_eq!(
        res.status(),
        403,
        "the old policy stays after a failed reload"
    );
    assert_eq!(res.headers()["x-roxy-rule"], "now-denied");
    h.stop().await;
}

/// `upstream.dns` is read once, at start: a reload that moves a
/// `static_hosts` entry keeps the running resolver (and warns), so the name
/// still resolves to the upstream it did at start.
#[tokio::test(flavor = "multi_thread")]
async fn hot_reload_keeps_the_running_resolver() {
    let h = Harness::start(ALLOW_UPSTREAM).await;
    let c = h.client();
    let url = h.http_url("/dns");
    assert_eq!(c.get(&url).send().await.unwrap().status(), 200);

    let rendered = h.render(&Opts {
        rules: ALLOW_UPSTREAM,
        ..Opts::default()
    });
    let moved = rendered.replace("upstream.test: 127.0.0.1", "upstream.test: 127.0.0.9");
    assert_ne!(moved, rendered);
    std::fs::write(&h.config_path, moved).unwrap();
    h.wait_events("config_reloaded", 1).await;
    assert_eq!(
        c.get(&url).send().await.unwrap().status(),
        200,
        "the running resolver answers, not the file's"
    );
    h.stop().await;
}

/// A config already past `valid_until` loads and denies everything with
/// `_expired`; `roxy health` stays healthy and says so; a reload that moves
/// the lease into the future lets traffic through again.
#[tokio::test(flavor = "multi_thread")]
async fn an_expired_valid_until_loads_denies_and_recovers_on_reload() {
    let lease = |extra: &'static str| Opts {
        rules: ALLOW_UPSTREAM,
        extra,
        ..Opts::default()
    };
    let h = Harness::start_with(lease("valid_until: 2000-01-01T00:00:00Z\n")).await;
    let c = h.client();
    let url = h.https_url("/r");
    let res = c.get(&url).send().await.unwrap();
    assert_eq!(res.status(), 403);
    assert_eq!(res.headers()["x-roxy-rule"], "_expired");
    let ev = h.wait_events("request", 1).await;
    assert_eq!(ev[0]["terminal_rule"], "_expired", "{ev:#?}");
    assert_eq!(ev[0]["reason"], "policy_expired", "{ev:#?}");
    h.wait_events("policy_expired", 1).await;

    let health_url = format!("http://{}/healthz", h.ca_server.unwrap());
    let health = || {
        std::process::Command::new(env!("CARGO_BIN_EXE_roxy"))
            .args(["health", "--url", &health_url])
            .output()
            .unwrap()
    };
    let out = health();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "ok (policy expired)\n"
    );

    std::fs::write(
        &h.config_path,
        h.render(&lease("valid_until: 2999-01-01T00:00:00Z\n")),
    )
    .unwrap();
    h.wait_events("config_reloaded", 1).await;
    let res = c.get(&url).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let out = health();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "ok\n");
    h.stop().await;
}

/// `tls.require_sni_match` is read when a connection is accepted: after a
/// reload turns it off, a new tunnel completes the handshake under a
/// mismatched SNI and is served a leaf for that SNI.
#[tokio::test(flavor = "multi_thread")]
async fn hot_reload_applies_require_sni_match_to_new_connections() {
    let h = Harness::start(ALLOW_UPSTREAM).await;
    let authority = format!("upstream.test:{}", h.upstream.https.port());
    let r = h.tls_tunnel(&authority, "alias.test").await;
    assert!(r.is_err(), "TLS must not complete with a mismatched SNI");
    let ev = h.wait_events("parse_error", 1).await;
    assert_eq!(ev[0]["reason"], "sni_mismatch");

    let relaxed = h.render(&Opts {
        rules: ALLOW_UPSTREAM,
        tls: "require_sni_match: false",
        ..Opts::default()
    });
    std::fs::write(&h.config_path, relaxed).unwrap();
    h.wait_events("config_reloaded", 1).await;
    // The client verified the leaf against `alias.test`, so the handshake
    // completing is also proof of which host the leaf names.
    h.tls_tunnel(&authority, "alias.test").await.unwrap();
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn per_client_connection_cap() {
    let h = Harness::start_with(Opts {
        rules: ALLOW_UPSTREAM,
        limits: "max_connections_per_client: 2",
        ..Opts::default()
    })
    .await;
    let port = h.upstream.http.port();
    // Each holds its slot once roxy has answered a request on it.
    let mut held = Vec::new();
    for _ in 0..2 {
        let mut s = TcpStream::connect(h.proxy).await.unwrap();
        s.write_all(
            format!(
                "GET http://upstream.test:{port}/ok HTTP/1.1\r\nHost: upstream.test:{port}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut status_line = [0u8; 12];
        s.read_exact(&mut status_line).await.unwrap();
        assert_eq!(&status_line, b"HTTP/1.1 200");
        held.push(s);
    }
    let mut c = TcpStream::connect(h.proxy).await.unwrap();
    let _ = c
        .write_all(
            format!(
                "GET http://upstream.test:{port}/ HTTP/1.1\r\nHost: upstream.test:{port}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await;
    let (out, eof) = read_to_eof(&mut c).await;
    assert!(eof);
    assert_eq!(out.len(), 0);
    let ev = h.wait_events("connection_refused", 1).await;
    assert_eq!(ev[0]["reason"], "max_connections_per_client");
    // Slots free up when connections close.
    drop(held);
    let client = h.client();
    let mut status = None;
    for _ in 0..100 {
        if let Ok(res) = client.get(h.http_url("/ok")).send().await {
            status = Some(res.status());
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(status, Some(reqwest::StatusCode::OK), "a slot never freed");
    h.stop().await;
}

const RATE_LIMITED: &str = r#"
  - id: burst
    when: host == "upstream.test" and metric.hits >= 3
    then: { deny: { status: 429, close: false } }
  - id: upstream
    when: host == "upstream.test"
    then: { allow: { private_ok: true } }
"#;

const HITS_METRIC: &str = r#"metrics:
  - id: hits
    count: requests
    where: host == "upstream.test"
    key: [client.ip]
    window: 1h
"#;

/// The built-in metric store enforces a rate limit end to end, and an
/// unrelated config edit (hot reload) does not reset the counter.
#[tokio::test(flavor = "multi_thread")]
async fn builtin_metric_store_rate_limits_and_survives_reload() {
    let h = Harness::start_with(Opts {
        rules: RATE_LIMITED,
        extra: HITS_METRIC,
        ..Opts::default()
    })
    .await;
    let c = h.client();
    let url = h.http_url("/m");
    for i in 0..3 {
        assert_eq!(
            c.get(&url).send().await.unwrap().status(),
            200,
            "request {i}"
        );
    }
    let res = c.get(&url).send().await.unwrap();
    assert_eq!(res.status(), 429, "the 4th request is over the limit");
    assert_eq!(res.headers()["x-roxy-rule"], "burst");

    // Reload with an extra, unrelated rule; the `hits` definition is unchanged.
    let edited = h.render(&Opts {
        rules: &format!(
            "{RATE_LIMITED}  - id: unrelated\n    when: host == \"nowhere.test\"\n    then: deny\n"
        ),
        extra: HITS_METRIC,
        ..Opts::default()
    });
    std::fs::write(&h.config_path, edited).unwrap();
    h.wait_events("config_reloaded", 1).await;
    let res = c.get(&url).send().await.unwrap();
    assert_eq!(res.status(), 429, "the counter survived the reload");
    h.stop().await;
}

// ----- address lists ----------------------

/// Editing a deny-list file reloads it: a pooled upstream connection that
/// served the previous request is not reused once the address is listed.
/// A malformed list file fails the reload and the old lists stay.
#[tokio::test(flavor = "multi_thread")]
async fn deny_list_file_reload_flips_allow_to_deny_and_keeps_old_lists_on_failure() {
    let lists = tempfile::tempdir().unwrap();
    let file = lists.path().join("blocked.txt");
    std::fs::write(&file, "# nothing local yet\n192.0.2.0/24\n").unwrap();
    let extra = format!(
        "address_lists:\n  - {{ name: blocked, file: {} }}\n",
        file.display()
    );
    let h = Harness::start_with(Opts {
        rules: ALLOW_UPSTREAM,
        extra: &extra,
        upstream: "deny_lists: [blocked]",
        ..Opts::default()
    })
    .await;
    let c = h.client();
    let url = h.http_url("/pooled");
    for _ in 0..3 {
        assert_eq!(c.get(&url).send().await.unwrap().status(), 200);
    }
    let served = h.upstream.seen().len();

    std::fs::write(&file, "192.0.2.0/24\n127.0.0.0/8 # now listed\n").unwrap();
    h.wait_events("config_reloaded", 1).await;
    let res = c.get(&url).send().await.unwrap();
    assert_eq!(res.status(), 403);
    assert_eq!(res.headers()["x-roxy-rule"], "_address_policy");
    let ev = h.wait_events("upstream_denied", 1).await;
    assert_eq!(ev[0]["list"], "blocked");
    assert_eq!(ev[0]["matched_cidr"], "127.0.0.0/8");
    assert_eq!(
        h.upstream.seen().len(),
        served,
        "the pooled connection was not used"
    );

    std::fs::write(&file, "127.0.0.0/8\n10.0.0.1/8\n").unwrap();
    let failed = h.wait_events("config_reload_failed", 1).await;
    let diags = failed[0]["diagnostics"].to_string();
    assert!(
        diags.contains(&format!("{}:2:", file.display())) && diags.contains("host bits"),
        "{diags}"
    );
    let res = c.get(&url).send().await.unwrap();
    assert_eq!(
        res.status(),
        403,
        "the old list stays after a failed reload"
    );
    assert_eq!(res.headers()["x-roxy-rule"], "_address_policy");

    // An emptied list (a valid file) allows again.
    std::fs::write(&file, "# cleared\n").unwrap();
    h.wait_events("config_reloaded", 2).await;
    assert_eq!(c.get(&url).send().await.unwrap().status(), 200);
    h.stop().await;
}

// ---------------------------------------------------------------------------
// Client-side HTTP/2
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn h2_allow_get_end_to_end() {
    let h = Harness::start(ALLOW_UPSTREAM).await;
    let res = h
        .client()
        .get(h.https_url("/hello?x=1"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.version(), reqwest::Version::HTTP_2);
    assert_eq!(res.status(), 200);
    let v = json(&res.bytes().await.unwrap());
    assert_eq!(v["path"], "/hello?x=1");
    assert_eq!(v["method"], "GET");
    let ev = h.wait_events("request", 1).await;
    let e = &ev[0];
    assert_eq!(e["decision"], "allow");
    assert_eq!(e["terminal_rule"], "upstream");
    assert_eq!(e["tls"]["alpn"], "h2");
    assert_eq!(e["tls"]["sni"], "upstream.test");
    assert_eq!(e["res"]["status"], 200);
    assert!(e["res"]["body_bytes"].as_u64().unwrap() > 0);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn h2_disabled_offers_http11_only() {
    let h = Harness::start_with(Opts {
        rules: ALLOW_UPSTREAM,
        http: "enable_h2: false",
        ..Opts::default()
    })
    .await;
    let authority = format!("upstream.test:{}", h.upstream.https.port());
    let tls = h
        .tls_tunnel_alpn(&authority, "upstream.test", &[b"h2", b"http/1.1"])
        .await
        .unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
    drop(tls);
    let res = h.client().get(h.https_url("/h1")).send().await.unwrap();
    assert_eq!(res.version(), reqwest::Version::HTTP_11);
    assert_eq!(res.status(), 200);
    let ev = h.wait_events("request", 1).await;
    assert_eq!(ev[0]["tls"]["alpn"], "http/1.1");
    h.stop().await;
}

// ----- capture ----------------------------------

fn flow_of(ev: &[Value], path: &str) -> String {
    ev.iter()
        .find(|e| e["req"]["path"] == path)
        .unwrap_or_else(|| panic!("no request event for {path}"))["flow"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// Past `limits.max_capture_body_bytes` capture records `truncated` and the
/// end still carries the full forwarded byte count; forwarding is unaffected.
#[tokio::test(flavor = "multi_thread")]
async fn capture_cap_truncates_explicitly() {
    let h = Harness::start_with(Opts {
        rules: ALLOW_UPSTREAM,
        capture: Some("all: true"),
        limits: "max_capture_body_bytes: 1kb",
        ..Opts::default()
    })
    .await;
    let res = h
        .client()
        .post(h.http_url("/capped"))
        .body(vec![b'z'; 10_000])
        .send()
        .await
        .unwrap();
    assert_eq!(json(&res.bytes().await.unwrap())["body_len"], 10_000);
    let ev = h.wait_events("request", 1).await;
    let records = h.captured();
    let req = capture_of(&records, &flow_of(&ev, "/capped"), "request");
    assert_eq!(capture_body(&req).len(), 1024);
    let kinds: Vec<&str> = req
        .iter()
        .map(|(h, _)| h["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"truncated"), "{kinds:?}");
    assert_eq!(req.last().unwrap().0["bytes"], 10_000);
    h.stop().await;
}

/// A capture destination that cannot keep up holds traffic back instead of
/// dropping captured bytes: `capture.rxc` is a FIFO whose reader does not
/// read until the test lets it.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_capture_log_holds_traffic() {
    use std::io::Read;
    let fifo_dir = tempfile::tempdir().unwrap();
    let fifo = fifo_dir.path().join("capture.rxc");
    let made = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(made.success(), "mkfifo");
    // The reader opens the FIFO (pairing with roxy's writer), then waits
    // for the go signal before draining it.
    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    let (seen_tx, seen_rx) = std::sync::mpsc::channel::<usize>();
    std::thread::spawn(move || {
        let mut f = std::fs::File::open(&fifo).unwrap();
        go_rx.recv().unwrap();
        let mut buf = vec![0u8; 1 << 16];
        let mut total = 0usize;
        let mut reported = false;
        // Report once the whole upload has come through, then keep
        // draining until the writer closes (at shutdown).
        loop {
            match f.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => total += n,
            }
            if !reported && total > 1 << 20 {
                reported = true;
                let _ = seen_tx.send(total);
            }
        }
    });
    let h = Harness::start_with(Opts {
        rules: ALLOW_UPSTREAM,
        capture: Some("all: true\nhigh_water: 64kb"),
        capture_dir: Some(fifo_dir.path()),
        ..Opts::default()
    })
    .await;
    // 1 MiB: far more than the pipe buffer plus the high-water mark.
    let c = h.client();
    let url = h.http_url("/held");
    let req = tokio::spawn(async move {
        c.post(url)
            .body(vec![b'p'; 1 << 20])
            .send()
            .await
            .map(|r| r.status())
    });
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert!(
        !req.is_finished(),
        "traffic moved while capture was stalled"
    );
    go_tx.send(()).unwrap();
    let status = tokio::time::timeout(Duration::from_secs(20), req)
        .await
        .expect("traffic resumes once capture catches up")
        .unwrap()
        .unwrap();
    assert_eq!(status, 200);
    let seen = seen_rx
        .recv_timeout(Duration::from_secs(20))
        .expect("the whole upload was captured");
    assert!(seen > 1 << 20);
    h.stop().await;
}
