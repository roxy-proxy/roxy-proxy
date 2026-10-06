//! Direct listeners: the client connects as
//! if to the origin, and roxy takes the target from the SNI or `Host`.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{Answer, Kit};

const RULES: &str = r#"
- id: direct-only
  when: listener.mode == "direct" and path starts_with "/explicit-only"
  then: deny
- id: up
  when: host == "up.test"
  then: allow
"#;

async fn kit() -> Kit {
    Kit::builder().rules(RULES).start().await
}

/// Reads until the peer closes.
async fn read_to_end(io: &mut tokio::io::DuplexStream) -> String {
    let mut out = Vec::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(10), io.read_to_end(&mut out))
        .await
        .expect("the connection closes");
    String::from_utf8_lossy(&out).into_owned()
}

#[tokio::test]
async fn tls_is_routed_by_sni() {
    for h2 in [false, true] {
        let kit = kit().await;
        let a = kit
            .direct_tls("up.test", h2)
            .await
            .call("GET", "/x?q=1", &[], b"")
            .await;
        assert_eq!(a.status, 200, "h2={h2}: {a:?}");
        let seen = kit.upstream.wait_seen(1).await;
        assert_eq!(seen[0].addr.port(), 443);
        assert_eq!(seen[0].path, "/x?q=1");
        let ev = kit.request_event().await;
        assert_eq!(ev["decision"], "allow", "{ev:#}");
        assert_eq!(ev["listener"], "direct");
        assert_eq!(ev["tls"]["sni"], "up.test");
        assert_eq!(ev["req"]["host"], "up.test");
        assert_eq!(ev["req"]["port"], 443);
    }
}

#[tokio::test]
async fn plaintext_is_routed_by_host() {
    let kit = kit().await;
    let a = kit
        .direct_plain("up.test")
        .await
        .call("POST", "/p", &[], b"body")
        .await;
    assert_eq!(a.status, 200, "{a:?}");
    let seen = kit.upstream.wait_seen(1).await;
    assert_eq!(seen[0].addr.port(), 80);
    assert_eq!(seen[0].body, b"body");
    let ev = kit.request_event().await;
    assert_eq!(ev["decision"], "allow", "{ev:#}");
    assert_eq!(ev["req"]["host"], "up.test");
    assert_eq!(ev["req"]["port"], 80);
    assert!(ev["tls"].is_null(), "{ev:#}");
}

#[tokio::test]
async fn rules_see_the_direct_mode() {
    let kit = kit().await;
    let a = kit
        .direct_tls("up.test", false)
        .await
        .call("GET", "/explicit-only", &[], b"")
        .await;
    assert_eq!(a.status, 403, "{a:?}");
    assert_eq!(kit.request_event().await["terminal_rule"], "direct-only");
    // The same request through the explicit proxy is allowed.
    let a = kit
        .tunnel("up.test", false)
        .await
        .call("GET", "/explicit-only", &[], b"")
        .await;
    assert_eq!(a.status, 200, "{a:?}");
}

#[tokio::test]
async fn the_host_must_match_the_sni() {
    let kit = kit().await;
    let mut c = kit.direct_tls("up.test", false).await;
    let req = http::Request::builder()
        .uri("/")
        .header("host", "other.test")
        .body(roxy_http::Body::empty())
        .unwrap();
    let res = c.send(req).await;
    let failed = res.map_or(true, |r| r.status() == 400);
    assert!(failed, "a mismatched Host is refused");
    let ev = kit.events("parse_error", 1).await;
    assert_eq!(ev[0]["reason"], "host_mismatch", "{ev:#?}");
    assert!(kit.upstream.seen().is_empty());
}

#[tokio::test]
async fn a_plaintext_host_port_must_be_the_listeners() {
    let kit = kit().await;
    let mut io = kit.connect_direct(80);
    io.write_all(b"GET / HTTP/1.1\r\nhost: up.test:8080\r\n\r\n")
        .await
        .unwrap();
    let out = read_to_end(&mut io).await;
    assert!(out.starts_with("HTTP/1.1 400"), "{out}");
    let ev = kit.events("parse_error", 1).await;
    assert_eq!(ev[0]["reason"], "host_mismatch", "{ev:#?}");
    assert!(kit.upstream.seen().is_empty());
}

#[tokio::test]
async fn a_request_line_in_pieces_is_still_http() {
    let kit = kit().await;
    let mut io = kit.connect_direct(80);
    io.write_all(b"G").await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    io.write_all(b"ET / HTTP/1.1\r\nhost: up.test\r\nconnection: close\r\n\r\n")
        .await
        .unwrap();
    let out = read_to_end(&mut io).await;
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
}

#[tokio::test]
async fn tls_without_sni_is_closed() {
    let kit = kit().await;
    let mut cfg = kit.client_tls();
    cfg.enable_sni = false;
    let name = roxy_tls::server_name(&roxy_http::url::parse_host(b"up.test").unwrap());
    let res = tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(name, kit.connect_direct(443))
        .await;
    assert!(res.is_err(), "the handshake fails");
    let ev = kit.events("parse_error", 1).await;
    assert_eq!(ev[0]["reason"], "no_sni", "{ev:#?}");
}

#[tokio::test]
async fn anything_else_is_closed() {
    let kit = kit().await;
    let mut io = kit.connect_direct(443);
    io.write_all(b"\x00\x01binary junk\r\n\r\n").await.unwrap();
    assert_eq!(read_to_end(&mut io).await, "");
    let ev = kit.events("parse_error", 1).await;
    assert_eq!(ev[0]["reason"], "non_http_on_direct", "{ev:#?}");
}

#[tokio::test]
async fn roxy_internal_serves_the_ca_over_plaintext() {
    let kit = kit().await;
    let a: Answer = kit
        .direct_plain("roxy.internal")
        .await
        .call("GET", "/roxy-ca.pem", &[], b"")
        .await;
    assert_eq!(a.status, 200, "{a:?}");
    assert!(a.text().starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(kit.upstream.seen().is_empty());
}

/// The SNI is a name: case does not matter, and the leaf, the routing and
/// the log all use the lower-case form.
#[tokio::test]
async fn an_upper_case_sni_is_the_same_host() {
    let kit = kit().await;
    let mut cfg = kit.client_tls();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let name = rustls::pki_types::ServerName::try_from("UP.TEST".to_owned()).unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(name, kit.connect_direct(443))
        .await
        .expect("the handshake completes");
    tls.write_all(b"GET /u HTTP/1.1\r\nhost: UP.TEST\r\n\r\n")
        .await
        .unwrap();
    let (head, _) = super::read_response(&mut tls).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let ev = kit.request_event().await;
    assert_eq!(ev["tls"]["sni"], "up.test", "{ev:#}");
    assert_eq!(ev["req"]["host"], "up.test", "{ev:#}");
}

/// A client that connected to an IP sends no SNI, and there is no other
/// way to learn the host: closed as `no_sni`, never forwarded.
#[tokio::test]
async fn an_ip_target_has_no_sni_and_is_closed() {
    let kit = kit().await;
    let name = roxy_tls::server_name(&roxy_http::url::parse_host(super::UP_IP.as_bytes()).unwrap());
    let res = tokio_rustls::TlsConnector::from(Arc::new(kit.client_tls()))
        .connect(name, kit.connect_direct(443))
        .await;
    assert!(res.is_err(), "the handshake fails");
    let ev = kit.events("parse_error", 1).await;
    assert_eq!(ev[0]["reason"], "no_sni", "{ev:#?}");
    assert!(kit.upstream.seen().is_empty());
}

/// An SNI carrying a port is not a host name: the listener refuses it as
/// `bad_sni` before rustls sees the hello, and nothing is forwarded. No
/// rustls client sends one, so the hello is a real one with the name
/// patched in place.
#[tokio::test]
async fn an_sni_with_a_port_is_closed() {
    let kit = kit().await;
    let (mut ours, theirs) = tokio::io::duplex(64 * 1024);
    let cfg = Arc::new(kit.client_tls());
    let name =
        roxy_tls::server_name(&roxy_http::url::parse_host("up.testx443".as_bytes()).unwrap());
    let hs = tokio::spawn(async move {
        tokio_rustls::TlsConnector::from(cfg)
            .connect(name, theirs)
            .await
    });
    let mut hello = vec![0u8; 16 * 1024];
    let n = ours.read(&mut hello).await.unwrap();
    hello.truncate(n);
    let at = hello
        .windows(11)
        .position(|w| w == b"up.testx443")
        .expect("the SNI is in the hello");
    hello[at..at + 11].copy_from_slice(b"up.test:443");
    let mut io = kit.connect_direct(443);
    io.write_all(&hello).await.unwrap();
    let out = read_to_end(&mut io).await;
    hs.abort();
    // The SNI is parsed as a bare host (`parse_host`), which `:443` is
    // not, so the connection is closed before the handshake starts:
    // nothing, not even a TLS alert, comes back.
    assert!(out.is_empty(), "{out:?}");
    let ev = kit.events("parse_error", 1).await;
    assert_eq!(ev[0]["reason"], "bad_sni", "{ev:#?}");
    assert_eq!(ev[0]["detail"], "up.test:443", "{ev:#?}");
    assert!(kit.upstream.seen().is_empty());
}
