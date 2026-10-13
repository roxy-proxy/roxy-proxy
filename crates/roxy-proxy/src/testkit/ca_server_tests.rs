//! The plain-HTTP CA endpoint (`ca_server.bind`).

use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpStream;

use super::{Kit, read_response, read_to_eof};

async fn fetch(kit: &Kit, request: &str) -> (String, Vec<u8>, bool) {
    let mut io = TcpStream::connect(kit.ca_server_addr()).await.unwrap();
    io.write_all(request.as_bytes()).await.unwrap();
    let (head, body) = read_response(&mut io).await;
    let (rest, eof) = read_to_eof(&mut io).await;
    assert!(rest.is_empty(), "{}", String::from_utf8_lossy(&rest));
    (head, body, eof)
}

/// `GET /roxy-ca.pem` is the CA certificate and nothing else is served:
/// not the key, not any other method. Each connection carries one
/// response and is then closed, so a client cannot hold the endpoint open.
#[tokio::test]
async fn serves_the_certificate_once_per_connection_and_nothing_else() {
    let kit = Kit::builder().ca_server().start().await;
    let (head, body, eof) = fetch(&kit, "GET /roxy-ca.pem HTTP/1.1\r\nhost: roxy\r\n\r\n").await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(
        head.to_ascii_lowercase().contains(&format!(
            "content-type: {}",
            crate::ca_server::PEM_CONTENT_TYPE
        )),
        "{head}"
    );
    assert_eq!(String::from_utf8(body).unwrap(), kit.ca_pem());
    assert!(eof, "the connection closes after one response");

    for req in [
        "POST /roxy-ca.pem HTTP/1.1\r\nhost: roxy\r\ncontent-length: 0\r\n\r\n",
        "GET /roxy-ca.key HTTP/1.1\r\nhost: roxy\r\n\r\n",
    ] {
        let (head, body, eof) = fetch(&kit, req).await;
        assert!(head.starts_with("HTTP/1.1 404"), "{req}: {head}");
        assert!(!body.windows(5).any(|w| w == b"BEGIN"), "{req}");
        assert!(eof, "{req}");
    }
}

/// `/healthz` is liveness: it stays `200` when the policy's lease has run
/// out, and says so in `x-roxy-policy`.
#[tokio::test]
async fn healthz_reports_the_lease_state() {
    let kit = Kit::builder().ca_server().start().await;
    let probe = "GET /healthz HTTP/1.1\r\nhost: roxy\r\n\r\n";
    let (head, body, _) = fetch(&kit, probe).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(
        head.to_ascii_lowercase().contains("x-roxy-policy: valid"),
        "{head}"
    );
    assert_eq!(body, b"ok");

    kit.reload_lease(
        super::ALLOW_UP,
        Some(chrono::Utc::now() - chrono::TimeDelta::seconds(1)),
    );
    let (head, body, _) = fetch(&kit, probe).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(
        head.to_ascii_lowercase().contains("x-roxy-policy: expired"),
        "{head}"
    );
    assert_eq!(body, b"ok");
    kit.events("policy_expired", 1).await;
}

/// `/readyz` is `200` once a policy has been applied and its lease has
/// not run out, and `503` with the reason otherwise; `/healthz` is `200`
/// throughout. The startup placeholder is `no_policy`; an empty policy is
/// a deny-all someone applied, so it is ready.
#[tokio::test]
async fn readiness_follows_the_applied_policy_and_liveness_does_not() {
    let kit = Kit::builder()
        .placeholder_policy()
        .ca_server()
        .start()
        .await;
    let readyz = "GET /readyz HTTP/1.1\r\nhost: roxy\r\n\r\n";
    let healthz = "GET /healthz HTTP/1.1\r\nhost: roxy\r\n\r\n";
    let (head, body, _) = fetch(&kit, readyz).await;
    assert!(head.starts_with("HTTP/1.1 503"), "{head}");
    assert_eq!(body, b"no_policy");
    let (head, _, _) = fetch(&kit, healthz).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");

    kit.reload("[]");
    let (head, body, eof) = fetch(&kit, readyz).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body, b"ready");
    assert!(eof);

    kit.reload_lease(
        super::ALLOW_UP,
        Some(chrono::Utc::now() - chrono::TimeDelta::seconds(1)),
    );
    let (head, body, _) = fetch(&kit, readyz).await;
    assert!(head.starts_with("HTTP/1.1 503"), "{head}");
    assert_eq!(body, b"policy_expired");
    let (head, _, _) = fetch(&kit, healthz).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");

    kit.reload_lease(
        super::ALLOW_UP,
        Some(chrono::Utc::now() + chrono::TimeDelta::hours(1)),
    );
    let (head, body, _) = fetch(&kit, readyz).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body, b"ready");
}
