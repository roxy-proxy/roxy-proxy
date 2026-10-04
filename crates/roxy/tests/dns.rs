//! End-to-end tests of DNS steering: `roxy run` with a DNS
//! listener and a direct listener, queried and used by real clients.

mod support;

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use support::{Harness, Opts, read_response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const RULES: &str = r#"
  - id: upstream
    when: host == "upstream.test" and listener.mode == "direct"
    then: { allow: { private_ok: true } }
"#;

async fn start() -> Harness {
    Harness::start_with(Opts {
        rules: RULES,
        listeners: "  - { name: direct, mode: direct, bind: 127.0.0.1:0, target_port: {HTTPS} }\n",
        extra: "dns:\n  bind: 127.0.0.1:0\n  answer: { ipv4: 127.0.0.1 }\n  ttl: 30s\n",
        flow_log: "dns_events: true",
        ..Opts::default()
    })
    .await
}

fn dns_addr(h: &Harness) -> SocketAddr {
    h.running.as_ref().unwrap().server.dns_addr().unwrap()
}

fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut m = id.to_be_bytes().to_vec();
    m.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for l in name.split('.') {
        m.push(u8::try_from(l.len()).unwrap());
        m.extend_from_slice(l.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&[0, 1]);
    m
}

/// The IPv4 addresses in an answer to `query` (one question, answers
/// pointing back at it).
fn a_records(query: &[u8], answer: &[u8]) -> Vec<Ipv4Addr> {
    assert_eq!(answer[..2], query[..2], "id");
    assert_eq!(answer[3] & 0xf, 0, "rcode");
    let count = u16::from_be_bytes([answer[6], answer[7]]);
    let mut at = query.len();
    let mut out = Vec::new();
    for _ in 0..count {
        let len = usize::from(u16::from_be_bytes([answer[at + 10], answer[at + 11]]));
        let rdata = &answer[at + 12..at + 12 + len];
        out.push(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]));
        at += 12 + len;
    }
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn dns_answers_over_udp_and_tcp() {
    let h = start().await;
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // Every name gets roxy's address, whether or not a rule would allow a
    // request to it: the rules decide once the request arrives.
    for name in ["example.com", "API.Example.org", "denied.test"] {
        let q = query(7, name, 1);
        udp.send_to(&q, dns_addr(&h)).await.unwrap();
        let mut buf = [0u8; 512];
        let n = tokio::time::timeout(Duration::from_secs(5), udp.recv(&mut buf))
            .await
            .expect("an answer")
            .unwrap();
        assert_eq!(
            a_records(&q, &buf[..n]),
            vec![Ipv4Addr::LOCALHOST],
            "{name}"
        );
    }

    // Over TCP: two queries on one connection.
    let mut tcp = TcpStream::connect(dns_addr(&h)).await.unwrap();
    for id in [1u16, 2] {
        let q = query(id, "example.com", 1);
        tcp.write_all(&u16::try_from(q.len()).unwrap().to_be_bytes())
            .await
            .unwrap();
        tcp.write_all(&q).await.unwrap();
        let len = usize::from(tcp.read_u16().await.unwrap());
        let mut answer = vec![0; len];
        tcp.read_exact(&mut answer).await.unwrap();
        assert_eq!(a_records(&q, &answer), vec![Ipv4Addr::LOCALHOST]);
    }

    let ev = h.wait_events("dns_query", 5).await;
    assert_eq!(ev[0]["transport"], "udp");
    assert_eq!(ev[0]["name"], "example.com");
    assert_eq!(ev[0]["qtype"], "A");
    assert_eq!(ev[0]["rcode"], "noerror");
    assert_eq!(ev[0]["answers"], serde_json::json!(["127.0.0.1"]));
    assert_eq!(ev[4]["transport"], "tcp");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_without_proxy_settings_is_steered_through_roxy() {
    let h = start().await;
    let direct = h
        .running
        .as_ref()
        .unwrap()
        .server
        .local_addr("direct")
        .unwrap();
    // Connected to the address roxy's DNS answered, with no proxy settings:
    // as far as the client knows, it is talking to upstream.test.
    let mut tls = h.tls_direct(direct, "upstream.test").await.unwrap();
    let port = h.upstream.https.port();
    tls.write_all(
        format!("GET /hello HTTP/1.1\r\nhost: upstream.test:{port}\r\nconnection: close\r\n\r\n")
            .as_bytes(),
    )
    .await
    .unwrap();
    let (head, body) = read_response(&mut tls).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["path"],
        "/hello"
    );
    let ev = h.wait_events("request", 1).await;
    assert_eq!(ev[0]["decision"], "allow", "{ev:#?}");
    assert_eq!(ev[0]["listener"], "direct");
    assert_eq!(ev[0]["tls"]["sni"], "upstream.test");
    assert_eq!(h.upstream.seen().len(), 1);

    // The same request through the explicit proxy matches no rule.
    let res = h.client().get(h.https_url("/hello")).send().await.unwrap();
    assert_eq!(res.status(), 403);
    h.stop().await;
}
