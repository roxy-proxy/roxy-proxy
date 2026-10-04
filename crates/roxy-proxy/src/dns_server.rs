//! The DNS listener (docs/dns.md): answers every name with roxy's own
//! address, so clients connect to the direct listeners
//! (docs/http.md#direct-listeners) as if to the origin. Nothing is ever
//! forwarded to another resolver. The wire format is `roxy-dns`.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use roxy_dns::{Parsed, TYPE_A, TYPE_AAAA};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::flowlog::{ClientInfo, FlowEvent};
use crate::server::Shared;

/// Largest query read. Queries roxy accepts are far smaller (one name of at
/// most 255 bytes and an OPT record); a longer datagram is cut here and
/// then fails to parse.
const MAX_QUERY: usize = 4096;

/// `dns.*`, as the server needs it.
#[derive(Debug, Clone)]
pub struct DnsServerSpec {
    /// Served over UDP and TCP on the same port.
    pub bind: SocketAddr,
    /// The `A` answer for every name.
    pub ipv4: Option<Ipv4Addr>,
    /// The `AAAA` answer for every name.
    pub ipv6: Option<Ipv6Addr>,
    /// Seconds.
    pub ttl: u32,
    /// Fixed answers by name (lower-case, no trailing dot), checked first.
    pub records: HashMap<String, Vec<IpAddr>>,
    /// Log a `dns_query` event per answer (`log.flow.dns_events`).
    pub log_queries: bool,
}

/// One answered message.
struct Reply {
    bytes: Vec<u8>,
    name: Option<String>,
    qtype: Option<u16>,
    rcode: roxy_dns::Rcode,
    answers: Vec<IpAddr>,
}

impl DnsServerSpec {
    fn reply(&self, msg: &[u8]) -> Option<Reply> {
        match roxy_dns::parse(msg) {
            Parsed::Drop => None,
            Parsed::Error {
                id,
                opcode,
                rd,
                rcode,
            } => Some(Reply {
                bytes: roxy_dns::error(id, opcode, rd, rcode),
                name: None,
                qtype: None,
                rcode,
                answers: Vec::new(),
            }),
            Parsed::Query(q) => {
                let addrs = match self.records.get(&q.name) {
                    Some(fixed) => fixed.clone(),
                    None => self
                        .ipv4
                        .map(IpAddr::V4)
                        .into_iter()
                        .chain(self.ipv6.map(IpAddr::V6))
                        .collect(),
                };
                let answers = addrs
                    .into_iter()
                    .filter(|ip| match q.qtype {
                        TYPE_A => ip.is_ipv4(),
                        TYPE_AAAA => ip.is_ipv6(),
                        _ => false,
                    })
                    .collect::<Vec<_>>();
                Some(Reply {
                    bytes: roxy_dns::answer(&q, &answers, self.ttl),
                    name: Some(q.name),
                    qtype: Some(q.qtype),
                    rcode: roxy_dns::Rcode::NoError,
                    answers,
                })
            }
        }
    }
}

fn qtype_name(t: u16) -> String {
    match t {
        TYPE_A => "A".to_owned(),
        TYPE_AAAA => "AAAA".to_owned(),
        other => other.to_string(),
    }
}

fn log(
    spec: &DnsServerSpec,
    shared: &Shared,
    transport: &'static str,
    peer: SocketAddr,
    r: &Reply,
) {
    if !spec.log_queries {
        return;
    }
    shared.sink.emit(&FlowEvent::DnsQuery {
        ts: chrono::Utc::now(),
        transport,
        client: ClientInfo {
            ip: peer.ip(),
            port: peer.port(),
            user: None,
        },
        name: r.name.clone(),
        qtype: r.qtype.map(qtype_name),
        rcode: r.rcode.as_str(),
        answers: r.answers.clone(),
    });
}

/// Serves DNS over UDP until shutdown.
pub(crate) async fn serve_udp(sock: UdpSocket, spec: Arc<DnsServerSpec>, shared: Arc<Shared>) {
    let mut buf = vec![0u8; MAX_QUERY];
    loop {
        let received = tokio::select! {
            r = sock.recv_from(&mut buf) => r,
            () = shared.stop.cancelled() => return,
        };
        let Ok((n, peer)) = received else {
            // ICMP errors from earlier sends surface here on some systems.
            continue;
        };
        let Some(reply) = spec.reply(&buf[..n]) else {
            continue;
        };
        log(&spec, &shared, "udp", peer, &reply);
        let _ = sock.send_to(&reply.bytes, peer).await;
    }
}

/// Serves DNS over TCP (RFC 7766) until shutdown. Connections count
/// against the connection caps.
pub(crate) async fn serve_tcp(tcp: TcpListener, spec: Arc<DnsServerSpec>, shared: Arc<Shared>) {
    loop {
        let accepted = tokio::select! {
            r = tcp.accept() => r,
            () = shared.stop.cancelled() => return,
        };
        let (stream, peer) = match accepted {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(error = %e, "dns accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Some(slot) = crate::server::conn_slot(&shared, peer.ip()) else {
            continue;
        };
        let s = shared.clone();
        let spec = spec.clone();
        shared.spawn_conn(slot, tcp_conn(stream, peer, spec, s));
    }
}

async fn tcp_conn(
    mut stream: TcpStream,
    peer: SocketAddr,
    spec: Arc<DnsServerSpec>,
    shared: Arc<Shared>,
) {
    let idle = shared.snapshot().limits.idle_timeout;
    let mut buf = vec![0u8; MAX_QUERY];
    loop {
        let read = async {
            let len = usize::from(stream.read_u16().await?);
            if len > MAX_QUERY {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
            stream.read_exact(&mut buf[..len]).await?;
            Ok::<_, std::io::Error>(len)
        };
        // A query too long for any name roxy answers closes the connection.
        let len = tokio::select! {
            r = tokio::time::timeout(idle, read) => match r {
                Ok(Ok(len)) => len,
                _ => return,
            },
            () = shared.stop.cancelled() => return,
        };
        let Some(reply) = spec.reply(&buf[..len]) else {
            return;
        };
        log(&spec, &shared, "tcp", peer, &reply);
        let Ok(n) = u16::try_from(reply.bytes.len()) else {
            return;
        };
        let mut out = Vec::with_capacity(2 + reply.bytes.len());
        out.extend_from_slice(&n.to_be_bytes());
        out.extend_from_slice(&reply.bytes);
        if stream.write_all(&out).await.is_err() {
            return;
        }
    }
}

/// Binds UDP on `bind`, then TCP on the same address and port (the port the
/// OS picked, when `bind` asks for port 0).
pub(crate) async fn bind(bind: SocketAddr) -> std::io::Result<(UdpSocket, TcpListener)> {
    let udp = UdpSocket::bind(bind).await?;
    let tcp = TcpListener::bind(udp.local_addr()?).await?;
    Ok((udp, tcp))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> DnsServerSpec {
        DnsServerSpec {
            bind: "127.0.0.1:0".parse().unwrap(),
            ipv4: Some(Ipv4Addr::new(10, 0, 0, 2)),
            ipv6: None,
            ttl: 30,
            records: HashMap::from([(
                "db.internal".to_owned(),
                vec!["10.0.0.9".parse().unwrap(), "fd00::9".parse().unwrap()],
            )]),
            log_queries: false,
        }
    }

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut m = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in name.split('.') {
            m.push(u8::try_from(l.len()).unwrap());
            m.extend_from_slice(l.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&qtype.to_be_bytes());
        m.extend_from_slice(&[0, 1]);
        m
    }

    #[test]
    fn every_name_gets_roxys_address() {
        let r = spec().reply(&query("Example.com", TYPE_A)).unwrap();
        assert_eq!(r.name.as_deref(), Some("example.com"));
        assert_eq!(r.answers, vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))]);
        // No IPv6 answer configured: NODATA.
        let r = spec().reply(&query("example.com", TYPE_AAAA)).unwrap();
        assert_eq!(r.rcode, roxy_dns::Rcode::NoError);
        assert_eq!(r.answers, Vec::<IpAddr>::new());
    }

    #[test]
    fn records_win_and_are_split_by_family() {
        let r = spec().reply(&query("DB.internal", TYPE_A)).unwrap();
        assert_eq!(r.answers, vec!["10.0.0.9".parse::<IpAddr>().unwrap()]);
        let r = spec().reply(&query("db.internal", TYPE_AAAA)).unwrap();
        assert_eq!(r.answers, vec!["fd00::9".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn https_records_get_nodata() {
        let r = spec().reply(&query("example.com", 65)).unwrap();
        assert_eq!(r.answers, Vec::<IpAddr>::new());
        assert_eq!(r.rcode, roxy_dns::Rcode::NoError);
    }

    #[test]
    fn garbage_is_dropped_or_refused() {
        assert!(spec().reply(&[1, 2, 3]).is_none());
        let mut chaos = query("version.bind", 16);
        let n = chaos.len();
        chaos[n - 1] = 3;
        assert_eq!(
            spec().reply(&chaos).unwrap().rcode,
            roxy_dns::Rcode::Refused
        );
    }
}
