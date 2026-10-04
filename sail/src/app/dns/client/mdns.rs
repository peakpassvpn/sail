//! Multicast DNS (RFC 6762), as sing-box's `mdns` server asks it
//! (dns/transport/mdns): a one-shot query (§5.1), asking for a unicast
//! response (§5.4), to 224.0.0.251 and
//! ff02::fb, port 5353, from a port of its own on each interface that is up,
//! multicast-capable and not loopback, the responders answering that port
//! directly. Unlike sing-box, which gathers answers until its deadline, the
//! first interface to answer the question ends the query: responders answer
//! within 120 ms (§6), and a name has one owner on a link.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use anyhow::{anyhow, Result};
use futures::stream::{FuturesUnordered, StreamExt};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Record, RecordType};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tracing::trace;

use crate::net::interface::{multicast_interfaces, MulticastInterface};

/// The port and groups of mDNS (RFC 6762 §3).
const PORT: u16 = 5353;
const GROUP_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);

/// How long a query waits at most for an answer: sing-box's (mdnsTimeout).
pub(super) const WAIT: Duration = Duration::from_secs(1);

/// The top bit of a class, the cache-flush bit of a record and the
/// unicast-response bit of a question (§10.2, §5.4).
const CLASS_TOP_BIT: u16 = 1 << 15;

/// The zones mDNS answers for: `.local`, and the reverse zones of
/// link-local addresses (§3, §4), as sing-box lists them.
const LOCAL_ZONES: &[&str] = &[
    "local",
    "254.169.in-addr.arpa",
    "8.e.f.ip6.arpa",
    "9.e.f.ip6.arpa",
    "a.e.f.ip6.arpa",
    "b.e.f.ip6.arpa",
];

/// Whether `name` is in a zone mDNS answers for.
pub(crate) fn is_local_domain(name: &str) -> bool {
    let name = name.trim_end_matches('.');
    LOCAL_ZONES.iter().any(|zone| {
        name.len() >= zone.len()
            && name[name.len() - zone.len()..].eq_ignore_ascii_case(zone)
            && (name.len() == zone.len() || name.as_bytes()[name.len() - zone.len() - 1] == b'.')
    })
}

/// A multicast DNS server: the interfaces it asks on, all usable ones
/// when none are named.
#[derive(Debug, Default)]
pub(super) struct Mdns {
    pub interfaces: Vec<String>,
}

/// An interface and a family to ask on.
struct Target {
    name: String,
    /// The group, with the interface's scope for IPv6.
    group: SocketAddr,
    /// The networks the interface is on, which answers come from.
    networks: Vec<(IpAddr, u8)>,
    /// The address, IPv4, or index, IPv6, multicast goes out of.
    via: Via,
}

enum Via {
    V4(Ipv4Addr),
    V6(u32),
}

impl Mdns {
    /// The answer to `request`, asked on each interface for at most `wait`.
    pub(super) async fn exchange(&self, request: &Message, wait: Duration) -> Result<Message> {
        let question = request
            .queries
            .first()
            .ok_or_else(|| anyhow!("a query without a question"))?
            .clone();
        let targets = self.targets()?;
        let wire = query(&question)?;
        let mut asks: FuturesUnordered<_> = targets
            .into_iter()
            .map(|target| {
                let wire = &wire;
                let question = &question;
                async move {
                    let socket = socket(&target)?;
                    ask_on(
                        &socket,
                        target.group,
                        &target.networks,
                        wire,
                        question,
                        PORT,
                    )
                    .await
                }
            })
            .collect();
        let mut records: Vec<Record> = Vec::new();
        let mut last_err = None;
        let deadline = tokio::time::sleep(wait);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                asked = asks.next() => match asked {
                    Some(Ok(answer)) => {
                        merge(&mut records, answer);
                        if answers(&records, &question) {
                            break;
                        }
                    }
                    Some(Err(e)) => {
                        trace!("mdns: {}", e);
                        last_err = Some(e);
                    }
                    None => break,
                },
                _ = &mut deadline => break,
            }
        }
        if records.is_empty() {
            return Err(last_err.unwrap_or_else(|| anyhow!("mdns: no answer")));
        }
        let mut response = Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
        response.metadata.authoritative = true;
        response.metadata.recursion_desired = request.metadata.recursion_desired;
        response.metadata.response_code = ResponseCode::NoError;
        response.add_query(question.clone());
        for record in records {
            response.add_answer(record);
        }
        Ok(response)
    }

    fn targets(&self) -> Result<Vec<Target>> {
        let all = multicast_interfaces().map_err(|e| anyhow!("mdns: interfaces: {}", e))?;
        let interfaces: Vec<MulticastInterface> = if self.interfaces.is_empty() {
            all
        } else {
            let mut named = Vec::new();
            for name in &self.interfaces {
                match all.iter().find(|i| &i.name == name) {
                    Some(interface) => named.push(interface.clone()),
                    None => tracing::warn!("mdns: interface {} is not up for multicast", name),
                }
            }
            named
        };
        let mut targets = Vec::new();
        for interface in interfaces {
            let networks: Vec<(IpAddr, u8)> = interface.addresses.clone();
            let v4 = networks.iter().find_map(|(ip, _)| match ip {
                IpAddr::V4(v4) => Some(*v4),
                IpAddr::V6(_) => None,
            });
            if let Some(v4) = v4 {
                targets.push(Target {
                    name: interface.name.clone(),
                    group: SocketAddr::new(GROUP_V4.into(), PORT),
                    networks: networks.clone(),
                    via: Via::V4(v4),
                });
            }
            if networks.iter().any(|(ip, _)| ip.is_ipv6()) {
                targets.push(Target {
                    name: interface.name.clone(),
                    group: SocketAddr::V6(std::net::SocketAddrV6::new(
                        GROUP_V6,
                        PORT,
                        0,
                        interface.index,
                    )),
                    networks,
                    via: Via::V6(interface.index),
                });
            }
        }
        if targets.is_empty() {
            return Err(anyhow!("mdns: no interface to ask on"));
        }
        Ok(targets)
    }
}

/// A socket that sends multicast out of `target`'s interface.
fn socket(target: &Target) -> Result<UdpSocket> {
    let e = |e: std::io::Error| anyhow!("mdns: {}: {}", target.name, e);
    let socket = match target.via {
        Via::V4(address) => {
            let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).map_err(e)?;
            socket.set_multicast_if_v4(&address).map_err(e)?;
            socket.set_multicast_ttl_v4(255).map_err(e)?;
            socket
                .bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)).into())
                .map_err(e)?;
            socket
        }
        Via::V6(index) => {
            let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).map_err(e)?;
            socket.set_only_v6(true).map_err(e)?;
            socket.set_multicast_if_v6(index).map_err(e)?;
            socket.set_multicast_hops_v6(255).map_err(e)?;
            socket
                .bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)).into())
                .map_err(e)?;
            socket
        }
    };
    crate::net::no_udp_connreset(socket2::SockRef::from(&socket));
    socket.set_nonblocking(true).map_err(e)?;
    UdpSocket::from_std(socket.into()).map_err(e)
}

/// The wire form of a one-shot query for `question`: ID 0, as §18.1 asks
/// of multicast queries, with the unicast-response bit (§5.4). From a port
/// other than 5353, responders answer by unicast either way (§6.7), but
/// Windows' answers only a question with the bit, as measured on
/// Windows 10; unlike sing-box's, which sends none and hears nothing from
/// it.
fn query(question: &Query) -> Result<Vec<u8>> {
    let mut message = Message::new(0, MessageType::Query, OpCode::Query);
    let mut question = question.clone();
    question.query_class =
        DNSClass::Unknown(u16::from(class(question.query_class)) | CLASS_TOP_BIT);
    message.add_query(question);
    Ok(message.to_vec()?)
}

/// Sends `wire` to `group` on `socket`, and reads what answers `question`
/// from a responder on `networks` until one answers it. `port` is where
/// responders answer from: 5353, but for tests.
async fn ask_on(
    socket: &UdpSocket,
    group: SocketAddr,
    networks: &[(IpAddr, u8)],
    wire: &[u8],
    question: &Query,
    port: u16,
) -> Result<Vec<Record>> {
    socket.send_to(wire, group).await?;
    let mut records = Vec::new();
    let mut buf = vec![0u8; 9000];
    loop {
        let (n, from) = socket.recv_from(&mut buf).await?;
        if from.port() != port || !on(networks, from.ip()) {
            continue;
        }
        let Ok(message) = Message::from_vec(&buf[..n]) else {
            continue;
        };
        if !valid(&message, question) {
            continue;
        }
        merge(&mut records, normalized(message));
        if answers(&records, question) {
            return Ok(records);
        }
    }
}

/// Whether `ip` is on one of `networks`.
fn on(networks: &[(IpAddr, u8)], ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    };
    networks.iter().any(|(network, len)| match (network, ip) {
        (IpAddr::V4(n), IpAddr::V4(a)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(*len)).unwrap_or(0);
            u32::from(*n) & mask == u32::from(a) & mask
        }
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(*len)).unwrap_or(0);
            u128::from(*n) & mask == u128::from(a) & mask
        }
        _ => false,
    })
}

/// Whether `message` is a response to `question`: a successful one that
/// repeats it, or holds a record for it.
fn valid(message: &Message, question: &Query) -> bool {
    if message.metadata.message_type != MessageType::Response
        || message.metadata.op_code != OpCode::Query
        || message.metadata.response_code != ResponseCode::NoError
    {
        return false;
    }
    let same = |q: &Query| {
        q.query_type() == question.query_type()
            && class(q.query_class()) == class(question.query_class())
            && q.name()
                .to_utf8()
                .eq_ignore_ascii_case(&question.name().to_utf8())
    };
    message.queries.iter().any(same)
        || message
            .answers
            .iter()
            .chain(&message.authorities)
            .chain(&message.additionals)
            .any(|r| for_question(r, question))
}

/// Whether `record` answers `question`: its name, and its type or a CNAME.
fn for_question(record: &Record, question: &Query) -> bool {
    record
        .name
        .to_utf8()
        .eq_ignore_ascii_case(&question.name().to_utf8())
        && (question.query_type() == RecordType::ANY
            || record.record_type() == question.query_type()
            || record.record_type() == RecordType::CNAME)
}

/// Whether `records` answer `question`.
fn answers(records: &[Record], question: &Query) -> bool {
    records.iter().any(|r| for_question(r, question))
}

/// The records of `message`, their cache-flush bits cleared.
fn normalized(message: Message) -> Vec<Record> {
    let mut records = message.answers;
    records.extend(message.authorities);
    records.extend(message.additionals);
    records
        .into_iter()
        .filter(|r| r.record_type() != RecordType::OPT)
        .map(|mut r| {
            r.dns_class = class(r.dns_class);
            r
        })
        .collect()
}

/// `records` with those of `more` it has not.
fn merge(records: &mut Vec<Record>, more: Vec<Record>) {
    for record in more {
        if !records.contains(&record) {
            records.push(record);
        }
    }
}

/// `class` without its top bit.
fn class(class: DNSClass) -> DNSClass {
    match class {
        DNSClass::Unknown(v) if v & CLASS_TOP_BIT != 0 => DNSClass::from(v & !CLASS_TOP_BIT),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::{rdata::A, Name, RData};

    #[test]
    fn local_domains_are_those_of_the_zones() {
        for name in [
            "printer.local",
            "Printer.LOCAL.",
            "local",
            "5.1.254.169.in-addr.arpa",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.",
        ] {
            assert!(is_local_domain(name), "{}", name);
        }
        for name in [
            "example.com",
            "notlocal",
            "local.example",
            "1.1.168.192.in-addr.arpa",
        ] {
            assert!(!is_local_domain(name), "{}", name);
        }
    }

    #[test]
    fn a_source_is_on_a_network_by_its_prefix() {
        let networks = [
            ("192.168.1.10".parse().unwrap(), 24),
            ("fe80::1".parse().unwrap(), 64),
        ];
        assert!(on(&networks, "192.168.1.77".parse().unwrap()));
        assert!(on(&networks, "::ffff:192.168.1.77".parse().unwrap()));
        assert!(on(&networks, "fe80::abcd".parse().unwrap()));
        assert!(!on(&networks, "192.168.2.1".parse().unwrap()));
        assert!(!on(&networks, "2001:db8::1".parse().unwrap()));
    }

    fn a_question(name: &str) -> Query {
        Query::query(Name::from_ascii(name).unwrap(), RecordType::A)
    }

    /// A responder's answer, its records' cache-flush bits set.
    fn response(name: &str, ip: Ipv4Addr) -> Vec<u8> {
        let mut message = Message::new(0, MessageType::Response, OpCode::Query);
        message.metadata.authoritative = true;
        let mut record = Record::from_rdata(Name::from_ascii(name).unwrap(), 120, RData::A(A(ip)));
        record.dns_class = DNSClass::Unknown(1 | CLASS_TOP_BIT);
        message.add_answer(record);
        message.to_vec().unwrap()
    }

    /// Answers from another port, another network, and for another name
    /// are left aside; the answer is taken, its cache-flush bit cleared.
    #[tokio::test]
    async fn a_query_takes_the_answer_of_a_responder_on_its_network() {
        let responder = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let group = responder.local_addr().unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = socket.local_addr().unwrap();
        let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let question = a_question("printer.local.");
        let wire = query(&question).unwrap();
        let answered = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, from) = responder.recv_from(&mut buf).await.unwrap();
            let asked = Message::from_vec(&buf[..n]).unwrap();
            assert_eq!(asked.metadata.id, 0);
            assert_eq!(
                asked.queries[0].query_class(),
                DNSClass::Unknown(1 | CLASS_TOP_BIT)
            );
            assert_eq!(asked.queries[0].name().to_utf8(), "printer.local.");
            // Another port first, then another name, then the answer.
            stranger
                .send_to(
                    &response("printer.local.", Ipv4Addr::new(10, 0, 0, 1)),
                    from,
                )
                .await
                .unwrap();
            responder
                .send_to(
                    &response("scanner.local.", Ipv4Addr::new(10, 0, 0, 2)),
                    from,
                )
                .await
                .unwrap();
            responder
                .send_to(
                    &response("printer.local.", Ipv4Addr::new(10, 0, 0, 3)),
                    from,
                )
                .await
                .unwrap();
        });
        let networks = [(IpAddr::from([127, 0, 0, 0]), 8)];
        let records = tokio::time::timeout(
            Duration::from_secs(5),
            ask_on(&socket, group, &networks, &wire, &question, group.port()),
        )
        .await
        .unwrap()
        .unwrap();
        answered.await.unwrap();
        assert_eq!(records.len(), 1, "{:?} at {}", records, client);
        assert_eq!(records[0].dns_class, DNSClass::IN);
        assert_eq!(records[0].data, RData::A(A(Ipv4Addr::new(10, 0, 0, 3))));
    }

    /// The host's own name answers on a host with a responder: run by hand,
    /// with the name, as `SAIL_MDNS_NAME=host.local`.
    #[tokio::test]
    #[ignore]
    async fn the_host_s_responder_answers() {
        let name = std::env::var("SAIL_MDNS_NAME").expect("SAIL_MDNS_NAME");
        let mut request = Message::new(7, MessageType::Query, OpCode::Query);
        request.add_query(a_question(&format!("{}.", name.trim_end_matches('.'))));
        let response = Mdns::default().exchange(&request, WAIT).await.unwrap();
        assert_eq!(response.metadata.id, 7);
        assert!(!response.answers.is_empty(), "{:?}", response);
    }
}
