use std::io;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;

use hickory_proto::op::{Message, MessageType};
use hickory_proto::rr::RData;
use lru::LruCache;
use tokio::sync::RwLock;

use crate::adapter::{OutboundDatagram, OutboundDatagramRecvHalf, OutboundDatagramSendHalf};
use crate::session::SocksAddr;
use crate::util::DnsMessageExt;

use super::{be_u16, Sniff};

/// The length of a DNS header.
const HEADER: usize = 12;

/// Whether the header bytes of `msg` there are may be a query's: not a
/// response, a question, no answers and no authorities.
fn query_header(msg: &[u8]) -> bool {
    let qr = msg.get(2).is_some_and(|flags| flags & 0x80 != 0);
    let no_question = msg.get(4..6).is_some_and(|count| count == [0, 0]);
    let records = msg.get(6..10).unwrap_or_default().iter().any(|b| *b != 0);
    !(qr || no_question || records)
}

/// A DNS query in a datagram. It names the domain asked about, which is not
/// where the query goes: a rule matches the protocol, and the session's
/// domain is left as it is.
pub fn query(msg: &[u8]) -> Sniff {
    if msg.len() < HEADER || !query_header(msg) {
        return Sniff::NotMatch;
    }
    let Ok(msg) = Message::from_vec(msg) else {
        return Sniff::NotMatch;
    };
    if msg.message_type() != MessageType::Query
        || !msg.answers().is_empty()
        || !msg.name_servers().is_empty()
    {
        return Sniff::NotMatch;
    }
    match msg.queries().first() {
        Some(query) => {
            let mut name = query.name().to_ascii();
            if name.len() > 1 && name.ends_with('.') {
                name.pop();
            }
            Sniff::Found(Some(name))
        }
        None => Sniff::NotMatch,
    }
}

/// A DNS query over a stream, after its two-byte length.
pub fn stream_query(buf: &[u8]) -> Sniff {
    let Some(len) = be_u16(buf) else {
        return Sniff::NeedMore;
    };
    let len = len as usize;
    if len < HEADER || !query_header(&buf[2..]) {
        return Sniff::NotMatch;
    }
    match buf.get(2..2 + len) {
        Some(msg) => query(msg),
        None => Sniff::NeedMore,
    }
}

#[derive(Clone)]
pub struct DnsSniffer {
    cache: Arc<RwLock<LruCache<IpAddr, String>>>,
}

impl Default for DnsSniffer {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsSniffer {
    pub fn new() -> Self {
        const CAP: NonZeroUsize = NonZeroUsize::new(2048).expect("2048 is not zero");
        DnsSniffer {
            cache: Arc::new(RwLock::new(LruCache::new(CAP))),
        }
    }

    pub async fn add(&self, ip: IpAddr, domain: String) {
        self.cache.write().await.put(ip, domain);
    }

    pub async fn get(&self, ip: &IpAddr) -> Option<String> {
        self.cache.read().await.peek(ip).cloned()
    }
}

pub struct SniffingDatagram {
    recv: SniffingDatagramRecvHalf,
    send: SniffingDatagramSendHalf,
}

impl SniffingDatagram {
    pub fn new(outbound: Box<dyn OutboundDatagram>, sniffer: DnsSniffer) -> Self {
        let (recv, send) = outbound.split();
        SniffingDatagram {
            recv: SniffingDatagramRecvHalf {
                inner: recv,
                sniffer: sniffer.clone(),
            },
            send: SniffingDatagramSendHalf { inner: send },
        }
    }
}

impl OutboundDatagram for SniffingDatagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        (Box::new(self.recv), Box::new(self.send))
    }
}

pub struct SniffingDatagramRecvHalf {
    inner: Box<dyn OutboundDatagramRecvHalf>,
    sniffer: DnsSniffer,
}

#[async_trait::async_trait]
impl OutboundDatagramRecvHalf for SniffingDatagramRecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        let (len, src_addr) = self.inner.recv_from(buf).await?;

        if let Ok(msg) = Message::from_vec(&buf[..len]) {
            if msg.message_type() == MessageType::Response {
                // Extract domain from the first query in the response
                let domain = if let Some(query) = msg.queries().first() {
                    let mut name = query.name().to_string();
                    if name.ends_with('.') {
                        name.pop();
                    }
                    Some(name)
                } else {
                    None
                };

                if let Some(domain) = domain {
                    for answer in msg.answers() {
                        match &answer.data {
                            RData::A(ip) => {
                                self.sniffer.add(IpAddr::V4(ip.0), domain.clone()).await;
                            }
                            RData::AAAA(ip) => {
                                self.sniffer.add(IpAddr::V6(ip.0), domain.clone()).await;
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        Ok((len, src_addr))
    }
}

pub struct SniffingDatagramSendHalf {
    inner: Box<dyn OutboundDatagramSendHalf>,
}

#[async_trait::async_trait]
impl OutboundDatagramSendHalf for SniffingDatagramSendHalf {
    async fn send_to(&mut self, buf: &[u8], dst_addr: &SocksAddr) -> io::Result<usize> {
        self.inner.send_to(buf, dst_addr).await
    }

    async fn close(&mut self) -> io::Result<()> {
        self.inner.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::{OutboundDatagram, OutboundDatagramRecvHalf, OutboundDatagramSendHalf};
    use crate::session::SocksAddr;
    use hickory_proto::op::OpCode;
    use hickory_proto::op::{Message, MessageType, Query};
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use std::io;
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    struct MockOutboundDatagramRecvHalf {
        data: Vec<u8>,
    }

    #[async_trait::async_trait]
    impl OutboundDatagramRecvHalf for MockOutboundDatagramRecvHalf {
        async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
            if self.data.is_empty() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof"));
            }
            let len = std::cmp::min(buf.len(), self.data.len());
            buf[..len].copy_from_slice(&self.data[..len]);
            self.data.clear(); // One-shot
            Ok((len, SocksAddr::any_ipv4()))
        }
    }

    struct MockOutboundDatagramSendHalf;

    #[async_trait::async_trait]
    impl OutboundDatagramSendHalf for MockOutboundDatagramSendHalf {
        async fn send_to(&mut self, _buf: &[u8], _dst_addr: &SocksAddr) -> io::Result<usize> {
            Ok(0)
        }
        async fn close(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct MockOutboundDatagram {
        recv: MockOutboundDatagramRecvHalf,
        send: MockOutboundDatagramSendHalf,
    }

    impl OutboundDatagram for MockOutboundDatagram {
        fn split(
            self: Box<Self>,
        ) -> (
            Box<dyn OutboundDatagramRecvHalf>,
            Box<dyn OutboundDatagramSendHalf>,
        ) {
            (Box::new(self.recv), Box::new(self.send))
        }
    }

    fn query_bytes(name: &str) -> Vec<u8> {
        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.set_id(7);
        msg.set_recursion_desired(true);
        msg.add_query(Query::query(
            Name::from_str(name).unwrap(),
            RecordType::AAAA,
        ));
        msg.to_vec().unwrap()
    }

    #[test]
    fn a_query_names_its_domain() {
        let msg = query_bytes("www.example.com.");
        assert_eq!(query(&msg), Sniff::Found(Some("www.example.com".into())));
        let mut stream = (msg.len() as u16).to_be_bytes().to_vec();
        stream.extend_from_slice(&msg);
        assert_eq!(
            stream_query(&stream),
            Sniff::Found(Some("www.example.com".into()))
        );
        for len in 0..stream.len() {
            assert_eq!(stream_query(&stream[..len]), Sniff::NeedMore, "{}", len);
        }
    }

    #[test]
    fn a_response_is_not_a_query() {
        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.set_message_type(MessageType::Response);
        let name = Name::from_str("example.com.").unwrap();
        msg.add_query(Query::query(name.clone(), RecordType::A));
        let a = RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(1, 2, 3, 4)));
        msg.add_answer(Record::from_rdata(name, 60, a));
        let msg = msg.to_vec().unwrap();
        assert_eq!(query(&msg), Sniff::NotMatch);
        let mut stream = (msg.len() as u16).to_be_bytes().to_vec();
        stream.extend_from_slice(&msg[..3]);
        assert_eq!(stream_query(&stream), Sniff::NotMatch);
        assert_eq!(query(&[0; 12]), Sniff::NotMatch);
        assert_eq!(query(b"GET / HTTP/1.1\r\n"), Sniff::NotMatch);
    }

    #[test]
    fn no_query_panics() {
        let msg = query_bytes("a.example.com.");
        for i in 0..msg.len() {
            for byte in [0x00, 0x01, 0x3f, 0x40, 0xc0, 0xff] {
                let mut bad = msg.clone();
                bad[i] = byte;
                let _ = query(&bad);
                let _ = query(&bad[..i]);
            }
        }
    }

    #[tokio::test]
    async fn test_dns_sniff() {
        let sniffer = DnsSniffer::new();

        // Construct a DNS response
        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.set_message_type(MessageType::Response);
        let name = Name::from_str("example.com.").unwrap();
        let query = Query::query(name.clone(), RecordType::A);
        msg.add_query(query);
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let answer = Record::from_rdata(name, 3600, RData::A(hickory_proto::rr::rdata::A(ip)));
        msg.add_answer(answer);

        let msg_bytes = msg.to_vec().unwrap();

        // Create a mock outbound datagram
        let mock_recv = MockOutboundDatagramRecvHalf { data: msg_bytes };
        let mock_send = MockOutboundDatagramSendHalf;
        let mock_outbound = Box::new(MockOutboundDatagram {
            recv: mock_recv,
            send: mock_send,
        });

        // Create sniffing datagram
        let sniffing_datagram = Box::new(SniffingDatagram::new(mock_outbound, sniffer.clone()));
        let (mut recv, _send) = sniffing_datagram.split();

        // Receive data (trigger sniffing)
        let mut buf = vec![0u8; 1500];
        let (_len, _addr) = recv.recv_from(&mut buf).await.unwrap();

        // Check if sniffed
        let sniffed_ip = IpAddr::V4(ip);
        let domain = sniffer.get(&sniffed_ip).await;
        assert_eq!(domain, Some("example.com".to_string()));
    }
}
