use std::io;

use crate::adapter::{OutboundDatagram, OutboundDatagramRecvHalf, OutboundDatagramSendHalf};
use crate::session::{SniffedProtocol, SocksAddr};

use super::{dns, misc, quic::QuicSniffer, Protocols, Sniff};

/// What sniffing made of a connection's first bytes, or of a UDP session's
/// first datagrams.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sniffed {
    /// None of the protocols looked for.
    NotMatch,
    /// One of them perhaps; more would tell.
    NeedMore,
    /// This protocol, naming this domain, if any.
    Found(SniffedProtocol, Option<String>),
}

/// Datagrams of a UDP session read looking for its protocol, at most: a
/// ClientHello takes Chrome two or three Initial packets.
pub const MAX_SNIFF_DATAGRAMS: usize = 8;

/// A sniff of the first datagrams a client sends in a UDP session. Only
/// QUIC, whose ClientHello may span several Initial packets, looks past
/// the first datagram.
pub struct DatagramSniff {
    protocols: Protocols,
    /// The QUIC session so far, once its first datagram is an Initial.
    quic: Option<QuicSniffer>,
    datagrams: usize,
}

impl DatagramSniff {
    pub fn new(protocols: Protocols) -> Self {
        DatagramSniff {
            protocols: protocols.datagram(),
            quic: None,
            datagrams: 0,
        }
    }

    /// Reads the next datagram the client sent.
    pub fn feed(&mut self, datagram: &[u8]) -> Sniffed {
        self.datagrams += 1;
        let exhausted = self.datagrams >= MAX_SNIFF_DATAGRAMS;
        if let Some(quic) = self.quic.as_mut() {
            return match quic.feed(datagram) {
                Sniff::Found(domain) => Sniffed::Found(SniffedProtocol::Quic, domain),
                Sniff::NeedMore if !exhausted => Sniffed::NeedMore,
                _ => Sniffed::NotMatch,
            };
        }
        for protocol in self.protocols.iter() {
            let sniff = match protocol {
                SniffedProtocol::Quic => {
                    let mut quic = QuicSniffer::new();
                    let sniff = quic.feed(datagram);
                    if sniff == Sniff::NeedMore {
                        self.quic = Some(quic);
                    }
                    sniff
                }
                SniffedProtocol::Dns => dns::query(datagram),
                SniffedProtocol::Stun => misc::stun(datagram),
                SniffedProtocol::Bittorrent => misc::bittorrent_datagram(datagram),
                SniffedProtocol::Dtls => misc::dtls(datagram),
                SniffedProtocol::Tls | SniffedProtocol::Http => Sniff::NotMatch,
            };
            match sniff {
                Sniff::Found(domain) => return Sniffed::Found(protocol, domain),
                Sniff::NeedMore if !exhausted => return Sniffed::NeedMore,
                Sniff::NeedMore | Sniff::NotMatch => {}
            }
        }
        Sniffed::NotMatch
    }

    /// What is known once no more datagrams are read: QUIC, when an
    /// Initial packet was read but not the whole ClientHello, as sing-box
    /// has it.
    pub fn settle(&self) -> Option<SniffedProtocol> {
        self.quic.as_ref().map(|_| SniffedProtocol::Quic)
    }
}

/// The datagrams of a UDP session whose destination a `sniff` rule
/// overrode with the domain it found: the client's datagrams to the address
/// it asked for go to the domain, and the replies from the domain come
/// back from that address, as sing-box's NAT does.
pub struct OverriddenDatagram {
    recv: OverriddenRecvHalf,
    send: OverriddenSendHalf,
}

impl OverriddenDatagram {
    pub fn new(inner: Box<dyn OutboundDatagram>, origin: SocksAddr, domain: SocksAddr) -> Self {
        let (recv, send) = inner.split();
        OverriddenDatagram {
            recv: OverriddenRecvHalf {
                inner: recv,
                origin: origin.clone(),
                domain: domain.clone(),
                unmap: true,
            },
            send: OverriddenSendHalf {
                inner: send,
                origin,
                domain,
            },
        }
    }
}

impl OverriddenDatagram {
    /// The same datagrams, whose answers come back from where they were
    /// sent, not from the destination asked for, when `disabled`: a
    /// rule's `udp_disable_domain_unmapping`, for an address a resolve
    /// rule handed on, as sing-box's unidirectional NAT
    /// (route/conn.go:238-241).
    pub fn without_unmapping(mut self, disabled: bool) -> Self {
        self.recv.unmap = !disabled;
        self
    }
}

impl OutboundDatagram for OverriddenDatagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        (Box::new(self.recv), Box::new(self.send))
    }
}

struct OverriddenRecvHalf {
    inner: Box<dyn OutboundDatagramRecvHalf>,
    origin: SocksAddr,
    domain: SocksAddr,
    /// Answers from `domain` come back from `origin`.
    unmap: bool,
}

#[async_trait::async_trait]
impl OutboundDatagramRecvHalf for OverriddenRecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        let (n, from) = self.inner.recv_from(buf).await?;
        if self.unmap && from == self.domain {
            return Ok((n, self.origin.clone()));
        }
        Ok((n, from))
    }
}

struct OverriddenSendHalf {
    inner: Box<dyn OutboundDatagramSendHalf>,
    origin: SocksAddr,
    domain: SocksAddr,
}

#[async_trait::async_trait]
impl OutboundDatagramSendHalf for OverriddenSendHalf {
    async fn send_to(&mut self, buf: &[u8], to: &SocksAddr) -> io::Result<usize> {
        if *to == self.origin {
            return self.inner.send_to(buf, &self.domain).await;
        }
        self.inner.send_to(buf, to).await
    }

    async fn close(&mut self) -> io::Result<()> {
        self.inner.close().await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    /// Records where datagrams are sent, and replies from each.
    struct Echo(Arc<Mutex<Vec<SocksAddr>>>);

    #[async_trait::async_trait]
    impl OutboundDatagramRecvHalf for Echo {
        async fn recv_from(&mut self, _buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
            let to = self.0.lock().unwrap().first().cloned();
            to.map(|to| (0, to))
                .ok_or_else(|| io::Error::other("nothing sent"))
        }
    }

    #[async_trait::async_trait]
    impl OutboundDatagramSendHalf for Echo {
        async fn send_to(&mut self, buf: &[u8], to: &SocksAddr) -> io::Result<usize> {
            self.0.lock().unwrap().push(to.clone());
            Ok(buf.len())
        }

        async fn close(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl OutboundDatagram for Echo {
        fn split(
            self: Box<Self>,
        ) -> (
            Box<dyn OutboundDatagramRecvHalf>,
            Box<dyn OutboundDatagramSendHalf>,
        ) {
            (Box::new(Echo(self.0.clone())), self)
        }
    }

    #[tokio::test]
    async fn an_overridden_destination_is_the_address_to_the_client() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let origin = SocksAddr::from(("1.2.3.4".parse::<std::net::IpAddr>().unwrap(), 443));
        let domain = SocksAddr::Domain("example.com".into(), 443);
        let other = SocksAddr::from(("5.6.7.8".parse::<std::net::IpAddr>().unwrap(), 443));
        let d = Box::new(OverriddenDatagram::new(
            Box::new(Echo(sent.clone())),
            origin.clone(),
            domain.clone(),
        ));
        let (mut recv, mut send) = d.split();
        send.send_to(b"a", &origin).await.unwrap();
        send.send_to(b"b", &other).await.unwrap();
        assert_eq!(*sent.lock().unwrap(), [domain.clone(), other.clone()]);
        assert_eq!(recv.recv_from(&mut [0; 4]).await.unwrap().1, origin);
        sent.lock().unwrap().remove(0);
        assert_eq!(recv.recv_from(&mut [0; 4]).await.unwrap().1, other);
    }

    #[test]
    fn only_quic_reads_past_the_first_datagram() {
        let mut stun = vec![0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42];
        stun.extend_from_slice(&[5; 12]);
        let mut sniff = DatagramSniff::new(Protocols::ALL);
        assert_eq!(
            sniff.feed(&stun),
            Sniffed::Found(SniffedProtocol::Stun, None)
        );

        let mut sniff = DatagramSniff::new(Protocols::NONE.with(SniffedProtocol::Dtls));
        assert_eq!(sniff.feed(&stun), Sniffed::NotMatch);

        // HTTP is not looked for in datagrams.
        let mut sniff = DatagramSniff::new(Protocols::ALL);
        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(sniff.feed(request), Sniffed::NotMatch);
    }
}
