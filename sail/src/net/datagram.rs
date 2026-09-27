use std::{
    io,
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
    sync::Arc,
};

use async_trait::async_trait;
use futures::TryFutureExt;
use lru::LruCache;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use crate::{
    app::SyncDnsClient,
    session::{DatagramSource, SocksAddr},
};

use super::*;

/// An outbound datagram wraps a normal UDP socket and used as a normal UDP socket.
pub struct StdOutboundDatagram {
    inner: UdpSocket,
}

impl StdOutboundDatagram {
    pub fn new(inner: UdpSocket) -> Self {
        Self { inner }
    }
}

impl OutboundDatagram for StdOutboundDatagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let r = Arc::new(self.inner);
        let s = r.clone();
        (
            Box::new(StdOutboundDatagramRecvHalf(r)),
            Box::new(StdOutboundDatagramSendHalf(s)),
        )
    }
}

pub struct StdOutboundDatagramRecvHalf(Arc<UdpSocket>);

#[async_trait]
impl OutboundDatagramRecvHalf for StdOutboundDatagramRecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        match self.0.recv_from(buf).await {
            Ok((n, a)) => Ok((n, SocksAddr::Ip(unmapped_ipv4(a)))),
            Err(e) => Err(e),
        }
    }
}

pub struct StdOutboundDatagramSendHalf(Arc<UdpSocket>);

#[async_trait]
impl OutboundDatagramSendHalf for StdOutboundDatagramSendHalf {
    async fn send_to(&mut self, buf: &[u8], target: &SocksAddr) -> io::Result<usize> {
        match target {
            SocksAddr::Ip(a) => self.0.send_to(buf, a).await,
            SocksAddr::Domain(domain, port) => Err(io::Error::other(format!(
                "unexpected domain address {}:{}",
                domain, port
            ))),
        }
    }

    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct DomainResolveOutboundDatagram {
    inner: UdpSocket,
    dns_client: SyncDnsClient,
}

impl DomainResolveOutboundDatagram {
    pub fn new(inner: UdpSocket, dns_client: SyncDnsClient) -> Self {
        Self { inner, dns_client }
    }
}

impl OutboundDatagram for DomainResolveOutboundDatagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let r = Arc::new(self.inner);
        let s = r.clone();
        (
            Box::new(DomainResolveOutboundDatagramRecvHalf(r)),
            Box::new(DomainResolveOutboundDatagramSendHalf(s, self.dns_client)),
        )
    }
}

pub struct DomainResolveOutboundDatagramRecvHalf(Arc<UdpSocket>);

#[async_trait]
impl OutboundDatagramRecvHalf for DomainResolveOutboundDatagramRecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        match self.0.recv_from(buf).await {
            Ok((n, a)) => Ok((n, SocksAddr::Ip(unmapped_ipv4(a)))),
            Err(e) => Err(e),
        }
    }
}

pub struct DomainResolveOutboundDatagramSendHalf(Arc<UdpSocket>, SyncDnsClient);

#[async_trait]
impl OutboundDatagramSendHalf for DomainResolveOutboundDatagramSendHalf {
    async fn send_to(&mut self, buf: &[u8], target: &SocksAddr) -> io::Result<usize> {
        match target {
            SocksAddr::Domain(domain, port) => {
                let ips = self
                    .1
                    .load_full()
                    .lookup(domain)
                    .map_err(|e| io::Error::other(format!("lookup {} failed: {}", domain, e)))
                    .await?;
                let ip = ips.first().ok_or_else(|| io::Error::other("no results"))?;
                self.0.send_to(buf, SocketAddr::new(*ip, *port)).await
            }
            SocksAddr::Ip(addr) => self.0.send_to(buf, addr).await,
        }
    }

    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// An outbound datagram that sends to a domain target.
pub struct DomainAssociatedOutboundDatagram {
    inner: UdpSocket,
    source: SocketAddr,
    destination: SocksAddr,
    dns_client: SyncDnsClient,
}

impl DomainAssociatedOutboundDatagram {
    pub fn new(
        inner: UdpSocket,
        source: SocketAddr,
        destination: SocksAddr,
        dns_client: SyncDnsClient,
    ) -> Self {
        DomainAssociatedOutboundDatagram {
            inner,
            source,
            destination,
            dns_client,
        }
    }
}

impl OutboundDatagram for DomainAssociatedOutboundDatagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let r = Arc::new(self.inner);
        let s = r.clone();
        let targets = DomainTargetMap::new();
        (
            Box::new(DomainAssociatedOutboundDatagramRecvHalf(
                r,
                self.destination,
                targets.clone(),
            )),
            Box::new(DomainAssociatedOutboundDatagramSendHalf(
                s,
                self.source,
                self.dns_client,
                targets,
            )),
        )
    }
}

/// The resolved addresses a domain-associated datagram sent to, each with
/// the target it was sent as.
///
/// A datagram to a domain goes out to the address it resolves to, and the
/// reply has to come back as from that domain. With one target per socket,
/// every reply was labelled with the socket's first target, so replies from
/// a second domain, or answered out of order, reached the client as if from
/// the first.
#[derive(Clone)]
struct DomainTargetMap {
    targets: Arc<Mutex<LruCache<SocketAddr, SocksAddr>>>,
}

impl DomainTargetMap {
    /// Addresses remembered per socket; the least recently used goes first.
    const CAPACITY: NonZeroUsize = NonZeroUsize::new(256).expect("256 is not zero");

    fn new() -> Self {
        Self {
            targets: Arc::new(Mutex::new(LruCache::new(Self::CAPACITY))),
        }
    }

    async fn record(&self, address: SocketAddr, target: SocksAddr) {
        self.targets
            .lock()
            .await
            .put(unmapped_ipv4(address), target);
    }

    async fn target(&self, address: SocketAddr, fallback: &SocksAddr) -> SocksAddr {
        self.targets
            .lock()
            .await
            .get(&unmapped_ipv4(address))
            .cloned()
            .unwrap_or_else(|| fallback.clone())
    }
}

fn unmapped_ipv4(addr: SocketAddr) -> SocketAddr {
    if let SocketAddr::V6(ref a) = addr {
        if let Some(a_v4) = a.ip().to_ipv4() {
            return SocketAddr::new(IpAddr::V4(a_v4), a.port());
        }
    }
    addr
}

pub struct DomainAssociatedOutboundDatagramRecvHalf(Arc<UdpSocket>, SocksAddr, DomainTargetMap);

#[async_trait]
impl OutboundDatagramRecvHalf for DomainAssociatedOutboundDatagramRecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        let (n, address) = self.0.recv_from(buf).await?;
        Ok((n, self.2.target(address, &self.1).await))
    }
}

pub struct DomainAssociatedOutboundDatagramSendHalf(
    Arc<UdpSocket>,
    SocketAddr,
    SyncDnsClient,
    DomainTargetMap,
);

#[async_trait]
impl OutboundDatagramSendHalf for DomainAssociatedOutboundDatagramSendHalf {
    async fn send_to(&mut self, buf: &[u8], target: &SocksAddr) -> io::Result<usize> {
        let addr = match target {
            SocksAddr::Domain(domain, port) => {
                let ips = {
                    self.2
                        .load_full()
                        .lookup(domain)
                        .map_err(|e| io::Error::other(format!("lookup {} failed: {}", domain, e)))
                        .await?
                };
                // FIXME Since FakeDns returns IPv4 address only, it's always bound
                // to IPv4 address if FakeDns is used.
                //
                // If the socket was bound to an IPv4 address, we need an IPv4
                // address for sending, and vice versa for IPv6.
                let needs_ipv4 = self.1.is_ipv4();
                if let Some(ip) = ips.into_iter().find(|x| x.is_ipv4() == needs_ipv4) {
                    SocketAddr::new(ip, port.to_owned())
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "could not resolve to any address",
                    ));
                }
            }
            SocksAddr::Ip(a) => a.to_owned(),
        };
        self.3.record(addr, target.clone()).await;
        self.0.send_to(buf, &addr).await
    }

    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// An inbound datagram simply wraps a UDP socket.
pub struct SimpleInboundDatagram(pub UdpSocket);

impl InboundDatagram for SimpleInboundDatagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn InboundDatagramRecvHalf>,
        Box<dyn InboundDatagramSendHalf>,
    ) {
        let r = Arc::new(self.0);
        let s = r.clone();
        (
            Box::new(SimpleInboundDatagramRecvHalf(r)),
            Box::new(SimpleInboundDatagramSendHalf(s)),
        )
    }

    fn into_std(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        self.0.into_std()
    }
}

pub struct SimpleInboundDatagramRecvHalf(Arc<UdpSocket>);

#[async_trait]
impl InboundDatagramRecvHalf for SimpleInboundDatagramRecvHalf {
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> ProxyResult<(usize, DatagramSource, SocksAddr)> {
        let (n, src_addr) = self
            .0
            .recv_from(buf)
            .map_err(|e| ProxyError::DatagramFatal(e.into()))
            .await?;
        Ok((
            n,
            DatagramSource::new(src_addr, None),
            // This should be the target address which is decoded by proxy
            // protocol layers, since this is a plain UDP socket, we use an
            // empty address as a workaround to avoid introducing the Option type.
            // The final address would be override by a proxy handler anyway.
            SocksAddr::any_ipv4(),
        ))
    }
}

pub struct SimpleInboundDatagramSendHalf(Arc<UdpSocket>);

#[async_trait]
impl InboundDatagramSendHalf for SimpleInboundDatagramSendHalf {
    async fn send_to(
        &mut self,
        buf: &[u8],
        _src_addr: &SocksAddr,
        dst_addr: &SocketAddr,
    ) -> io::Result<usize> {
        self.0.send_to(buf, dst_addr).await
    }

    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn replies_carry_the_target_their_address_was_sent_as() {
        let targets = DomainTargetMap::new();
        let first_address = "127.0.0.1:41001".parse().unwrap();
        let second_address = "127.0.0.1:41002".parse().unwrap();
        let unknown_address = "127.0.0.1:41003".parse().unwrap();
        let first = SocksAddr::Domain("first.example".into(), 53);
        let second = SocksAddr::Domain("second.example".into(), 5353);
        let fallback = SocksAddr::any_ipv4();

        targets.record(first_address, first.clone()).await;
        targets.record(second_address, second.clone()).await;

        // The second reply arrives first.
        assert_eq!(targets.target(second_address, &fallback).await, second);
        assert_eq!(targets.target(first_address, &fallback).await, first);
        assert_eq!(targets.target(unknown_address, &fallback).await, fallback);
    }
}
