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

use super::accept::{self, AcceptBackoff};
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
            Box::new(StdOutboundDatagramRecvHalf(r, udp_backoff())),
            Box::new(StdOutboundDatagramSendHalf(s)),
        )
    }
}

pub struct StdOutboundDatagramRecvHalf(Arc<UdpSocket>, AcceptBackoff);

#[async_trait]
impl OutboundDatagramRecvHalf for StdOutboundDatagramRecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        let (n, a) = accept::recv_from(&self.0, buf, &mut self.1).await?;
        Ok((n, SocksAddr::Ip(unmapped_ipv4(a))))
    }
}

/// What an unconnected socket's receiving half waits out: an ICMP error
/// some target answered an earlier datagram with, which some systems
/// report here, is no reason to end the session with every other target.
fn udp_backoff() -> AcceptBackoff {
    AcceptBackoff::new("udp: receive")
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
    /// The outbound's, which say how its names resolve.
    dial: Arc<DialOptions>,
}

impl DomainResolveOutboundDatagram {
    pub fn new(inner: UdpSocket, dns_client: SyncDnsClient, dial: Arc<DialOptions>) -> Self {
        Self {
            inner,
            dns_client,
            dial,
        }
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
            Box::new(DomainResolveOutboundDatagramRecvHalf(r, udp_backoff())),
            Box::new(DomainResolveOutboundDatagramSendHalf(
                s,
                self.dns_client,
                self.dial,
            )),
        )
    }
}

pub struct DomainResolveOutboundDatagramRecvHalf(Arc<UdpSocket>, AcceptBackoff);

#[async_trait]
impl OutboundDatagramRecvHalf for DomainResolveOutboundDatagramRecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        let (n, a) = accept::recv_from(&self.0, buf, &mut self.1).await?;
        Ok((n, SocksAddr::Ip(unmapped_ipv4(a))))
    }
}

pub struct DomainResolveOutboundDatagramSendHalf(Arc<UdpSocket>, SyncDnsClient, Arc<DialOptions>);

#[async_trait]
impl OutboundDatagramSendHalf for DomainResolveOutboundDatagramSendHalf {
    async fn send_to(&mut self, buf: &[u8], target: &SocksAddr) -> io::Result<usize> {
        match target {
            SocksAddr::Domain(domain, port) => {
                let ips = self
                    .1
                    .load_full()
                    .lookup_dial(domain, &self.2)
                    .map_err(|e| io::Error::other(format!("lookup {} failed: {}", domain, e)))
                    .await?;
                let ip = ips.first().ok_or_else(|| io::Error::other("no results"))?;
                let addr = for_socket(&self.0, SocketAddr::new(*ip, *port));
                self.0.send_to(buf, addr).await
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
    destination: SocksAddr,
    dns_client: SyncDnsClient,
    /// The outbound's, which say how its names resolve.
    dial: Arc<DialOptions>,
    /// Answers come as from the domain they were sent to.
    unmap: bool,
}

impl DomainAssociatedOutboundDatagram {
    pub fn new(
        inner: UdpSocket,
        destination: SocksAddr,
        dns_client: SyncDnsClient,
        dial: Arc<DialOptions>,
    ) -> Self {
        DomainAssociatedOutboundDatagram {
            inner,
            destination,
            dns_client,
            dial,
            unmap: true,
        }
    }

    /// The same datagram, whose answers come as from the address a domain
    /// resolved to, not from the domain, when `disabled`: a rule's
    /// `udp_disable_domain_unmapping`.
    pub fn without_unmapping(mut self, disabled: bool) -> Self {
        self.unmap = !disabled;
        self
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
                self.unmap.then(|| targets.clone()),
                udp_backoff(),
            )),
            Box::new(DomainAssociatedOutboundDatagramSendHalf(
                s,
                self.dns_client,
                targets,
                self.dial,
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

/// `addr` as `socket` sends to it: an IPv4 address IPv4-mapped from an
/// IPv6 socket, which fails to send to it as it is.
fn for_socket(socket: &UdpSocket, addr: SocketAddr) -> SocketAddr {
    match (socket.local_addr(), addr) {
        (Ok(SocketAddr::V6(_)), SocketAddr::V4(v4)) => {
            SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port())
        }
        _ => addr,
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

/// With the targets answers come as from, unless unmapping is off.
pub struct DomainAssociatedOutboundDatagramRecvHalf(
    Arc<UdpSocket>,
    SocksAddr,
    Option<DomainTargetMap>,
    AcceptBackoff,
);

#[async_trait]
impl OutboundDatagramRecvHalf for DomainAssociatedOutboundDatagramRecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        let (n, address) = accept::recv_from(&self.0, buf, &mut self.3).await?;
        match &self.2 {
            Some(targets) => Ok((n, targets.target(address, &self.1).await)),
            None => Ok((n, SocksAddr::Ip(unmapped_ipv4(address)))),
        }
    }
}

/// A datagram of a connected socket, as a rule's `udp_connect` asks: it
/// sends to the one address it is connected to, whatever the target, and
/// hears from that one alone, reported as `from`.
pub struct ConnectedOutboundDatagram {
    inner: UdpSocket,
    from: SocksAddr,
}

impl ConnectedOutboundDatagram {
    pub fn new(inner: UdpSocket, from: SocksAddr) -> Self {
        Self { inner, from }
    }
}

impl OutboundDatagram for ConnectedOutboundDatagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let r = Arc::new(self.inner);
        let s = r.clone();
        (
            Box::new(ConnectedRecvHalf(r, self.from)),
            Box::new(ConnectedSendHalf(s)),
        )
    }
}

struct ConnectedRecvHalf(Arc<UdpSocket>, SocksAddr);

#[async_trait]
impl OutboundDatagramRecvHalf for ConnectedRecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        let n = self.0.recv(buf).await?;
        Ok((n, self.1.clone()))
    }
}

struct ConnectedSendHalf(Arc<UdpSocket>);

#[async_trait]
impl OutboundDatagramSendHalf for ConnectedSendHalf {
    async fn send_to(&mut self, buf: &[u8], _target: &SocksAddr) -> io::Result<usize> {
        self.0.send(buf).await
    }

    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct DomainAssociatedOutboundDatagramSendHalf(
    Arc<UdpSocket>,
    SyncDnsClient,
    DomainTargetMap,
    Arc<DialOptions>,
);

#[async_trait]
impl OutboundDatagramSendHalf for DomainAssociatedOutboundDatagramSendHalf {
    async fn send_to(&mut self, buf: &[u8], target: &SocksAddr) -> io::Result<usize> {
        let addr = match target {
            SocksAddr::Domain(domain, port) => {
                let ips = {
                    self.1
                        .load_full()
                        .lookup_dial(domain, &self.3)
                        .map_err(|e| io::Error::other(format!("lookup {} failed: {}", domain, e)))
                        .await?
                };
                // An IPv4 socket sends to IPv4 addresses only; a dual-stack
                // IPv6 one to either.
                let dual_stack = self.0.local_addr()?.is_ipv6();
                if let Some(ip) = ips.into_iter().find(|x| dual_stack || x.is_ipv4()) {
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
        self.2.record(addr, target.clone()).await;
        self.0.send_to(buf, for_socket(&self.0, addr)).await
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
            Box::new(SimpleInboundDatagramRecvHalf(r, udp_backoff())),
            Box::new(SimpleInboundDatagramSendHalf(s)),
        )
    }

    fn into_std(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        self.0.into_std()
    }
}

/// The socket an inbound listens on: what fails for one datagram, or for
/// want of buffers, is waited out, and the inbound serves on.
pub struct SimpleInboundDatagramRecvHalf(Arc<UdpSocket>, AcceptBackoff);

#[async_trait]
impl InboundDatagramRecvHalf for SimpleInboundDatagramRecvHalf {
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> ProxyResult<(usize, DatagramSource, SocksAddr)> {
        let (n, src_addr) = accept::recv_from(&self.0, buf, &mut self.1)
            .await
            .map_err(|e| ProxyError::DatagramFatal(e.into()))?;
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

    #[tokio::test]
    async fn a_dual_stack_socket_sends_to_an_ipv4_address() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket = UdpSocket::bind("[::]:0").await.unwrap();
        let to = for_socket(&socket, peer.local_addr().unwrap());
        assert!(to.is_ipv6());
        socket.send_to(b"ping", to).await.unwrap();
        let mut buf = [0u8; 4];
        let (n, _) = peer.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping");
        let v4 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert_eq!(
            for_socket(&v4, peer.local_addr().unwrap()),
            peer.local_addr().unwrap()
        );
    }
}
