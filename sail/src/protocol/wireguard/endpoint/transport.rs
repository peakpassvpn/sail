//! Where an endpoint's WireGuard datagrams go: a UDP socket of its own,
//! opened with the endpoint's dial fields, or another outbound's datagram
//! path (`detour`).

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use async_trait::async_trait;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, Notify};
use tracing::{debug, warn};

use crate::adapter::{AnyOutboundHandler, OutboundDatagramRecvHalf, OutboundDatagramSendHalf};
use crate::app::SyncDnsClient;
use crate::net::DialOptions;
use crate::protocol::wireguard::Transport;
use crate::session::{Network, Session, SocksAddr};

/// A UDP socket. Bound to IPv6 it takes IPv4 peers too, as IPv4-mapped
/// addresses, which it maps back so that peers are known by one address.
pub struct SocketTransport {
    socket: UdpSocket,
    v6: bool,
}

impl SocketTransport {
    /// A socket on `port` (0: any), IPv6 and dual-stack when `v6`.
    pub async fn bind(port: u16, v6: bool, dial: &DialOptions) -> io::Result<Self> {
        let ip: IpAddr = if v6 {
            std::net::Ipv6Addr::UNSPECIFIED.into()
        } else {
            std::net::Ipv4Addr::UNSPECIFIED.into()
        };
        let socket = crate::net::new_udp_socket(&SocketAddr::new(ip, port), dial).await?;
        let v6 = socket.local_addr()?.is_ipv6();
        Ok(SocketTransport { socket, v6 })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

fn unmap(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(v4.into(), v6.port()),
            None => addr,
        },
        v4 => v4,
    }
}

#[async_trait]
impl Transport for SocketTransport {
    async fn send_to(&self, datagram: &[u8], dst: SocketAddr) -> io::Result<()> {
        let dst = match dst {
            SocketAddr::V4(v4) if self.v6 => {
                SocketAddr::new(v4.ip().to_ipv6_mapped().into(), v4.port())
            }
            other => other,
        };
        self.socket.send_to(datagram, dst).await.map(|_| ())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (n, src) = self.socket.recv_from(buf).await?;
        Ok((n, unmap(src)))
    }
}

/// How long a datagram waits for the detour to open.
const OPEN_WAIT: Duration = Duration::from_secs(5);

/// The datagram path of another outbound. It is opened when the first
/// datagram is received for, and opened again when it fails.
pub struct DetourTransport {
    detour: AnyOutboundHandler,
    dns_client: SyncDnsClient,
    /// What the path is opened for: the endpoint, and its first peer.
    session: Session,
    send: Mutex<Option<Box<dyn OutboundDatagramSendHalf>>>,
    recv: Mutex<Option<Box<dyn OutboundDatagramRecvHalf>>>,
    /// Tells the receiving side that the path failed while sending.
    failed: Notify,
    /// Tells senders waiting for the path that it is open.
    opened: Notify,
}

impl DetourTransport {
    pub fn new(
        tag: &str,
        detour: AnyOutboundHandler,
        dns_client: SyncDnsClient,
        first_peer: SocksAddr,
    ) -> Self {
        let session = Session {
            network: Network::Udp,
            destination: first_peer,
            inbound_tag: tag.to_string(),
            ..Default::default()
        };
        DetourTransport {
            detour,
            dns_client,
            session,
            send: Mutex::new(None),
            recv: Mutex::new(None),
            failed: Notify::new(),
            opened: Notify::new(),
        }
    }

    async fn open(&self) -> io::Result<()> {
        let transport = crate::net::connect_datagram_outbound(
            &self.session,
            self.dns_client.clone(),
            &self.detour,
        )
        .await?;
        let datagram = self
            .detour
            .datagram()?
            .handle(&self.session, transport)
            .await?;
        let (recv, send) = datagram.split();
        *self.recv.lock().await = Some(recv);
        *self.send.lock().await = Some(send);
        self.opened.notify_waiters();
        debug!(
            "wireguard [{}]: datagrams go through [{}]",
            self.session.inbound_tag,
            self.detour.tag()
        );
        Ok(())
    }
}

#[async_trait]
impl Transport for DetourTransport {
    async fn send_to(&self, datagram: &[u8], dst: SocketAddr) -> io::Result<()> {
        // Not open yet, or failed: the receiving side opens it. A handshake
        // waits for it a while rather than for WireGuard to send again.
        let opened = self.opened.notified();
        tokio::pin!(opened);
        opened.as_mut().enable();
        if self.send.lock().await.is_none() {
            let _ = tokio::time::timeout(OPEN_WAIT, opened).await;
        }
        let mut send = self.send.lock().await;
        let Some(half) = send.as_mut() else {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "the detour is not open",
            ));
        };
        if let Err(e) = half.send_to(datagram, &SocksAddr::Ip(dst)).await {
            *send = None;
            self.failed.notify_one();
            return Err(e);
        }
        Ok(())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        // Only the one receiving task takes this lock; `open` takes the
        // sending side's after it.
        loop {
            if self.recv.lock().await.is_none() {
                if let Err(e) = self.open().await {
                    warn!(
                        "wireguard [{}]: opening the detour [{}] failed: {}",
                        self.session.inbound_tag,
                        self.detour.tag(),
                        e
                    );
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    return Err(e);
                }
            }
            let mut recv = self.recv.lock().await;
            let Some(half) = recv.as_mut() else {
                continue;
            };
            let result = tokio::select! {
                r = half.recv_from(buf) => Some(r),
                () = self.failed.notified() => None,
            };
            match result {
                Some(Ok((n, SocksAddr::Ip(src)))) => return Ok((n, unmap(src))),
                Some(Ok((_, SocksAddr::Domain(domain, port)))) => {
                    debug!(
                        "wireguard [{}]: a datagram from {}:{}, not an address, is dropped",
                        self.session.inbound_tag, domain, port
                    );
                }
                Some(Err(e)) => {
                    *recv = None;
                    *self.send.lock().await = None;
                    return Err(e);
                }
                None => {
                    *recv = None;
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "the detour failed",
                    ));
                }
            }
        }
    }
}
