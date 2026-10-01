//! Where an endpoint's WireGuard datagrams go: a UDP socket of its own,
//! opened with the endpoint's dial fields, or the datagrams of its dialer's
//! `detour`.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::net::UdpSocket;
use tokio::sync::{watch, Mutex, Notify};
use tracing::{debug, warn};

use crate::adapter::{OutboundDatagramRecvHalf, OutboundDatagramSendHalf};
use crate::app::SyncDnsClient;
use crate::net::Dialer;
use crate::protocol::wireguard::Transport;
use crate::session::{Network, Session, SocksAddr};

/// The socket buffers asked for, each way.
const SOCKET_BUFFER: usize = 7 << 20;

/// How long a rebind waits for the old socket to be let go of, so that the
/// new one can bind its port.
const RELEASE_WAIT: Duration = Duration::from_secs(1);

/// A UDP socket. Bound to IPv6 it takes IPv4 peers too, as IPv4-mapped
/// addresses, which it maps back so that peers are known by one address.
pub struct SocketTransport {
    /// None while it is bound anew, or when that failed.
    socket: watch::Sender<Option<Arc<UdpSocket>>>,
    v6: bool,
    /// The port it has, which a rebind binds again.
    port: AtomicU16,
    /// Whether the port was configured, and so must be the one bound.
    fixed: bool,
    dialer: Dialer,
    rebinding: Mutex<()>,
}

impl SocketTransport {
    /// A socket on `port` (0: any), IPv6 and dual-stack when `v6`.
    pub async fn bind(port: u16, v6: bool, dialer: &Dialer) -> io::Result<Self> {
        let socket = open(port, v6, dialer).await?;
        let local = socket.local_addr()?;
        Ok(SocketTransport {
            socket: watch::Sender::new(Some(Arc::new(socket))),
            v6: local.is_ipv6(),
            port: AtomicU16::new(local.port()),
            fixed: port != 0,
            dialer: dialer.clone(),
            rebinding: Mutex::new(()),
        })
    }

    fn socket(&self) -> io::Result<Arc<UdpSocket>> {
        self.socket
            .borrow()
            .clone()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "the socket is being bound"))
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket()?.local_addr()
    }
}

async fn open(port: u16, v6: bool, dialer: &Dialer) -> io::Result<UdpSocket> {
    let ip: IpAddr = if v6 {
        std::net::Ipv6Addr::UNSPECIFIED.into()
    } else {
        std::net::Ipv4Addr::UNSPECIFIED.into()
    };
    let socket = dialer.udp_socket(&SocketAddr::new(ip, port)).await?;
    set_buffers(&socket);
    Ok(socket)
}

/// Room for a burst of the tunnel's packets, as wireguard-go asks for:
/// beyond `net.core.rmem_max` where the process may (Linux, with
/// CAP_NET_ADMIN), else what the system grants.
fn set_buffers(socket: &UdpSocket) {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let size = SOCKET_BUFFER as libc::c_int;
        let mut forced = true;
        for option in [libc::SO_RCVBUFFORCE, libc::SO_SNDBUFFORCE] {
            // SAFETY: setsockopt with an int option on a socket we own.
            let r = unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    option,
                    &size as *const libc::c_int as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            forced &= r == 0;
        }
        if forced {
            return;
        }
    }
    let sock = socket2::SockRef::from(socket);
    for result in [
        sock.set_recv_buffer_size(SOCKET_BUFFER),
        sock.set_send_buffer_size(SOCKET_BUFFER),
    ] {
        if let Err(e) = result {
            debug!("wireguard: setting a socket buffer size failed: {}", e);
        }
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
        self.socket()?.send_to(datagram, dst).await.map(|_| ())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut current = self.socket.subscribe();
        loop {
            // Held only while no rebind wants it gone.
            let socket = current.borrow_and_update().clone();
            let Some(socket) = socket else {
                current
                    .changed()
                    .await
                    .map_err(|_| io::Error::from(io::ErrorKind::NotConnected))?;
                continue;
            };
            tokio::select! {
                r = socket.recv_from(buf) => {
                    let (n, src) = r?;
                    return Ok((n, unmap(src)));
                }
                _ = current.changed() => {}
            }
        }
    }

    /// Closes the socket and binds its port again with the dialer, as
    /// wireguard-go's StdNetBind, on whichever interface the dialer now
    /// picks. A port not configured that is taken meanwhile gives way to
    /// any.
    async fn rebind(&self) -> io::Result<()> {
        let _rebinding = self.rebinding.lock().await;
        if let Some(old) = self.socket.send_replace(None) {
            let old = Arc::downgrade(&old);
            let deadline = tokio::time::Instant::now() + RELEASE_WAIT;
            while old.strong_count() > 0 && tokio::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        let port = self.port.load(Ordering::Relaxed);
        let socket = match open(port, self.v6, &self.dialer).await {
            Err(e) if !self.fixed => {
                debug!("wireguard: binding port {} again: {}", port, e);
                open(0, self.v6, &self.dialer).await?
            }
            socket => socket?,
        };
        let local = socket.local_addr()?;
        self.port.store(local.port(), Ordering::Relaxed);
        debug!("wireguard: bound anew on udp {}", local);
        self.socket.send_replace(Some(Arc::new(socket)));
        Ok(())
    }
}

/// How long a datagram waits for the detour to open.
const OPEN_WAIT: Duration = Duration::from_secs(5);

/// The datagrams of the dialer's detour. They are opened when the first
/// datagram is received for, and opened again when they fail.
pub struct DetourTransport {
    dialer: Dialer,
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
        dialer: Dialer,
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
            dialer,
            dns_client,
            session,
            send: Mutex::new(None),
            recv: Mutex::new(None),
            failed: Notify::new(),
            opened: Notify::new(),
        }
    }

    async fn open(&self) -> io::Result<()> {
        let datagram = self
            .dialer
            .datagram(
                &self.dns_client,
                Some(&self.session),
                &self.session.destination,
            )
            .await?;
        let (recv, send) = datagram.split();
        *self.recv.lock().await = Some(recv);
        *self.send.lock().await = Some(send);
        self.opened.notify_waiters();
        debug!(
            "wireguard [{}]: datagrams go through [{}]",
            self.session.inbound_tag,
            self.dialer.detour().unwrap_or_default()
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
                        self.dialer.detour().unwrap_or_default(),
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

    /// Lets the detour's datagrams go, as sing-box's ClientBind: the
    /// receiving side opens them again.
    async fn rebind(&self) -> io::Result<()> {
        *self.send.lock().await = None;
        self.failed.notify_one();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use tokio::sync::mpsc;
    use tokio::time::timeout;

    use super::*;
    use crate::protocol::wireguard::crypto;
    use crate::protocol::wireguard::shell::InboundPacket;
    use crate::protocol::wireguard::{Device, DeviceConfig, PeerConfig, PeerId, WireGuard};

    fn ipv4_udp(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let total = 28 + payload.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[8] = 64;
        p[9] = 17;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        p[28..].copy_from_slice(payload);
        p
    }

    fn device(private: [u8; 32], peer_public: [u8; 32], peer_ip: &str) -> (Device, PeerId) {
        let mut device = Device::new(
            DeviceConfig::new(private),
            tokio::time::Instant::now().into_std(),
        );
        let mut peer = PeerConfig::new(peer_public);
        peer.allowed_ips = vec![(peer_ip.parse::<IpAddr>().unwrap(), 32)];
        let id = device.add_peer(peer).unwrap();
        (device, id)
    }

    /// A packet each way, `n` its payload.
    async fn exchange(
        (a, rx_a): (&WireGuard, &mut mpsc::Receiver<InboundPacket>),
        (b, rx_b): (&WireGuard, &mut mpsc::Receiver<InboundPacket>),
        n: u8,
    ) {
        let p = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], &[n]);
        a.send(&p).await.unwrap();
        let got = timeout(Duration::from_secs(5), rx_b.recv()).await;
        assert_eq!(got.unwrap().unwrap().packet, p);
        let p = ipv4_udp([10, 0, 0, 2], [10, 0, 0, 1], &[n]);
        b.send(&p).await.unwrap();
        let got = timeout(Duration::from_secs(5), rx_a.recv()).await;
        assert_eq!(got.unwrap().unwrap().packet, p);
    }

    /// A rebind closes the socket and binds its port again; the tunnel,
    /// its receive pending across it, goes on with the session it had.
    #[tokio::test]
    async fn a_rebind_keeps_the_port_and_the_session() {
        let ka = crypto::generate_private_key();
        let kb = crypto::generate_private_key();
        let transport = Arc::new(
            SocketTransport::bind(0, false, &Dialer::system())
                .await
                .unwrap(),
        );
        let port = transport.local_addr().unwrap().port();
        let (device_a, pa) = device(ka, crypto::public_key(&kb), "10.0.0.2");
        let (a, mut rx_a) = WireGuard::spawn(device_a, transport.clone());
        let b_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b_addr = b_socket.local_addr().unwrap();
        let (b, mut rx_b) = WireGuard::spawn(
            device(kb, crypto::public_key(&ka), "10.0.0.1").0,
            Arc::new(b_socket),
        );
        a.with_device(|d, _| (d.set_endpoint(pa, b_addr).unwrap(), Vec::new()))
            .await;

        exchange((&a, &mut rx_a), (&b, &mut rx_b), 1).await;
        let handshake = a
            .with_device(|d, _| (d.peer_stats(pa).unwrap().last_handshake, Vec::new()))
            .await;
        assert!(handshake.is_some());

        let old = Arc::downgrade(&transport.socket().unwrap());
        transport.rebind().await.unwrap();
        assert!(old.upgrade().is_none(), "the old socket is still open");
        assert_eq!(transport.local_addr().unwrap().port(), port);

        exchange((&a, &mut rx_a), (&b, &mut rx_b), 2).await;
        let stats = a
            .with_device(|d, _| (d.peer_stats(pa).unwrap(), Vec::new()))
            .await;
        assert!(stats.has_session);
        assert_eq!(stats.last_handshake, handshake);
    }
}
