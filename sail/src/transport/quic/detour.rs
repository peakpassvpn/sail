//! A UDP socket for quinn over the datagrams of an outbound, so that what
//! runs on QUIC -- Hysteria2, TUIC, the quic transport, DNS over QUIC and
//! HTTP/3 -- can dial through a `detour`.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};

use tokio::sync::mpsc;
use tracing::debug;

use crate::adapter::AnyOutboundDatagram;
use crate::session::SocksAddr;

/// Packets queued each way. Past that, packets are dropped, as a socket
/// buffer would drop them, and QUIC sends them again.
const QUEUE: usize = 256;
/// The largest datagram.
const MAX_DATAGRAM: usize = 65535;

/// The address quinn is told a server named by a domain is at: it wants
/// an address, and the detour wants the name, which resolves at its far
/// end. From TEST-NET-2 (RFC 5737), which is never anyone's.
const NAMED: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));

/// Talks to one server, `to`, through the datagrams of an outbound.
///
/// quinn knows the server as `peer`: its address, or a stand-in for its
/// name. Datagrams to the peer's address go to the server, on whatever
/// port quinn sends to (Hysteria2's port hopping changes it); datagrams
/// from the far end come back as from the peer, whatever address the
/// outbound reports them from, for quinn drops what comes from an address
/// it does not know.
pub struct DetourSocket {
    peer: SocketAddr,
    tx: mpsc::Sender<(Vec<u8>, SocksAddr)>,
    rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    /// Where datagrams to the peer's address go, but for the port.
    to: SocksAddr,
    tasks: [tokio::task::AbortHandle; 2],
}

impl DetourSocket {
    pub fn new(datagram: AnyOutboundDatagram, to: SocksAddr) -> Self {
        let peer = match &to {
            SocksAddr::Ip(addr) => *addr,
            SocksAddr::Domain(_, port) => SocketAddr::new(NAMED, *port),
        };
        let (mut recv_half, mut send_half) = datagram.split();
        let (tx, mut send_rx) = mpsc::channel::<(Vec<u8>, SocksAddr)>(QUEUE);
        let (recv_tx, rx) = mpsc::channel::<Vec<u8>>(QUEUE);
        let sender = tokio::spawn(async move {
            while let Some((packet, dst)) = send_rx.recv().await {
                if let Err(e) = send_half.send_to(&packet, &dst).await {
                    debug!("send quic packet through outbound failed: {}", e);
                    break;
                }
            }
            let _ = send_half.close().await;
        });
        let receiver = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            loop {
                match recv_half.recv_from(&mut buf).await {
                    Ok((n, _)) => match recv_tx.try_send(buf[..n].to_vec()) {
                        Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
                        Err(mpsc::error::TrySendError::Closed(_)) => break,
                    },
                    Err(e) => {
                        debug!("receive quic packet through outbound failed: {}", e);
                        break;
                    }
                }
            }
        });
        Self {
            peer,
            tx,
            rx: Mutex::new(rx),
            to,
            tasks: [sender.abort_handle(), receiver.abort_handle()],
        }
    }

    /// The address quinn is to connect to.
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Where a datagram quinn sends to `destination` goes.
    fn destination(&self, destination: SocketAddr) -> SocksAddr {
        if destination.ip() != self.peer.ip() {
            return SocksAddr::Ip(destination);
        }
        match &self.to {
            SocksAddr::Ip(_) => SocksAddr::Ip(destination),
            SocksAddr::Domain(name, _) => SocksAddr::Domain(name.clone(), destination.port()),
        }
    }
}

impl Drop for DetourSocket {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl fmt::Debug for DetourSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DetourSocket")
            .field("to", &self.to)
            .finish()
    }
}

/// Sending never waits: a full queue drops the packet.
#[derive(Debug)]
struct AlwaysWritable;

impl quinn::UdpPoller for AlwaysWritable {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl quinn::AsyncUdpSocket for DetourSocket {
    fn create_io_poller(self: std::sync::Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> io::Result<()> {
        let packet = (
            transmit.contents.to_vec(),
            self.destination(transmit.destination),
        );
        match self.tx.try_send(packet) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "outbound datagram closed",
            )),
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let (Some(buf), Some(meta)) = (bufs.first_mut(), meta.first_mut()) else {
            return Poll::Ready(Ok(0));
        };
        let mut rx = self.rx.lock().unwrap_or_else(|e| e.into_inner());
        match rx.poll_recv(cx) {
            Poll::Ready(Some(packet)) => {
                let n = packet.len().min(buf.len());
                buf[..n].copy_from_slice(&packet[..n]);
                meta.addr = self.peer;
                meta.len = n;
                meta.stride = n;
                meta.ecn = None;
                meta.dst_ip = None;
                Poll::Ready(Ok(1))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "outbound datagram closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(match self.peer {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        })
    }
}
