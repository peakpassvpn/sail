//! A UDP socket for quinn over the datagrams of an outbound, so that QUIC
//! upstreams can be reached through a proxy.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
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

/// Talks to one peer, `peer`, whatever address the outbound reports its
/// packets from.
pub(super) struct DatagramSocket {
    peer: SocketAddr,
    tx: mpsc::Sender<Vec<u8>>,
    rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    tasks: [tokio::task::AbortHandle; 2],
}

impl DatagramSocket {
    pub fn new(datagram: AnyOutboundDatagram, peer: SocketAddr) -> Self {
        let (mut recv_half, mut send_half) = datagram.split();
        let (tx, mut send_rx) = mpsc::channel::<Vec<u8>>(QUEUE);
        let (recv_tx, rx) = mpsc::channel::<Vec<u8>>(QUEUE);
        let dst = SocksAddr::from(peer);
        let sender = tokio::spawn(async move {
            while let Some(packet) = send_rx.recv().await {
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
            tasks: [sender.abort_handle(), receiver.abort_handle()],
        }
    }
}

impl Drop for DatagramSocket {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl fmt::Debug for DatagramSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatagramSocket")
            .field("peer", &self.peer)
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

impl quinn::AsyncUdpSocket for DatagramSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> io::Result<()> {
        match self.tx.try_send(transmit.contents.to_vec()) {
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
