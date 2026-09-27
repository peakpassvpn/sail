//! The endpoint as an outbound: TCP connections the stack opens, and UDP
//! it originates, into the tunnel.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::adapter::{
    AnyOutboundDatagram, AnyOutboundTransport, AnyStream, DatagramTransportType, OutboundConnect,
    OutboundDatagram, OutboundDatagramHandler, OutboundDatagramRecvHalf, OutboundDatagramSendHalf,
    OutboundStreamHandler,
};
use crate::session::{Session, SocksAddr};

use super::{Running, Shared};

/// Datagrams queued for one outbound UDP session.
const FLOW_QUEUE: usize = 256;

impl Shared {
    /// The addresses `destination` is reached at through the tunnel: of the
    /// families the endpoint has an address of, in the order the DNS gives
    /// them.
    async fn targets(
        &self,
        running: &Running,
        destination: &SocksAddr,
    ) -> io::Result<Vec<SocketAddr>> {
        let addrs = match destination {
            SocksAddr::Ip(addr) => vec![*addr],
            SocksAddr::Domain(host, port) => self
                .dns_client
                .load_full()
                .lookup(host)
                .await
                .map_err(|e| io::Error::other(format!("lookup {} failed: {}", host, e)))?
                .into_iter()
                .map(|ip| SocketAddr::new(ip, *port))
                .collect(),
        };
        let usable: Vec<SocketAddr> = addrs
            .iter()
            .copied()
            .filter(|a| running.local_for(a.ip()).is_some())
            .collect();
        if usable.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!(
                    "endpoint [{}] has no address of the family of {}",
                    self.tag, destination
                ),
            ));
        }
        Ok(usable)
    }
}

pub(super) struct StreamHandler(pub(super) Arc<Shared>);

#[async_trait]
impl OutboundStreamHandler for StreamHandler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        _stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        let running = self.0.running().await?;
        let mut last = None;
        for target in self.0.targets(&running, &sess.destination).await? {
            let local = SocketAddr::new(
                running.local_for(target.ip()).expect("filtered by family"),
                0,
            );
            let mut control = running.control.clone();
            match tokio::time::timeout(self.0.dial.connect_timeout, control.connect(local, target))
                .await
            {
                Ok(Ok(conn)) => return Ok(Box::new(conn.stream)),
                Ok(Err(e)) => last = Some(e),
                Err(_) => {
                    last = Some(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("connect {} through [{}] timed out", target, self.0.tag),
                    ))
                }
            }
        }
        Err(last.unwrap_or_else(|| io::Error::other("no address to connect to")))
    }
}

pub(super) struct DatagramHandler(pub(super) Arc<Shared>);

#[async_trait]
impl OutboundDatagramHandler for DatagramHandler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Unreliable
    }

    async fn handle<'a>(
        &'a self,
        _sess: &'a Session,
        _transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        let running = self.0.running().await?;
        let (tx, rx) = mpsc::channel(FLOW_QUEUE);
        Ok(Box::new(Datagram {
            send: SendHalf {
                shared: self.0.clone(),
                running,
                tx,
                v4: None,
                v6: None,
            },
            recv: RecvHalf(rx),
        }))
    }
}

struct Datagram {
    send: SendHalf,
    recv: RecvHalf,
}

impl OutboundDatagram for Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        (Box::new(self.recv), Box::new(self.send))
    }
}

struct RecvHalf(mpsc::Receiver<(SocketAddr, Vec<u8>)>);

#[async_trait]
impl OutboundDatagramRecvHalf for RecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        let (source, payload) = self.0.recv().await.ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "the endpoint's flow closed")
        })?;
        let n = payload.len().min(buf.len());
        buf[..n].copy_from_slice(&payload[..n]);
        Ok((n, SocksAddr::Ip(source)))
    }
}

/// Sends from one local address per family, each taken when first used,
/// and given back when the session ends.
struct SendHalf {
    shared: Arc<Shared>,
    running: Arc<Running>,
    tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    v4: Option<SocketAddr>,
    v6: Option<SocketAddr>,
}

impl SendHalf {
    fn local(&mut self, remote: IpAddr) -> io::Result<SocketAddr> {
        let ip = self.running.local_for(remote).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!(
                    "endpoint [{}] has no address for {}",
                    self.shared.tag, remote
                ),
            )
        })?;
        let slot = if remote.is_ipv4() {
            &mut self.v4
        } else {
            &mut self.v6
        };
        if let Some(local) = slot {
            return Ok(*local);
        }
        let local = self.running.bind(ip, self.tx.clone())?;
        *slot = Some(local);
        Ok(local)
    }

    fn release(&mut self) {
        for local in [self.v4.take(), self.v6.take()].into_iter().flatten() {
            self.running.release(&local);
        }
    }
}

#[async_trait]
impl OutboundDatagramSendHalf for SendHalf {
    async fn send_to(&mut self, buf: &[u8], dst: &SocksAddr) -> io::Result<usize> {
        let target = self.shared.targets(&self.running, dst).await?[0];
        let local = self.local(target.ip())?;
        let mut control = self.running.control.clone();
        control.send_udp(local, target, buf.to_vec()).await?;
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        self.release();
        Ok(())
    }
}

impl Drop for SendHalf {
    fn drop(&mut self) {
        self.release();
    }
}
