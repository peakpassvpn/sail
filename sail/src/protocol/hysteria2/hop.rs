//! Port hopping: the client moves to another of the server's ports, from a
//! new local socket, every so often, while quinn keeps talking to one
//! address.
//!
//! quinn sees a single server address, the first port. Datagrams to it go
//! to the current port instead, and datagrams from any port of the server
//! come back as from it. After a hop the previous socket is still read, for
//! what was in flight to it.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};

use anyhow::{anyhow, Result};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use rand::seq::SliceRandom;

/// The server's ports, from sing-box's `server_ports`: each a port or a
/// range, "20000:30000" (or "20000-30000").
pub fn parse_ports(specs: &[String]) -> Result<Vec<u16>> {
    let mut ports = Vec::new();
    for spec in specs {
        let parse = |s: &str| {
            s.trim()
                .parse::<u16>()
                .ok()
                .filter(|p| *p != 0)
                .ok_or_else(|| anyhow!("invalid port \"{}\"", s))
        };
        match spec.split_once([':', '-']) {
            Some((start, end)) => {
                let (start, end) = (parse(start)?, parse(end)?);
                if start > end {
                    return Err(anyhow!("invalid port range \"{}\"", spec));
                }
                ports.extend(start..=end);
            }
            None => ports.push(parse(spec)?),
        }
    }
    ports.sort_unstable();
    ports.dedup();
    if ports.is_empty() {
        return Err(anyhow!("no ports"));
    }
    Ok(ports)
}

struct State {
    generation: u64,
    port: u16,
    current: Arc<dyn AsyncUdpSocket>,
    previous: Option<Arc<dyn AsyncUdpSocket>>,
}

struct Snapshot {
    generation: u64,
    port: u16,
    current: Arc<dyn AsyncUdpSocket>,
    previous: Option<Arc<dyn AsyncUdpSocket>>,
}

pub struct HopSocket {
    server: IpAddr,
    ports: Vec<u16>,
    /// The address quinn talks to.
    virtual_addr: SocketAddr,
    state: RwLock<State>,
}

impl fmt::Debug for HopSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HopSocket")
            .field("virtual_addr", &self.virtual_addr)
            .finish()
    }
}

impl HopSocket {
    /// Starts on a random one of `ports`, which must not be empty.
    pub fn new(server: IpAddr, ports: Vec<u16>, socket: Arc<dyn AsyncUdpSocket>) -> Self {
        let port = random_port(&ports, None);
        Self {
            server,
            virtual_addr: SocketAddr::new(server, ports[0]),
            ports,
            state: RwLock::new(State {
                generation: 0,
                port,
                current: socket,
                previous: None,
            }),
        }
    }

    pub fn virtual_addr(&self) -> SocketAddr {
        self.virtual_addr
    }

    /// Moves to another port, sending from `socket` from now on.
    pub fn hop(&self, socket: Arc<dyn AsyncUdpSocket>) {
        let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
        let port = random_port(&self.ports, Some(state.port));
        let previous = std::mem::replace(&mut state.current, socket);
        state.previous = Some(previous);
        state.port = port;
        state.generation += 1;
    }

    /// The state as it is, not held locked.
    fn sockets(&self) -> Snapshot {
        let state = self.state.read().unwrap_or_else(|e| e.into_inner());
        Snapshot {
            generation: state.generation,
            port: state.port,
            current: state.current.clone(),
            previous: state.previous.clone(),
        }
    }

    fn poll_one(
        &self,
        socket: &Arc<dyn AsyncUdpSocket>,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        match socket.poll_recv(cx, bufs, meta) {
            Poll::Ready(Ok(n)) => {
                for meta in meta.iter_mut().take(n) {
                    if meta.addr.ip() == self.server
                        || meta.addr.ip().to_canonical() == self.server.to_canonical()
                    {
                        meta.addr = self.virtual_addr;
                    }
                }
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }
}

fn random_port(ports: &[u16], not: Option<u16>) -> u16 {
    let mut rng = rand::thread_rng();
    if ports.len() > 1 {
        loop {
            let port = *ports.choose(&mut rng).unwrap_or(&ports[0]);
            if Some(port) != not {
                return port;
            }
        }
    }
    ports[0]
}

impl AsyncUdpSocket for HopSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(HopPoller {
            socket: self,
            generation: None,
            inner: None,
        })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let Snapshot { port, current, .. } = self.sockets();
        let destination = if transmit.destination == self.virtual_addr {
            SocketAddr::new(self.server, port)
        } else {
            transmit.destination
        };
        current.try_send(&Transmit {
            destination,
            ..transmit.clone()
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let Snapshot {
            current, previous, ..
        } = self.sockets();
        if let Poll::Ready(r) = self.poll_one(&current, cx, bufs, meta) {
            return Poll::Ready(r);
        }
        match previous {
            // An error of the old socket is no reason to stop.
            Some(previous) => match self.poll_one(&previous, cx, bufs, meta) {
                Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
                _ => Poll::Pending,
            },
            None => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.sockets().current.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.sockets().current.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.sockets().current.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.sockets().current.may_fragment()
    }
}

/// Waits on whichever socket is current, following hops.
struct HopPoller {
    socket: Arc<HopSocket>,
    generation: Option<u64>,
    inner: Option<Pin<Box<dyn UdpPoller>>>,
}

impl fmt::Debug for HopPoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HopPoller").finish()
    }
}

impl UdpPoller for HopPoller {
    fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let Snapshot {
            generation,
            current,
            ..
        } = self.socket.sockets();
        let this = &mut *self;
        if this.generation != Some(generation) || this.inner.is_none() {
            this.generation = Some(generation);
            this.inner = Some(current.create_io_poller());
        }
        match this.inner.as_mut() {
            Some(inner) => inner.as_mut().poll_writable(cx),
            None => Poll::Ready(Ok(())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_parse_from_ranges_and_single_ports() {
        let specs = [
            "443".to_string(),
            "20000:20002".into(),
            "30000-30001".into(),
        ];
        assert_eq!(
            parse_ports(&specs).unwrap(),
            vec![443, 20000, 20001, 20002, 30000, 30001]
        );
        assert!(parse_ports(&["2:1".to_string()]).is_err());
        assert!(parse_ports(&["0".to_string()]).is_err());
        assert!(parse_ports(&["x".to_string()]).is_err());
        assert!(parse_ports(&[]).is_err());
    }

    #[test]
    fn a_hop_takes_another_port() {
        let ports = [1u16, 2, 3];
        for _ in 0..50 {
            assert_ne!(random_port(&ports, Some(2)), 2);
        }
        assert_eq!(random_port(&[7], Some(7)), 7);
    }

    /// A connection keeps going across hops: between a server's own port,
    /// and a second port relayed to it.
    #[tokio::test]
    async fn a_connection_survives_hops() {
        use crate::protocol::hysteria2::quic;
        use std::net::Ipv4Addr;

        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let alpns = quic::alpns(None);
        let config = quic::server_config(&cert.pem(), &key_pair.serialize_pem(), &alpns).unwrap();
        let server = quinn::Endpoint::new(
            quinn_btls::helpers::default_endpoint_config(),
            Some(config),
            std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();
        let server_addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            while let Some(incoming) = server.accept().await {
                tokio::spawn(async move {
                    let conn = incoming.await.unwrap();
                    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                        tokio::spawn(async move {
                            let _ = tokio::io::copy(&mut recv, &mut send).await;
                            let _ = send.finish();
                        });
                    }
                });
            }
        });

        // The second port: a relay to the first.
        let relay = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let upstream = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay_port = relay.local_addr().unwrap().port();
        let client_addr = Arc::new(std::sync::Mutex::new(None));
        {
            let (relay, upstream, client_addr) =
                (relay.clone(), upstream.clone(), client_addr.clone());
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                while let Ok((n, from)) = relay.recv_from(&mut buf).await {
                    *client_addr.lock().unwrap() = Some(from);
                    let _ = upstream.send_to(&buf[..n], server_addr).await;
                }
            });
        }
        {
            let (relay, upstream, client_addr) =
                (relay.clone(), upstream.clone(), client_addr.clone());
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                while let Ok((n, _)) = upstream.recv_from(&mut buf).await {
                    let to = *client_addr.lock().unwrap();
                    if let Some(to) = to {
                        let _ = relay.send_to(&buf[..n], to).await;
                    }
                }
            });
        }

        let new_socket =
            || quic::wrap_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap(), None).unwrap();
        let hop = Arc::new(HopSocket::new(
            Ipv4Addr::LOCALHOST.into(),
            vec![server_addr.port(), relay_port],
            new_socket(),
        ));
        let mut client = quinn::Endpoint::new_with_abstract_socket(
            quinn_btls::helpers::default_endpoint_config(),
            None,
            hop.clone(),
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();
        let crypto = quic::client_crypto(Some(&cert.pem()), false, &alpns).unwrap();
        client.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
        let conn = client
            .connect(hop.virtual_addr(), "localhost")
            .unwrap()
            .await
            .unwrap();

        for round in 0..4u8 {
            let (mut send, mut recv) = conn.open_bi().await.unwrap();
            send.write_all(&[round; 3000]).await.unwrap();
            send.finish().unwrap();
            let echoed =
                tokio::time::timeout(std::time::Duration::from_secs(5), recv.read_to_end(1 << 16))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(echoed, vec![round; 3000]);
            hop.hop(new_socket());
        }
    }
}
