//! An association's UDP relay: the socket bound for one `UDP ASSOCIATE`,
//! taking the client's datagrams only, and ending with its control
//! connection.

use std::convert::TryFrom;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::anyhow;
use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;

use super::association::{ClientFilter, Slot};
use crate::{
    adapter::*,
    net::accept::AcceptBackoff,
    session::{DatagramSource, SocksAddr, SocksAddrWireType, UdpAssociationOwner},
};

/// A relay socket on `ip`, on a port the system picks, bound as the
/// inbound's listener binds its sockets, with their `mark`.
pub fn bind(ip: IpAddr, mark: Option<u32>) -> io::Result<UdpSocket> {
    let socket = crate::net::bind_udp(&SocketAddr::new(ip, 0))?;
    socket.set_nonblocking(true)?;
    crate::net::fit_largest_datagram(socket2::SockRef::from(&socket))?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Some(mark) = mark {
        socket2::SockRef::from(&socket).set_mark(mark)?;
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let _ = mark;
    UdpSocket::from_std(socket)
}

/// The socket, and the association's place, which is free again once both
/// halves have let the socket go.
struct Shared {
    socket: UdpSocket,
    _slot: Slot,
}

/// One association's relay.
pub struct Relay {
    shared: Arc<Shared>,
    control: AnyStream,
    filter: ClientFilter,
    user: Option<crate::user::UserRef>,
}

impl Relay {
    /// The relay of `socket`, for the client `filter` lets through, who
    /// authenticated as `user` on `control`. The association lasts until
    /// `control` closes.
    pub fn new(
        socket: UdpSocket,
        slot: Slot,
        control: AnyStream,
        filter: ClientFilter,
        user: Option<crate::user::UserRef>,
    ) -> Self {
        Relay {
            shared: Arc::new(Shared {
                socket,
                _slot: slot,
            }),
            control,
            filter,
            user,
        }
    }
}

impl InboundDatagram for Relay {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn InboundDatagramRecvHalf>,
        Box<dyn InboundDatagramSendHalf>,
    ) {
        (
            Box::new(RecvHalf {
                shared: self.shared.clone(),
                control: self.control,
                filter: self.filter,
                user: self.user,
                owner: UdpAssociationOwner::new(),
                packet: Vec::new(),
                backoff: AcceptBackoff::new("socks: udp association: receive"),
            }),
            Box::new(SendHalf(self.shared)),
        )
    }

    fn into_std(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "a socks udp relay is not a plain socket",
        ))
    }
}

struct RecvHalf {
    shared: Arc<Shared>,
    control: AnyStream,
    filter: ClientFilter,
    user: Option<crate::user::UserRef>,
    /// Keeps the association alive; the NAT manager ends its sessions when
    /// this half, and with it the owner, goes.
    owner: UdpAssociationOwner,
    packet: Vec<u8>,
    /// Waits out what fails for one datagram, or for want of buffers.
    backoff: AcceptBackoff,
}

#[async_trait]
impl InboundDatagramRecvHalf for RecvHalf {
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> ProxyResult<(usize, DatagramSource, SocksAddr)> {
        let RecvHalf {
            shared,
            control,
            filter,
            user,
            owner,
            packet,
            backoff,
        } = self;
        packet.resize(buf.len() + 512, 0);
        let mut ignored = [0u8; 512];
        loop {
            tokio::select! {
                // The socket first: a client that sends its last datagrams
                // and closes the control connection at once has them
                // queued here before the close arrives, and they are
                // relayed, not dropped by which branch a fair select
                // happens to pick.
                biased;
                received = shared.socket.recv_from(packet) => {
                    let (n, src) = match received {
                        Ok(r) => {
                            backoff.succeeded();
                            r
                        }
                        // An unreachable client, as some systems report
                        // on an unconnected socket, or no buffers for the
                        // moment: waited out.
                        Err(e) => {
                            backoff
                                .failed(e)
                                .await
                                .map_err(|e| ProxyError::DatagramFatal(e.into()))?;
                            continue;
                        }
                    };
                    if !filter.accept(src) {
                        return Err(ProxyError::DatagramWarn(anyhow!(
                            "datagram from {} is not the client's, dropped",
                            src
                        )));
                    }
                    let (n, dst) = unwrap(&packet[..n], buf)?;
                    let src = DatagramSource::new(src, None)
                        .with_user(user.clone())
                        .with_association(Some(owner.association().clone()));
                    return Ok((n, src, dst));
                }
                read = control.read(&mut ignored) => match read {
                    // What the client sends on it meanwhile means nothing.
                    Ok(n) if n > 0 => continue,
                    _ => {
                        return Err(ProxyError::DatagramFatal(anyhow!(
                            "udp association ended with its control connection"
                        )));
                    }
                },
            }
        }
    }
}

/// The payload of a SOCKS5 UDP request `packet`, copied into `buf`, and
/// where it goes.
fn unwrap(packet: &[u8], buf: &mut [u8]) -> ProxyResult<(usize, SocksAddr)> {
    let n = packet.len();
    if n < 3 {
        return Err(ProxyError::DatagramWarn(anyhow!("Short message")));
    }
    // Fragments are not supported; RFC 1928 lets a server drop them.
    if packet[2] != 0 {
        return Err(ProxyError::DatagramWarn(anyhow!(
            "Fragmented datagram dropped"
        )));
    }
    let dst_addr = SocksAddr::try_from((&packet[3..n], SocksAddrWireType::PortLast))
        .map_err(|e| ProxyError::DatagramWarn(anyhow!("Parse target address failed: {}", e)))?;
    let header_size = 3 + dst_addr.size();
    let payload_size = n
        .checked_sub(header_size)
        .ok_or_else(|| ProxyError::DatagramWarn(anyhow!("Short message")))?;
    if payload_size > buf.len() {
        return Err(ProxyError::DatagramWarn(anyhow!(
            "Datagram of {} bytes exceeds the {}-byte buffer, dropped",
            payload_size,
            buf.len()
        )));
    }
    buf[..payload_size].copy_from_slice(&packet[header_size..header_size + payload_size]);
    Ok((payload_size, dst_addr))
}

struct SendHalf(Arc<Shared>);

#[async_trait]
impl InboundDatagramSendHalf for SendHalf {
    async fn send_to(
        &mut self,
        buf: &[u8],
        src_addr: &SocksAddr,
        dst_addr: &SocketAddr,
    ) -> io::Result<usize> {
        let mut send_buf = BytesMut::with_capacity(3 + src_addr.size() + buf.len());
        send_buf.put_u16(0);
        send_buf.put_u8(0);
        src_addr.write_buf(&mut send_buf, SocksAddrWireType::PortLast);
        send_buf.put_slice(buf);
        self.0.socket.send_to(&send_buf[..], dst_addr).await
    }

    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(frag: u8, payload: usize) -> Vec<u8> {
        let mut p = vec![0, 0, frag, 0x01, 1, 2, 3, 4, 0, 53];
        p.resize(p.len() + payload, 0xab);
        p
    }

    fn recv(packet: Vec<u8>, buf_len: usize) -> ProxyResult<usize> {
        let mut buf = vec![0u8; buf_len];
        unwrap(&packet, &mut buf).map(|(n, _)| n)
    }

    #[test]
    fn payload_is_unwrapped() {
        assert_eq!(recv(packet(0, 100), 2048).unwrap(), 100);
    }

    #[test]
    fn oversized_payload_is_dropped_not_a_panic() {
        assert!(matches!(
            recv(packet(0, 3000), 2048),
            Err(ProxyError::DatagramWarn(_))
        ));
    }

    /// A client that sends its last datagrams and closes the control
    /// connection at once has them relayed before the association ends.
    #[tokio::test]
    async fn datagrams_sent_before_the_control_closes_are_relayed() {
        use super::super::association::Associations;
        use std::net::Ipv4Addr;

        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        for _ in 0..50 {
            let relay_socket = bind(loopback, None).unwrap();
            let relay_addr = relay_socket.local_addr().unwrap();
            let client = UdpSocket::bind((loopback, 0)).await.unwrap();
            // A real connection: its close and the datagrams reach the
            // reactor as they would in use.
            let listener = tokio::net::TcpListener::bind((loopback, 0)).await.unwrap();
            let peer = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (control, _) = listener.accept().await.unwrap();
            let relay = Box::new(Relay::new(
                relay_socket,
                Arc::new(Associations::default()).acquire().unwrap(),
                Box::new(control),
                ClientFilter::new(client.local_addr().unwrap(), &SocksAddr::any()),
                None,
            ));
            let (mut r, _s) = relay.split();
            for i in 0..3 {
                client
                    .send_to(&packet(0, 10 + i), relay_addr)
                    .await
                    .unwrap();
            }
            drop(peer);
            let mut buf = vec![0u8; 2048];
            for i in 0..3 {
                let (n, _, _) = r.recv_from(&mut buf).await.unwrap();
                assert_eq!(n, 10 + i);
            }
            assert!(matches!(
                r.recv_from(&mut buf).await,
                Err(ProxyError::DatagramFatal(_))
            ));
        }
    }

    #[test]
    fn truncated_header_and_fragments_are_dropped() {
        let mut short = packet(0, 0);
        short.truncate(7);
        assert!(matches!(
            recv(short, 2048),
            Err(ProxyError::DatagramWarn(_))
        ));
        assert!(matches!(
            recv(packet(1, 10), 2048),
            Err(ProxyError::DatagramWarn(_))
        ));
    }
}
