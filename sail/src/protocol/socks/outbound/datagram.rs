//! SOCKS5 `UDP ASSOCIATE` (RFC 1928, 7): a control connection to the
//! server, and a UDP socket sending to the relay the server names.
//!
//! The request declares 0.0.0.0:0, as RFC 1928 has a client that does not
//! know the address it will send from do: behind NAT the server would see
//! another one, and a server that holds the client to its declaration would
//! drop every datagram. The relay is the reply's BND.ADDR and BND.PORT; an
//! unspecified BND.ADDR is the server's own address.

use std::convert::TryFrom;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

use crate::{adapter::*, app::SyncDnsClient, net::resolver::Resolver, net::*, session::*};

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub dns_client: SyncDnsClient,
    pub dial: std::sync::Arc<crate::net::DialOptions>,
}

impl TcpConnector for Handler {}
impl UdpConnector for Handler {}

/// Negotiates with the server on `stream` and asks it to associate,
/// authenticating as `auth` if given. Returns the relay the reply names.
pub(crate) async fn associate<S>(
    stream: &mut S,
    auth: Option<(&str, &str)>,
) -> io::Result<SocksAddr>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let methods: &[u8] = if auth.is_some() {
        &[0x00, 0x02]
    } else {
        &[0x00]
    };
    let mut greeting = vec![0x05, methods.len() as u8];
    greeting.extend_from_slice(methods);
    stream.write_all(&greeting).await?;
    let mut selected = [0u8; 2];
    stream.read_exact(&mut selected).await?;
    if selected[0] != 0x05 {
        return Err(io::Error::other(format!(
            "socks server answered version {}",
            selected[0]
        )));
    }
    match (selected[1], auth) {
        (0x00, _) => {}
        (0x02, Some((username, password))) => {
            if username.len() > 255 || password.len() > 255 {
                return Err(io::Error::other(
                    "socks username and password must be at most 255 bytes",
                ));
            }
            let mut request = vec![0x01, username.len() as u8];
            request.extend_from_slice(username.as_bytes());
            request.push(password.len() as u8);
            request.extend_from_slice(password.as_bytes());
            stream.write_all(&request).await?;
            let mut status = [0u8; 2];
            stream.read_exact(&mut status).await?;
            if status[1] != 0x00 {
                return Err(io::Error::other("socks authentication failed"));
            }
        }
        (method, _) => {
            return Err(io::Error::other(format!(
                "socks server chose authentication method {}, not one offered",
                method
            )));
        }
    }
    // UDP ASSOCIATE, from an address not known: 0.0.0.0:0.
    stream
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    let mut reply = [0u8; 3];
    stream.read_exact(&mut reply).await?;
    if reply[0] != 0x05 {
        return Err(io::Error::other(format!(
            "socks server answered version {}",
            reply[0]
        )));
    }
    if reply[1] != 0x00 {
        return Err(io::Error::other(format!(
            "socks server refused udp associate: reply {}",
            reply[1]
        )));
    }
    SocksAddr::read_from(stream, SocksAddrWireType::PortLast).await
}

#[async_trait]
impl OutboundDatagramHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Proxy(Network::Udp, self.address.clone(), self.port)
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Unreliable
    }

    async fn handle<'a>(
        &'a self,
        _sess: &'a Session,
        _transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        tracing::trace!("handling outbound datagram");
        let mut stream = self
            .new_tcp_stream(
                self.dns_client.clone(),
                &self.address,
                &self.port,
                &self.dial,
            )
            .await?;
        let auth =
            (!self.username.is_empty()).then_some((self.username.as_str(), self.password.as_str()));
        let bound = associate(&mut stream, auth).await?;
        let relay = match bound {
            SocksAddr::Ip(addr) if addr.ip().is_unspecified() => {
                SocketAddr::new(self.server_ip().await?, addr.port())
            }
            SocksAddr::Ip(addr) => addr,
            SocksAddr::Domain(domain, port) => {
                Resolver::new(self.dns_client.clone(), &domain, &port, &self.dial)
                    .await
                    .map_err(|e| {
                        io::Error::other(format!("resolve socks relay {}: {}", domain, e))
                    })?
                    .next()
                    .ok_or_else(|| {
                        io::Error::other(format!("no address for socks relay {}", domain))
                    })?
            }
        };
        let unspecified = match relay {
            SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
            SocketAddr::V6(_) => SocketAddr::from(([0u16; 8], 0)),
        };
        let socket = self.new_udp_socket(&unspecified, &self.dial).await?;
        socket.connect(relay).await?;
        tracing::debug!("socks udp relay {}", relay);
        let socket = Arc::new(socket);
        Ok(Box::new(Datagram {
            socket,
            control: stream,
        }))
    }
}

impl Handler {
    /// The server's address, for a relay whose address the server left
    /// unspecified.
    async fn server_ip(&self) -> io::Result<std::net::IpAddr> {
        Resolver::new(
            self.dns_client.clone(),
            &self.address,
            &self.port,
            &self.dial,
        )
        .await
        .map_err(|e| io::Error::other(format!("resolve socks server: {}", e)))?
        .next()
        .map(|a| a.ip())
        .ok_or_else(|| io::Error::other("no address for socks server"))
    }
}

pub struct Datagram {
    socket: Arc<UdpSocket>,
    /// The control connection: the association lasts while it is open.
    control: AnyStream,
}

impl OutboundDatagram for Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        // Each half holds a side of the control connection, which stays
        // open until both are gone.
        let (control_read, control_write) = tokio::io::split(self.control);
        (
            Box::new(DatagramRecvHalf {
                socket: self.socket.clone(),
                control: control_read,
                packet: Vec::new(),
            }),
            Box::new(DatagramSendHalf {
                socket: self.socket,
                _control: control_write,
            }),
        )
    }
}

pub struct DatagramRecvHalf {
    socket: Arc<UdpSocket>,
    control: tokio::io::ReadHalf<AnyStream>,
    /// A reply is read into this, reused from one to the next.
    packet: Vec<u8>,
}

#[async_trait]
impl OutboundDatagramRecvHalf for DatagramRecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        let Self {
            socket,
            control,
            packet,
        } = self;
        packet.resize(buf.len() + 512, 0);
        let mut ignored = [0u8; 64];
        loop {
            tokio::select! {
                received = socket.recv(packet) => {
                    let n = received?;
                    match unwrap(&packet[..n], buf) {
                        Some(r) => return Ok(r),
                        None => {
                            tracing::debug!("malformed socks udp reply dropped");
                            continue;
                        }
                    }
                }
                read = control.read(&mut ignored) => match read {
                    Ok(n) if n > 0 => continue,
                    _ => return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "socks server closed the udp association",
                    )),
                },
            }
        }
    }
}

/// The payload of a SOCKS5 UDP reply `packet`, copied into `buf`, and where
/// it came from; None for one that is malformed, fragmented or too big.
fn unwrap(packet: &[u8], buf: &mut [u8]) -> Option<(usize, SocksAddr)> {
    if packet.len() < 3 || packet[2] != 0 {
        return None;
    }
    let from = SocksAddr::try_from((&packet[3..], SocksAddrWireType::PortLast)).ok()?;
    let payload = packet.get(3 + from.size()..)?;
    let dst = buf.get_mut(..payload.len())?;
    dst.copy_from_slice(payload);
    Some((payload.len(), from))
}

pub struct DatagramSendHalf {
    socket: Arc<UdpSocket>,
    _control: tokio::io::WriteHalf<AnyStream>,
}

#[async_trait]
impl OutboundDatagramSendHalf for DatagramSendHalf {
    async fn send_to(&mut self, buf: &[u8], target: &SocksAddr) -> io::Result<usize> {
        let mut packet = BytesMut::with_capacity(3 + target.size() + buf.len());
        packet.put_u16(0);
        packet.put_u8(0);
        target.write_buf(&mut packet, SocksAddrWireType::PortLast);
        packet.put_slice(buf);
        self.socket.send(&packet).await?;
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// The request declares 0.0.0.0:0, and the reply's address is the
    /// relay.
    #[tokio::test]
    async fn associate_declares_nothing_and_takes_the_bound_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 4];
            s.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x02, 0x00, 0x02]);
            s.write_all(&[0x05, 0x02]).await.unwrap();
            let mut auth = [0u8; 7];
            s.read_exact(&mut auth).await.unwrap();
            assert_eq!(&auth, b"\x01\x02ab\x02cd");
            s.write_all(&[0x01, 0x00]).await.unwrap();
            let mut request = [0u8; 10];
            s.read_exact(&mut request).await.unwrap();
            assert_eq!(request, [0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
            s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x12, 0x34])
                .await
                .unwrap();
        });
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let bound = associate(&mut stream, Some(("ab", "cd"))).await.unwrap();
        assert_eq!(bound.to_string(), "127.0.0.1:4660");
        server.await.unwrap();
    }

    #[test]
    fn replies_are_unwrapped() {
        let mut buf = [0u8; 16];
        let packet = [0, 0, 0, 0x01, 1, 2, 3, 4, 0, 53, b'h', b'i'];
        let (n, from) = unwrap(&packet, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"hi");
        assert_eq!(from.to_string(), "1.2.3.4:53");
        // Fragments, and payloads too big for the buffer, are dropped.
        let mut fragment = packet;
        fragment[2] = 1;
        assert!(unwrap(&fragment, &mut buf).is_none());
        assert!(unwrap(&packet, &mut [0u8; 1]).is_none());
    }
}
