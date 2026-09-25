//! Addresses as VMess, VLESS and Mux.Cool write them, and XUDP: UDP over
//! Mux.Cool framing, as Xray and sing-box speak it.
//!
//! A Mux.Cool frame is a two-byte metadata length, the metadata -- session
//! ID (2), status (1), option (1), then for a new session or a UDP packet the
//! network (1) and a port-first address -- and, with the data option, a
//! two-byte length and the data. XUDP is one UDP session on such a
//! connection whose packets each carry their own address, which is what
//! makes it full cone: replies come back with the address they came from.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

use crate::adapter::*;
use crate::session::{DatagramSource, SocksAddr, SocksAddrWireType};

const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 2;
const ATYP_IPV6: u8 = 3;

pub const STATUS_NEW: u8 = 1;
pub const STATUS_KEEP: u8 = 2;
pub const STATUS_END: u8 = 3;
pub const STATUS_KEEP_ALIVE: u8 = 4;

pub const OPTION_DATA: u8 = 1;
pub const OPTION_ERROR: u8 = 2;

pub const NETWORK_TCP: u8 = 1;
pub const NETWORK_UDP: u8 = 2;

/// Longest metadata a frame may carry: the fixed part, a network, the
/// longest address and a global ID, with room to spare.
const MAX_METADATA: usize = 512;

fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what.to_string())
}

/// Reads a port-first address: port, type (1 IPv4, 2 domain, 3 IPv6),
/// address.
pub async fn read_addr_port<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<SocksAddr> {
    let port = r.read_u16().await?;
    match r.read_u8().await? {
        ATYP_IPV4 => Ok(SocksAddr::from((Ipv4Addr::from(r.read_u32().await?), port))),
        ATYP_IPV6 => Ok(SocksAddr::from((
            Ipv6Addr::from(r.read_u128().await?),
            port,
        ))),
        ATYP_DOMAIN => {
            let len = r.read_u8().await? as usize;
            let mut domain = vec![0u8; len];
            r.read_exact(&mut domain).await?;
            domain_addr(domain, port)
        }
        _ => Err(invalid("invalid address type")),
    }
}

fn domain_addr(domain: Vec<u8>, port: u16) -> io::Result<SocksAddr> {
    if domain.is_empty() {
        return Err(invalid("empty domain"));
    }
    let domain = String::from_utf8(domain).map_err(|_| invalid("invalid domain"))?;
    // An IP address sent as a domain is still an IP address.
    SocksAddr::try_from((domain, port))
}

/// Parses a port-first address at the start of `buf`: the address and how
/// many bytes it took.
pub fn parse_addr_port(buf: &[u8]) -> io::Result<(SocksAddr, usize)> {
    let short = || invalid("address too short");
    if buf.len() < 3 {
        return Err(short());
    }
    let port = u16::from_be_bytes([buf[0], buf[1]]);
    let rest = &buf[3..];
    match buf[2] {
        ATYP_IPV4 => {
            let ip: [u8; 4] = rest
                .get(..4)
                .ok_or_else(short)?
                .try_into()
                .map_err(|_| short())?;
            Ok((SocksAddr::from((Ipv4Addr::from(ip), port)), 7))
        }
        ATYP_IPV6 => {
            let ip: [u8; 16] = rest
                .get(..16)
                .ok_or_else(short)?
                .try_into()
                .map_err(|_| short())?;
            Ok((SocksAddr::from((Ipv6Addr::from(ip), port)), 19))
        }
        ATYP_DOMAIN => {
            let len = *rest.first().ok_or_else(short)? as usize;
            let domain = rest.get(1..1 + len).ok_or_else(short)?;
            Ok((domain_addr(domain.to_vec(), port)?, 4 + len))
        }
        _ => Err(invalid("invalid address type")),
    }
}

/// Writes `addr` port first.
pub fn write_addr_port(out: &mut BytesMut, addr: &SocksAddr) {
    addr.write_buf(out, SocksAddrWireType::PortFirst);
}

/// The metadata of one Mux.Cool frame.
#[derive(Debug)]
pub struct Metadata {
    pub session_id: u16,
    pub status: u8,
    pub option: u8,
    pub network: Option<u8>,
    pub addr: Option<SocksAddr>,
}

/// Reads the metadata of the next frame.
pub async fn read_metadata<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Metadata> {
    let len = r.read_u16().await? as usize;
    if !(4..=MAX_METADATA).contains(&len) {
        return Err(invalid("bad mux frame metadata length"));
    }
    let mut meta = [0u8; MAX_METADATA];
    let meta = &mut meta[..len];
    r.read_exact(meta).await?;
    let mut metadata = Metadata {
        session_id: u16::from_be_bytes([meta[0], meta[1]]),
        status: meta[2],
        option: meta[3],
        network: None,
        addr: None,
    };
    // A new session names its network and target; a UDP packet of a kept
    // session may name its own address. Anything after it -- a new XUDP
    // session's global ID -- is not needed here.
    if len > 4 && matches!(metadata.status, STATUS_NEW | STATUS_KEEP) {
        let network = meta[4];
        metadata.network = Some(network);
        if len > 5 {
            metadata.addr = Some(parse_addr_port(&meta[5..])?.0);
        }
    }
    Ok(metadata)
}

/// Reads the data of a frame with the data option into `buf`: its length,
/// cut to `buf` (a UDP packet larger than the buffer loses its tail).
pub async fn read_data<R: AsyncRead + Unpin>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let len = r.read_u16().await? as usize;
    let n = len.min(buf.len());
    r.read_exact(&mut buf[..n]).await?;
    if len > n {
        let mut rest = r.take((len - n) as u64);
        tokio::io::copy(&mut rest, &mut tokio::io::sink()).await?;
    }
    Ok(n)
}

/// Appends one UDP packet frame: `status` new or keep, with `addr`.
fn put_packet(out: &mut BytesMut, session_id: u16, status: u8, addr: &SocksAddr, data: &[u8]) {
    let mut meta = BytesMut::with_capacity(5 + addr.size() + 3);
    meta.put_u16(session_id);
    meta.put_u8(status);
    meta.put_u8(OPTION_DATA);
    meta.put_u8(NETWORK_UDP);
    write_addr_port(&mut meta, addr);
    out.put_u16(meta.len() as u16);
    out.put_slice(&meta);
    out.put_u16(data.len() as u16);
    out.put_slice(data);
}

fn check_packet_len(data: &[u8]) -> io::Result<()> {
    if data.len() > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "packet too large",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The client side
// ---------------------------------------------------------------------------

/// XUDP from the client: a stream that has asked its server for a Mux
/// connection. The first packet opens session 0 with its address; each
/// packet after that names its own.
pub struct ClientDatagram<S> {
    stream: S,
    destination: SocksAddr,
}

impl<S> ClientDatagram<S> {
    /// `destination` stands for the address of packets the server sends
    /// without one.
    pub fn new(stream: S, destination: SocksAddr) -> Self {
        Self {
            stream,
            destination,
        }
    }
}

impl<S> OutboundDatagram for ClientDatagram<S>
where
    S: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let (r, w) = tokio::io::split(self.stream);
        (
            Box::new(ClientRecvHalf {
                reader: r,
                destination: self.destination,
            }),
            Box::new(ClientSendHalf {
                writer: w,
                opened: false,
            }),
        )
    }
}

struct ClientRecvHalf<S> {
    reader: ReadHalf<S>,
    destination: SocksAddr,
}

#[async_trait]
impl<S> OutboundDatagramRecvHalf for ClientRecvHalf<S>
where
    S: AsyncRead + AsyncWrite + Send + Sync,
{
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        loop {
            let meta = read_metadata(&mut self.reader).await?;
            match meta.status {
                STATUS_KEEP | STATUS_KEEP_ALIVE => {}
                STATUS_END => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "xudp session ended",
                    ))
                }
                _ => return Err(invalid("unexpected mux frame from the server")),
            }
            if meta.option & OPTION_ERROR != 0 {
                return Err(io::Error::other("xudp session closed with an error"));
            }
            if meta.option & OPTION_DATA == 0 {
                continue;
            }
            let n = read_data(&mut self.reader, buf).await?;
            if meta.status == STATUS_KEEP_ALIVE {
                continue;
            }
            let from = match meta.addr {
                Some(addr) if meta.network == Some(NETWORK_UDP) => addr,
                _ => self.destination.clone(),
            };
            return Ok((n, from));
        }
    }
}

struct ClientSendHalf<S> {
    writer: WriteHalf<S>,
    opened: bool,
}

#[async_trait]
impl<S> OutboundDatagramSendHalf for ClientSendHalf<S>
where
    S: AsyncRead + AsyncWrite + Send + Sync,
{
    async fn send_to(&mut self, buf: &[u8], target: &SocksAddr) -> io::Result<usize> {
        check_packet_len(buf)?;
        let status = if self.opened { STATUS_KEEP } else { STATUS_NEW };
        let mut frame = BytesMut::with_capacity(16 + target.size() + buf.len());
        put_packet(&mut frame, 0, status, target, buf);
        self.writer.write_all(&frame).await?;
        self.writer.flush().await?;
        self.opened = true;
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        self.writer.shutdown().await
    }
}

// ---------------------------------------------------------------------------
// The server side
// ---------------------------------------------------------------------------

/// XUDP on the server: the UDP session a client opens on a Mux connection.
/// Mux.Cool sessions carrying TCP are not served.
pub struct ServerDatagram<S> {
    stream: S,
    source: DatagramSource,
}

impl<S> ServerDatagram<S> {
    pub fn new(stream: S, source: DatagramSource) -> Self {
        Self { stream, source }
    }
}

/// No session opened yet.
const NO_SESSION: u32 = u32::MAX;

impl<S> InboundDatagram for ServerDatagram<S>
where
    S: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn InboundDatagramRecvHalf>,
        Box<dyn InboundDatagramSendHalf>,
    ) {
        let (r, w) = tokio::io::split(self.stream);
        let session = Arc::new(AtomicU32::new(NO_SESSION));
        (
            Box::new(ServerRecvHalf {
                reader: r,
                source: self.source,
                session: session.clone(),
                target: None,
            }),
            Box::new(ServerSendHalf { writer: w, session }),
        )
    }

    fn into_std(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        Err(io::Error::other("stream transport"))
    }
}

struct ServerRecvHalf<S> {
    reader: ReadHalf<S>,
    source: DatagramSource,
    session: Arc<AtomicU32>,
    // Where packets that name no address of their own go.
    target: Option<SocksAddr>,
}

fn fatal(e: io::Error) -> ProxyError {
    ProxyError::DatagramFatal(e.into())
}

#[async_trait]
impl<S> InboundDatagramRecvHalf for ServerRecvHalf<S>
where
    S: AsyncRead + AsyncWrite + Send + Sync,
{
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> ProxyResult<(usize, DatagramSource, SocksAddr)> {
        loop {
            let meta = read_metadata(&mut self.reader).await.map_err(fatal)?;
            let session = self.session.load(Ordering::Relaxed);
            match meta.status {
                STATUS_NEW => {
                    if meta.network != Some(NETWORK_UDP) {
                        return Err(fatal(io::Error::other(
                            "mux: only XUDP is served, not Mux.Cool TCP sessions",
                        )));
                    }
                    if session != NO_SESSION && session != meta.session_id as u32 {
                        return Err(fatal(io::Error::other(
                            "mux: only one XUDP session per connection is served",
                        )));
                    }
                    let target = meta
                        .addr
                        .clone()
                        .ok_or_else(|| fatal(invalid("new session without a target")))?;
                    self.target = Some(target);
                    self.session
                        .store(meta.session_id as u32, Ordering::Relaxed);
                }
                STATUS_KEEP => {
                    if session != meta.session_id as u32 {
                        return Err(fatal(invalid("mux: frame of an unknown session")));
                    }
                }
                STATUS_END => {
                    return Err(fatal(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "xudp session ended",
                    )))
                }
                STATUS_KEEP_ALIVE => {}
                _ => return Err(fatal(invalid("bad mux session status"))),
            }
            if meta.option & OPTION_DATA == 0 {
                continue;
            }
            let n = read_data(&mut self.reader, buf).await.map_err(fatal)?;
            if meta.status == STATUS_KEEP_ALIVE {
                continue;
            }
            let target = match meta.addr {
                Some(addr) if meta.network == Some(NETWORK_UDP) => addr,
                _ => self
                    .target
                    .clone()
                    .ok_or_else(|| fatal(invalid("packet without a target")))?,
            };
            return Ok((n, self.source.clone(), target));
        }
    }
}

struct ServerSendHalf<S> {
    writer: WriteHalf<S>,
    session: Arc<AtomicU32>,
}

#[async_trait]
impl<S> InboundDatagramSendHalf for ServerSendHalf<S>
where
    S: AsyncRead + AsyncWrite + Send + Sync,
{
    async fn send_to(
        &mut self,
        buf: &[u8],
        src_addr: &SocksAddr,
        _dst_addr: &SocketAddr,
    ) -> io::Result<usize> {
        check_packet_len(buf)?;
        let session = self.session.load(Ordering::Relaxed);
        if session == NO_SESSION {
            return Err(io::Error::other("xudp: no session to reply on"));
        }
        let mut frame = BytesMut::with_capacity(16 + src_addr.size() + buf.len());
        put_packet(&mut frame, session as u16, STATUS_KEEP, src_addr, buf);
        self.writer.write_all(&frame).await?;
        self.writer.flush().await?;
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        self.writer.shutdown().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addrs() -> Vec<SocksAddr> {
        vec![
            SocksAddr::from(("1.2.3.4".parse::<Ipv4Addr>().unwrap(), 53)),
            SocksAddr::from(("::1".parse::<Ipv6Addr>().unwrap(), 443)),
            SocksAddr::try_from(("example.com", 8080)).unwrap(),
        ]
    }

    #[tokio::test]
    async fn test_addr_port_round_trip() {
        for addr in addrs() {
            let mut buf = BytesMut::new();
            write_addr_port(&mut buf, &addr);
            let (parsed, n) = parse_addr_port(&buf).unwrap();
            assert_eq!(parsed, addr);
            assert_eq!(n, buf.len());
            let mut r = &buf[..];
            assert_eq!(read_addr_port(&mut r).await.unwrap(), addr);
            // Any truncation is an error, not a panic.
            for cut in 0..buf.len() {
                assert!(parse_addr_port(&buf[..cut]).is_err());
            }
        }
        assert!(parse_addr_port(&[0, 53, 9, 1, 2, 3, 4]).is_err());
    }

    // What Xray's PacketWriter and sing-box's XUDPConn send.
    #[tokio::test]
    async fn test_client_frames_as_xray_writes_them() {
        let (client, mut server) = tokio::io::duplex(1 << 16);
        let dgram = Box::new(ClientDatagram::new(client, addrs()[0].clone()));
        let (_r, mut w) = dgram.split();
        w.send_to(b"one", &addrs()[0]).await.unwrap();
        w.send_to(b"two", &addrs()[2]).await.unwrap();
        let mut wire = vec![0u8; 7 + 7 + 2 + 3];
        server.read_exact(&mut wire).await.unwrap();
        assert_eq!(
            wire,
            [
                &[0, 12, 0, 0, STATUS_NEW, OPTION_DATA, NETWORK_UDP][..],
                &[0, 53, 1, 1, 2, 3, 4],
                &[0, 3],
                b"one"
            ]
            .concat()
        );
        let meta = read_metadata(&mut server).await.unwrap();
        assert_eq!(meta.status, STATUS_KEEP);
        assert_eq!(meta.addr, Some(addrs()[2].clone()));
        let mut buf = [0u8; 16];
        let n = read_data(&mut server, &mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"two");
    }

    #[tokio::test]
    async fn test_server_and_client_talk() {
        let (client, server) = tokio::io::duplex(1 << 16);
        let source = DatagramSource::new("127.0.0.1:1".parse().unwrap(), None);
        let (mut sr, mut sw) = Box::new(ServerDatagram::new(server, source)).split();
        let (mut cr, mut cw) = Box::new(ClientDatagram::new(client, addrs()[0].clone())).split();
        let peer: SocketAddr = "127.0.0.1:1".parse().unwrap();

        // Replying before the client opened a session is an error.
        assert!(sw.send_to(b"x", &addrs()[1], &peer).await.is_err());

        for (i, addr) in addrs().iter().enumerate() {
            cw.send_to(&[i as u8; 100], addr).await.unwrap();
            let mut buf = [0u8; 256];
            let (n, _, target) = sr.recv_from(&mut buf).await.map_err(|_| ()).unwrap();
            assert_eq!(&buf[..n], &[i as u8; 100]);
            assert_eq!(&target, addr);
            // Full cone: the reply names where it came from.
            sw.send_to(b"reply", &addrs()[2], &peer).await.unwrap();
            let (n, from) = cr.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"reply");
            assert_eq!(from, addrs()[2]);
        }
    }

    #[tokio::test]
    async fn test_server_refuses_mux_tcp() {
        let (mut client, server) = tokio::io::duplex(1 << 16);
        let source = DatagramSource::new("127.0.0.1:1".parse().unwrap(), None);
        let (mut sr, _sw) = Box::new(ServerDatagram::new(server, source)).split();
        client
            .write_all(&[
                0,
                12,
                0,
                1,
                STATUS_NEW,
                0,
                NETWORK_TCP,
                0,
                80,
                1,
                1,
                2,
                3,
                4,
            ])
            .await
            .unwrap();
        let mut buf = [0u8; 16];
        assert!(sr.recv_from(&mut buf).await.is_err());
    }

    #[tokio::test]
    async fn test_bad_metadata_length_is_an_error() {
        let mut r = &[0u8, 2, 0, 0][..];
        assert!(read_metadata(&mut r).await.is_err());
        let mut r = &[0xffu8, 0xff][..];
        assert!(read_metadata(&mut r).await.is_err());
    }
}
