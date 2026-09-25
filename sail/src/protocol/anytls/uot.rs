//! UDP over TCP, version 2, as sing-box speaks it: what a stream to
//! `sp.v2.udp-over-tcp.arpa` carries.
//!
//! The stream starts with a request, `is_connect u8 | destination`, the
//! destination as a SOCKS5 address. Then come packets: `length u16 |
//! payload` in connect mode, where every packet goes to the destination,
//! and otherwise `address | length u16 | payload`, with the address in
//! UoT's own form: type `0` IPv4, `1` IPv6, `2` a length-prefixed domain,
//! then the port.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::session::{SocksAddr, SocksAddrWireType};

const IPV4: u8 = 0x00;
const IPV6: u8 = 0x01;
const FQDN: u8 = 0x02;

/// The request that opens the stream.
pub fn put_request(buf: &mut BytesMut, is_connect: bool, destination: &SocksAddr) {
    buf.put_u8(is_connect as u8);
    destination.write_buf(buf, SocksAddrWireType::PortLast);
}

pub async fn read_request<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<(bool, SocksAddr)> {
    let is_connect = match r.read_u8().await? {
        0 => false,
        1 => true,
        n => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("udp-over-tcp: invalid is_connect {}", n),
            ))
        }
    };
    let destination = SocksAddr::read_from(r, SocksAddrWireType::PortLast).await?;
    Ok((is_connect, destination))
}

/// A packet's address, in UoT's form.
pub fn put_addr(buf: &mut BytesMut, addr: &SocksAddr) -> io::Result<()> {
    match addr {
        SocksAddr::Ip(std::net::SocketAddr::V4(a)) => {
            buf.put_u8(IPV4);
            buf.put_slice(&a.ip().octets());
            buf.put_u16(a.port());
        }
        SocksAddr::Ip(std::net::SocketAddr::V6(a)) => {
            buf.put_u8(IPV6);
            buf.put_slice(&a.ip().octets());
            buf.put_u16(a.port());
        }
        SocksAddr::Domain(domain, port) => {
            let len = u8::try_from(domain.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "udp-over-tcp: domain too long")
            })?;
            buf.put_u8(FQDN);
            buf.put_u8(len);
            buf.put_slice(domain.as_bytes());
            buf.put_u16(*port);
        }
    }
    Ok(())
}

pub async fn read_addr<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<SocksAddr> {
    match r.read_u8().await? {
        IPV4 => {
            let ip = Ipv4Addr::from(r.read_u32().await?);
            Ok(SocksAddr::from((ip, r.read_u16().await?)))
        }
        IPV6 => {
            let ip = Ipv6Addr::from(r.read_u128().await?);
            Ok(SocksAddr::from((ip, r.read_u16().await?)))
        }
        FQDN => {
            let len = r.read_u8().await? as usize;
            let mut domain = vec![0; len];
            r.read_exact(&mut domain).await?;
            let domain = String::from_utf8(domain).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "udp-over-tcp: invalid domain")
            })?;
            let port = r.read_u16().await?;
            SocksAddr::try_from((domain, port))
        }
        n => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("udp-over-tcp: invalid address type {}", n),
        )),
    }
}

/// A whole packet, ready to write.
pub fn encode_packet(addr: Option<&SocksAddr>, payload: &[u8]) -> io::Result<BytesMut> {
    let len = u16::try_from(payload.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "udp-over-tcp: packet too large",
        )
    })?;
    let mut buf = BytesMut::with_capacity(1 + 1 + 255 + 2 + 2 + payload.len());
    if let Some(addr) = addr {
        put_addr(&mut buf, addr)?;
    }
    buf.put_u16(len);
    buf.put_slice(payload);
    Ok(buf)
}

/// Reads a packet's length and payload into `buf`. A payload larger than
/// `buf` is read and dropped, and reported as `Ok(None)`, so that the
/// stream stays in step.
pub async fn read_payload<R: AsyncRead + Unpin>(
    r: &mut R,
    buf: &mut [u8],
) -> io::Result<Option<usize>> {
    let len = r.read_u16().await? as usize;
    if len > buf.len() {
        let mut rest = len;
        let mut scratch = [0u8; 1024];
        while rest > 0 {
            let n = rest.min(scratch.len());
            r.read_exact(&mut scratch[..n]).await?;
            rest -= n;
        }
        return Ok(None);
    }
    r.read_exact(&mut buf[..len]).await?;
    Ok(Some(len))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
    }

    #[test]
    fn addresses_use_uot_types() {
        let mut buf = BytesMut::new();
        put_addr(&mut buf, &SocksAddr::from((Ipv4Addr::new(1, 2, 3, 4), 53))).unwrap();
        assert_eq!(&buf[..], &[0, 1, 2, 3, 4, 0, 53]);
        let mut buf = BytesMut::new();
        put_addr(&mut buf, &SocksAddr::Domain("ab".into(), 80)).unwrap();
        assert_eq!(&buf[..], &[2, 2, b'a', b'b', 0, 80]);
    }

    #[test]
    fn packets_and_requests_round_trip() {
        runtime().block_on(async {
            let dest = SocksAddr::Domain("example.com".into(), 443);
            let mut buf = BytesMut::new();
            put_request(&mut buf, false, &dest);
            buf.extend_from_slice(&encode_packet(Some(&dest), b"hi").unwrap());
            let v6 = SocksAddr::from((Ipv6Addr::LOCALHOST, 9));
            buf.extend_from_slice(&encode_packet(Some(&v6), b"there").unwrap());
            buf.extend_from_slice(&encode_packet(Some(&v6), &[7; 10]).unwrap());
            let mut r = &buf[..];
            assert_eq!(read_request(&mut r).await.unwrap(), (false, dest.clone()));
            let mut out = [0u8; 8];
            assert_eq!(read_addr(&mut r).await.unwrap(), dest);
            assert_eq!(read_payload(&mut r, &mut out).await.unwrap(), Some(2));
            assert_eq!(&out[..2], b"hi");
            assert_eq!(read_addr(&mut r).await.unwrap(), v6);
            assert_eq!(read_payload(&mut r, &mut out).await.unwrap(), Some(5));
            // Too large for the buffer: dropped, and the stream stays in step.
            assert_eq!(read_addr(&mut r).await.unwrap(), v6);
            assert_eq!(read_payload(&mut r, &mut out).await.unwrap(), None);
            assert!(r.is_empty());
        });
    }
}
