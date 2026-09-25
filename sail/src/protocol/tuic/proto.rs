//! TUIC v5 commands on the wire.
//!
//! Every command is `VER TYPE OPT`. What differs from SOCKS is the address:
//! its type bytes are TUIC's own, and `None` (a lone `0xff`, no port) stands
//! for the address of a fragment that is not the first of its packet.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::session::SocksAddr;

pub const VERSION: u8 = 0x05;

pub const CMD_AUTHENTICATE: u8 = 0x00;
pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_PACKET: u8 = 0x02;
pub const CMD_DISSOCIATE: u8 = 0x03;
pub const CMD_HEARTBEAT: u8 = 0x04;

const ADDR_NONE: u8 = 0xff;
const ADDR_DOMAIN: u8 = 0x00;
const ADDR_IPV4: u8 = 0x01;
const ADDR_IPV6: u8 = 0x02;

/// `Packet` without `VER TYPE`: `ASSOC_ID PKT_ID FRAG_TOTAL FRAG_ID SIZE`.
pub const PACKET_FIXED_LEN: usize = 8;

/// The length of the token `Authenticate` carries, exported from TLS.
pub const TOKEN_LEN: usize = 32;

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("tuic: {}", msg))
}

/// The encoded length of `addr`, `None` included.
pub fn address_len(addr: Option<&SocksAddr>) -> usize {
    match addr {
        None => 1,
        Some(SocksAddr::Ip(SocketAddr::V4(_))) => 1 + 4 + 2,
        Some(SocksAddr::Ip(SocketAddr::V6(_))) => 1 + 16 + 2,
        Some(SocksAddr::Domain(domain, _)) => 1 + 1 + domain.len() + 2,
    }
}

pub fn write_address<B: BufMut>(buf: &mut B, addr: Option<&SocksAddr>) -> io::Result<()> {
    match addr {
        None => buf.put_u8(ADDR_NONE),
        Some(SocksAddr::Ip(SocketAddr::V4(a))) => {
            buf.put_u8(ADDR_IPV4);
            buf.put_slice(&a.ip().octets());
            buf.put_u16(a.port());
        }
        Some(SocksAddr::Ip(SocketAddr::V6(a))) => {
            buf.put_u8(ADDR_IPV6);
            buf.put_slice(&a.ip().octets());
            buf.put_u16(a.port());
        }
        Some(SocksAddr::Domain(domain, port)) => {
            let len = u8::try_from(domain.len())
                .ok()
                .filter(|n| *n > 0)
                .ok_or_else(|| invalid("domain length out of range"))?;
            buf.put_u8(ADDR_DOMAIN);
            buf.put_u8(len);
            buf.put_slice(domain.as_bytes());
            buf.put_u16(*port);
        }
    }
    Ok(())
}

fn domain_addr(domain: &[u8], port: u16) -> io::Result<SocksAddr> {
    let domain = std::str::from_utf8(domain).map_err(|_| invalid("domain is not UTF-8"))?;
    if domain.is_empty() {
        return Err(invalid("empty domain"));
    }
    SocksAddr::try_from((domain, port))
}

fn ipv6_addr(octets: [u8; 16], port: u16) -> SocksAddr {
    // Go writes an IPv4 address it keeps in 16 bytes as IPv6.
    let ip = Ipv6Addr::from(octets);
    match ip.to_ipv4_mapped() {
        Some(v4) => SocksAddr::from((IpAddr::V4(v4), port)),
        None => SocksAddr::from((IpAddr::V6(ip), port)),
    }
}

/// Reads an address off the front of `buf`, returning it and how many bytes
/// it took.
pub fn decode_address(buf: &[u8]) -> io::Result<(Option<SocksAddr>, usize)> {
    let short = || invalid("address truncated");
    let (&kind, rest) = buf.split_first().ok_or_else(short)?;
    let port_at = |rest: &[u8], n: usize| -> io::Result<u16> {
        rest.get(n..n + 2)
            .map(|p| u16::from_be_bytes([p[0], p[1]]))
            .ok_or_else(short)
    };
    match kind {
        ADDR_NONE => Ok((None, 1)),
        ADDR_IPV4 => {
            let ip: [u8; 4] = rest
                .get(..4)
                .ok_or_else(short)?
                .try_into()
                .map_err(|_| short())?;
            let port = port_at(rest, 4)?;
            Ok((Some(SocksAddr::from((Ipv4Addr::from(ip), port))), 1 + 4 + 2))
        }
        ADDR_IPV6 => {
            let ip: [u8; 16] = rest
                .get(..16)
                .ok_or_else(short)?
                .try_into()
                .map_err(|_| short())?;
            let port = port_at(rest, 16)?;
            Ok((Some(ipv6_addr(ip, port)), 1 + 16 + 2))
        }
        ADDR_DOMAIN => {
            let (&len, rest) = rest.split_first().ok_or_else(short)?;
            let len = len as usize;
            let domain = rest.get(..len).ok_or_else(short)?;
            let port = port_at(rest, len)?;
            Ok((Some(domain_addr(domain, port)?), 1 + 1 + len + 2))
        }
        other => Err(invalid(&format!("unknown address type {:#04x}", other))),
    }
}

/// Reads an address from a stream.
pub async fn read_address<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<SocksAddr>> {
    match r.read_u8().await? {
        ADDR_NONE => Ok(None),
        ADDR_IPV4 => {
            let mut ip = [0u8; 4];
            r.read_exact(&mut ip).await?;
            let port = r.read_u16().await?;
            Ok(Some(SocksAddr::from((Ipv4Addr::from(ip), port))))
        }
        ADDR_IPV6 => {
            let mut ip = [0u8; 16];
            r.read_exact(&mut ip).await?;
            let port = r.read_u16().await?;
            Ok(Some(ipv6_addr(ip, port)))
        }
        ADDR_DOMAIN => {
            let len = r.read_u8().await? as usize;
            let mut domain = vec![0u8; len];
            r.read_exact(&mut domain).await?;
            let port = r.read_u16().await?;
            Ok(Some(domain_addr(&domain, port)?))
        }
        other => Err(invalid(&format!("unknown address type {:#04x}", other))),
    }
}

/// Reads `VER TYPE`, checking the version, and returns the type.
pub async fn read_command<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<u8> {
    let mut head = [0u8; 2];
    r.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Err(invalid(&format!("unsupported version {:#04x}", head[0])));
    }
    Ok(head[1])
}

#[cfg_attr(not(feature = "outbound-tuic"), allow(dead_code))]
pub fn encode_authenticate(uuid: &[u8; 16], token: &[u8; TOKEN_LEN]) -> Bytes {
    let mut buf = BytesMut::with_capacity(2 + 16 + TOKEN_LEN);
    buf.put_u8(VERSION);
    buf.put_u8(CMD_AUTHENTICATE);
    buf.put_slice(uuid);
    buf.put_slice(token);
    buf.freeze()
}

/// `Connect` to `addr`, with `payload` after it.
#[cfg_attr(not(feature = "outbound-tuic"), allow(dead_code))]
pub fn encode_connect(addr: &SocksAddr, payload: &[u8]) -> io::Result<Bytes> {
    let mut buf = BytesMut::with_capacity(2 + address_len(Some(addr)) + payload.len());
    buf.put_u8(VERSION);
    buf.put_u8(CMD_CONNECT);
    write_address(&mut buf, Some(addr))?;
    buf.put_slice(payload);
    Ok(buf.freeze())
}

#[cfg_attr(not(feature = "outbound-tuic"), allow(dead_code))]
pub fn encode_dissociate(assoc_id: u16) -> Bytes {
    let mut buf = BytesMut::with_capacity(4);
    buf.put_u8(VERSION);
    buf.put_u8(CMD_DISSOCIATE);
    buf.put_u16(assoc_id);
    buf.freeze()
}

pub fn encode_heartbeat() -> Bytes {
    Bytes::from_static(&[VERSION, CMD_HEARTBEAT])
}

/// The header of one `Packet`: one fragment of a UDP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketHeader {
    pub assoc_id: u16,
    pub pkt_id: u16,
    pub frag_total: u8,
    pub frag_id: u8,
    /// The target from the client, the source from the server; only the
    /// first fragment has one.
    pub addr: Option<SocksAddr>,
}

impl PacketHeader {
    /// The encoded length of the whole command, `VER TYPE` included,
    /// without the payload.
    pub fn len(&self) -> usize {
        2 + PACKET_FIXED_LEN + address_len(self.addr.as_ref())
    }

    fn check(&self) -> io::Result<()> {
        if self.frag_total == 0 || self.frag_id >= self.frag_total {
            return Err(invalid("fragment id out of range"));
        }
        if self.frag_id == 0 && self.addr.is_none() {
            return Err(invalid("first fragment without an address"));
        }
        Ok(())
    }
}

/// The whole `Packet` command: header and `payload`.
pub fn encode_packet(header: &PacketHeader, payload: &[u8]) -> io::Result<Bytes> {
    let size = u16::try_from(payload.len()).map_err(|_| invalid("packet too large"))?;
    let mut buf = BytesMut::with_capacity(header.len() + payload.len());
    buf.put_u8(VERSION);
    buf.put_u8(CMD_PACKET);
    buf.put_u16(header.assoc_id);
    buf.put_u16(header.pkt_id);
    buf.put_u8(header.frag_total);
    buf.put_u8(header.frag_id);
    buf.put_u16(size);
    write_address(&mut buf, header.addr.as_ref())?;
    buf.put_slice(payload);
    Ok(buf.freeze())
}

/// A `Packet` after its `VER TYPE`, read from a unidirectional stream.
pub async fn read_packet<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<(PacketHeader, Bytes)> {
    let mut fixed = [0u8; PACKET_FIXED_LEN];
    r.read_exact(&mut fixed).await?;
    let addr = read_address(r).await?;
    let header = PacketHeader {
        assoc_id: u16::from_be_bytes([fixed[0], fixed[1]]),
        pkt_id: u16::from_be_bytes([fixed[2], fixed[3]]),
        frag_total: fixed[4],
        frag_id: fixed[5],
        addr,
    };
    header.check()?;
    let size = u16::from_be_bytes([fixed[6], fixed[7]]) as usize;
    let mut payload = vec![0u8; size];
    r.read_exact(&mut payload).await?;
    Ok((header, Bytes::from(payload)))
}

/// What a QUIC datagram carries.
#[derive(Debug, PartialEq, Eq)]
pub enum Datagram {
    Packet(PacketHeader, Bytes),
    Heartbeat,
}

pub fn decode_datagram(data: Bytes) -> io::Result<Datagram> {
    if data.len() < 2 {
        return Err(invalid("datagram truncated"));
    }
    if data[0] != VERSION {
        return Err(invalid(&format!("unsupported version {:#04x}", data[0])));
    }
    match data[1] {
        CMD_HEARTBEAT => Ok(Datagram::Heartbeat),
        CMD_PACKET => {
            let body = &data[2..];
            if body.len() < PACKET_FIXED_LEN {
                return Err(invalid("packet truncated"));
            }
            let (addr, addr_len) = decode_address(&body[PACKET_FIXED_LEN..])?;
            let header = PacketHeader {
                assoc_id: u16::from_be_bytes([body[0], body[1]]),
                pkt_id: u16::from_be_bytes([body[2], body[3]]),
                frag_total: body[4],
                frag_id: body[5],
                addr,
            };
            header.check()?;
            let size = u16::from_be_bytes([body[6], body[7]]) as usize;
            let start = 2 + PACKET_FIXED_LEN + addr_len;
            if data.len() - start != size {
                return Err(invalid("packet size mismatch"));
            }
            Ok(Datagram::Packet(header, data.slice(start..)))
        }
        other => Err(invalid(&format!(
            "unexpected command {:#04x} in a datagram",
            other
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(addr: Option<SocksAddr>) {
        let mut buf = BytesMut::new();
        write_address(&mut buf, addr.as_ref()).unwrap();
        assert_eq!(buf.len(), address_len(addr.as_ref()));
        let (decoded, n) = decode_address(&buf).unwrap();
        assert_eq!(n, buf.len());
        assert_eq!(decoded, addr);
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let read = rt.block_on(read_address(&mut &buf[..])).unwrap();
        assert_eq!(read, addr);
    }

    #[test]
    fn addresses_roundtrip() {
        roundtrip(None);
        roundtrip(Some("1.2.3.4:53".parse::<SocketAddr>().unwrap().into()));
        roundtrip(Some(
            "[2001:db8::1]:443".parse::<SocketAddr>().unwrap().into(),
        ));
        roundtrip(Some(SocksAddr::Domain("example.com".into(), 8080)));
    }

    #[test]
    fn address_wire_format_is_tuic() {
        let mut buf = BytesMut::new();
        write_address(&mut buf, Some(&SocksAddr::Domain("ab".into(), 0x0102))).unwrap();
        assert_eq!(&buf[..], &[0x00, 2, b'a', b'b', 0x01, 0x02]);
        buf.clear();
        let v4: SocketAddr = "10.0.0.1:80".parse().unwrap();
        write_address(&mut buf, Some(&v4.into())).unwrap();
        assert_eq!(&buf[..], &[0x01, 10, 0, 0, 1, 0, 80]);
        buf.clear();
        write_address(&mut buf, None).unwrap();
        assert_eq!(&buf[..], &[0xff]);
    }

    #[test]
    fn mapped_ipv6_reads_as_ipv4() {
        let mut wire = vec![ADDR_IPV6];
        wire.extend_from_slice(&Ipv4Addr::new(1, 2, 3, 4).to_ipv6_mapped().octets());
        wire.extend_from_slice(&53u16.to_be_bytes());
        let (addr, _) = decode_address(&wire).unwrap();
        assert_eq!(
            addr,
            Some("1.2.3.4:53".parse::<SocketAddr>().unwrap().into())
        );
    }

    #[test]
    fn bad_addresses_are_errors() {
        assert!(decode_address(&[]).is_err());
        assert!(decode_address(&[0x07]).is_err());
        assert!(decode_address(&[ADDR_IPV4, 1, 2, 3]).is_err());
        assert!(decode_address(&[ADDR_DOMAIN, 5, b'a', b'b']).is_err());
        assert!(decode_address(&[ADDR_DOMAIN, 0, 0, 80]).is_err());
        assert!(decode_address(&[ADDR_DOMAIN, 2, 0xff, 0xfe, 0, 80]).is_err());
        let long = SocksAddr::Domain("a".repeat(256), 1);
        assert!(write_address(&mut BytesMut::new(), Some(&long)).is_err());
    }

    #[test]
    fn commands_encode_as_the_spec_says() {
        let uuid = [7u8; 16];
        let token = [9u8; TOKEN_LEN];
        let auth = encode_authenticate(&uuid, &token);
        assert_eq!(auth.len(), 2 + 16 + 32);
        assert_eq!(&auth[..2], &[VERSION, CMD_AUTHENTICATE]);
        assert_eq!(&auth[2..18], &uuid);
        assert_eq!(&auth[18..], &token);

        let dst: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let connect = encode_connect(&dst.into(), b"hi").unwrap();
        assert_eq!(&connect[..], &[5, 1, 1, 1, 1, 1, 1, 0x01, 0xbb, b'h', b'i']);

        assert_eq!(&encode_dissociate(0x0102)[..], &[5, 3, 1, 2]);
        assert_eq!(&encode_heartbeat()[..], &[5, 4]);
    }

    #[test]
    fn packets_roundtrip_through_datagrams_and_streams() {
        let header = PacketHeader {
            assoc_id: 0xabcd,
            pkt_id: 7,
            frag_total: 1,
            frag_id: 0,
            addr: Some(SocksAddr::Domain("example.org".into(), 53)),
        };
        let wire = encode_packet(&header, b"payload").unwrap();
        assert_eq!(&wire[..4], &[5, 2, 0xab, 0xcd]);
        assert_eq!(wire.len(), header.len() + 7);
        match decode_datagram(wire.clone()).unwrap() {
            Datagram::Packet(h, p) => {
                assert_eq!(h, header);
                assert_eq!(&p[..], b"payload");
            }
            other => panic!("{:?}", other),
        }
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let mut r = &wire[..];
        let (h, p) = rt
            .block_on(async {
                assert_eq!(read_command(&mut r).await?, CMD_PACKET);
                read_packet(&mut r).await
            })
            .unwrap();
        assert_eq!(h, header);
        assert_eq!(&p[..], b"payload");
        assert_eq!(
            decode_datagram(encode_heartbeat()).unwrap(),
            Datagram::Heartbeat
        );
    }

    #[test]
    fn malformed_datagrams_are_errors() {
        let header = PacketHeader {
            assoc_id: 1,
            pkt_id: 1,
            frag_total: 1,
            frag_id: 0,
            addr: Some("1.2.3.4:5".parse::<SocketAddr>().unwrap().into()),
        };
        let wire = encode_packet(&header, b"abc").unwrap();
        // Size says more than there is, or less.
        assert!(decode_datagram(wire.slice(..wire.len() - 1)).is_err());
        let mut longer = BytesMut::from(&wire[..]);
        longer.put_u8(0);
        assert!(decode_datagram(longer.freeze()).is_err());
        // Another version.
        let mut v4 = BytesMut::from(&wire[..]);
        v4[0] = 4;
        assert!(decode_datagram(v4.freeze()).is_err());
        // A fragment id past the total, a first fragment without address.
        let bad = PacketHeader {
            frag_id: 1,
            ..header.clone()
        };
        assert!(decode_datagram(encode_packet(&bad, b"x").unwrap()).is_err());
        let bad = PacketHeader {
            addr: None,
            ..header.clone()
        };
        assert!(decode_datagram(encode_packet(&bad, b"x").unwrap()).is_err());
        let bad = PacketHeader {
            frag_total: 0,
            ..header
        };
        assert!(decode_datagram(encode_packet(&bad, b"x").unwrap()).is_err());
        // Commands that do not travel in datagrams.
        assert!(decode_datagram(encode_dissociate(1)).is_err());
        assert!(decode_datagram(Bytes::from_static(&[5])).is_err());
    }
}
