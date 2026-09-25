//! The Hysteria2 wire format: QUIC varints, the TCP request and response
//! that open a proxied stream, the UDP message carried in a QUIC datagram,
//! and the "host:port" addresses they all use.
//!
//! See <https://v2.hysteria.network/docs/developers/Protocol/>.

use std::io;

use bytes::{BufMut, BytesMut};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::session::SocksAddr;

/// The HTTP/3 frame type a proxied TCP stream starts with.
pub const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;

/// The status of a successful authentication.
pub const STATUS_AUTH_OK: u16 = 233;

pub const AUTH_HOST: &str = "hysteria";
pub const AUTH_PATH: &str = "/auth";
pub const HEADER_AUTH: &str = "hysteria-auth";
pub const HEADER_CC_RX: &str = "hysteria-cc-rx";
pub const HEADER_PADDING: &str = "hysteria-padding";
pub const HEADER_UDP: &str = "hysteria-udp";

/// Limits the reference implementation also enforces, so that a peer
/// cannot make us allocate much for a request.
pub const MAX_ADDRESS_LENGTH: u64 = 2048;
pub const MAX_MESSAGE_LENGTH: u64 = 2048;
pub const MAX_PADDING_LENGTH: u64 = 4096;

/// Mbps as a sing-box configuration gives it, in bytes per second.
pub const MBPS_TO_BPS: u64 = 125_000;

/// Paddings as half-open length ranges, the same as the reference
/// implementation's so that lengths look alike.
pub const AUTH_REQUEST_PADDING: (usize, usize) = (256, 2048);
pub const AUTH_RESPONSE_PADDING: (usize, usize) = (256, 2048);
pub const TCP_REQUEST_PADDING: (usize, usize) = (64, 512);
pub const TCP_RESPONSE_PADDING: (usize, usize) = (128, 1024);

/// A random alphanumeric padding with a length in `range`.
pub fn padding((min, max): (usize, usize)) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    let len = rng.gen_range(min..max);
    (0..len)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect()
}

// ---------------------------------------------------------------------------
// Varints
// ---------------------------------------------------------------------------

/// The largest value a QUIC varint holds.
pub const VARINT_MAX: u64 = (1 << 62) - 1;

/// How many bytes `v` takes as a varint.
pub fn varint_len(v: u64) -> usize {
    if v < 1 << 6 {
        1
    } else if v < 1 << 14 {
        2
    } else if v < 1 << 30 {
        4
    } else {
        8
    }
}

/// Appends `v` as a varint. Values above `VARINT_MAX` do not occur here:
/// every one written is a length or a constant.
pub fn put_varint(buf: &mut impl BufMut, v: u64) {
    debug_assert!(v <= VARINT_MAX);
    match varint_len(v) {
        1 => buf.put_u8(v as u8),
        2 => buf.put_u16(v as u16 | 0x4000),
        4 => buf.put_u32(v as u32 | 0x8000_0000),
        _ => buf.put_u64(v | 0xc000_0000_0000_0000),
    }
}

/// Reads a varint off the front of `buf`, returning it and the bytes it
/// took, or None if `buf` ends before it does.
pub fn get_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1 << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut v = (first & 0x3f) as u64;
    for b in &buf[1..len] {
        v = (v << 8) | *b as u64;
    }
    Some((v, len))
}

/// Reads a varint from `r`.
pub async fn read_varint<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<u64> {
    let first = r.read_u8().await?;
    let len = 1usize << (first >> 6);
    let mut v = (first & 0x3f) as u64;
    for _ in 1..len {
        v = (v << 8) | r.read_u8().await? as u64;
    }
    Ok(v)
}

/// Reads `len` bytes, which must be at most `max`, from `r`.
async fn read_bounded<R: AsyncRead + Unpin>(
    r: &mut R,
    len: u64,
    max: u64,
    what: &str,
) -> io::Result<Vec<u8>> {
    if len > max {
        return Err(invalid(format!("{} too long: {}", what, len)));
    }
    let mut buf = vec![0; len as usize];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Reads and throws away a varint-prefixed padding.
async fn skip_padding<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<()> {
    let len = read_varint(r).await?;
    if len > MAX_PADDING_LENGTH {
        return Err(invalid(format!("padding too long: {}", len)));
    }
    let copied = tokio::io::copy(&mut (&mut *r).take(len), &mut tokio::io::sink()).await?;
    if copied != len {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(())
}

fn invalid(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

// ---------------------------------------------------------------------------
// Addresses
// ---------------------------------------------------------------------------

/// `addr` as "host:port", an IPv6 host in brackets.
pub fn format_addr(addr: &SocksAddr) -> String {
    // `SocketAddr` puts an IPv6 address in brackets already.
    addr.to_string()
}

/// Reads a "host:port" address.
pub fn parse_addr(s: &str) -> io::Result<SocksAddr> {
    let (host, port) = s
        .rsplit_once(':')
        .ok_or_else(|| invalid(format!("address without a port: {}", s)))?;
    let port: u16 = port
        .parse()
        .map_err(|_| invalid(format!("invalid port in address: {}", s)))?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if host.is_empty() {
        return Err(invalid(format!("address without a host: {}", s)));
    }
    SocksAddr::try_from((host, port))
}

// ---------------------------------------------------------------------------
// TCP
// ---------------------------------------------------------------------------

/// A TCPRequest for `addr`, followed by `payload`.
pub fn tcp_request(addr: &SocksAddr, payload: &[u8]) -> BytesMut {
    let addr = format_addr(addr);
    let padding = padding(TCP_REQUEST_PADDING);
    let mut buf = BytesMut::with_capacity(16 + addr.len() + padding.len() + payload.len());
    put_varint(&mut buf, FRAME_TYPE_TCP_REQUEST);
    put_varint(&mut buf, addr.len() as u64);
    buf.put_slice(addr.as_bytes());
    put_varint(&mut buf, padding.len() as u64);
    buf.put_slice(padding.as_bytes());
    buf.put_slice(payload);
    buf
}

/// Reads the rest of a TCPRequest, after the frame type: the address the
/// stream is for.
pub async fn read_tcp_request<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<SocksAddr> {
    let len = read_varint(r).await?;
    if len == 0 {
        return Err(invalid("empty address".to_string()));
    }
    let addr = read_bounded(r, len, MAX_ADDRESS_LENGTH, "address").await?;
    skip_padding(r).await?;
    let addr = std::str::from_utf8(&addr).map_err(|_| invalid("address not UTF-8".into()))?;
    parse_addr(addr)
}

/// A TCPResponse: OK, or an error with `message`.
pub fn tcp_response(ok: bool, message: &str) -> BytesMut {
    let message = &message.as_bytes()[..message.len().min(MAX_MESSAGE_LENGTH as usize)];
    let padding = padding(TCP_RESPONSE_PADDING);
    let mut buf = BytesMut::with_capacity(12 + message.len() + padding.len());
    buf.put_u8(if ok { 0 } else { 1 });
    put_varint(&mut buf, message.len() as u64);
    buf.put_slice(message);
    put_varint(&mut buf, padding.len() as u64);
    buf.put_slice(padding.as_bytes());
    buf
}

/// Reads a TCPResponse, failing with its message if it is not OK.
pub async fn read_tcp_response<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<()> {
    let status = r.read_u8().await?;
    let len = read_varint(r).await?;
    let message = read_bounded(r, len, MAX_MESSAGE_LENGTH, "message").await?;
    skip_padding(r).await?;
    if status != 0 {
        return Err(io::Error::other(format!(
            "server refused: {}",
            String::from_utf8_lossy(&message)
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// UDP
// ---------------------------------------------------------------------------

/// A UDPMessage, or one fragment of one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpMessage<'a> {
    pub session_id: u32,
    pub packet_id: u16,
    pub fragment_id: u8,
    pub fragment_count: u8,
    pub addr: &'a str,
    pub payload: &'a [u8],
}

impl<'a> UdpMessage<'a> {
    /// The bytes before the payload.
    pub fn header_len(addr: &str) -> usize {
        8 + varint_len(addr.len() as u64) + addr.len()
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.reserve(Self::header_len(self.addr) + self.payload.len());
        buf.put_u32(self.session_id);
        buf.put_u16(self.packet_id);
        buf.put_u8(self.fragment_id);
        buf.put_u8(self.fragment_count);
        put_varint(buf, self.addr.len() as u64);
        buf.put_slice(self.addr.as_bytes());
        buf.put_slice(self.payload);
    }

    pub fn decode(buf: &'a [u8]) -> io::Result<Self> {
        let short = || invalid("short UDP message".to_string());
        if buf.len() < 8 {
            return Err(short());
        }
        let (addr_len, n) = get_varint(&buf[8..]).ok_or_else(short)?;
        if addr_len == 0 || addr_len > MAX_ADDRESS_LENGTH {
            return Err(invalid(format!("invalid address length: {}", addr_len)));
        }
        let start = 8 + n;
        let end = start + addr_len as usize;
        if buf.len() < end {
            return Err(short());
        }
        let addr = std::str::from_utf8(&buf[start..end])
            .map_err(|_| invalid("address not UTF-8".to_string()))?;
        Ok(UdpMessage {
            session_id: u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
            packet_id: u16::from_be_bytes([buf[4], buf[5]]),
            fragment_id: buf[6],
            fragment_count: buf[7],
            addr,
            payload: &buf[end..],
        })
    }
}

/// Encodes `payload` for `addr` as one message, or as fragments that each
/// fit in `max_datagram` bytes. Fails if it would take more fragments than
/// a message can count, or if not even the header fits.
pub fn fragment(
    session_id: u32,
    packet_id: u16,
    addr: &str,
    payload: &[u8],
    max_datagram: usize,
) -> io::Result<Vec<BytesMut>> {
    let header = UdpMessage::header_len(addr);
    let room = max_datagram.saturating_sub(header);
    if room == 0 {
        return Err(io::Error::other("datagrams too small for the UDP header"));
    }
    let chunks: Vec<&[u8]> = if payload.len() <= room {
        vec![payload]
    } else {
        payload.chunks(room).collect()
    };
    let count = u8::try_from(chunks.len())
        .map_err(|_| io::Error::other(format!("UDP packet too large: {}", payload.len())))?;
    Ok(chunks
        .into_iter()
        .enumerate()
        .map(|(i, chunk)| {
            let mut buf = BytesMut::new();
            UdpMessage {
                session_id,
                packet_id,
                fragment_id: i as u8,
                fragment_count: count,
                addr,
                payload: chunk,
            }
            .encode(&mut buf);
            buf
        })
        .collect())
}

/// Puts fragmented packets of one session back together.
///
/// Like the reference implementation it keeps one packet at a time: a
/// fragment of another packet drops the one being assembled. Fragments of
/// one packet travel back to back, so this loses little and bounds what a
/// session holds to one packet.
#[derive(Default)]
pub struct Defragger {
    packet_id: u16,
    fragments: Vec<Option<Vec<u8>>>,
    received: usize,
    size: usize,
}

impl Defragger {
    /// Takes one message, returning the whole packet once it is complete.
    pub fn feed(&mut self, msg: &UdpMessage<'_>) -> Option<Vec<u8>> {
        if msg.fragment_count <= 1 {
            return Some(msg.payload.to_vec());
        }
        if msg.fragment_id >= msg.fragment_count {
            return None;
        }
        if msg.packet_id != self.packet_id || self.fragments.len() != msg.fragment_count as usize {
            self.packet_id = msg.packet_id;
            self.fragments = vec![None; msg.fragment_count as usize];
            self.received = 0;
            self.size = 0;
        }
        let slot = &mut self.fragments[msg.fragment_id as usize];
        if slot.is_none() {
            *slot = Some(msg.payload.to_vec());
            self.received += 1;
            self.size += msg.payload.len();
        }
        if self.received < self.fragments.len() {
            return None;
        }
        let mut packet = Vec::with_capacity(self.size);
        for fragment in self.fragments.drain(..) {
            packet.extend_from_slice(&fragment.unwrap_or_default());
        }
        self.received = 0;
        self.size = 0;
        Some(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints_round_trip_at_every_length() {
        for v in [0, 63, 64, 16383, 16384, (1 << 30) - 1, 1 << 30, VARINT_MAX] {
            let mut buf = BytesMut::new();
            put_varint(&mut buf, v);
            assert_eq!(buf.len(), varint_len(v));
            assert_eq!(get_varint(&buf), Some((v, buf.len())));
            assert_eq!(get_varint(&buf[..buf.len() - 1]), None);
        }
        // RFC 9000, appendix A.1.
        assert_eq!(get_varint(&[0x7b, 0xbd]), Some((15293, 2)));
        assert_eq!(get_varint(&[0x9d, 0x7f, 0x3e, 0x7d]), Some((494878333, 4)));
    }

    #[tokio::test]
    async fn a_tcp_request_carries_the_address_and_payload_after_its_padding() {
        let addr = SocksAddr::try_from(("example.com", 443)).unwrap();
        let buf = tcp_request(&addr, b"hello");
        let mut r = &buf[..];
        assert_eq!(read_varint(&mut r).await.unwrap(), FRAME_TYPE_TCP_REQUEST);
        assert_eq!(read_tcp_request(&mut r).await.unwrap(), addr);
        assert_eq!(r, b"hello");
    }

    #[tokio::test]
    async fn a_tcp_request_for_an_ipv6_address_brackets_it() {
        let addr: SocksAddr = "[::1]:53".parse::<std::net::SocketAddr>().unwrap().into();
        let buf = tcp_request(&addr, b"");
        assert!(buf.windows(8).any(|w| w == b"[::1]:53"));
        let mut r = &buf[..];
        read_varint(&mut r).await.unwrap();
        assert_eq!(read_tcp_request(&mut r).await.unwrap(), addr);
    }

    #[tokio::test]
    async fn a_tcp_response_says_ok_or_carries_the_error() {
        let ok = tcp_response(true, "");
        read_tcp_response(&mut &ok[..]).await.unwrap();
        let refused = tcp_response(false, "no route");
        let err = read_tcp_response(&mut &refused[..]).await.unwrap_err();
        assert!(err.to_string().contains("no route"), "{}", err);
    }

    #[tokio::test]
    async fn an_oversized_padding_is_refused() {
        let mut buf = BytesMut::new();
        put_varint(&mut buf, 4);
        buf.put_slice(b"a:80");
        put_varint(&mut buf, MAX_PADDING_LENGTH + 1);
        assert!(read_tcp_request(&mut &buf[..]).await.is_err());
    }

    #[test]
    fn addresses_parse_as_the_reference_implementation_writes_them() {
        assert_eq!(
            parse_addr("1.2.3.4:80").unwrap(),
            SocksAddr::Ip("1.2.3.4:80".parse().unwrap())
        );
        assert_eq!(
            parse_addr("[2001:db8::1]:443").unwrap(),
            SocksAddr::Ip("[2001:db8::1]:443".parse().unwrap())
        );
        assert_eq!(
            parse_addr("example.com:53").unwrap(),
            SocksAddr::Domain("example.com".into(), 53)
        );
        assert!(parse_addr("example.com").is_err());
        assert!(parse_addr(":80").is_err());
        assert!(parse_addr("a:99999").is_err());
    }

    #[test]
    fn udp_messages_round_trip() {
        let msg = UdpMessage {
            session_id: 0x01020304,
            packet_id: 7,
            fragment_id: 0,
            fragment_count: 1,
            addr: "8.8.8.8:53",
            payload: b"query",
        };
        let mut buf = BytesMut::new();
        msg.encode(&mut buf);
        assert_eq!(&buf[..8], &[1, 2, 3, 4, 0, 7, 0, 1]);
        assert_eq!(UdpMessage::decode(&buf).unwrap(), msg);
        assert!(UdpMessage::decode(&buf[..12]).is_err());
    }

    #[test]
    fn a_large_packet_is_fragmented_and_put_back_together() {
        let payload: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        let fragments = fragment(9, 42, "1.1.1.1:53", &payload, 1200).unwrap();
        assert_eq!(fragments.len(), 5);
        assert!(fragments.iter().all(|f| f.len() <= 1200));

        let mut defragger = Defragger::default();
        // Out of order, with a duplicate.
        let order = [3, 0, 4, 0, 1, 2];
        let mut out = None;
        for (n, i) in order.iter().enumerate() {
            let msg = UdpMessage::decode(&fragments[*i]).unwrap();
            assert_eq!(msg.packet_id, 42);
            let done = defragger.feed(&msg);
            if n < order.len() - 1 {
                assert!(done.is_none());
            }
            out = done;
        }
        assert_eq!(out.unwrap(), payload);
    }

    #[test]
    fn a_new_packet_drops_the_incomplete_one() {
        let payload = vec![1u8; 3000];
        let first = fragment(1, 1, "a:1", &payload, 1200).unwrap();
        let second = fragment(1, 2, "a:1", &payload, 1200).unwrap();
        let mut defragger = Defragger::default();
        assert!(defragger
            .feed(&UdpMessage::decode(&first[0]).unwrap())
            .is_none());
        let mut out = None;
        for f in &second {
            out = defragger.feed(&UdpMessage::decode(f).unwrap());
        }
        assert_eq!(out.unwrap(), payload);
        // The rest of the first packet alone does not complete it.
        assert!(defragger
            .feed(&UdpMessage::decode(&first[1]).unwrap())
            .is_none());
    }

    #[test]
    fn a_packet_needing_too_many_fragments_is_refused() {
        assert!(fragment(1, 1, "a:1", &vec![0; 256 * 100], 100).is_err());
        assert!(fragment(1, 1, "a:1", b"x", 8).is_err());
    }
}
