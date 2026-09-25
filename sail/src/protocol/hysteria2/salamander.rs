//! Salamander, the obfuscation Hysteria2 can wrap every QUIC packet in:
//! an 8-byte random salt, then the packet XORed with
//! BLAKE2b-256(password || salt), repeated.
//!
//! It sits between quinn and the UDP socket, as an `AsyncUdpSocket`.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use rand::RngCore;

pub const SALT_LEN: usize = 8;

/// The Salamander key: the password it is configured with.
#[derive(Clone)]
pub struct Salamander {
    password: Arc<[u8]>,
}

impl fmt::Debug for Salamander {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Salamander")
    }
}

impl Salamander {
    pub fn new(password: &str) -> Self {
        Self {
            password: password.as_bytes().into(),
        }
    }

    fn key(&self, salt: &[u8]) -> [u8; 32] {
        let mut hasher = Blake2b::<U32>::new();
        hasher.update(&self.password);
        hasher.update(salt);
        hasher.finalize().into()
    }

    /// `packet` obfuscated under a fresh salt.
    pub fn obfuscate(&self, packet: &[u8]) -> Vec<u8> {
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        self.obfuscate_with(salt, packet)
    }

    fn obfuscate_with(&self, salt: [u8; SALT_LEN], packet: &[u8]) -> Vec<u8> {
        let key = self.key(&salt);
        let mut out = Vec::with_capacity(SALT_LEN + packet.len());
        out.extend_from_slice(&salt);
        out.extend(packet.iter().zip(key.iter().cycle()).map(|(b, k)| b ^ k));
        out
    }

    /// Deobfuscates `datagram` in place, moving the packet to its front, and
    /// returns the packet's length; None for a datagram too short to be
    /// one, which is to be dropped.
    pub fn deobfuscate(&self, datagram: &mut [u8]) -> Option<usize> {
        if datagram.len() <= SALT_LEN {
            return None;
        }
        let key = self.key(&datagram[..SALT_LEN]);
        let len = datagram.len() - SALT_LEN;
        for i in 0..len {
            datagram[i] = datagram[i + SALT_LEN] ^ key[i % key.len()];
        }
        Some(len)
    }
}

/// A UDP socket whose datagrams are Salamander-obfuscated.
#[derive(Debug)]
pub struct SalamanderSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    obfs: Salamander,
}

impl SalamanderSocket {
    pub fn new(inner: Arc<dyn AsyncUdpSocket>, obfs: Salamander) -> Self {
        Self { inner, obfs }
    }
}

impl AsyncUdpSocket for SalamanderSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // One datagram per transmit, see `max_transmit_segments`.
        let contents = self.obfs.obfuscate(transmit.contents);
        self.inner.try_send(&Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &contents,
            segment_size: None,
            src_ip: transmit.src_ip,
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let n = ready!(self.inner.poll_recv(cx, bufs, meta))?;
        for (buf, meta) in bufs.iter_mut().zip(meta.iter_mut()).take(n) {
            deobfuscate_segments(&self.obfs, &mut buf[..meta.len], meta);
        }
        Poll::Ready(Ok(n))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Each datagram takes its own salt, so quinn must not hand over several
    /// to be sent as one.
    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

/// Deobfuscates the datagrams of one receive, which with GRO are several at
/// `meta.stride` apart, packing them at the new stride. A datagram too short
/// to be one can only be the last; it is dropped.
fn deobfuscate_segments(obfs: &Salamander, buf: &mut [u8], meta: &mut RecvMeta) {
    let stride = meta.stride.max(1);
    let new_stride = stride.saturating_sub(SALT_LEN);
    let mut read = 0;
    let mut written = 0;
    while read < buf.len() {
        let end = (read + stride).min(buf.len());
        if let Some(len) = obfs.deobfuscate(&mut buf[read..end]) {
            buf.copy_within(read..read + len, written);
            written += len;
        }
        read = end;
    }
    meta.len = written;
    // quinn splits the buffer at the stride; it must not be zero.
    meta.stride = new_stride.max(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_packet_round_trips() {
        let obfs = Salamander::new("cry me a r1ver");
        let packet: Vec<u8> = (0..100u8).collect();
        let mut datagram = obfs.obfuscate(&packet);
        assert_eq!(datagram.len(), packet.len() + SALT_LEN);
        assert_ne!(&datagram[SALT_LEN..], &packet[..]);
        let len = obfs.deobfuscate(&mut datagram).unwrap();
        assert_eq!(&datagram[..len], &packet[..]);
    }

    /// The same bytes the reference implementation produces for this salt
    /// and password: the key is BLAKE2b-256("password" || salt).
    #[test]
    fn the_key_is_blake2b_of_password_then_salt() {
        let obfs = Salamander::new("password");
        let salt = [1, 2, 3, 4, 5, 6, 7, 8];
        let key = obfs.key(&salt);
        let mut hasher = Blake2b::<U32>::new();
        hasher.update(b"password\x01\x02\x03\x04\x05\x06\x07\x08");
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(key, expected);
        // Zeroes come out as the key itself, repeating after 32 bytes.
        let out = obfs.obfuscate_with(salt, &[0; 40]);
        assert_eq!(&out[..SALT_LEN], &salt);
        assert_eq!(&out[SALT_LEN..SALT_LEN + 32], &key);
        assert_eq!(&out[SALT_LEN + 32..], &key[..8]);
    }

    #[test]
    fn blake2b_256_matches_a_known_answer() {
        // BLAKE2b-256 of the empty string.
        let digest: [u8; 32] = Blake2b::<U32>::new().finalize().into();
        let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            hex,
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
        );
    }

    #[test]
    fn short_datagrams_are_dropped() {
        let obfs = Salamander::new("x");
        assert_eq!(obfs.deobfuscate(&mut [0; SALT_LEN]), None);
        assert_eq!(obfs.deobfuscate(&mut []), None);
    }

    #[test]
    fn gro_segments_are_each_deobfuscated_and_packed() {
        let obfs = Salamander::new("gro");
        let a = vec![0xaa; 20];
        let b = vec![0xbb; 20];
        let c = vec![0xcc; 5];
        let mut buf = Vec::new();
        buf.extend(obfs.obfuscate(&a));
        buf.extend(obfs.obfuscate(&b));
        buf.extend(obfs.obfuscate(&c));
        let mut meta = RecvMeta {
            len: buf.len(),
            stride: 28,
            ..Default::default()
        };
        deobfuscate_segments(&obfs, &mut buf, &mut meta);
        assert_eq!(meta.stride, 20);
        assert_eq!(meta.len, 45);
        assert_eq!(&buf[..45], &[a.clone(), b, c].concat()[..]);

        // A last segment too short to carry a packet is dropped.
        let mut buf = obfs.obfuscate(&a);
        buf.extend([0u8; SALT_LEN]);
        let mut meta = RecvMeta {
            len: buf.len(),
            stride: 28,
            ..Default::default()
        };
        deobfuscate_segments(&obfs, &mut buf, &mut meta);
        assert_eq!(meta.len, 20);
        assert_eq!(&buf[..20], &a[..]);
    }
}
