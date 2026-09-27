//! The server name of a QUIC client's ClientHello, from its Initial
//! packets (RFC 9000, RFC 9001; RFC 9369 for version 2).
//!
//! Initial packets are protected with keys anyone can derive from the
//! destination connection ID. The ClientHello is carried in CRYPTO frames,
//! which a client may split across several Initial packets and send in any
//! order, as Chrome does, so the frames are put back together by offset
//! across the datagrams of a session until the ClientHello is whole.

use super::{tls, Sniff, MAX_SNIFF_LEN};

/// The versions whose Initial packets are read: 1, 2, and the last draft,
/// which old clients still send.
const VERSION_1: u32 = 0x0000_0001;
const VERSION_2: u32 = 0x6b33_43cf;
const DRAFT_29: u32 = 0xff00_001d;

/// Fragments of the CRYPTO stream kept, at most. Chrome splits a ClientHello
/// into a few dozen.
const MAX_FRAGMENTS: usize = 256;

/// The CRYPTO stream of a QUIC session so far, put back together from the
/// Initial packets read.
#[derive(Default)]
pub struct QuicSniffer {
    /// The stream from offset 0, up to the furthest byte received.
    data: Vec<u8>,
    /// The ranges of `data` received, merged and in order.
    received: Vec<(usize, usize)>,
}

impl QuicSniffer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reads the Initial packets of a client's datagram: the server name of
    /// the ClientHello once the CRYPTO frames read make it whole.
    pub fn feed(&mut self, datagram: &[u8]) -> Sniff {
        let mut rest = datagram;
        let mut initials = 0;
        while !rest.is_empty() {
            // What follows the first Initial is let be when it is not one:
            // other packets coalesced, or padding.
            let Some(packet) = LongPacket::parse(rest) else {
                if initials == 0 {
                    return Sniff::NotMatch;
                }
                break;
            };
            let bytes = &rest[..packet.end];
            rest = &rest[packet.end..];
            if !packet.is_initial() {
                if initials == 0 {
                    return Sniff::NotMatch;
                }
                continue;
            }
            let Some(payload) = decrypt(&packet, bytes) else {
                return Sniff::NotMatch;
            };
            if !self.read_frames(&payload) {
                return Sniff::NotMatch;
            }
            initials += 1;
        }
        if initials == 0 {
            return Sniff::NotMatch;
        }
        match tls::client_hello(&self.data[..self.contiguous()]) {
            Sniff::Found(name) => Sniff::Found(name),
            Sniff::NotMatch => Sniff::NotMatch,
            Sniff::NeedMore if self.data.len() >= MAX_SNIFF_LEN => Sniff::NotMatch,
            Sniff::NeedMore => Sniff::NeedMore,
        }
    }

    /// How much of the stream from offset 0 is received.
    fn contiguous(&self) -> usize {
        match self.received.first() {
            Some(&(0, end)) => end,
            _ => 0,
        }
    }

    /// Reads the frames of an Initial packet's payload, keeping the CRYPTO
    /// ones; false when they are not what a client's Initial carries.
    fn read_frames(&mut self, mut payload: &[u8]) -> bool {
        while let Some((&kind, rest)) = payload.split_first() {
            payload = rest;
            match kind {
                // PADDING, PING
                0x00 | 0x01 => {}
                // ACK, with ECN counts for 0x03
                0x02 | 0x03 => {
                    let Some([_largest, _delay, ranges, _first]) = varints(&mut payload) else {
                        return false;
                    };
                    for _ in 0..ranges.min(payload.len() as u64) {
                        if varints::<2>(&mut payload).is_none() {
                            return false;
                        }
                    }
                    if kind == 0x03 && varints::<3>(&mut payload).is_none() {
                        return false;
                    }
                }
                // CRYPTO
                0x06 => {
                    let Some([offset, len]) = varints(&mut payload) else {
                        return false;
                    };
                    let len = len as usize;
                    if payload.len() < len || !self.add(offset, &payload[..len]) {
                        return false;
                    }
                    payload = &payload[len..];
                }
                // CONNECTION_CLOSE
                0x1c => {
                    let Some([_code, _frame, len]) = varints(&mut payload) else {
                        return false;
                    };
                    let Some(rest) = payload.get(len as usize..) else {
                        return false;
                    };
                    payload = rest;
                }
                _ => return false,
            }
        }
        true
    }

    /// Adds the CRYPTO bytes at `offset`; false when they reach past what
    /// is kept.
    fn add(&mut self, offset: u64, bytes: &[u8]) -> bool {
        let Some(end) = offset.checked_add(bytes.len() as u64) else {
            return false;
        };
        if end > MAX_SNIFF_LEN as u64 {
            return false;
        }
        if bytes.is_empty() {
            return true;
        }
        let (start, end) = (offset as usize, end as usize);
        if self.data.len() < end {
            self.data.resize(end, 0);
        }
        self.data[start..end].copy_from_slice(bytes);
        // Merged into the ranges received.
        let mut merged = (start, end);
        self.received.retain(|&(s, e)| {
            if s <= merged.1 && merged.0 <= e {
                merged = (merged.0.min(s), merged.1.max(e));
                false
            } else {
                true
            }
        });
        let at = self.received.partition_point(|&(s, _)| s < merged.0);
        self.received.insert(at, merged);
        self.received.len() <= MAX_FRAGMENTS
    }
}

/// Reads `N` variable-length integers off the front of `buf`.
fn varints<const N: usize>(buf: &mut &[u8]) -> Option<[u64; N]> {
    let mut out = [0; N];
    for v in out.iter_mut() {
        *v = varint(buf)?;
    }
    Some(out)
}

/// Reads a variable-length integer off the front of `buf`.
fn varint(buf: &mut &[u8]) -> Option<u64> {
    let first = *buf.first()?;
    let len = 1 << (first >> 6);
    let bytes = buf.get(..len)?;
    let mut v = (first & 0x3f) as u64;
    for b in &bytes[1..] {
        v = v << 8 | *b as u64;
    }
    *buf = &buf[len..];
    Some(v)
}

/// A long header packet of a version whose Initial packets are read.
// Without btls, nothing decrypts it.
#[cfg_attr(not(feature = "btls"), allow(dead_code))]
struct LongPacket<'a> {
    version: u32,
    kind: u8,
    dcid: &'a [u8],
    /// Where its packet number starts: the header up to it.
    pn_offset: usize,
    /// Where it ends, after its payload.
    end: usize,
}

impl<'a> LongPacket<'a> {
    fn parse(buf: &'a [u8]) -> Option<Self> {
        let mut rest = buf;
        let first = *rest.first()?;
        // The header form and the fixed bit.
        if first & 0xc0 != 0xc0 {
            return None;
        }
        let version = u32::from_be_bytes(rest.get(1..5)?.try_into().ok()?);
        if !matches!(version, VERSION_1 | VERSION_2 | DRAFT_29) {
            return None;
        }
        rest = &rest[5..];
        let dcid = take_cid(&mut rest)?;
        take_cid(&mut rest)?;
        let kind = (first >> 4) & 0x03;
        let packet = LongPacket {
            version,
            kind,
            dcid,
            pn_offset: 0,
            end: 0,
        };
        if packet.is_retry() {
            return None;
        }
        if packet.is_initial() {
            let token = varint(&mut rest)? as usize;
            rest = rest.get(token..)?;
        }
        let len = varint(&mut rest)? as usize;
        let pn_offset = buf.len() - rest.len();
        // A packet number and a sample, at least.
        if len < 4 + 16 || rest.len() < len {
            return None;
        }
        Some(LongPacket {
            pn_offset,
            end: pn_offset + len,
            ..packet
        })
    }

    fn is_initial(&self) -> bool {
        match self.version {
            VERSION_2 => self.kind == 0b01,
            _ => self.kind == 0b00,
        }
    }

    fn is_retry(&self) -> bool {
        match self.version {
            VERSION_2 => self.kind == 0b00,
            _ => self.kind == 0b11,
        }
    }
}

/// Reads a connection ID, of at most 20 bytes, off the front of `buf`.
fn take_cid<'a>(buf: &mut &'a [u8]) -> Option<&'a [u8]> {
    let len = *buf.first()? as usize;
    if len > 20 {
        return None;
    }
    let cid = buf.get(1..1 + len)?;
    *buf = &buf[1 + len..];
    Some(cid)
}

/// The keys a client protects its Initial packets with.
#[cfg(feature = "btls")]
struct InitialKeys {
    key: [u8; 16],
    iv: [u8; 12],
    hp: [u8; 16],
}

#[cfg(feature = "btls")]
impl InitialKeys {
    /// The client's keys for the connection ID `dcid` in `version`.
    fn client(version: u32, dcid: &[u8]) -> Option<Self> {
        use btls::hash::MessageDigest;
        use btls::hkdf::HkdfSuite;

        const SALT_1: [u8; 20] = [
            0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
            0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
        ];
        const SALT_2: [u8; 20] = [
            0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26,
            0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
        ];
        const SALT_DRAFT_29: [u8; 20] = [
            0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61,
            0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99,
        ];

        /// TLS 1.3's HKDF-Expand-Label, with an empty context.
        fn expand_label(
            hkdf: &HkdfSuite,
            secret: &[u8],
            label: &str,
            out: &mut [u8],
        ) -> Option<()> {
            let mut info = Vec::with_capacity(4 + 6 + label.len());
            info.extend_from_slice(&(out.len() as u16).to_be_bytes());
            info.push((6 + label.len()) as u8);
            info.extend_from_slice(b"tls13 ");
            info.extend_from_slice(label.as_bytes());
            info.push(0);
            hkdf.expand(secret, &info, out).ok()
        }

        let (salt, prefix) = match version {
            VERSION_2 => (&SALT_2, "quicv2 "),
            VERSION_1 => (&SALT_1, "quic "),
            _ => (&SALT_DRAFT_29, "quic "),
        };
        let hkdf = HkdfSuite::new(MessageDigest::sha256());
        let initial = hkdf.extract(salt, dcid).ok()?;
        let mut secret = [0u8; 32];
        expand_label(&hkdf, &initial, "client in", &mut secret)?;
        let mut keys = InitialKeys {
            key: [0; 16],
            iv: [0; 12],
            hp: [0; 16],
        };
        expand_label(&hkdf, &secret, &format!("{}key", prefix), &mut keys.key)?;
        expand_label(&hkdf, &secret, &format!("{}iv", prefix), &mut keys.iv)?;
        expand_label(&hkdf, &secret, &format!("{}hp", prefix), &mut keys.hp)?;
        Some(keys)
    }

    /// The header protection mask of the ciphertext `sample`.
    fn mask(&self, sample: &[u8]) -> Option<[u8; 16]> {
        use btls::symm::{Cipher, Crypter, Mode};

        let mut crypter =
            Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, &self.hp, None).ok()?;
        crypter.pad(false);
        let mut out = [0u8; 32];
        if crypter.update(sample, &mut out).ok()? != 16 {
            return None;
        }
        out[..16].try_into().ok()
    }

    /// The nonce of the packet numbered `number`.
    fn nonce(&self, number: u64) -> [u8; 12] {
        let mut nonce = self.iv;
        for (n, b) in nonce[4..].iter_mut().zip(number.to_be_bytes()) {
            *n ^= b;
        }
        nonce
    }

    fn aead(&self) -> Option<btls::aead::AeadCtx> {
        use btls::aead::{AeadCtx, Algorithm};
        AeadCtx::new_default_tag(&Algorithm::aes_128_gcm(), &self.key).ok()
    }
}

/// The payload of the Initial packet `bytes`, its header protection and
/// packet protection removed with the client's initial keys.
#[cfg(feature = "btls")]
fn decrypt(packet: &LongPacket, bytes: &[u8]) -> Option<Vec<u8>> {
    let keys = InitialKeys::client(packet.version, packet.dcid)?;
    // The mask is of the sample 4 bytes past the start of the packet
    // number, whatever its length.
    let pn = packet.pn_offset;
    let mask = keys.mask(bytes.get(pn + 4..pn + 4 + 16)?)?;
    let mut header = bytes[..pn].to_vec();
    header[0] ^= mask[0] & 0x0f;
    let pn_len = (header[0] & 0x03) as usize + 1;
    // The first packet numbers are small enough to be whole as sent.
    let mut number = 0;
    for i in 0..pn_len {
        let b = bytes[pn + i] ^ mask[1 + i];
        header.push(b);
        number = number << 8 | b as u64;
    }
    let body = &bytes[pn + pn_len..];
    let (ciphertext, tag) = body.split_at(body.len().checked_sub(16)?);
    let mut payload = ciphertext.to_vec();
    keys.aead()?
        .open_in_place_mut(&keys.nonce(number), &mut payload, tag, &header)
        .ok()?;
    Some(payload)
}

/// Without btls, nothing to decrypt with: no Initial packet is read.
#[cfg(not(feature = "btls"))]
fn decrypt(_packet: &LongPacket, _bytes: &[u8]) -> Option<Vec<u8>> {
    None
}

/// A client's Initial packet of `version` to `dcid`, numbered `number`,
/// carrying `frames`: what a client sends, for the tests and the fuzz
/// targets.
#[cfg(feature = "btls")]
#[doc(hidden)]
pub fn protect(version: u32, dcid: &[u8], number: u32, frames: &[u8]) -> Option<Vec<u8>> {
    let keys = InitialKeys::client(version, dcid)?;
    let kind = if version == VERSION_2 { 0b01 } else { 0b00 };
    // A four-byte packet number.
    let mut packet = vec![0xc0 | kind << 4 | 0x03];
    packet.extend_from_slice(&version.to_be_bytes());
    packet.push(u8::try_from(dcid.len()).ok()?);
    packet.extend_from_slice(dcid);
    // No source connection ID, no token.
    packet.extend_from_slice(&[0, 0]);
    let len = u16::try_from(4 + frames.len() + 16)
        .ok()
        .filter(|len| *len < 0x4000)?;
    packet.extend_from_slice(&(0x4000 | len).to_be_bytes());
    let pn = packet.len();
    packet.extend_from_slice(&number.to_be_bytes());
    let mut payload = frames.to_vec();
    let mut tag = [0u8; 16];
    keys.aead()?
        .seal_in_place_mut(&keys.nonce(number as u64), &mut payload, &mut tag, &packet)
        .ok()?;
    packet.extend_from_slice(&payload);
    packet.extend_from_slice(&tag);
    let mask = keys.mask(packet.get(pn + 4..pn + 20)?)?;
    packet[0] ^= mask[0] & 0x0f;
    for i in 0..4 {
        packet[pn + i] ^= mask[1 + i];
    }
    Some(packet)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints_as_rfc_9000_encodes_them() {
        for (bytes, v) in [
            (&[0x25][..], 37),
            (&[0x40, 0x25], 37),
            (&[0x7b, 0xbd], 15293),
            (&[0x9d, 0x7f, 0x3e, 0x7d], 494878333),
            (
                &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
                151288809941952652,
            ),
        ] {
            let mut buf = bytes;
            assert_eq!(varint(&mut buf), Some(v));
            assert!(buf.is_empty());
            let mut short = &bytes[..bytes.len() - 1];
            assert_eq!(varint(&mut short), None);
        }
    }

    #[test]
    fn crypto_fragments_in_any_order() {
        let hello = tls::tests::hello("example.com");
        let mut sniffer = QuicSniffer::new();
        let chunks: Vec<(usize, &[u8])> = hello
            .chunks(7)
            .enumerate()
            .map(|(i, c)| (i * 7, c))
            .collect();
        for (offset, chunk) in chunks.iter().rev() {
            assert!(sniffer.contiguous() < hello.len());
            assert!(sniffer.add(*offset as u64, chunk));
            // Again, overlapping what is there.
            assert!(sniffer.add(*offset as u64, &chunk[..chunk.len() / 2]));
        }
        assert_eq!(sniffer.received, [(0, hello.len())]);
        assert_eq!(
            tls::client_hello(&sniffer.data[..sniffer.contiguous()]),
            Sniff::Found(Some("example.com".into()))
        );
        assert!(!sniffer.add(MAX_SNIFF_LEN as u64, &[1]));
        assert!(!sniffer.add(u64::MAX, &[1]));
    }

    /// RFC 9001's client Initial (appendix A.2), whose ClientHello names
    /// example.com.
    #[cfg(feature = "btls")]
    const RFC_9001_INITIAL: &str = include_str!("testdata/rfc9001-client-initial.hex");

    #[cfg(feature = "btls")]
    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[cfg(feature = "btls")]
    #[test]
    fn the_client_initial_of_rfc_9001() {
        let packet = unhex(RFC_9001_INITIAL);
        assert_eq!(packet.len(), 1200);
        assert_eq!(
            QuicSniffer::new().feed(&packet),
            Sniff::Found(Some("example.com".into()))
        );
        // Any byte changed fails the authentication, or the parsing.
        for i in [0, 5, 6, 17, 18, 20, 100, 1199] {
            let mut bad = packet.clone();
            bad[i] ^= 0x01;
            assert_eq!(QuicSniffer::new().feed(&bad), Sniff::NotMatch, "{}", i);
        }
        for len in [0, 1, 10, 30, 600, 1199] {
            assert_eq!(QuicSniffer::new().feed(&packet[..len]), Sniff::NotMatch);
        }
    }

    /// A CRYPTO frame of `data` at `offset`.
    #[cfg(feature = "btls")]
    fn crypto(offset: usize, data: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x06];
        frame.extend_from_slice(&(0x4000 | offset as u16).to_be_bytes());
        frame.extend_from_slice(&(0x4000 | data.len() as u16).to_be_bytes());
        frame.extend_from_slice(data);
        frame
    }

    /// The Initial datagrams Chrome sends a ClientHello in: CRYPTO frames of
    /// a few bytes to a few hundred, shuffled, with PINGs and PADDING
    /// between them, spread over `datagrams` Initial packets each padded to
    /// 1200 bytes, the one with offset 0 last.
    #[cfg(feature = "btls")]
    fn chrome_initials(version: u32, hello: &[u8], datagrams: usize) -> Vec<Vec<u8>> {
        let dcid = [0x5a; 8];
        // A fixed shuffle, from a linear congruential generator.
        let mut seed = 0x2545_f491_u32;
        let mut next = move |n: usize| {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            (seed >> 8) as usize % n
        };
        let mut frames = Vec::new();
        let mut offset = 0;
        while offset < hello.len() {
            let len = (1 + next(300)).min(hello.len() - offset);
            frames.push(crypto(offset, &hello[offset..offset + len]));
            offset += len;
        }
        for i in (1..frames.len()).rev() {
            frames.swap(i, next(i + 1));
        }
        // The frame at offset 0 in the last packet.
        let first = frames.iter().position(|f| f[1..3] == [0x40, 0]).unwrap();
        let last = frames.len() - 1;
        frames.swap(first, last);
        let per = frames.len().div_ceil(datagrams);
        frames
            .chunks(per)
            .enumerate()
            .map(|(i, chunk)| {
                let mut payload = Vec::new();
                for frame in chunk {
                    payload.push(0x01);
                    payload.extend_from_slice(frame);
                    payload.extend_from_slice(&[0; 3]);
                }
                let room = 1200 - (1 + 4 + 1 + dcid.len() + 2 + 2 + 4 + 16);
                assert!(payload.len() <= room, "{} bytes of frames", payload.len());
                payload.resize(room, 0);
                protect(version, &dcid, i as u32, &payload).unwrap()
            })
            .collect()
    }

    #[cfg(feature = "btls")]
    fn captured(name: &str) -> Vec<u8> {
        let path = format!(
            "{}/tests/fixtures/tls/{}.hello",
            env!("CARGO_MANIFEST_DIR"),
            name
        );
        std::fs::read(path).unwrap()
    }

    #[cfg(feature = "btls")]
    #[test]
    fn a_client_hello_across_initial_packets_in_any_order() {
        let hello = captured("chrome-154");
        for version in [VERSION_1, VERSION_2, DRAFT_29] {
            for datagrams in [3, 4] {
                let initials = chrome_initials(version, &hello, datagrams);
                assert_eq!(initials.len(), datagrams);
                let mut sniffer = QuicSniffer::new();
                for initial in &initials[..datagrams - 1] {
                    assert_eq!(initial.len(), 1200);
                    assert_eq!(sniffer.feed(initial), Sniff::NeedMore);
                }
                assert_eq!(
                    sniffer.feed(&initials[datagrams - 1]),
                    Sniff::Found(Some("localhost".into())),
                    "version {:x}, {} datagrams",
                    version,
                    datagrams
                );
            }
        }
    }

    #[cfg(feature = "btls")]
    #[test]
    fn packets_coalesced_with_an_initial() {
        let hello = tls::tests::hello("example.com");
        let mut frames = crypto(0, &hello);
        frames.resize(1100, 0);
        let initial = protect(VERSION_1, &[1, 2, 3, 4], 0, &frames).unwrap();
        // Zeros after it, as some clients pad a datagram.
        let mut padded = initial.clone();
        padded.extend_from_slice(&[0; 64]);
        let found = Sniff::Found(Some("example.com".into()));
        assert_eq!(QuicSniffer::new().feed(&padded), found);
        // A 0-RTT packet after it.
        let mut zero_rtt = initial.clone();
        zero_rtt.extend_from_slice(&[0xd3, 0, 0, 0, 1, 4, 1, 2, 3, 4, 0, 0x40, 20]);
        zero_rtt.extend_from_slice(&[0x55; 20]);
        assert_eq!(QuicSniffer::new().feed(&zero_rtt), found);
        // Two Initials, each with half.
        let half = hello.len() / 2;
        let mut first = crypto(half, &hello[half..]);
        first.resize(500, 0);
        let mut second = crypto(0, &hello[..half]);
        second.resize(500, 0);
        let mut both = protect(VERSION_1, &[9; 20], 0, &first).unwrap();
        both.extend_from_slice(&protect(VERSION_1, &[9; 20], 1, &second).unwrap());
        assert_eq!(QuicSniffer::new().feed(&both), found);
    }

    #[cfg(feature = "btls")]
    #[test]
    fn frames_a_client_initial_does_not_carry() {
        let hello = tls::tests::hello("example.com");
        for extra in [
            &[0x08, 0, 0][..],
            &[0x1c, 0, 0, 0x7f, 0xff],
            &[0x06, 0x7f, 0xff, 0x40, 0x10],
        ] {
            let mut frames = crypto(0, &hello);
            frames.extend_from_slice(extra);
            frames.resize(1100, 0);
            let initial = protect(VERSION_1, &[1; 8], 0, &frames).unwrap();
            assert_eq!(
                QuicSniffer::new().feed(&initial),
                Sniff::NotMatch,
                "{:?}",
                extra
            );
        }
        // An ACK, and a CONNECTION_CLOSE with a reason, are stepped over.
        let mut frames = vec![0x02, 0, 0, 1, 0, 0, 0, 0x1c, 1, 0, 2, b'n', b'o'];
        frames.extend_from_slice(&crypto(0, &hello));
        frames.resize(1100, 0);
        let initial = protect(VERSION_1, &[1; 8], 0, &frames).unwrap();
        assert_eq!(
            QuicSniffer::new().feed(&initial),
            Sniff::Found(Some("example.com".into()))
        );
    }

    #[cfg(feature = "btls")]
    #[test]
    fn no_initial_panics() {
        let hello = tls::tests::hello("example.com");
        let mut frames = crypto(0, &hello);
        frames.resize(300, 0);
        let initial = protect(VERSION_1, &[7; 8], 0, &frames).unwrap();
        for i in 0..initial.len() {
            for byte in [0x00, 0x01, 0x40, 0x7f, 0x80, 0xc0, 0xff] {
                let mut bad = initial.clone();
                bad[i] = byte;
                let _ = QuicSniffer::new().feed(&bad);
                let _ = QuicSniffer::new().feed(&bad[..i]);
            }
        }
        // Frames inside a valid packet, cut or changed anywhere.
        for i in 0..frames.len().min(200) {
            for byte in [0x00, 0x06, 0x3f, 0x40, 0x80, 0xc0, 0xff] {
                let mut bad = frames.clone();
                bad[i] = byte;
                let _ = QuicSniffer::new().feed(&protect(VERSION_1, &[7; 8], 0, &bad).unwrap());
            }
        }
    }

    /// Initial datagrams a quinn client sends to a server named `name`
    /// offering `alpns`, until the sniffer finds the name.
    #[cfg(feature = "quic")]
    async fn quinn_initials(name: &str, alpns: &[Vec<u8>]) -> (Sniff, usize) {
        use crate::transport::quic::{client_crypto, endpoint};
        use std::net::Ipv4Addr;
        use std::sync::Arc;

        let server = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let client = endpoint(
            std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
            None,
        )
        .unwrap();
        let crypto = client_crypto(None, true, alpns).unwrap();
        let config = quinn::ClientConfig::new(Arc::new(crypto));
        let _connecting = client
            .connect_with(config, server.local_addr().unwrap(), name)
            .unwrap();
        let mut sniffer = QuicSniffer::new();
        let mut buf = vec![0u8; 65536];
        for n in 1..=8 {
            let (len, _) = server.recv_from(&mut buf).await.unwrap();
            match sniffer.feed(&buf[..len]) {
                Sniff::NeedMore => continue,
                outcome => return (outcome, n),
            }
        }
        (Sniff::NeedMore, 8)
    }

    #[cfg(feature = "quic")]
    #[tokio::test]
    async fn the_initials_of_a_quinn_client() {
        let found = Sniff::Found(Some("quic.example.com".into()));
        let (sniff, _) = quinn_initials("quic.example.com", &[b"h3".to_vec()]).await;
        assert_eq!(sniff, found);
        // Enough ALPNs that the ClientHello takes more than one packet.
        let alpns: Vec<Vec<u8>> = (0..80)
            .map(|i| format!("proto-{:04}", i).into_bytes())
            .collect();
        let (sniff, datagrams) = quinn_initials("quic.example.com", &alpns).await;
        assert_eq!(sniff, found);
        assert!(datagrams >= 2, "{} datagrams", datagrams);
    }

    /// The first datagrams of a QUIC connection `name` captured.
    #[cfg(feature = "btls")]
    fn captured_initials(name: &str) -> Vec<Vec<u8>> {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/quic");
        (0..)
            .map(|i| std::fs::read(format!("{}/{}-{}.initial", dir, name, i)))
            .take_while(Result::is_ok)
            .map(Result::unwrap)
            .collect()
    }

    #[cfg(feature = "btls")]
    #[test]
    fn the_initials_chrome_sends() {
        let initials = captured_initials("chrome-154");
        assert!(initials.len() >= 2);
        let found = Sniff::Found(Some("localhost".into()));
        // In the order sent: the ClientHello takes two datagrams.
        let mut sniffer = QuicSniffer::new();
        assert_eq!(sniffer.feed(&initials[0]), Sniff::NeedMore);
        assert_eq!(sniffer.feed(&initials[1]), found);
        // And the other way round.
        let mut sniffer = QuicSniffer::new();
        assert_eq!(sniffer.feed(&initials[1]), Sniff::NeedMore);
        assert_eq!(sniffer.feed(&initials[0]), found);
    }

    #[test]
    fn what_is_not_an_initial() {
        let mut sniffer = QuicSniffer::new();
        assert_eq!(sniffer.feed(&[]), Sniff::NotMatch);
        assert_eq!(sniffer.feed(&[0x40; 1200]), Sniff::NotMatch);
        // A version negotiation packet.
        let mut vn = vec![0xc0, 0, 0, 0, 0, 8];
        vn.extend_from_slice(&[1; 8]);
        vn.extend_from_slice(&[0; 1200]);
        assert_eq!(sniffer.feed(&vn), Sniff::NotMatch);
    }
}
