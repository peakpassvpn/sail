//! Wire formats, whitepaper section 5.4. All integers are little-endian.
//!
//! Every message starts with a type byte and three reserved bytes. The
//! protocol sends the reserved bytes as zero and Linux and wireguard-go
//! reject anything else, but Cloudflare WARP puts a client identifier there.
//! We write a per-peer value on send and ignore the bytes on receive.

use super::crypto::{KEY_LEN, MAC_LEN, TAG_LEN, XNONCE_LEN};
use super::tai64n;

pub const TYPE_INITIATION: u8 = 1;
pub const TYPE_RESPONSE: u8 = 2;
pub const TYPE_COOKIE_REPLY: u8 = 3;
pub const TYPE_DATA: u8 = 4;

/// type(1) reserved(3) sender(4) ephemeral(32) static(48) timestamp(28)
/// mac1(16) mac2(16).
pub const INITIATION_LEN: usize = 148;
/// type(1) reserved(3) sender(4) receiver(4) ephemeral(32) empty(16)
/// mac1(16) mac2(16).
pub const RESPONSE_LEN: usize = 92;
/// type(1) reserved(3) receiver(4) nonce(24) cookie(32).
pub const COOKIE_REPLY_LEN: usize = 64;
/// type(1) reserved(3) receiver(4) counter(8).
pub const DATA_HEADER_LEN: usize = 16;
/// The smallest transport message: a keepalive, header and tag.
pub const DATA_MIN_LEN: usize = DATA_HEADER_LEN + TAG_LEN;

/// Plaintexts are padded to a multiple of this.
pub const PADDING_MULTIPLE: usize = 16;

pub const ENCRYPTED_STATIC_LEN: usize = KEY_LEN + TAG_LEN;
pub const ENCRYPTED_TIMESTAMP_LEN: usize = tai64n::LEN + TAG_LEN;
pub const ENCRYPTED_EMPTY_LEN: usize = TAG_LEN;
pub const ENCRYPTED_COOKIE_LEN: usize = MAC_LEN + TAG_LEN;

/// The header shared by all messages: type and reserved bytes.
pub fn write_header(buf: &mut [u8], ty: u8, reserved: [u8; 3]) {
    buf[0] = ty;
    buf[1..4].copy_from_slice(&reserved);
}

fn u32_at(buf: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(buf[at..at + 4].try_into().unwrap())
}

fn arr<const N: usize>(buf: &[u8], at: usize) -> [u8; N] {
    buf[at..at + N].try_into().unwrap()
}

/// Handshake initiation.
#[derive(Clone)]
pub struct Initiation {
    pub reserved: [u8; 3],
    pub sender: u32,
    pub ephemeral: [u8; KEY_LEN],
    pub encrypted_static: [u8; ENCRYPTED_STATIC_LEN],
    pub encrypted_timestamp: [u8; ENCRYPTED_TIMESTAMP_LEN],
    pub mac1: [u8; MAC_LEN],
    pub mac2: [u8; MAC_LEN],
}

impl Initiation {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() != INITIATION_LEN || buf[0] != TYPE_INITIATION {
            return None;
        }
        Some(Initiation {
            reserved: arr(buf, 1),
            sender: u32_at(buf, 4),
            ephemeral: arr(buf, 8),
            encrypted_static: arr(buf, 40),
            encrypted_timestamp: arr(buf, 88),
            mac1: arr(buf, 116),
            mac2: arr(buf, 132),
        })
    }

    pub fn to_bytes(&self) -> [u8; INITIATION_LEN] {
        let mut b = [0u8; INITIATION_LEN];
        write_header(&mut b, TYPE_INITIATION, self.reserved);
        b[4..8].copy_from_slice(&self.sender.to_le_bytes());
        b[8..40].copy_from_slice(&self.ephemeral);
        b[40..88].copy_from_slice(&self.encrypted_static);
        b[88..116].copy_from_slice(&self.encrypted_timestamp);
        b[116..132].copy_from_slice(&self.mac1);
        b[132..148].copy_from_slice(&self.mac2);
        b
    }
}

/// Handshake response.
#[derive(Clone)]
pub struct Response {
    pub reserved: [u8; 3],
    pub sender: u32,
    pub receiver: u32,
    pub ephemeral: [u8; KEY_LEN],
    pub encrypted_nothing: [u8; ENCRYPTED_EMPTY_LEN],
    pub mac1: [u8; MAC_LEN],
    pub mac2: [u8; MAC_LEN],
}

impl Response {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() != RESPONSE_LEN || buf[0] != TYPE_RESPONSE {
            return None;
        }
        Some(Response {
            reserved: arr(buf, 1),
            sender: u32_at(buf, 4),
            receiver: u32_at(buf, 8),
            ephemeral: arr(buf, 12),
            encrypted_nothing: arr(buf, 44),
            mac1: arr(buf, 60),
            mac2: arr(buf, 76),
        })
    }

    pub fn to_bytes(&self) -> [u8; RESPONSE_LEN] {
        let mut b = [0u8; RESPONSE_LEN];
        write_header(&mut b, TYPE_RESPONSE, self.reserved);
        b[4..8].copy_from_slice(&self.sender.to_le_bytes());
        b[8..12].copy_from_slice(&self.receiver.to_le_bytes());
        b[12..44].copy_from_slice(&self.ephemeral);
        b[44..60].copy_from_slice(&self.encrypted_nothing);
        b[60..76].copy_from_slice(&self.mac1);
        b[76..92].copy_from_slice(&self.mac2);
        b
    }
}

/// Cookie reply.
#[derive(Clone)]
pub struct CookieReply {
    pub reserved: [u8; 3],
    pub receiver: u32,
    pub nonce: [u8; XNONCE_LEN],
    pub encrypted_cookie: [u8; ENCRYPTED_COOKIE_LEN],
}

impl CookieReply {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() != COOKIE_REPLY_LEN || buf[0] != TYPE_COOKIE_REPLY {
            return None;
        }
        Some(CookieReply {
            reserved: arr(buf, 1),
            receiver: u32_at(buf, 4),
            nonce: arr(buf, 8),
            encrypted_cookie: arr(buf, 32),
        })
    }

    pub fn to_bytes(&self) -> [u8; COOKIE_REPLY_LEN] {
        let mut b = [0u8; COOKIE_REPLY_LEN];
        write_header(&mut b, TYPE_COOKIE_REPLY, self.reserved);
        b[4..8].copy_from_slice(&self.receiver.to_le_bytes());
        b[8..32].copy_from_slice(&self.nonce);
        b[32..64].copy_from_slice(&self.encrypted_cookie);
        b
    }
}

/// The header of a transport data message; the encrypted packet follows.
#[derive(Clone, Copy, Debug)]
pub struct DataHeader {
    pub receiver: u32,
    pub counter: u64,
}

impl DataHeader {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < DATA_MIN_LEN || buf[0] != TYPE_DATA {
            return None;
        }
        Some(DataHeader {
            receiver: u32_at(buf, 4),
            counter: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
        })
    }

    pub fn write(&self, buf: &mut [u8], reserved: [u8; 3]) {
        write_header(buf, TYPE_DATA, reserved);
        buf[4..8].copy_from_slice(&self.receiver.to_le_bytes());
        buf[8..16].copy_from_slice(&self.counter.to_le_bytes());
    }
}

/// The offsets of mac1 and mac2 in a handshake message of length `len`:
/// mac1 covers everything before it, mac2 everything before mac2.
pub fn mac_offsets(len: usize) -> (usize, usize) {
    (len - 2 * MAC_LEN, len - MAC_LEN)
}

/// How many zero bytes pad a plaintext of `len` for an interface of `mtu`,
/// as Linux computes it: to a multiple of 16, but not beyond the MTU.
pub fn padding(len: usize, mtu: usize) -> usize {
    if mtu == 0 {
        return len.next_multiple_of(PADDING_MULTIPLE) - len;
    }
    let last_unit = if len > mtu { len % mtu } else { len };
    let padded = mtu.min(last_unit.next_multiple_of(PADDING_MULTIPLE));
    padded.saturating_sub(last_unit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let i = Initiation {
            reserved: [1, 2, 3],
            sender: 0x0403_0201,
            ephemeral: [5; 32],
            encrypted_static: [6; 48],
            encrypted_timestamp: [7; 28],
            mac1: [8; 16],
            mac2: [9; 16],
        };
        let b = i.to_bytes();
        assert_eq!(&b[..8], &[1, 1, 2, 3, 1, 2, 3, 4]);
        let p = Initiation::parse(&b).unwrap();
        assert_eq!(p.to_bytes(), b);

        let r = Response {
            reserved: [0; 3],
            sender: 1,
            receiver: 2,
            ephemeral: [3; 32],
            encrypted_nothing: [4; 16],
            mac1: [5; 16],
            mac2: [6; 16],
        };
        assert_eq!(
            Response::parse(&r.to_bytes()).unwrap().to_bytes(),
            r.to_bytes()
        );

        let c = CookieReply {
            reserved: [0; 3],
            receiver: 9,
            nonce: [1; 24],
            encrypted_cookie: [2; 32],
        };
        assert_eq!(
            CookieReply::parse(&c.to_bytes()).unwrap().to_bytes(),
            c.to_bytes()
        );
    }

    #[test]
    fn exact_lengths() {
        assert!(Initiation::parse(&[1u8; INITIATION_LEN - 1]).is_none());
        assert!(Response::parse(&[2u8; RESPONSE_LEN + 1]).is_none());
        assert!(DataHeader::parse(&[4u8; DATA_MIN_LEN - 1]).is_none());
        assert!(DataHeader::parse(&[4u8; DATA_MIN_LEN]).is_some());
    }

    #[test]
    fn padding_as_linux() {
        assert_eq!(padding(0, 1420), 0);
        assert_eq!(padding(1, 1420), 15);
        assert_eq!(padding(84, 1420), 12);
        assert_eq!(padding(1419, 1420), 1);
        assert_eq!(padding(1420, 1420), 0);
        assert_eq!(padding(1415, 1420), 5);
        assert_eq!(padding(17, 0), 15);
    }
}
