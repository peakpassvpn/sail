//! Working out what a connection carries from its first bytes, as
//! sing-box's `sniff` rule action does: the protocol, and for TLS, QUIC and
//! HTTP the domain the client asks for.
//!
//! Each parser takes the bytes read so far and says whether they are its
//! protocol, are not, or may be once more arrive. None of them keeps more
//! than it is given, and nothing reads more than [`MAX_SNIFF_LEN`] for them.

pub mod dns;
pub mod http;
pub mod misc;
pub mod quic;
pub mod tls;

mod datagram;
mod stream;

pub use datagram::*;
pub use stream::*;

use crate::config::model::Sniffer;
use crate::session::SniffedProtocol;

/// How much of a connection, or of the first datagrams of a UDP session, is
/// read looking for its protocol.
pub const MAX_SNIFF_LEN: usize = 16 * 1024;

/// What a parser makes of the bytes it was given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sniff {
    /// They are not its protocol.
    NotMatch,
    /// They may be its protocol; more bytes would tell.
    NeedMore,
    /// They are its protocol, naming this domain, if any.
    Found(Option<String>),
}

/// The protocols a `sniff` rule looks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Protocols(u8);

impl Protocols {
    /// Every protocol sail sniffs.
    pub const ALL: Protocols = Protocols((1 << SniffedProtocol::ALL.len()) - 1);
    /// None at all.
    pub const NONE: Protocols = Protocols(0);

    /// The protocols of a rule's `sniffer`: all of them when it names none.
    pub fn of(sniffers: &[Sniffer]) -> Self {
        if sniffers.is_empty() {
            return Self::ALL;
        }
        sniffers
            .iter()
            .fold(Self::NONE, |set, sniffer| set.with(protocol_of(*sniffer)))
    }

    fn bit(protocol: SniffedProtocol) -> u8 {
        let i = SniffedProtocol::ALL
            .iter()
            .position(|p| *p == protocol)
            .expect("every protocol is in ALL");
        1 << i
    }

    /// These and `protocol`.
    pub fn with(self, protocol: SniffedProtocol) -> Self {
        Protocols(self.0 | Self::bit(protocol))
    }

    pub fn contains(self, protocol: SniffedProtocol) -> bool {
        self.0 & Self::bit(protocol) != 0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Those of them a stream can carry.
    pub fn stream(self) -> Self {
        self.only(&STREAM)
    }

    /// Those of them datagrams can carry.
    pub fn datagram(self) -> Self {
        self.only(&DATAGRAM)
    }

    fn only(self, protocols: &[SniffedProtocol]) -> Self {
        protocols
            .iter()
            .filter(|p| self.contains(**p))
            .fold(Self::NONE, |set, p| set.with(*p))
    }

    /// Them, in the order they are tried.
    pub fn iter(self) -> impl Iterator<Item = SniffedProtocol> {
        SniffedProtocol::ALL
            .into_iter()
            .filter(move |p| self.contains(*p))
    }
}

/// The protocols sniffed on streams.
const STREAM: [SniffedProtocol; 4] = [
    SniffedProtocol::Tls,
    SniffedProtocol::Http,
    SniffedProtocol::Dns,
    SniffedProtocol::Bittorrent,
];

/// The protocols sniffed on datagrams.
const DATAGRAM: [SniffedProtocol; 5] = [
    SniffedProtocol::Quic,
    SniffedProtocol::Dns,
    SniffedProtocol::Stun,
    SniffedProtocol::Bittorrent,
    SniffedProtocol::Dtls,
];

fn protocol_of(sniffer: Sniffer) -> SniffedProtocol {
    match sniffer {
        Sniffer::Tls => SniffedProtocol::Tls,
        Sniffer::Http => SniffedProtocol::Http,
        Sniffer::Quic => SniffedProtocol::Quic,
        Sniffer::Dns => SniffedProtocol::Dns,
        Sniffer::Stun => SniffedProtocol::Stun,
        Sniffer::Bittorrent => SniffedProtocol::Bittorrent,
        Sniffer::Dtls => SniffedProtocol::Dtls,
    }
}

/// Whether connections to `port` are left unsniffed: SMTP, IMAP and POP3,
/// where the server speaks first and the client would only wait out the
/// timeout. sing-box skips the same ports.
pub fn skips_port(port: u16) -> bool {
    matches!(port, 25 | 465 | 587 | 143 | 993 | 110 | 995)
}

/// Whether `name` is a domain name a destination can be, as Go's
/// `net.isDomainName`, which sing-box checks before it overrides a
/// destination: labels of letters, digits, `-` and `_`, not all of it
/// numeric, so that an address is not taken for a name.
pub fn is_domain_name(name: &str) -> bool {
    let name = name.as_bytes();
    if name.is_empty() || name.len() > 254 {
        return false;
    }
    let mut last = b'.';
    let mut non_numeric = false;
    let mut label_len = 0;
    for &c in name {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                non_numeric = true;
                label_len += 1;
            }
            b'0'..=b'9' => label_len += 1,
            b'-' => {
                if last == b'.' {
                    return false;
                }
                label_len += 1;
                non_numeric = true;
            }
            b'.' => {
                if last == b'.' || last == b'-' || label_len > 63 {
                    return false;
                }
                label_len = 0;
            }
            _ => return false,
        }
        last = c;
    }
    last != b'-' && label_len <= 63 && non_numeric
}

/// The big-endian `u16` at the start of `buf`, if it holds two bytes.
fn be_u16(buf: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes([*buf.first()?, *buf.get(1)?]))
}

/// The big-endian `u24` at the start of `buf`, if it holds three bytes.
fn be_u24(buf: &[u8]) -> Option<usize> {
    let b = buf.get(..3)?;
    Some((b[0] as usize) << 16 | (b[1] as usize) << 8 | b[2] as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_names_are_go_s() {
        for name in [
            "example.com",
            "a.b-c.d",
            "_dmarc.example.com",
            "xn--p1ai",
            "1.example",
            "example.com.",
        ] {
            assert!(is_domain_name(name), "{}", name);
        }
        let long_label = "a".repeat(64);
        for name in [
            "",
            "1.2.3.4",
            "::1",
            "-a.com",
            "a-.com",
            "a..com",
            "a b.com",
            "a.com:443",
            "é.com",
            &long_label,
        ] {
            assert!(!is_domain_name(name), "{}", name);
        }
    }

    #[test]
    fn a_rule_without_sniffers_looks_for_all() {
        assert_eq!(Protocols::of(&[]), Protocols::ALL);
        assert_eq!(
            Protocols::ALL.iter().collect::<Vec<_>>(),
            SniffedProtocol::ALL
        );
        let quic = Protocols::of(&[Sniffer::Quic]);
        assert!(quic.contains(SniffedProtocol::Quic));
        assert!(!quic.contains(SniffedProtocol::Tls));
        assert!(quic.stream().is_empty());
        assert_eq!(quic.datagram(), quic);
        assert_eq!(
            Protocols::ALL.stream().iter().collect::<Vec<_>>(),
            [
                SniffedProtocol::Tls,
                SniffedProtocol::Http,
                SniffedProtocol::Dns,
                SniffedProtocol::Bittorrent
            ]
        );
    }
}
