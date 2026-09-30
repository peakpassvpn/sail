//! ShadowTLS v3: a TLS handshake with a real site, relayed by the server,
//! after which the connection carries the inner protocol in TLS
//! application-data records of its own.
//!
//! The client authenticates in its ClientHello: the last four bytes of the
//! session ID are an HMAC-SHA1, under the password, of the ClientHello with
//! those four bytes zeroed. The server relays an authenticated client's
//! handshake with the site, and marks each application-data record the site
//! sends with an HMAC chained over the server random, XORing its body with
//! a key from the password and the server random, so that the client can
//! tell the server from a middlebox answering in its place. Then each side
//! sends its data in application-data records whose first four bytes chain
//! an HMAC over everything that side has sent: "C" for the client's, "S" for
//! the server's. Everyone else is relayed to the site whole.
//!
//! As sing-shadowtls implements it, which the reference server matches;
//! versions 1 and 2 are not supported.

use std::io;

use bytes::BytesMut;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt};

#[cfg(feature = "inbound-shadowtls")]
pub mod inbound;
#[cfg(feature = "outbound-shadowtls")]
pub mod outbound;
mod stream;

pub use stream::VerifiedStream;

pub(crate) type HmacSha1 = Hmac<Sha1>;

/// The one version implemented.
pub const VERSION: u32 = 3;

/// The error for a configured version other than 3; sing-box's default is 1.
pub(crate) fn check_version(version: u32) -> Result<(), &'static str> {
    match version {
        VERSION => Ok(()),
        _ => Err("ShadowTLS v1/v2 are not supported; use version 3"),
    }
}

const HEADER_LEN: usize = 5;
const RANDOM_LEN: usize = 32;
const SESSION_ID_LEN: usize = 32;
/// Of the HMACs carried: the first four bytes.
const TAG_LEN: usize = 4;
/// A record header and the HMAC after it.
const TAGGED_HEADER_LEN: usize = HEADER_LEN + TAG_LEN;

const HANDSHAKE: u8 = 22;
const ALERT: u8 = 21;
const APPLICATION_DATA: u8 = 23;
#[cfg_attr(not(feature = "inbound-shadowtls"), allow(dead_code))]
const CLIENT_HELLO: u8 = 1;
const SERVER_HELLO: u8 = 2;

/// Where the server random starts in a ServerHello record: after the record
/// header, the handshake header and the version.
const SERVER_RANDOM_AT: usize = HEADER_LEN + 4 + 2;
/// Where the session ID's length is in a ClientHello or ServerHello record.
const SESSION_ID_LEN_AT: usize = SERVER_RANDOM_AT + RANDOM_LEN;

/// The most plaintext one record carries, as TLS limits it.
const MAX_PAYLOAD: usize = 16384;

/// A new HMAC-SHA1 under `password`.
pub(crate) fn hmac(password: &[u8]) -> HmacSha1 {
    <HmacSha1 as Mac>::new_from_slice(password).expect("HMAC takes any key size")
}

/// The first four bytes of what `mac` has taken so far.
fn tag(mac: &HmacSha1) -> [u8; TAG_LEN] {
    let sum = mac.clone().finalize().into_bytes();
    [sum[0], sum[1], sum[2], sum[3]]
}

/// The HMAC under `password` of the server random and `label`, from which
/// each side's data records are chained.
pub(crate) fn data_hmac(
    password: &[u8],
    server_random: &[u8; RANDOM_LEN],
    label: &[u8],
) -> HmacSha1 {
    let mut mac = hmac(password);
    mac.update(server_random);
    mac.update(label);
    mac
}

/// The key the site's application data is XORed with while it is relayed.
fn xor_key(password: &[u8], server_random: &[u8; RANDOM_LEN]) -> [u8; 32] {
    let mut sha = Sha256::new();
    sha.update(password);
    sha.update(server_random);
    sha.finalize().into()
}

fn xor(data: &mut [u8], key: &[u8; 32]) {
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= key[i % key.len()];
    }
}

/// The session ID a client sends: 28 random bytes, then the tag of the
/// ClientHello message `hello` (with its four-byte header) as it is with
/// those 28 bytes and four zeros for a session ID.
#[cfg_attr(not(feature = "outbound-shadowtls"), allow(dead_code))]
pub(crate) fn session_id(password: &[u8], hello: &[u8], random: [u8; 28]) -> io::Result<[u8; 32]> {
    // The handshake header, the version, the random and the length.
    const AT: usize = 4 + 2 + RANDOM_LEN + 1;
    if hello.len() < AT + SESSION_ID_LEN || hello[AT - 1] as usize != SESSION_ID_LEN {
        return Err(io::Error::other("unexpected ClientHello"));
    }
    let mut session_id = [0u8; SESSION_ID_LEN];
    session_id[..28].copy_from_slice(&random);
    let mut mac = hmac(password);
    mac.update(&hello[..AT]);
    mac.update(&session_id);
    mac.update(&hello[AT + SESSION_ID_LEN..]);
    session_id[28..].copy_from_slice(&tag(&mac));
    Ok(session_id)
}

/// Which of `passwords` signed the ClientHello record `frame`, by index.
#[cfg_attr(not(feature = "inbound-shadowtls"), allow(dead_code))]
pub(crate) fn authenticate<'a>(
    frame: &[u8],
    passwords: impl IntoIterator<Item = &'a [u8]>,
) -> Result<usize, &'static str> {
    const TAG_AT: usize = SESSION_ID_LEN_AT + 1 + SESSION_ID_LEN - TAG_LEN;
    if frame.len() < SESSION_ID_LEN_AT + 1 + SESSION_ID_LEN {
        return Err("ClientHello too short");
    }
    if frame[0] != HANDSHAKE {
        return Err("not a handshake record");
    }
    if frame[HEADER_LEN] != CLIENT_HELLO {
        return Err("not a ClientHello");
    }
    if frame[SESSION_ID_LEN_AT] as usize != SESSION_ID_LEN {
        return Err("the session ID is not 32 bytes");
    }
    for (i, password) in passwords.into_iter().enumerate() {
        let mut mac = hmac(password);
        mac.update(&frame[HEADER_LEN..TAG_AT]);
        mac.update(&[0; TAG_LEN]);
        mac.update(&frame[TAG_AT + TAG_LEN..]);
        if tag(&mac) == frame[TAG_AT..TAG_AT + TAG_LEN] {
            return Ok(i);
        }
    }
    Err("no user's password signed it")
}

/// The server random of a ServerHello record.
pub(crate) fn server_random(frame: &[u8]) -> Option<[u8; RANDOM_LEN]> {
    if frame.len() < SERVER_RANDOM_AT + RANDOM_LEN
        || frame[0] != HANDSHAKE
        || frame[HEADER_LEN] != SERVER_HELLO
    {
        return None;
    }
    frame[SERVER_RANDOM_AT..SERVER_RANDOM_AT + RANDOM_LEN]
        .try_into()
        .ok()
}

/// Whether a ServerHello record picks TLS 1.3: the first extensions up to
/// supported_versions are read, and it must say 1.3.
pub(crate) fn picks_tls13(frame: &[u8]) -> bool {
    fn read(frame: &[u8]) -> Option<bool> {
        let mut at = SESSION_ID_LEN_AT;
        let session_id_len = *frame.get(at)? as usize;
        // The session ID, the cipher suite and the compression method.
        at += 1 + session_id_len + 3;
        let count = u16::from_be_bytes(frame.get(at..at + 2)?.try_into().ok()?);
        at += 2;
        // sing-shadowtls counts the extensions by the length of the list, as
        // if each took a byte; a ServerHello has few enough for that to
        // reach supported_versions.
        for _ in 0..count {
            let kind = u16::from_be_bytes(frame.get(at..at + 2)?.try_into().ok()?);
            let len = u16::from_be_bytes(frame.get(at + 2..at + 4)?.try_into().ok()?) as usize;
            at += 4;
            if kind != 43 {
                frame.get(at..at + len)?;
                at += len;
                continue;
            }
            if len != 2 {
                return Some(false);
            }
            return Some(frame.get(at..at + 2)? == [3, 4]);
        }
        Some(false)
    }
    read(frame).unwrap_or(false)
}

/// The server name a ClientHello record asks for, empty without one.
#[cfg_attr(not(feature = "inbound-shadowtls"), allow(dead_code))]
pub(crate) fn server_name(frame: &[u8]) -> Option<String> {
    let body = frame.get(HEADER_LEN..)?;
    if *body.first()? != CLIENT_HELLO {
        return None;
    }
    let len = u32::from_be_bytes([0, body[1], body[2], *body.get(3)?]) as usize;
    let hello = body.get(4..4 + len)?;
    // The version and the random.
    let mut at = 2 + RANDOM_LEN;
    let skip8 = |at: &mut usize| -> Option<()> {
        *at += 1 + *hello.get(*at)? as usize;
        Some(())
    };
    let skip16 = |at: &mut usize| -> Option<()> {
        *at += 2 + u16::from_be_bytes(hello.get(*at..*at + 2)?.try_into().ok()?) as usize;
        Some(())
    };
    skip8(&mut at)?; // session ID
    skip16(&mut at)?; // cipher suites
    skip8(&mut at)?; // compression methods
    if at == hello.len() {
        return Some(String::new());
    }
    let end = at + 2 + u16::from_be_bytes(hello.get(at..at + 2)?.try_into().ok()?) as usize;
    let extensions = hello.get(at + 2..end)?;
    let mut at = 0;
    while at < extensions.len() {
        let kind = u16::from_be_bytes(extensions.get(at..at + 2)?.try_into().ok()?);
        let len = u16::from_be_bytes(extensions.get(at + 2..at + 4)?.try_into().ok()?) as usize;
        let data = extensions.get(at + 4..at + 4 + len)?;
        at += 4 + len;
        if kind != 0 {
            continue;
        }
        // The list's length, then entries of a type and a name.
        let mut at = 2;
        while at + 3 <= data.len() {
            let name_len = u16::from_be_bytes(data[at + 1..at + 3].try_into().ok()?) as usize;
            let name = data.get(at + 3..at + 3 + name_len)?;
            if data[at] == 0 {
                return String::from_utf8(name.to_vec()).ok();
            }
            at += 3 + name_len;
        }
        return None;
    }
    Some(String::new())
}

/// The site's application-data records as the server relays them to an
/// authenticated client during the handshake: XORed, and marked with an
/// HMAC chained over the server random and the bodies so far.
pub(crate) struct SiteRecords {
    mac: HmacSha1,
    key: [u8; 32],
}

impl SiteRecords {
    pub(crate) fn new(password: &[u8], server_random: &[u8; RANDOM_LEN]) -> Self {
        let mut mac = hmac(password);
        mac.update(server_random);
        Self {
            mac,
            key: xor_key(password, server_random),
        }
    }

    /// The server's side: `record` as the client is sent it.
    #[cfg_attr(not(feature = "inbound-shadowtls"), allow(dead_code))]
    pub(crate) fn mark(&mut self, mut record: BytesMut) -> BytesMut {
        if record[0] != APPLICATION_DATA {
            return record;
        }
        xor(&mut record[HEADER_LEN..], &self.key);
        self.mac.update(&record[HEADER_LEN..]);
        let mut out = BytesMut::with_capacity(record.len() + TAG_LEN);
        out.extend_from_slice(&record[..3]);
        out.extend_from_slice(&((record.len() - HEADER_LEN + TAG_LEN) as u16).to_be_bytes());
        out.extend_from_slice(&tag(&self.mac));
        out.extend_from_slice(&record[HEADER_LEN..]);
        out
    }

    /// The client's side: the site's record back from a marked one, or
    /// `None` if the mark is not the server's. Anything shorter than a mark
    /// and a byte is not taken for one.
    #[cfg_attr(not(feature = "outbound-shadowtls"), allow(dead_code))]
    pub(crate) fn unmark(&mut self, mut record: BytesMut) -> Option<BytesMut> {
        if !self.check(&record) {
            return None;
        }
        xor(&mut record[TAGGED_HEADER_LEN..], &self.key);
        let mut header = [0u8; HEADER_LEN];
        header.copy_from_slice(&record[..HEADER_LEN]);
        header[3..].copy_from_slice(&((record.len() - TAGGED_HEADER_LEN) as u16).to_be_bytes());
        // The header moves up over the mark.
        let mut out = record.split_off(TAG_LEN);
        out[..HEADER_LEN].copy_from_slice(&header);
        Some(out)
    }

    /// Whether `record` carries the next mark.
    #[cfg_attr(not(feature = "outbound-shadowtls"), allow(dead_code))]
    pub(crate) fn check(&mut self, record: &[u8]) -> bool {
        if record.len() <= TAGGED_HEADER_LEN {
            return false;
        }
        self.mac.update(&record[TAGGED_HEADER_LEN..]);
        tag(&self.mac) == record[HEADER_LEN..TAGGED_HEADER_LEN]
    }
}

/// Reads TLS records whole, keeping what it read past the last one. It can
/// be cancelled between records without losing any.
#[derive(Default)]
pub(crate) struct Records {
    buf: BytesMut,
}

impl Records {
    /// The next record, header and all; `None` at the end of the stream
    /// between records.
    pub(crate) async fn next<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> io::Result<Option<BytesMut>> {
        loop {
            if self.buf.len() >= HEADER_LEN {
                let len = HEADER_LEN + u16::from_be_bytes([self.buf[3], self.buf[4]]) as usize;
                if self.buf.len() >= len {
                    return Ok(Some(self.buf.split_to(len)));
                }
                self.buf.reserve(len - self.buf.len());
            } else {
                self.buf.reserve(4096);
            }
            if reader.read_buf(&mut self.buf).await? == 0 {
                return match self.buf.is_empty() {
                    true => Ok(None),
                    false => Err(io::ErrorKind::UnexpectedEof.into()),
                };
            }
        }
    }

    /// Like `next`, the end of the stream being an error.
    pub(crate) async fn expect<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> io::Result<BytesMut> {
        self.next(reader)
            .await?
            .ok_or_else(|| io::ErrorKind::UnexpectedEof.into())
    }

    /// What was read past the last record.
    pub(crate) fn into_inner(self) -> BytesMut {
        self.buf
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    // The vectors come from sing-shadowtls v0.2.1, run with Go: its
    // generateSessionID and verifyClientHello (user "b" of "other" and
    // "pw"), kdf, verifiedConn.Write and copyByFrameWithModification, on the
    // inputs the tests below give. The server random is 0, 1, .., 31.

    /// A ClientHello record that generateSessionID signed with "pw".
    const SIGNED_HELLO: &str = "160301004f0100004c0303aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
        aaaaaaaaaaaaaaaaaaaaaaaa20cf9e0a252177fab77fa71026003b5b06a402bcf804da84c834\
        1b48c1518c90de0002130101000000";

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn to_hex(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }

    fn server_random_0_31() -> [u8; 32] {
        std::array::from_fn(|i| i as u8)
    }

    #[test]
    fn test_session_id_matches_sing_shadowtls() {
        let frame = unhex(SIGNED_HELLO);
        let passwords: [&[u8]; 2] = [b"other", b"pw"];
        assert_eq!(authenticate(&frame, passwords), Ok(1));
        let wrong: [&[u8]; 1] = [b"wrong"];
        assert!(authenticate(&frame, wrong).is_err());

        // Signing the same message with the same 28 random bytes gives the
        // same session ID.
        let mut hello = frame[HEADER_LEN..].to_vec();
        let signed: [u8; 32] = hello[39..71].try_into().unwrap();
        hello[39..71].fill(0);
        let random: [u8; 28] = signed[..28].try_into().unwrap();
        assert_eq!(session_id(b"pw", &hello, random).unwrap(), signed);
        assert!(session_id(b"pw", &hello[..60], random).is_err());
    }

    #[test]
    fn test_xor_key_matches_sing_shadowtls() {
        assert_eq!(
            to_hex(xor_key(b"pw", &server_random_0_31())),
            "401c0cd67fd248367ee991ca15b187a7f65ff1e16b071c7e20e9024d6767f425"
        );
    }

    #[test]
    fn test_data_frames_match_sing_shadowtls() {
        let mut add = data_hmac(b"pw", &server_random_0_31(), b"C");
        let mut out = Vec::new();
        stream::frame(&mut add, b"hello", &mut out);
        stream::frame(&mut add, b"world!", &mut out);
        assert_eq!(
            to_hex(out),
            "1703030009bbf19be768656c6c6f170303000add7f6d3f776f726c6421"
        );
    }

    #[test]
    fn test_relayed_site_records_match_sing_shadowtls() {
        let random = server_random_0_31();
        let mut relay = SiteRecords::new(b"pw", &random);
        let mut out = Vec::new();
        for record in [&[23u8, 3, 3, 0, 4, 1, 2, 3, 4][..], &[23, 3, 3, 0, 2, 9, 9]] {
            out.extend_from_slice(&relay.mark(record.into()));
        }
        assert_eq!(
            to_hex(&out),
            "1703030008e1e8f3d2411e0fd21703030006ae5eeb164915"
        );

        // The client takes them back.
        let mut check = SiteRecords::new(b"pw", &random);
        let first = check.unmark(out[..13].into()).unwrap();
        assert_eq!(&first[..], &[23, 3, 3, 0, 4, 1, 2, 3, 4]);
        let second = check.unmark(out[13..].into()).unwrap();
        assert_eq!(&second[..], &[23, 3, 3, 0, 2, 9, 9]);
        let mut again = SiteRecords::new(b"other", &random);
        assert!(again.unmark(out[..13].into()).is_none());
    }

    #[test]
    fn test_server_hello() {
        let mut frame = vec![HANDSHAKE, 3, 3, 0, 0, SERVER_HELLO, 0, 0, 0, 3, 3];
        frame.extend_from_slice(&[7; 32]);
        frame.push(0);
        frame.extend_from_slice(&[0x13, 0x01, 0x00]);
        // Two extensions: key_share (empty here), supported_versions 1.3.
        frame.extend_from_slice(&[0, 10, 0, 51, 0, 0, 0, 43, 0, 2, 3, 4]);
        assert_eq!(server_random(&frame), Some([7; 32]));
        assert!(picks_tls13(&frame));
        let n = frame.len();
        frame[n - 1] = 3;
        assert!(!picks_tls13(&frame));
        assert!(!picks_tls13(&frame[..40]));
        assert_eq!(server_random(&frame[..20]), None);
    }

    #[test]
    fn test_server_name() {
        let record = |mut hello: Vec<u8>| {
            let len = hello.len() - 4;
            hello[1..4].copy_from_slice(&(len as u32).to_be_bytes()[1..]);
            let mut frame = vec![HANDSHAKE, 3, 1];
            frame.extend_from_slice(&(hello.len() as u16).to_be_bytes());
            frame.extend_from_slice(&hello);
            frame
        };
        let hello = unhex(SIGNED_HELLO)[HEADER_LEN..].to_vec();
        assert_eq!(server_name(&record(hello.clone())).as_deref(), Some(""));
        // With a server_name extension for "a.example".
        let mut hello = hello;
        let name = b"a.example";
        let mut ext = vec![0, 0];
        ext.extend_from_slice(&((name.len() + 5) as u16).to_be_bytes());
        ext.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        ext.push(0);
        ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        ext.extend_from_slice(name);
        let n = hello.len();
        hello.truncate(n - 2);
        hello.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hello.extend_from_slice(&ext);
        let frame = record(hello);
        assert_eq!(server_name(&frame).as_deref(), Some("a.example"));
        assert_eq!(server_name(&frame[..frame.len() - 3]), None);
    }
}
