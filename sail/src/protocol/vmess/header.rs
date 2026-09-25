//! The VMess request and response headers, AEAD form only.
//!
//! A request is an auth ID -- a timestamp, four random bytes and their
//! CRC32, AES-encrypted under a key from the user's -- then the header's
//! length and the header, each sealed with AES-128-GCM under keys derived
//! from the user's key, the auth ID and a connection nonce. The header
//! carries the body keys, the options, the security and the command and
//! destination. The response is its own sealed length and header, under
//! keys derived from the body keys.

use std::collections::HashSet;
use std::io;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use btls::aead::{AeadCtx, Algorithm};
use bytes::{BufMut, BytesMut};
use md5::{Digest, Md5};
use parking_lot::Mutex;
use rand::{Rng, RngCore};
use tokio::io::{AsyncRead, AsyncReadExt};

use super::kdf::*;
use super::xudp::{parse_addr_port, write_addr_port};
use crate::session::SocksAddr;

pub const VERSION: u8 = 1;

pub const SECURITY_AES128_GCM: u8 = 3;
pub const SECURITY_CHACHA20_POLY1305: u8 = 4;
pub const SECURITY_NONE: u8 = 5;

pub const OPTION_CHUNK_STREAM: u8 = 0x01;
pub const OPTION_CHUNK_MASKING: u8 = 0x04;
pub const OPTION_GLOBAL_PADDING: u8 = 0x08;
pub const OPTION_AUTHENTICATED_LENGTH: u8 = 0x10;

pub const COMMAND_TCP: u8 = 1;
pub const COMMAND_UDP: u8 = 2;
pub const COMMAND_MUX: u8 = 3;

/// How far a client's clock may be from ours.
const MAX_TIME_DIFFERENCE: u64 = 120;

/// The longest request header there can be: the fixed part, the longest
/// address, the most padding and the checksum.
const MAX_HEADER_LEN: usize = 38 + 1 + 255 + 2 + 15 + 4;

const TAG_LEN: usize = 16;

/// The user's key: MD5 of the UUID and a constant.
pub fn cmd_key(uuid: &[u8; 16]) -> [u8; 16] {
    let mut md5 = Md5::new();
    md5.update(uuid);
    md5.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    md5.finalize().into()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn crypto_error() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "vmess: bad header")
}

fn gcm(key: &[u8]) -> io::Result<AeadCtx> {
    AeadCtx::new_default_tag(&Algorithm::aes_128_gcm(), key).map_err(io::Error::other)
}

/// Seals `data` with AES-128-GCM, appending the tag.
fn seal(key: &[u8], nonce: &[u8], data: &mut Vec<u8>, aad: &[u8]) -> io::Result<()> {
    let mut tag = [0u8; TAG_LEN];
    gcm(key)?
        .seal_in_place_mut(nonce, data, &mut tag, aad)
        .map_err(io::Error::other)?;
    data.extend_from_slice(&tag);
    Ok(())
}

/// Opens `data`, ciphertext and tag, in place; the plaintext is what is
/// left.
fn open(key: &[u8], nonce: &[u8], data: &mut Vec<u8>, aad: &[u8]) -> io::Result<()> {
    if data.len() < TAG_LEN {
        return Err(crypto_error());
    }
    let tag = data.split_off(data.len() - TAG_LEN);
    gcm(key)?
        .open_in_place_mut(nonce, data, &tag, aad)
        .map_err(|_| crypto_error())
}

fn auth_id_cipher(cmd_key: &[u8; 16]) -> Aes128 {
    let key = vmess_kdf_1_one_shot(cmd_key, KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY);
    Aes128::new((&key[..16]).into())
}

fn auth_id(cmd_key: &[u8; 16], time: u64) -> [u8; 16] {
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&time.to_be_bytes());
    rand::thread_rng().fill_bytes(&mut id[8..12]);
    let crc = crc32fast::hash(&id[..12]);
    id[12..].copy_from_slice(&crc.to_be_bytes());
    auth_id_cipher(cmd_key).encrypt_block((&mut id).into());
    id
}

/// FNV-1a, 32 bits: the checksum at the end of a request header.
fn fnv1a(data: &[u8]) -> u32 {
    data.iter().fold(0x811c9dc5u32, |h, b| {
        (h ^ *b as u32).wrapping_mul(0x01000193)
    })
}

/// A request header, the part that is sealed.
#[derive(Debug, Clone)]
pub struct RequestHeader {
    pub body_iv: [u8; 16],
    pub body_key: [u8; 16],
    /// Echoed by the server in its response.
    pub response_auth: u8,
    pub option: u8,
    pub security: u8,
    pub command: u8,
    /// None for Mux.
    pub address: Option<SocksAddr>,
}

impl RequestHeader {
    /// A new request with fresh body keys.
    pub fn new(option: u8, security: u8, command: u8, address: Option<SocksAddr>) -> Self {
        let mut rng = rand::thread_rng();
        let mut header = RequestHeader {
            body_iv: [0; 16],
            body_key: [0; 16],
            response_auth: rng.gen(),
            option,
            security,
            command,
            address,
        };
        rng.fill_bytes(&mut header.body_iv);
        rng.fill_bytes(&mut header.body_key);
        header
    }

    fn encode(&self) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let padding: u8 = rng.gen_range(0..16);
        let mut buf = BytesMut::with_capacity(64);
        buf.put_u8(VERSION);
        buf.put_slice(&self.body_iv);
        buf.put_slice(&self.body_key);
        buf.put_u8(self.response_auth);
        buf.put_u8(self.option);
        buf.put_u8(padding << 4 | self.security);
        buf.put_u8(0);
        buf.put_u8(self.command);
        if let Some(address) = &self.address {
            write_addr_port(&mut buf, address);
        }
        let mut pad = [0u8; 15];
        rng.fill_bytes(&mut pad);
        buf.put_slice(&pad[..padding as usize]);
        let checksum = fnv1a(&buf);
        buf.put_u32(checksum);
        buf.to_vec()
    }

    fn decode(buf: &[u8]) -> io::Result<Self> {
        let invalid =
            |what: &str| io::Error::new(io::ErrorKind::InvalidData, format!("vmess: {}", what));
        if buf.len() < 38 + 4 {
            return Err(invalid("header too short"));
        }
        let (body, checksum) = buf.split_at(buf.len() - 4);
        if fnv1a(body).to_be_bytes() != checksum {
            return Err(invalid("bad header checksum"));
        }
        if body[0] != VERSION {
            return Err(invalid("unknown version"));
        }
        let mut header = RequestHeader {
            body_iv: body[1..17].try_into().map_err(|_| invalid("short"))?,
            body_key: body[17..33].try_into().map_err(|_| invalid("short"))?,
            response_auth: body[33],
            option: body[34],
            security: body[35] & 0x0f,
            command: body[37],
            address: None,
        };
        let padding = (body[35] >> 4) as usize;
        let rest = &body[38..];
        let used = match header.command {
            COMMAND_TCP | COMMAND_UDP => {
                let (address, used) = parse_addr_port(rest)?;
                header.address = Some(address);
                used
            }
            COMMAND_MUX => 0,
            _ => return Err(invalid("unknown command")),
        };
        if rest.len() != used + padding {
            return Err(invalid("bad header length"));
        }
        Ok(header)
    }

    /// The request as it goes on the wire, sealed for the user `cmd_key`.
    pub fn seal(&self, cmd_key: &[u8; 16]) -> io::Result<Vec<u8>> {
        let auth_id = auth_id(cmd_key, now());
        let mut nonce = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut nonce);
        let header = self.encode();

        let mut length = (header.len() as u16).to_be_bytes().to_vec();
        let key = vmess_kdf_3_one_shot(
            cmd_key,
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
            &auth_id,
            &nonce,
        );
        let iv = vmess_kdf_3_one_shot(
            cmd_key,
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
            &auth_id,
            &nonce,
        );
        seal(&key[..16], &iv[..12], &mut length, &auth_id)?;

        let mut payload = header;
        let key = vmess_kdf_3_one_shot(
            cmd_key,
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY,
            &auth_id,
            &nonce,
        );
        let iv = vmess_kdf_3_one_shot(
            cmd_key,
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV,
            &auth_id,
            &nonce,
        );
        seal(&key[..16], &iv[..12], &mut payload, &auth_id)?;

        let mut out = Vec::with_capacity(16 + length.len() + 8 + payload.len());
        out.extend_from_slice(&auth_id);
        out.extend_from_slice(&length);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&payload);
        Ok(out)
    }

    /// The key and IV of the response body: the first 16 bytes of the
    /// SHA-256 of the request's.
    pub fn response_keys(&self) -> ([u8; 16], [u8; 16]) {
        use sha2::Sha256;
        let key = Sha256::digest(self.body_key);
        let iv = Sha256::digest(self.body_iv);
        (
            key[..16].try_into().expect("SHA-256 is 32 bytes"),
            iv[..16].try_into().expect("SHA-256 is 32 bytes"),
        )
    }

    /// The server's response header, sealed.
    pub fn seal_response(&self) -> io::Result<Vec<u8>> {
        let (key, iv) = self.response_keys();
        let mut length = 4u16.to_be_bytes().to_vec();
        let len_key = vmess_kdf_1_one_shot(&key, KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY);
        let len_iv = vmess_kdf_1_one_shot(&iv, KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV);
        seal(&len_key[..16], &len_iv[..12], &mut length, &[])?;
        // The echoed byte, the option, and no command.
        let mut header = vec![self.response_auth, self.option, 0, 0];
        let key = vmess_kdf_1_one_shot(&key, KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY);
        let iv = vmess_kdf_1_one_shot(&iv, KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV);
        seal(&key[..16], &iv[..12], &mut header, &[])?;
        length.extend_from_slice(&header);
        Ok(length)
    }
}

/// Reads the server's response for a request: `pending` holds what has
/// been read so far. Returns how many bytes the response took, or None if
/// more are needed.
pub fn open_response(request: &RequestHeader, pending: &[u8]) -> io::Result<Option<usize>> {
    const LEN_PART: usize = 2 + TAG_LEN;
    if pending.len() < LEN_PART {
        return Ok(None);
    }
    let (key, iv) = request.response_keys();
    let len_key = vmess_kdf_1_one_shot(&key, KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY);
    let len_iv = vmess_kdf_1_one_shot(&iv, KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV);
    let mut length = pending[..LEN_PART].to_vec();
    open(&len_key[..16], &len_iv[..12], &mut length, &[])?;
    let len = u16::from_be_bytes([length[0], length[1]]) as usize;
    let total = LEN_PART + len + TAG_LEN;
    if pending.len() < total {
        return Ok(None);
    }
    let key = vmess_kdf_1_one_shot(&key, KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY);
    let iv = vmess_kdf_1_one_shot(&iv, KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV);
    let mut header = pending[LEN_PART..total].to_vec();
    open(&key[..16], &iv[..12], &mut header, &[])?;
    if header.first() != Some(&request.response_auth) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "vmess: response is not for this request",
        ));
    }
    Ok(Some(total))
}

/// Auth IDs seen recently. An ID is good for the two minutes either side
/// of its timestamp, so each is remembered for at least four: IDs go into
/// a generation that is at most four minutes old, and are dropped with the
/// one before it. A generation that fills up is rotated early, which
/// bounds the memory at the cost of remembering less under a flood.
pub struct ReplayFilter {
    inner: Mutex<Generations>,
}

struct Generations {
    current: HashSet<[u8; 16]>,
    previous: HashSet<[u8; 16]>,
    since: Instant,
}

const REPLAY_WINDOW: Duration = Duration::from_secs(2 * MAX_TIME_DIFFERENCE);
const REPLAY_MAX_ENTRIES: usize = 1 << 20;

impl Default for ReplayFilter {
    fn default() -> Self {
        ReplayFilter {
            inner: Mutex::new(Generations {
                current: HashSet::new(),
                previous: HashSet::new(),
                since: Instant::now(),
            }),
        }
    }
}

impl ReplayFilter {
    /// Whether `id` is new; it is remembered either way.
    pub fn check(&self, id: &[u8; 16]) -> bool {
        let mut g = self.inner.lock();
        let age = g.since.elapsed();
        if age >= 2 * REPLAY_WINDOW {
            g.current.clear();
            g.previous.clear();
            g.since = Instant::now();
        } else if age >= REPLAY_WINDOW || g.current.len() >= REPLAY_MAX_ENTRIES {
            g.previous = std::mem::take(&mut g.current);
            g.since = Instant::now();
        }
        if g.previous.contains(id) {
            return false;
        }
        g.current.insert(*id)
    }
}

/// A VMess user as the server knows it.
pub struct User<T> {
    pub cmd_key: [u8; 16],
    cipher: Aes128,
    pub data: T,
}

impl<T> User<T> {
    pub fn new(uuid: &[u8; 16], data: T) -> Self {
        let cmd_key = cmd_key(uuid);
        User {
            cmd_key,
            cipher: auth_id_cipher(&cmd_key),
            data,
        }
    }
}

/// The server's side of authentication: its users and the auth IDs they
/// used.
pub struct Authenticator<T> {
    users: Vec<User<T>>,
    replay: ReplayFilter,
}

/// Why a request was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum AuthError {
    UnknownUser,
    BadTime,
    Replayed,
}

impl<T> Authenticator<T> {
    pub fn new(users: Vec<User<T>>) -> Self {
        Authenticator {
            users,
            replay: ReplayFilter::default(),
        }
    }

    /// The user an auth ID is from, if it is theirs, current and new.
    pub fn authenticate(&self, auth_id: &[u8; 16], now: u64) -> Result<&User<T>, AuthError> {
        for user in &self.users {
            let mut id = *auth_id;
            user.cipher.decrypt_block((&mut id).into());
            let crc = u32::from_be_bytes([id[12], id[13], id[14], id[15]]);
            if crc32fast::hash(&id[..12]) != crc {
                continue;
            }
            let time = u64::from_be_bytes(id[..8].try_into().expect("8 bytes"));
            if time.abs_diff(now) > MAX_TIME_DIFFERENCE {
                return Err(AuthError::BadTime);
            }
            if !self.replay.check(auth_id) {
                return Err(AuthError::Replayed);
            }
            return Ok(user);
        }
        Err(AuthError::UnknownUser)
    }

    /// Reads and opens a request: the user it is from and its header.
    pub async fn read_request<R: AsyncRead + Unpin>(
        &self,
        r: &mut R,
    ) -> io::Result<(&User<T>, RequestHeader)> {
        let mut auth_id = [0u8; 16];
        r.read_exact(&mut auth_id).await?;
        let user = self.authenticate(&auth_id, now()).map_err(|e| {
            io::Error::new(io::ErrorKind::PermissionDenied, format!("vmess: {:?}", e))
        })?;
        let mut length = vec![0u8; 2 + TAG_LEN];
        r.read_exact(&mut length).await?;
        let mut nonce = [0u8; 8];
        r.read_exact(&mut nonce).await?;
        let key = vmess_kdf_3_one_shot(
            &user.cmd_key,
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
            &auth_id,
            &nonce,
        );
        let iv = vmess_kdf_3_one_shot(
            &user.cmd_key,
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
            &auth_id,
            &nonce,
        );
        open(&key[..16], &iv[..12], &mut length, &auth_id)?;
        let len = u16::from_be_bytes([length[0], length[1]]) as usize;
        if len > MAX_HEADER_LEN {
            return Err(crypto_error());
        }
        let mut header = vec![0u8; len + TAG_LEN];
        r.read_exact(&mut header).await?;
        let key = vmess_kdf_3_one_shot(
            &user.cmd_key,
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY,
            &auth_id,
            &nonce,
        );
        let iv = vmess_kdf_3_one_shot(
            &user.cmd_key,
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV,
            &auth_id,
            &nonce,
        );
        open(&key[..16], &iv[..12], &mut header, &auth_id)?;
        Ok((user, RequestHeader::decode(&header)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: [u8; 16] = [0x42; 16];

    fn request() -> RequestHeader {
        RequestHeader::new(
            OPTION_CHUNK_STREAM | OPTION_CHUNK_MASKING,
            SECURITY_AES128_GCM,
            COMMAND_TCP,
            Some(SocksAddr::try_from(("example.com", 443)).unwrap()),
        )
    }

    #[tokio::test]
    async fn test_request_round_trip() {
        let auth = Authenticator::new(vec![User::new(&[1; 16], "bob"), User::new(&UUID, "alice")]);
        for header in [
            request(),
            RequestHeader::new(0, SECURITY_NONE, COMMAND_MUX, None),
        ] {
            let wire = header.seal(&cmd_key(&UUID)).unwrap();
            let (user, opened) = auth.read_request(&mut &wire[..]).await.unwrap();
            assert_eq!(user.data, "alice");
            assert_eq!(opened.body_key, header.body_key);
            assert_eq!(opened.body_iv, header.body_iv);
            assert_eq!(opened.option, header.option);
            assert_eq!(opened.security, header.security);
            assert_eq!(opened.command, header.command);
            assert_eq!(opened.address, header.address);
        }
    }

    #[tokio::test]
    async fn test_replayed_request_is_refused() {
        let auth = Authenticator::new(vec![User::new(&UUID, ())]);
        let wire = request().seal(&cmd_key(&UUID)).unwrap();
        assert!(auth.read_request(&mut &wire[..]).await.is_ok());
        let Err(err) = auth.read_request(&mut &wire[..]).await else {
            panic!("a replayed request was accepted");
        };
        assert!(err.to_string().contains("Replayed"), "{}", err);
    }

    #[test]
    fn test_auth_id_checks() {
        let auth = Authenticator::new(vec![User::new(&UUID, ())]);
        let key = cmd_key(&UUID);
        let t = now();
        assert!(auth.authenticate(&auth_id(&key, t - 100), t).is_ok());
        assert_eq!(
            auth.authenticate(&auth_id(&key, t - 200), t).err(),
            Some(AuthError::BadTime)
        );
        assert_eq!(
            auth.authenticate(&auth_id(&cmd_key(&[9; 16]), t), t).err(),
            Some(AuthError::UnknownUser)
        );
        let id = auth_id(&key, t);
        assert!(auth.authenticate(&id, t).is_ok());
        assert_eq!(auth.authenticate(&id, t).err(), Some(AuthError::Replayed));
    }

    #[test]
    fn test_replay_filter_generations() {
        let filter = ReplayFilter::default();
        assert!(filter.check(&[1; 16]));
        assert!(!filter.check(&[1; 16]));
        // Rotated once, an ID is still remembered.
        filter.inner.lock().since -= REPLAY_WINDOW;
        assert!(!filter.check(&[1; 16]));
        assert!(filter.check(&[2; 16]));
        // Twice, it is gone.
        filter.inner.lock().since -= REPLAY_WINDOW * 2;
        assert!(filter.check(&[1; 16]));
    }

    #[tokio::test]
    async fn test_tampered_request_is_refused() {
        let auth = Authenticator::new(vec![User::new(&UUID, ())]);
        let wire = request().seal(&cmd_key(&UUID)).unwrap();
        for i in [20, 40, wire.len() - 1] {
            let mut bad = wire.clone();
            bad[i] ^= 1;
            assert!(auth.read_request(&mut &bad[..]).await.is_err());
        }
        for cut in 0..wire.len() {
            let auth = Authenticator::new(vec![User::new(&UUID, ())]);
            assert!(auth.read_request(&mut &wire[..cut]).await.is_err());
        }
    }

    #[test]
    fn test_response_round_trip() {
        let header = request();
        let response = header.seal_response().unwrap();
        for cut in 0..response.len() {
            assert_eq!(open_response(&header, &response[..cut]).unwrap(), None);
        }
        assert_eq!(
            open_response(&header, &response).unwrap(),
            Some(response.len())
        );
        let other = request();
        assert!(open_response(&other, &response).is_err());
    }

    #[test]
    fn test_fnv1a() {
        assert_eq!(fnv1a(b""), 0x811c9dc5);
        assert_eq!(fnv1a(b"a"), 0xe40c292c);
    }
}
