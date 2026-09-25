//! Shadowsocks 2022 (SIP022), with extensible identity headers (SIP023)
//! for multi-user servers.
//!
//! The pieces both directions share live here: methods, keys, the AEAD and
//! AES block primitives, and the replay defences. The TCP stream is in
//! [`stream`], the UDP packet codec in [`udp`].

// Both sides are compiled into either handler; a build with only one of
// them leaves the other side's pieces unused.
#![cfg_attr(
    not(all(feature = "inbound-shadowsocks", feature = "outbound-shadowsocks")),
    allow(dead_code)
)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use base64::Engine;
use btls::aead::{AeadCtx, Algorithm};
use btls::symm::{Cipher, Crypter, Mode};

pub mod stream;
pub mod udp;

/// Header type of what the client sends.
const HEADER_TYPE_CLIENT: u8 = 0;
/// Header type of what the server sends.
const HEADER_TYPE_SERVER: u8 = 1;
/// The spec's cap on padding, in both the TCP request and UDP packets.
const MAX_PADDING: usize = 900;
/// How far a peer's clock may be from ours, in seconds.
const MAX_TIME_DIFF: u64 = 30;
/// Every AEAD the methods use has a 16-byte tag.
const TAG_LEN: usize = 16;
/// Length of an identity header, one AES block.
const EIH_LEN: usize = 16;

/// Whether `method` names a Shadowsocks 2022 method, supported or not: the
/// `2022-` prefix is what tells the two protocol generations apart.
pub fn is_2022(method: &str) -> bool {
    method.starts_with("2022-")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Method {
    pub fn from_name(name: &str) -> Result<Self> {
        match name {
            "2022-blake3-aes-128-gcm" => Ok(Method::Aes128Gcm),
            "2022-blake3-aes-256-gcm" => Ok(Method::Aes256Gcm),
            "2022-blake3-chacha20-poly1305" => Ok(Method::ChaCha20Poly1305),
            _ => Err(anyhow!("unsupported cipher: {}", name)),
        }
    }

    /// Length of the PSK, of every subkey and of the TCP salt.
    pub fn key_len(self) -> usize {
        match self {
            Method::Aes128Gcm => 16,
            Method::Aes256Gcm | Method::ChaCha20Poly1305 => 32,
        }
    }

    /// Identity headers are AES blocks, so only the AES methods have them.
    pub fn supports_eih(self) -> bool {
        self != Method::ChaCha20Poly1305
    }

    fn algorithm(self) -> Algorithm {
        match self {
            Method::Aes128Gcm => Algorithm::aes_128_gcm(),
            Method::Aes256Gcm => Algorithm::aes_256_gcm(),
            Method::ChaCha20Poly1305 => Algorithm::chacha20_poly1305(),
        }
    }
}

/// Decodes one base64 PSK, which must be exactly the method's key length: a
/// key of another length is a configuration mistake, not something to hash
/// into shape.
pub fn decode_psk(method: Method, psk: &str) -> Result<Vec<u8>> {
    let key = base64::engine::general_purpose::STANDARD
        .decode(psk.trim())
        .map_err(|e| anyhow!("invalid base64 PSK: {}", e))?;
    if key.len() != method.key_len() {
        return Err(anyhow!(
            "PSK is {} bytes, the method needs {}",
            key.len(),
            method.key_len()
        ));
    }
    Ok(key)
}

/// Decodes a client password: one PSK, or `iPSK:...:uPSK` for servers with
/// identity headers, each hop's key before the next one's.
pub fn decode_psk_list(method: Method, password: &str) -> Result<Vec<Vec<u8>>> {
    let keys = password
        .split(':')
        .map(|k| decode_psk(method, k))
        .collect::<Result<Vec<_>>>()?;
    if keys.len() > 1 && !method.supports_eih() {
        return Err(anyhow!(
            "identity headers (iPSK:uPSK passwords) need an AES method"
        ));
    }
    Ok(keys)
}

fn derive(context: &str, psk: &[u8], salt: &[u8], out_len: usize) -> Vec<u8> {
    let mut material = Vec::with_capacity(psk.len() + salt.len());
    material.extend_from_slice(psk);
    material.extend_from_slice(salt);
    // derive_key is an XOF, so a 16-byte key is the prefix of the 32-byte one.
    blake3::derive_key(context, &material)[..out_len].to_vec()
}

/// The AEAD key of one TCP direction or one UDP session.
pub fn session_subkey(psk: &[u8], salt: &[u8]) -> Vec<u8> {
    derive("shadowsocks 2022 session subkey", psk, salt, psk.len())
}

/// The AES key a TCP identity header is encrypted with.
pub fn identity_subkey(psk: &[u8], salt: &[u8]) -> Vec<u8> {
    derive("shadowsocks 2022 identity subkey", psk, salt, psk.len())
}

/// What an identity header carries: the first 16 bytes of the next key's
/// BLAKE3 hash.
pub fn psk_hash(psk: &[u8]) -> [u8; EIH_LEN] {
    let mut out = [0u8; EIH_LEN];
    out.copy_from_slice(&blake3::hash(psk).as_bytes()[..EIH_LEN]);
    out
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

fn check_timestamp(ts: u64) -> io::Result<()> {
    if now_secs().abs_diff(ts) > MAX_TIME_DIFF {
        return Err(io::Error::other(format!(
            "bad timestamp {}, off by more than {}s",
            ts, MAX_TIME_DIFF
        )));
    }
    Ok(())
}

/// A random padding length for a message that would otherwise carry no or
/// little payload, as the spec asks of clients.
fn padding_len(payload_len: usize) -> usize {
    use rand::Rng;
    if payload_len < MAX_PADDING {
        rand::thread_rng().gen_range(1..=MAX_PADDING)
    } else {
        0
    }
}

pub fn crypto_err() -> io::Error {
    io::Error::other("crypto error")
}

/// One AEAD key. The nonce is the caller's: a counter for TCP chunks, part
/// of the header for UDP.
pub struct Aead(AeadCtx);

impl Aead {
    fn new(algorithm: &Algorithm, key: &[u8]) -> io::Result<Self> {
        AeadCtx::new(algorithm, key, TAG_LEN)
            .map(Aead)
            .map_err(|e| io::Error::other(format!("new aead key failed: {}", e)))
    }

    /// The session AEAD of `method` under `key`.
    pub fn session(method: Method, key: &[u8]) -> io::Result<Self> {
        Self::new(&method.algorithm(), key)
    }

    /// XChaCha20-Poly1305, which seals whole UDP packets of the ChaCha
    /// method under the PSK itself.
    pub fn xchacha(key: &[u8]) -> io::Result<Self> {
        Self::new(&Algorithm::xchacha20_poly1305(), key)
    }

    /// Encrypts `buf[start..]` in place and appends the tag.
    pub fn seal(&mut self, nonce: &[u8], buf: &mut Vec<u8>, start: usize) -> io::Result<()> {
        let mut tag = [0u8; TAG_LEN];
        let n = self
            .0
            .seal_in_place_mut(nonce, &mut buf[start..], &mut tag, &[])
            .map_err(|_| crypto_err())?
            .len();
        buf.extend_from_slice(&tag[..n]);
        Ok(())
    }

    /// Decrypts ciphertext followed by its tag in place and returns the
    /// plaintext length.
    pub fn open(&mut self, nonce: &[u8], buf: &mut [u8]) -> io::Result<usize> {
        let n = buf.len().checked_sub(TAG_LEN).ok_or_else(crypto_err)?;
        let (ciphertext, tag) = buf.split_at_mut(n);
        self.0
            .open_in_place_mut(nonce, ciphertext, tag, &[])
            .map_err(|_| crypto_err())?;
        Ok(n)
    }
}

/// The AEAD of one TCP direction: nonces count up from zero, little
/// endian, one per chunk.
pub struct ChunkAead {
    aead: Aead,
    counter: u64,
}

impl ChunkAead {
    pub fn new(method: Method, key: &[u8]) -> io::Result<Self> {
        Ok(ChunkAead {
            aead: Aead::session(method, key)?,
            counter: 0,
        })
    }

    fn next_nonce(&mut self) -> io::Result<[u8; 12]> {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&self.counter.to_le_bytes());
        // A 64-bit counter never wraps in practice; refuse rather than
        // reuse a nonce if it ever did.
        self.counter = self.counter.checked_add(1).ok_or_else(crypto_err)?;
        Ok(nonce)
    }

    pub fn seal(&mut self, buf: &mut Vec<u8>, start: usize) -> io::Result<()> {
        let nonce = self.next_nonce()?;
        self.aead.seal(&nonce, buf, start)
    }

    pub fn open(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let nonce = self.next_nonce()?;
        self.aead.open(&nonce, buf)
    }
}

/// Single-block AES, for identity headers and the UDP separate header.
pub struct AesBlock {
    key: Vec<u8>,
}

impl AesBlock {
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != 16 && key.len() != 32 {
            return Err(anyhow!("AES key of {} bytes", key.len()));
        }
        Ok(AesBlock { key: key.to_vec() })
    }

    fn cipher(&self) -> Cipher {
        if self.key.len() == 16 {
            Cipher::aes_128_ecb()
        } else {
            Cipher::aes_256_ecb()
        }
    }

    fn apply(&self, mode: Mode, block: &mut [u8]) -> io::Result<()> {
        if block.len() != 16 {
            return Err(crypto_err());
        }
        let mut c = Crypter::new(self.cipher(), mode, &self.key, None).map_err(|_| crypto_err())?;
        c.pad(false);
        let mut out = [0u8; 32];
        let n = c.update(block, &mut out).map_err(|_| crypto_err())?;
        if n != 16 {
            return Err(crypto_err());
        }
        block.copy_from_slice(&out[..16]);
        Ok(())
    }

    pub fn encrypt(&self, block: &mut [u8]) -> io::Result<()> {
        self.apply(Mode::Encrypt, block)
    }

    pub fn decrypt(&self, block: &mut [u8]) -> io::Result<()> {
        self.apply(Mode::Decrypt, block)
    }
}

/// The users of a multi-user server, found by the hash of their PSK that
/// identity headers carry.
#[derive(Clone)]
pub struct Users {
    by_hash: HashMap<[u8; EIH_LEN], usize>,
    users: Vec<User>,
}

#[derive(Clone)]
pub struct User {
    pub name: Option<std::sync::Arc<str>>,
    pub psk: Vec<u8>,
}

impl Users {
    pub fn new(users: Vec<User>) -> Result<Self> {
        let mut by_hash = HashMap::new();
        for (i, user) in users.iter().enumerate() {
            if by_hash.insert(psk_hash(&user.psk), i).is_some() {
                return Err(anyhow!("two users have the same password"));
            }
        }
        Ok(Users { by_hash, users })
    }

    pub fn find(&self, hash: &[u8]) -> Option<(usize, &User)> {
        let i = *self.by_hash.get(hash)?;
        Some((i, &self.users[i]))
    }

    pub fn get(&self, i: usize) -> Option<&User> {
        self.users.get(i)
    }
}

/// How long a salt is remembered: twice the timestamp tolerance, so a
/// replay is either caught here or has an expired timestamp.
const SALT_TTL: Duration = Duration::from_secs(2 * MAX_TIME_DIFF);
/// Salts remembered at most. When it is full of live salts, new
/// connections are refused rather than an unexpired salt forgotten, which
/// would reopen the replay window.
const SALT_POOL_CAP: usize = 256 * 1024;

/// The TCP request salts seen within [`SALT_TTL`].
pub struct SaltPool {
    inner: Mutex<SaltPoolInner>,
}

#[derive(Default)]
struct SaltPoolInner {
    set: HashSet<[u8; 32]>,
    order: VecDeque<(Instant, [u8; 32])>,
}

impl Default for SaltPool {
    fn default() -> Self {
        Self::new()
    }
}

impl SaltPool {
    pub fn new() -> Self {
        SaltPool {
            inner: Mutex::new(SaltPoolInner::default()),
        }
    }

    /// Records `salt`, or fails if it was seen within the TTL or the pool
    /// is full.
    pub fn check_and_insert(&self, salt: &[u8]) -> io::Result<()> {
        self.check_and_insert_at(salt, Instant::now(), SALT_POOL_CAP)
    }

    fn check_and_insert_at(&self, salt: &[u8], now: Instant, cap: usize) -> io::Result<()> {
        let mut key = [0u8; 32];
        let n = salt.len().min(32);
        key[..n].copy_from_slice(&salt[..n]);
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("salt pool poisoned"))?;
        while let Some((t, s)) = inner.order.front().copied() {
            if now.saturating_duration_since(t) < SALT_TTL {
                break;
            }
            inner.order.pop_front();
            inner.set.remove(&s);
        }
        if inner.set.contains(&key) {
            return Err(io::Error::other("repeated salt"));
        }
        if inner.set.len() >= cap {
            return Err(io::Error::other("salt pool full"));
        }
        inner.set.insert(key);
        inner.order.push_back((now, key));
        Ok(())
    }
}

/// Packet IDs a UDP session tracks behind the highest one seen.
const WINDOW_BITS: u64 = 2048;
const WINDOW_WORDS: usize = (WINDOW_BITS / 64) as usize;

/// A sliding window of the packet IDs seen in one UDP session, to drop
/// replays. Packets may arrive out of order up to the window's width.
pub struct ReplayWindow {
    last: Option<u64>,
    bits: [u64; WINDOW_WORDS],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    pub fn new() -> Self {
        ReplayWindow {
            last: None,
            bits: [0; WINDOW_WORDS],
        }
    }

    fn bit(id: u64) -> (usize, u64) {
        let i = id % WINDOW_BITS;
        ((i / 64) as usize, 1 << (i % 64))
    }

    /// Whether `id` is new. Checked before the packet is authenticated; it
    /// is only recorded, with [`add`](Self::add), after.
    pub fn check(&self, id: u64) -> bool {
        let Some(last) = self.last else {
            return true;
        };
        if id > last {
            return true;
        }
        if last - id >= WINDOW_BITS {
            return false;
        }
        let (w, b) = Self::bit(id);
        self.bits[w] & b == 0
    }

    pub fn add(&mut self, id: u64) {
        match self.last {
            Some(last) if id <= last => {}
            Some(last) if id - last < WINDOW_BITS => {
                for skipped in last + 1..=id {
                    let (w, b) = Self::bit(skipped);
                    self.bits[w] &= !b;
                }
                self.last = Some(id);
            }
            _ => {
                self.bits = [0; WINDOW_WORDS];
                self.last = Some(id);
            }
        }
        let (w, b) = Self::bit(id);
        self.bits[w] |= b;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn methods() {
        assert_eq!(
            Method::from_name("2022-blake3-aes-128-gcm")
                .unwrap()
                .key_len(),
            16
        );
        assert_eq!(
            Method::from_name("2022-blake3-aes-256-gcm")
                .unwrap()
                .key_len(),
            32
        );
        let chacha = Method::from_name("2022-blake3-chacha20-poly1305").unwrap();
        assert_eq!(chacha.key_len(), 32);
        assert!(!chacha.supports_eih());
        assert!(Method::from_name("aes-128-gcm").is_err());
        assert!(Method::from_name("2022-blake3-aes-192-gcm").is_err());
        assert!(is_2022("2022-blake3-aes-192-gcm"));
        assert!(!is_2022("aes-128-gcm"));
    }

    #[test]
    fn psk_lengths() {
        let b64 = |n: usize| base64::engine::general_purpose::STANDARD.encode(vec![7u8; n]);
        assert!(decode_psk(Method::Aes128Gcm, &b64(16)).is_ok());
        assert!(decode_psk(Method::Aes128Gcm, &b64(32)).is_err());
        assert!(decode_psk(Method::Aes256Gcm, &b64(16)).is_err());
        assert!(decode_psk(Method::Aes256Gcm, &b64(32)).is_ok());
        assert!(decode_psk(Method::Aes256Gcm, "not base64!").is_err());
        let two = format!("{}:{}", b64(32), b64(32));
        assert_eq!(decode_psk_list(Method::Aes256Gcm, &two).unwrap().len(), 2);
        assert!(decode_psk_list(Method::ChaCha20Poly1305, &two).is_err());
        assert!(decode_psk_list(Method::Aes256Gcm, &format!("{}:", b64(32))).is_err());
    }

    // BLAKE3's derive_key against its reference test vector (the empty
    // input), and the prefix property 16-byte keys rely on.
    #[test]
    fn blake3_derive_key_vector() {
        let key = blake3::derive_key("BLAKE3 2019-12-27 16:29:52 test vectors context", &[]);
        assert_eq!(
            hex_encode(&key),
            "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d"
        );
        let psk = [1u8; 16];
        let salt = [2u8; 16];
        let k16 = session_subkey(&psk, &salt);
        let k32 = derive("shadowsocks 2022 session subkey", &psk, &salt, 32);
        assert_eq!(k16.len(), 16);
        assert_eq!(&k32[..16], &k16[..]);
        assert_ne!(session_subkey(&psk, &salt), identity_subkey(&psk, &salt));
    }

    fn hex_encode(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    // FIPS-197 appendix C vectors.
    #[test]
    fn aes_block_vectors() {
        let pt: Vec<u8> = (0..16u8).map(|i| i * 0x11).collect();
        let key128: Vec<u8> = (0..16).collect();
        let key256: Vec<u8> = (0..32).collect();
        for (key, ct) in [
            (&key128, "69c4e0d86a7b0430d8cdb78070b4c55a"),
            (&key256, "8ea2b7ca516745bfeafc49904b496089"),
        ] {
            let aes = AesBlock::new(key).unwrap();
            let mut block = pt.clone();
            aes.encrypt(&mut block).unwrap();
            assert_eq!(hex_encode(&block), ct);
            aes.decrypt(&mut block).unwrap();
            assert_eq!(block, pt);
        }
        assert!(AesBlock::new(&[0u8; 24]).is_err());
    }

    // BoringSSL's XChaCha20-Poly1305 against RustCrypto's.
    #[test]
    fn xchacha_matches_rustcrypto() {
        use chacha20poly1305::aead::{Aead as _, KeyInit};
        let key: Vec<u8> = (0..32).collect();
        let nonce: Vec<u8> = (100..124).collect();
        let pt = b"shadowsocks 2022 udp".to_vec();
        let expected = chacha20poly1305::XChaCha20Poly1305::new_from_slice(&key)
            .unwrap()
            .encrypt(chacha20poly1305::XNonce::from_slice(&nonce), &pt[..])
            .unwrap();
        let mut aead = Aead::xchacha(&key).unwrap();
        let mut buf = pt.clone();
        aead.seal(&nonce, &mut buf, 0).unwrap();
        assert_eq!(buf, expected);
        let n = aead.open(&nonce, &mut buf).unwrap();
        assert_eq!(&buf[..n], &pt[..]);
    }

    #[test]
    fn chunk_nonces_count_from_zero() {
        use aes_gcm::aead::{Aead as _, KeyInit};
        let key = [9u8; 16];
        let mut aead = ChunkAead::new(Method::Aes128Gcm, &key).unwrap();
        let gcm = aes_gcm::Aes128Gcm::new_from_slice(&key).unwrap();
        for i in 0u64..3 {
            let mut nonce = [0u8; 12];
            nonce[..8].copy_from_slice(&i.to_le_bytes());
            let expected = gcm
                .encrypt(aes_gcm::Nonce::from_slice(&nonce), &b"chunk"[..])
                .unwrap();
            let mut buf = b"chunk".to_vec();
            aead.seal(&mut buf, 0).unwrap();
            assert_eq!(buf, expected, "chunk {}", i);
        }
    }

    #[test]
    fn salt_replay_rejected() {
        let pool = SaltPool::new();
        let t0 = Instant::now();
        pool.check_and_insert_at(&[1; 32], t0, 4).unwrap();
        assert!(pool.check_and_insert_at(&[1; 32], t0, 4).is_err());
        pool.check_and_insert_at(&[2; 16], t0, 4).unwrap();
        // Remembered until the TTL passes, then forgotten.
        let later = t0 + SALT_TTL - Duration::from_secs(1);
        assert!(pool.check_and_insert_at(&[1; 32], later, 4).is_err());
        let expired = t0 + SALT_TTL;
        pool.check_and_insert_at(&[1; 32], expired, 4).unwrap();
    }

    #[test]
    fn salt_pool_bounded() {
        let pool = SaltPool::new();
        let t0 = Instant::now();
        for i in 0..3u8 {
            pool.check_and_insert_at(&[i; 16], t0, 3).unwrap();
        }
        // Full of live salts: refuse, never forget one.
        assert!(pool.check_and_insert_at(&[9; 16], t0, 3).is_err());
        assert!(pool.check_and_insert_at(&[0; 16], t0, 3).is_err());
        pool.check_and_insert_at(&[9; 16], t0 + SALT_TTL, 3)
            .unwrap();
    }

    #[test]
    fn replay_window() {
        let mut w = ReplayWindow::new();
        assert!(w.check(0));
        w.add(0);
        assert!(!w.check(0));
        w.add(5);
        assert!(w.check(3));
        w.add(3);
        assert!(!w.check(3));
        assert!(!w.check(5));
        w.add(5 + WINDOW_BITS);
        // Too old now, and the bits reused for new IDs are clear.
        assert!(!w.check(5));
        assert!(w.check(6 + WINDOW_BITS));
        assert!(!w.check(5 + WINDOW_BITS));
        w.add(u64::MAX);
        assert!(!w.check(u64::MAX));
        assert!(w.check(u64::MAX - 1));
    }

    #[test]
    fn users_by_hash() {
        let users = Users::new(vec![
            User {
                name: Some("a".into()),
                psk: vec![1; 16],
            },
            User {
                name: Some("b".into()),
                psk: vec![2; 16],
            },
        ])
        .unwrap();
        let (i, u) = users.find(&psk_hash(&[2; 16])).unwrap();
        assert_eq!(i, 1);
        assert_eq!(u.name.as_deref(), Some("b"));
        assert!(users.find(&psk_hash(&[3; 16])).is_none());
        assert!(Users::new(vec![
            User {
                name: None,
                psk: vec![1; 16]
            },
            User {
                name: None,
                psk: vec![1; 16]
            },
        ])
        .is_err());
    }
}
