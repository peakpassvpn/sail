//! The primitives of the WireGuard whitepaper, section 5.4: HASH, MAC,
//! HMAC, KDF, DH, AEAD and XAEAD.
//!
//! X25519, ChaCha20-Poly1305 and XChaCha20-Poly1305 come from BoringSSL
//! through btls; BLAKE2s from the `blake2` crate. HMAC over BLAKE2s is
//! written out here, as RFC 2104 with a 64-byte block.

use blake2::digest::consts::U16;
use blake2::digest::{Digest, KeyInit, Mac};
use blake2::{Blake2s256, Blake2sMac};
use btls::aead::{AeadCtx, Algorithm};

/// Length of keys, hashes and X25519 values.
pub const KEY_LEN: usize = 32;
/// Length of every AEAD tag.
pub const TAG_LEN: usize = 16;
/// Length of MAC outputs: mac1, mac2 and cookies.
pub const MAC_LEN: usize = 16;
/// Length of the XAEAD nonce in cookie replies.
pub const XNONCE_LEN: usize = 24;

const BLAKE2S_BLOCK: usize = 64;

/// HASH(parts[0] || parts[1] || ...): BLAKE2s-256.
pub fn hash(parts: &[&[u8]]) -> [u8; KEY_LEN] {
    let mut h = Blake2s256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// MAC(key, input): keyed BLAKE2s with a 16-byte output.
pub fn mac(key: &[u8], parts: &[&[u8]]) -> [u8; MAC_LEN] {
    let mut m = <Blake2sMac<U16> as KeyInit>::new_from_slice(key)
        .expect("BLAKE2s keys up to 32 bytes are valid");
    for p in parts {
        Mac::update(&mut m, p);
    }
    m.finalize().into_bytes().into()
}

/// HMAC(key, input) over BLAKE2s-256.
pub fn hmac(key: &[u8; KEY_LEN], parts: &[&[u8]]) -> [u8; KEY_LEN] {
    let mut ipad = [0x36u8; BLAKE2S_BLOCK];
    let mut opad = [0x5cu8; BLAKE2S_BLOCK];
    for (i, k) in key.iter().enumerate() {
        ipad[i] ^= k;
        opad[i] ^= k;
    }
    let mut inner = Blake2s256::new();
    inner.update(ipad);
    for p in parts {
        inner.update(p);
    }
    let inner = inner.finalize();
    let mut outer = Blake2s256::new();
    outer.update(opad);
    outer.update(inner);
    let out = outer.finalize().into();
    wipe(&mut ipad);
    wipe(&mut opad);
    out
}

/// KDF1(key, input).
pub fn kdf1(key: &[u8; KEY_LEN], input: &[u8]) -> [u8; KEY_LEN] {
    let mut t0 = hmac(key, &[input]);
    let t1 = hmac(&t0, &[&[1]]);
    wipe(&mut t0);
    t1
}

/// KDF2(key, input).
pub fn kdf2(key: &[u8; KEY_LEN], input: &[u8]) -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
    let mut t0 = hmac(key, &[input]);
    let t1 = hmac(&t0, &[&[1]]);
    let t2 = hmac(&t0, &[&t1, &[2]]);
    wipe(&mut t0);
    (t1, t2)
}

/// KDF3(key, input).
pub fn kdf3(key: &[u8; KEY_LEN], input: &[u8]) -> ([u8; KEY_LEN], [u8; KEY_LEN], [u8; KEY_LEN]) {
    let mut t0 = hmac(key, &[input]);
    let t1 = hmac(&t0, &[&[1]]);
    let t2 = hmac(&t0, &[&t1, &[2]]);
    let t3 = hmac(&t0, &[&t2, &[3]]);
    wipe(&mut t0);
    (t1, t2, t3)
}

/// A fresh X25519 private key, clamped as `wg genkey` clamps it.
pub fn generate_private_key() -> [u8; KEY_LEN] {
    let mut k = [0u8; KEY_LEN];
    btls::rand::rand_bytes(&mut k).expect("BoringSSL RNG");
    clamp(&mut k);
    k
}

/// Clamps an X25519 scalar (RFC 7748, section 5).
pub fn clamp(k: &mut [u8; KEY_LEN]) {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
}

/// The public key of `private`.
pub fn public_key(private: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let mut public = [0u8; KEY_LEN];
    // SAFETY: both buffers are 32 bytes, as X25519 requires.
    unsafe { btls_sys::X25519_public_from_private(public.as_mut_ptr(), private.as_ptr()) };
    public
}

/// DH(private, public). `None` when the result is all zeros, that is when
/// `public` is a point of small order; the handshake must then fail.
pub fn dh(private: &[u8; KEY_LEN], public: &[u8; KEY_LEN]) -> Option<[u8; KEY_LEN]> {
    let mut shared = [0u8; KEY_LEN];
    // SAFETY: all three buffers are 32 bytes. X25519 returns 0 exactly when
    // the output is all zeros.
    let ok = unsafe { btls_sys::X25519(shared.as_mut_ptr(), private.as_ptr(), public.as_ptr()) };
    (ok == 1).then_some(shared)
}

/// Random bytes from BoringSSL.
pub fn random_bytes(buf: &mut [u8]) {
    btls::rand::rand_bytes(buf).expect("BoringSSL RNG");
}

/// A random u32, for session indices.
pub fn random_u32() -> u32 {
    let mut b = [0u8; 4];
    random_bytes(&mut b);
    u32::from_le_bytes(b)
}

/// Constant-time equality.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && btls::memcmp::eq(a, b)
}

/// Zeroes secret memory in a way the optimiser keeps.
pub fn wipe(buf: &mut [u8]) {
    // SAFETY: the pointer and length describe `buf`.
    unsafe { btls_sys::OPENSSL_cleanse(buf.as_mut_ptr().cast(), buf.len()) };
}

/// The 12-byte ChaCha20-Poly1305 nonce: 32 zero bits, then the counter
/// little-endian.
fn nonce(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    n
}

/// A ChaCha20-Poly1305 key held as a BoringSSL context, so that transport
/// data does not set the key up again for every packet.
pub struct AeadKey(AeadCtx);

impl AeadKey {
    pub fn new(key: &[u8; KEY_LEN]) -> Self {
        AeadKey(
            AeadCtx::new(&Algorithm::chacha20_poly1305(), key, TAG_LEN)
                .expect("a 32-byte ChaCha20-Poly1305 key"),
        )
    }

    /// Encrypts `buf[..len - TAG_LEN]` in place and writes the tag to the
    /// last TAG_LEN bytes.
    pub fn seal_in_place(&mut self, counter: u64, buf: &mut [u8], aad: &[u8]) {
        let split = buf.len() - TAG_LEN;
        let (text, tag) = buf.split_at_mut(split);
        self.0
            .seal_in_place_mut(&nonce(counter), text, tag, aad)
            .expect("ChaCha20-Poly1305 seal");
    }

    /// Decrypts `buf` (ciphertext then tag) in place. On success the
    /// plaintext is `buf[..len - TAG_LEN]`.
    pub fn open_in_place(&mut self, counter: u64, buf: &mut [u8], aad: &[u8]) -> bool {
        if buf.len() < TAG_LEN {
            return false;
        }
        let split = buf.len() - TAG_LEN;
        let (text, tag) = buf.split_at_mut(split);
        self.0
            .open_in_place_mut(&nonce(counter), text, tag, aad)
            .is_ok()
    }
}

/// AEAD(key, counter, plaintext, aad), for the handshake fields: returns
/// ciphertext || tag into `out`, which is plaintext.len() + TAG_LEN long.
pub fn aead_seal(key: &[u8; KEY_LEN], counter: u64, plaintext: &[u8], aad: &[u8], out: &mut [u8]) {
    debug_assert_eq!(out.len(), plaintext.len() + TAG_LEN);
    out[..plaintext.len()].copy_from_slice(plaintext);
    AeadKey::new(key).seal_in_place(counter, out, aad);
}

/// The inverse of [`aead_seal`]: `out` is ciphertext.len() - TAG_LEN long.
pub fn aead_open(
    key: &[u8; KEY_LEN],
    counter: u64,
    ciphertext: &[u8],
    aad: &[u8],
    out: &mut [u8],
) -> bool {
    if ciphertext.len() != out.len() + TAG_LEN {
        return false;
    }
    let mut buf = ciphertext.to_vec();
    let ok = AeadKey::new(key).open_in_place(counter, &mut buf, aad);
    if ok {
        out.copy_from_slice(&buf[..out.len()]);
    }
    wipe(&mut buf);
    ok
}

/// XAEAD(key, nonce, plaintext, aad): XChaCha20-Poly1305, for cookies.
pub fn xaead_seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; XNONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
    out: &mut [u8],
) {
    debug_assert_eq!(out.len(), plaintext.len() + TAG_LEN);
    let mut ctx = AeadCtx::new(&Algorithm::xchacha20_poly1305(), key, TAG_LEN)
        .expect("a 32-byte XChaCha20-Poly1305 key");
    let split = plaintext.len();
    out[..split].copy_from_slice(plaintext);
    let (text, tag) = out.split_at_mut(split);
    ctx.seal_in_place_mut(nonce, text, tag, aad)
        .expect("XChaCha20-Poly1305 seal");
}

/// The inverse of [`xaead_seal`].
pub fn xaead_open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; XNONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
    out: &mut [u8],
) -> bool {
    if ciphertext.len() != out.len() + TAG_LEN {
        return false;
    }
    let mut ctx = AeadCtx::new(&Algorithm::xchacha20_poly1305(), key, TAG_LEN)
        .expect("a 32-byte XChaCha20-Poly1305 key");
    let (text, tag) = ciphertext.split_at(out.len());
    out.copy_from_slice(text);
    if ctx.open_in_place_mut(nonce, out, tag, aad).is_ok() {
        true
    } else {
        wipe(out);
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn arr(s: &str) -> [u8; 32] {
        unhex(s).try_into().unwrap()
    }

    /// RFC 7693, appendix B.
    #[test]
    fn blake2s_rfc7693() {
        assert_eq!(
            hash(&[b"abc"]).to_vec(),
            unhex("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982")
        );
    }

    /// Keyed BLAKE2s with a 16-byte digest, the MAC of mac1, mac2 and
    /// cookies. The digest length is in the parameter block, so this is not
    /// a truncation of the 32-byte hash: the value is Python's
    /// `hashlib.blake2s(b"", key=bytes(range(32)), digest_size=16)`.
    #[test]
    fn keyed_blake2s_16() {
        let key: Vec<u8> = (0u8..32).collect();
        assert_eq!(
            mac(&key, &[b""]).to_vec(),
            unhex("9536f9b267655743dee97b8a670f9f53")
        );
    }

    /// The Noise initial chaining key and hash, as wireguard-go hardcodes
    /// them (device/noise-protocol.go, InitialChainKey and InitialHash).
    #[test]
    fn initial_chaining_key_and_hash() {
        let ck = hash(&[super::super::noise::CONSTRUCTION]);
        assert_eq!(
            ck,
            arr("60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36")
        );
        let h = hash(&[&ck, super::super::noise::IDENTIFIER]);
        assert_eq!(
            h,
            arr("2211b361081ac566691243db458ad5322d9c6c662293e8b70ee19c65ba079ef3")
        );
    }

    /// RFC 4231's first case with BLAKE2s-256, checked against Python's
    /// `hmac.new(b"\x0b" * 32, b"Hi There", hashlib.blake2s)`.
    #[test]
    fn hmac_blake2s() {
        let key = [0x0bu8; 32];
        assert_eq!(
            hmac(&key, &[b"Hi There"]).to_vec(),
            unhex("0a22725a2d3d42c8f0515617bf249fcd1aaec274c7e94a5058549a5691941426")
        );
    }

    /// RFC 7748, section 6.1.
    #[test]
    fn x25519_rfc7748() {
        let a = arr("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let a_pub = arr("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let b = arr("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let b_pub = arr("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let shared = arr("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(public_key(&a), a_pub);
        assert_eq!(public_key(&b), b_pub);
        assert_eq!(dh(&a, &b_pub), Some(shared));
        assert_eq!(dh(&b, &a_pub), Some(shared));
        // The identity: a point of small order yields all zeros.
        assert_eq!(dh(&a, &[0u8; 32]), None);
    }

    /// RFC 8439, section 2.8.2.
    #[test]
    fn chacha20_poly1305_rfc8439() {
        let key = arr("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let aad = unhex("50515253c0c1c2c3c4c5c6c7");
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected_ct = unhex(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6
             3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36
             92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc
             3ff4def08e4b7a9de576d26586cec64b6116",
        );
        let expected_tag = unhex("1ae10b594f09e26a7e902ecbd0600691");
        // The RFC's nonce is 07000000 4041424344454647: not WireGuard's
        // layout, so drive the context directly.
        let mut ctx = AeadCtx::new(&Algorithm::chacha20_poly1305(), &key, TAG_LEN).unwrap();
        let nonce = unhex("070000004041424344454647");
        let mut buf = pt.to_vec();
        let mut tag = [0u8; TAG_LEN];
        ctx.seal_in_place_mut(&nonce, &mut buf, &mut tag, &aad)
            .unwrap();
        assert_eq!(buf, expected_ct);
        assert_eq!(tag.to_vec(), expected_tag);
    }

    /// WireGuard's nonce layout, round trip, and the counter in the nonce.
    #[test]
    fn aead_counter_nonce() {
        let key = [7u8; 32];
        let mut out = [0u8; 5 + TAG_LEN];
        aead_seal(&key, 42, b"hello", b"ad", &mut out);
        let mut pt = [0u8; 5];
        assert!(aead_open(&key, 42, &out, b"ad", &mut pt));
        assert_eq!(&pt, b"hello");
        assert!(!aead_open(&key, 43, &out, b"ad", &mut pt));
        assert!(!aead_open(&key, 42, &out, b"AD", &mut pt));
    }

    /// draft-irtf-cfrg-xchacha-03, appendix A.3.1.
    #[test]
    fn xchacha20_poly1305_draft() {
        let key = arr("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce: [u8; 24] = unhex("404142434445464748494a4b4c4d4e4f5051525354555657")
            .try_into()
            .unwrap();
        let aad = unhex("50515253c0c1c2c3c4c5c6c7");
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected = unhex(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb
             731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452
             2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9
             21f9664c97637da9768812f615c68b13b52e
             c0875924c1c7987947deafd8780acf49",
        );
        let mut out = vec![0u8; pt.len() + TAG_LEN];
        xaead_seal(&key, &nonce, pt, &aad, &mut out);
        assert_eq!(out, expected);
        let mut back = vec![0u8; pt.len()];
        assert!(xaead_open(&key, &nonce, &out, &aad, &mut back));
        assert_eq!(back, pt);
    }
}
