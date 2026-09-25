use anyhow::{anyhow, Result};

pub trait Cipher<N>: Sync + Send + Unpin
where
    N: NonceSequence,
{
    type Enc;
    type Dec;

    fn encryptor(&self, key: &[u8], nonce: N) -> Result<Self::Enc>;
    fn decryptor(&self, key: &[u8], nonce: N) -> Result<Self::Dec>;
}

pub trait SizedCipher {
    fn key_len(&self) -> usize;
    fn nonce_len(&self) -> usize;

    fn tag_len(&self) -> usize {
        // All AEAD ciphers we support use 128-bit tags.
        16
    }
}

pub trait Encryptor: Sync + Send + Unpin {
    fn encrypt<InOut>(&mut self, in_out: &mut InOut) -> Result<()>
    where
        InOut: AsRef<[u8]> + AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>;
}

pub trait Decryptor: Sync + Send + Unpin {
    fn decrypt<InOut>(&mut self, in_out: &mut InOut) -> Result<()>
    where
        InOut: AsRef<[u8]> + AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>;
}

pub trait NonceSequence: Sync + Send + Unpin {
    fn advance(&mut self) -> Result<Vec<u8>>;
}

#[cfg(feature = "aead")]
pub mod aead {
    use btls::aead::{AeadCtx, Algorithm};

    use super::*;

    /// The tag every supported cipher appends.
    const TAG_LEN: usize = 16;

    fn algorithm(cipher: &str) -> Option<Algorithm> {
        match cipher {
            "chacha20-poly1305" | "chacha20-ietf-poly1305" => Some(Algorithm::chacha20_poly1305()),
            "aes-256-gcm" => Some(Algorithm::aes_256_gcm()),
            "aes-128-gcm" => Some(Algorithm::aes_128_gcm()),
            _ => None,
        }
    }

    pub struct AeadCipher {
        algorithm: Algorithm,
    }

    impl AeadCipher {
        pub fn new(cipher: &str) -> Result<Self> {
            let algorithm =
                algorithm(cipher).ok_or_else(|| anyhow!("unsupported cipher: {}", cipher))?;
            Ok(AeadCipher { algorithm })
        }

        fn ctx(&self, key: &[u8]) -> Result<AeadCtx> {
            if key.len() != self.algorithm.key_length() {
                return Err(anyhow!("new aead key failed: wrong key length"));
            }
            AeadCtx::new(&self.algorithm, key, TAG_LEN)
                .map_err(|e| anyhow!("new aead key failed: {}", e))
        }
    }

    impl<N> Cipher<N> for AeadCipher
    where
        N: 'static + NonceSequence,
    {
        type Enc = AeadEncryptor<N>;
        type Dec = AeadDecryptor<N>;

        fn encryptor(&self, key: &[u8], nonce: N) -> Result<Self::Enc> {
            Ok(AeadEncryptor {
                ctx: self.ctx(key)?,
                nonce,
            })
        }

        fn decryptor(&self, key: &[u8], nonce: N) -> Result<Self::Dec> {
            Ok(AeadDecryptor {
                ctx: self.ctx(key)?,
                nonce,
            })
        }
    }

    impl SizedCipher for AeadCipher {
        fn key_len(&self) -> usize {
            self.algorithm.key_length()
        }

        fn nonce_len(&self) -> usize {
            self.algorithm.nonce_len()
        }
    }

    pub struct AeadEncryptor<N> {
        ctx: AeadCtx,
        nonce: N,
    }

    impl<N> Encryptor for AeadEncryptor<N>
    where
        N: NonceSequence,
    {
        /// Encrypts in place and appends the tag.
        fn encrypt<InOut>(&mut self, in_out: &mut InOut) -> Result<()>
        where
            InOut: AsRef<[u8]> + AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
        {
            let nonce = self
                .nonce
                .advance()
                .map_err(|e| anyhow!("encrypt failed: {}", e))?;
            let mut tag = [0u8; TAG_LEN];
            let tag_len = self
                .ctx
                .seal_in_place_mut(&nonce, in_out.as_mut(), &mut tag, &[])
                .map_err(|e| anyhow!("encrypt failed: {}", e))?
                .len();
            in_out.extend(&tag[..tag_len]);
            Ok(())
        }
    }

    pub struct AeadDecryptor<N> {
        ctx: AeadCtx,
        nonce: N,
    }

    impl<N> Decryptor for AeadDecryptor<N>
    where
        N: NonceSequence,
    {
        /// Decrypts ciphertext followed by its tag in place. The plaintext is
        /// the part before the tag; the caller drops the rest.
        fn decrypt<InOut>(&mut self, in_out: &mut InOut) -> Result<()>
        where
            InOut: AsRef<[u8]> + AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
        {
            let nonce = self
                .nonce
                .advance()
                .map_err(|e| anyhow!("decrypt failed: {}", e))?;
            let buf = in_out.as_mut();
            if buf.len() < TAG_LEN {
                return Err(anyhow!("decrypt failed: shorter than the tag"));
            }
            let (ciphertext, tag) = buf.split_at_mut(buf.len() - TAG_LEN);
            self.ctx
                .open_in_place_mut(&nonce, ciphertext, tag, &[])
                .map_err(|e| anyhow!("decrypt failed: {}", e))?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "aead")]
    fn test_aead_enc_dec() {
        struct ShadowsocksNonceSequence(Vec<u8>);

        impl ShadowsocksNonceSequence {
            fn new(size: usize) -> Self {
                let mut c = Vec::new();
                for _ in 0..size {
                    c.push(0xff);
                }
                ShadowsocksNonceSequence(c)
            }

            fn inc(&mut self) {
                for x in &mut self.0 {
                    *x = (*x).wrapping_add(1);
                    if *x != 0 {
                        return;
                    }
                }
            }
        }

        impl NonceSequence for ShadowsocksNonceSequence {
            fn advance(&mut self) -> Result<Vec<u8>> {
                self.inc();
                Ok(self.0.clone())
            }
        }
        let plaintext = b"Hello, world!";
        let cipher = aead::AeadCipher::new("chacha20-poly1305").unwrap();
        let key = vec![0u8; cipher.key_len()];

        let mut buf = Vec::new();
        buf.extend_from_slice(plaintext);

        let nonce = ShadowsocksNonceSequence::new(cipher.nonce_len());
        let mut enc = cipher.encryptor(&key, nonce).unwrap();
        enc.encrypt(&mut buf).unwrap();

        let dec_nonce = ShadowsocksNonceSequence::new(cipher.nonce_len());
        let mut dec = cipher.decryptor(&key, dec_nonce).unwrap();
        dec.decrypt(&mut buf).unwrap();

        assert_eq!(&buf[..plaintext.len()], plaintext);
    }

    /// A fixed nonce sequence: the same nonce every time.
    #[cfg(feature = "aead")]
    struct FixedNonce(Vec<u8>);

    #[cfg(feature = "aead")]
    impl NonceSequence for FixedNonce {
        fn advance(&mut self) -> Result<Vec<u8>> {
            Ok(self.0.clone())
        }
    }

    // BoringSSL and RustCrypto agree on every cipher: same ciphertext and
    // tag, and each opens the other's.
    #[test]
    #[cfg(feature = "aead")]
    fn test_aead_matches_rustcrypto() {
        use aes_gcm::aead::{Aead, KeyInit};
        let key: Vec<u8> = (0..32).collect();
        let nonce: Vec<u8> = (0..12).collect();
        let plaintext = b"leaf aead known answer".to_vec();

        let reference = |cipher: &str, key: &[u8]| -> Vec<u8> {
            let n = aes_gcm::Nonce::from_slice(&nonce);
            match cipher {
                "aes-128-gcm" => aes_gcm::Aes128Gcm::new_from_slice(key)
                    .unwrap()
                    .encrypt(n, &plaintext[..]),
                "aes-256-gcm" => aes_gcm::Aes256Gcm::new_from_slice(key)
                    .unwrap()
                    .encrypt(n, &plaintext[..]),
                _ => chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)
                    .unwrap()
                    .encrypt(chacha20poly1305::Nonce::from_slice(&nonce), &plaintext[..]),
            }
            .unwrap()
        };

        for name in [
            "aes-128-gcm",
            "aes-256-gcm",
            "chacha20-poly1305",
            "chacha20-ietf-poly1305",
        ] {
            let cipher = aead::AeadCipher::new(name).unwrap();
            let key = &key[..cipher.key_len()];
            let expected = reference(name, key);

            let mut buf = plaintext.clone();
            let mut enc = cipher.encryptor(key, FixedNonce(nonce.clone())).unwrap();
            enc.encrypt(&mut buf).unwrap();
            assert_eq!(buf, expected, "{} seal", name);

            let mut dec = cipher.decryptor(key, FixedNonce(nonce.clone())).unwrap();
            dec.decrypt(&mut buf).unwrap();
            assert_eq!(&buf[..plaintext.len()], &plaintext[..], "{} open", name);

            // A flipped bit fails authentication.
            let mut bad = expected.clone();
            bad[0] ^= 1;
            let mut dec = cipher.decryptor(key, FixedNonce(nonce.clone())).unwrap();
            assert!(dec.decrypt(&mut bad).is_err(), "{} tamper", name);
        }
        assert!(aead::AeadCipher::new("rc4-md5").is_err());
    }
}
