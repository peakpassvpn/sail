//! What a client's `tls` block sets beyond the certificate to trust: the
//! TLS versions it may negotiate (`min_version`, `max_version`) and the
//! public keys it pins (`certificate_public_key_sha256`), as sing-box reads
//! them, and the whole certificates it pins (`certificate_sha256`), as
//! Mihomo's `fingerprint` does. Every client over BoringSSL applies them alike: the TLS outbound,
//! ShadowTLS, the QUIC outbounds and the DNS servers over TLS and QUIC.

use std::fmt;
use std::sync::{Arc, OnceLock};

use anyhow::{anyhow, Result};
use btls::error::ErrorStack;
use btls::ex_data::Index;
use btls::ssl::{
    Ssl, SslAlert, SslContextBuilder, SslRef, SslVerifyError, SslVerifyMode, SslVersion,
};
use btls::stack::Stack;
use btls::x509::store::X509StoreBuilder;
use btls::x509::verify::{X509VerifyFlags, X509VerifyParamRef};
use btls::x509::{X509StoreContext, X509VerifyResult, X509};

/// A TLS version a `tls` block names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Version {
    Tls10,
    Tls11,
    Tls12,
    Tls13,
}

impl Version {
    /// `1.0` to `1.3`, as sing-box names them.
    pub fn from_name(name: &str) -> Result<Self> {
        match name {
            "1.0" => Ok(Self::Tls10),
            "1.1" => Ok(Self::Tls11),
            "1.2" => Ok(Self::Tls12),
            "1.3" => Ok(Self::Tls13),
            _ => Err(anyhow!(
                "unknown TLS version \"{}\", one of 1.0, 1.1, 1.2, 1.3",
                name
            )),
        }
    }

    pub(crate) fn ssl(self) -> SslVersion {
        match self {
            Self::Tls10 => SslVersion::TLS1,
            Self::Tls11 => SslVersion::TLS1_1,
            Self::Tls12 => SslVersion::TLS1_2,
            Self::Tls13 => SslVersion::TLS1_3,
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Tls10 => "1.0",
            Self::Tls11 => "1.1",
            Self::Tls12 => "1.2",
            Self::Tls13 => "1.3",
        })
    }
}

/// The TLS versions a client or server may negotiate. Either end unset is
/// the default: TLS 1.2 to TLS 1.3, as in sing-box.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TlsVersionRange {
    pub min: Option<Version>,
    pub max: Option<Version>,
}

impl TlsVersionRange {
    pub const DEFAULT_MIN: Version = Version::Tls12;
    pub const DEFAULT_MAX: Version = Version::Tls13;

    /// From `min_version` and `max_version`; empty is unset, as in
    /// sing-box. Errors name the field. A range with nothing in it is an
    /// error here, where sing-box fails every handshake.
    pub fn parse(min: Option<&str>, max: Option<&str>) -> Result<Self> {
        let parse = |field: &str, value: Option<&str>| {
            value
                .filter(|v| !v.is_empty())
                .map(Version::from_name)
                .transpose()
                .map_err(|e| anyhow!("{}: {}", field, e))
        };
        let range = Self {
            min: parse("min_version", min)?,
            max: parse("max_version", max)?,
        };
        if range.lowest() > range.highest() {
            return Err(anyhow!(
                "min_version: {} is above max_version {}",
                range.lowest(),
                range.highest()
            ));
        }
        Ok(range)
    }

    /// Whether either end is set.
    pub fn is_set(&self) -> bool {
        self.min.is_some() || self.max.is_some()
    }

    pub fn lowest(&self) -> Version {
        self.min.unwrap_or(Self::DEFAULT_MIN)
    }

    pub fn highest(&self) -> Version {
        self.max.unwrap_or(Self::DEFAULT_MAX)
    }

    /// Whether TLS 1.3, all that QUIC, ECH and REALITY speak, is in it.
    pub fn has_tls13(&self) -> bool {
        self.highest() == Version::Tls13
    }

    /// Whether it is `lowest` to `highest`, whichever ends are set.
    pub fn is(&self, lowest: Version, highest: Version) -> bool {
        self.lowest() == lowest && self.highest() == highest
    }

    /// Sets the ends that are set on `builder`; the others keep what the
    /// builder has.
    pub fn apply(&self, builder: &mut SslContextBuilder) -> Result<()> {
        if let Some(min) = self.min {
            builder.set_min_proto_version(Some(min.ssl()))?;
        }
        if let Some(max) = self.max {
            builder.set_max_proto_version(Some(max.ssl()))?;
        }
        Ok(())
    }

    /// Refuses a range without TLS 1.3, for a handshake that is TLS 1.3
    /// only, such as QUIC's; `what` names it.
    pub fn require_tls13(&self, what: &str) -> Result<()> {
        if self.has_tls13() {
            return Ok(());
        }
        Err(anyhow!(
            "max_version: {} is TLS 1.3 only, and {} leaves it out",
            what,
            self.highest()
        ))
    }
}

/// The SHA-256 hashes of the public keys a client accepts from a server:
/// with them, the server's certificate is taken if the public key of its
/// first certificate (its SubjectPublicKeyInfo, DER) hashes to one of them,
/// and on nothing else. No CA is consulted and no name is checked, even
/// with `insecure`, as in sing-box.
#[derive(Clone)]
pub struct PublicKeyPins(Arc<[[u8; 32]]>);

impl fmt::Debug for PublicKeyPins {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(|h| btls::base64::encode_block(h)))
            .finish()
    }
}

impl PublicKeyPins {
    /// From `certificate_public_key_sha256`: each a SHA-256 hash in
    /// standard, padded base64, as `openssl dgst -sha256 -binary | openssl
    /// enc -base64` writes it. None when there are none. Errors name the
    /// field and the entry; a hash of any other length is an error here,
    /// where sing-box would match no key.
    pub fn parse(hashes: &[String]) -> Result<Option<Self>> {
        const FIELD: &str = "certificate_public_key_sha256";
        let mut pins = Vec::with_capacity(hashes.len());
        for (i, hash) in hashes.iter().enumerate() {
            let invalid = |why: &str| anyhow!("{}[{}]: {}", FIELD, i, why);
            if hash.is_empty() || hash.len() % 4 != 0 || hash.trim() != hash {
                return Err(invalid("not base64 (standard, padded) of a SHA-256 hash"));
            }
            let bytes = btls::base64::decode_block(hash)
                .map_err(|_| invalid("not base64 (standard, padded) of a SHA-256 hash"))?;
            let pin: [u8; 32] = bytes.try_into().map_err(|b: Vec<u8>| {
                anyhow!(
                    "{}[{}]: {} bytes, where a SHA-256 hash has 32",
                    FIELD,
                    i,
                    b.len()
                )
            })?;
            pins.push(pin);
        }
        Ok((!pins.is_empty()).then(|| Self(pins.into())))
    }

    /// The pin of a public key: the SHA-256 of its SubjectPublicKeyInfo.
    pub fn hash(spki_der: &[u8]) -> [u8; 32] {
        btls::sha::sha256(spki_der)
    }

    /// Whether `spki_der`, a SubjectPublicKeyInfo, is one of the pinned
    /// keys; if not, why, with the key's hash as the field would take it.
    pub fn check(&self, spki_der: &[u8]) -> std::result::Result<(), String> {
        let hash = Self::hash(spki_der);
        if self.0.contains(&hash) {
            return Ok(());
        }
        Err(format!(
            "certificate_public_key_sha256: the server's public key, {}, is not pinned",
            btls::base64::encode_block(&hash)
        ))
    }

    /// `check`, of the first certificate the server of `ssl` sent.
    pub fn check_peer(&self, ssl: &SslRef) -> std::result::Result<(), String> {
        let cert = ssl
            .peer_certificate()
            .ok_or("certificate_public_key_sha256: the server sent no certificate")?;
        let spki = cert
            .public_key()
            .and_then(|key| key.public_key_to_der())
            .map_err(|e| format!("certificate_public_key_sha256: the server's key: {}", e))?;
        self.check(&spki)
    }
}

/// The SHA-256 hashes of whole certificates (their DER) a client takes a
/// server by, a sail extension with Mihomo's `fingerprint` semantics. The
/// certificates the server sends are looked through in order, leaf first,
/// for one that hashes to a pin:
///
/// - the leaf: the server is taken, with no CA consulted, no name checked
///   and no validity period either. A leaf pin trusts that exact
///   certificate for any server name;
/// - a certificate after it, an intermediate or a root: the leaf is
///   verified with that certificate as the only trust anchor, the ones
///   between them as intermediates, and against the server name, as a CA
///   would be;
/// - none: the handshake fails.
///
/// The certificates trusted and `insecure` play no part.
#[derive(Clone)]
pub struct CertificatePins(Arc<[[u8; 32]]>);

impl fmt::Debug for CertificatePins {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(|h| hex(h)))
            .finish()
    }
}

impl CertificatePins {
    const FIELD: &'static str = "certificate_sha256";

    /// From `certificate_sha256`: each a SHA-256 hash in hex, either case,
    /// colons between the digits or not, as `openssl x509 -noout
    /// -fingerprint -sha256` writes it. None when there are none. Errors
    /// name the field and the entry.
    pub fn parse(hashes: &[String]) -> Result<Option<Self>> {
        let mut pins = Vec::with_capacity(hashes.len());
        for (i, hash) in hashes.iter().enumerate() {
            let digits: Vec<u8> = hash.bytes().filter(|&b| b != b':').collect();
            let invalid = || anyhow!("{}[{}]: not the hex of a SHA-256 hash", Self::FIELD, i);
            if !digits.len().is_multiple_of(2) {
                return Err(invalid());
            }
            let bytes = digits
                .chunks(2)
                .map(|pair| {
                    let digit = |d: u8| (d as char).to_digit(16);
                    Some((digit(pair[0])? * 16 + digit(pair[1])?) as u8)
                })
                .collect::<Option<Vec<u8>>>()
                .ok_or_else(invalid)?;
            let pin: [u8; 32] = bytes.try_into().map_err(|b: Vec<u8>| {
                anyhow!(
                    "{}[{}]: {} bytes, where a SHA-256 hash has 32",
                    Self::FIELD,
                    i,
                    b.len()
                )
            })?;
            pins.push(pin);
        }
        Ok((!pins.is_empty()).then(|| Self(pins.into())))
    }

    /// The pin of a certificate: the SHA-256 of its DER.
    pub fn hash(cert_der: &[u8]) -> [u8; 32] {
        btls::sha::sha256(cert_der)
    }

    /// Takes the server of `ssl` or not, by the certificates it sent and
    /// the name `ssl` verifies; if not, why, with the leaf's hash as the
    /// field would take it.
    pub fn check_peer(&self, ssl: &mut SslRef) -> std::result::Result<(), String> {
        let field = Self::FIELD;
        let chain: Vec<X509> = ssl
            .peer_cert_chain()
            .map(|chain| chain.iter().map(|c| c.to_owned()).collect())
            .unwrap_or_default();
        let Some(leaf) = chain.first() else {
            return Err(format!("{}: the server sent no certificate", field));
        };
        let mut leaf_hash = None;
        for (i, cert) in chain.iter().enumerate() {
            let der = cert
                .to_der()
                .map_err(|e| format!("{}: the server's certificate: {}", field, e))?;
            let hash = Self::hash(&der);
            leaf_hash.get_or_insert(hash);
            if !self.0.contains(&hash) {
                continue;
            }
            if i == 0 {
                return Ok(());
            }
            return verify_by(cert, leaf, &chain[1..i], ssl.verify_param_mut()).map_err(|e| {
                format!(
                    "{}: the server's certificate, {}, is not verified by the pinned {}: {}",
                    field,
                    hex(leaf_hash.as_ref().expect("the leaf's")),
                    hex(&hash),
                    e
                )
            });
        }
        Err(format!(
            "{}: the server's certificate, {}, is not pinned, nor is any sent with it",
            field,
            hex(leaf_hash.as_ref().expect("the leaf's"))
        ))
    }
}

/// Verifies `leaf` with `anchor` as the only certificate trusted and
/// `intermediates` in between, as BoringSSL verifies a server's: for TLS
/// servers, by `param`, which holds the name to verify.
fn verify_by(
    anchor: &X509,
    leaf: &X509,
    intermediates: &[X509],
    param: &X509VerifyParamRef,
) -> std::result::Result<(), String> {
    use foreign_types::ForeignTypeRef;
    let run = || -> std::result::Result<X509VerifyResult, ErrorStack> {
        let mut store = X509StoreBuilder::new()?;
        store.add_cert(anchor)?;
        let store = store.build();
        let mut stack = Stack::new()?;
        for cert in intermediates {
            stack.push(cert.clone())?;
        }
        let mut context = X509StoreContext::new()?;
        context.init(&store, leaf, &stack, |context| {
            // As BoringSSL verifies a server's chain itself: its purpose
            // and trust, then the connection's parameters.
            // SAFETY: the context is initialised, and the name a C string.
            if unsafe {
                btls_sys::X509_STORE_CTX_set_default(context.as_ptr(), c"ssl_server".as_ptr())
            } != 1
            {
                return Err(ErrorStack::get());
            }
            context.verify_param_mut().copy_from(param)?;
            // The anchor may be an intermediate, not self-signed.
            context
                .verify_param_mut()
                .set_flags(X509VerifyFlags::PARTIAL_CHAIN);
            context.verify_cert()?;
            Ok(context.verify_result())
        })
    };
    match run() {
        Ok(result) => result.map_err(|e| e.to_string()),
        Err(e) => Err(e.to_string()),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// How a client takes a server's certificate in place of the certificates
/// trusted and of `insecure`: by its public key, as sing-box does, or by
/// the whole certificate, as Mihomo does.
#[derive(Clone, Debug)]
pub enum Pins {
    PublicKeys(PublicKeyPins),
    Certificates(CertificatePins),
}

impl Pins {
    /// Verifies servers by the pins, in place of the certificates trusted
    /// and of `insecure`: BoringSSL runs no verification of its own
    /// beside it. A server the pins do not take fails the handshake, with
    /// a bad_certificate alert, and [`pin_failure`] says why.
    pub fn apply(&self, builder: &mut SslContextBuilder) {
        let pins = self.clone();
        builder.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
            super::guarded(
                || Err(SslVerifyError::Invalid(SslAlert::INTERNAL_ERROR)),
                || {
                    let checked = match &pins {
                        Self::PublicKeys(pins) => pins.check_peer(ssl),
                        Self::Certificates(pins) => pins.check_peer(ssl),
                    };
                    checked.map_err(|why| {
                        tracing::warn!("tls: {}", why);
                        ssl.set_ex_data(failure_index(), why);
                        SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE)
                    })
                },
            )
        });
    }

    /// `apply`, to a QUIC client configuration.
    #[cfg(feature = "quic")]
    pub fn apply_quic(&self, crypto: &mut quinn_btls::ClientConfig) {
        use foreign_types::ForeignType;
        let ctx = crypto.ctx_mut().as_ptr();
        // SAFETY: the builder takes a reference of its own to the context,
        // given back when it drops. The context is not in use yet: nothing
        // configures it at the same time.
        unsafe {
            btls_sys::SSL_CTX_up_ref(ctx);
            let mut builder = SslContextBuilder::from_ptr(ctx);
            self.apply(&mut builder);
        }
    }
}

/// Why the pins refused the server of `ssl`, once they have.
pub fn pin_failure(ssl: &SslRef) -> Option<&str> {
    ssl.ex_data(failure_index()).map(String::as_str)
}

fn failure_index() -> Index<Ssl, String> {
    static INDEX: OnceLock<Index<Ssl, String>> = OnceLock::new();
    *INDEX.get_or_init(|| Ssl::new_ex_index().expect("allocate an SSL ex_data index"))
}

/// The versions and the pins of a client's `tls` block, as a TLS client
/// takes them.
#[derive(Clone, Debug, Default)]
pub struct ClientOptions {
    pub versions: TlsVersionRange,
    pub pins: Option<Pins>,
}

impl ClientOptions {
    /// Sets both on `builder`: the versions after whatever else set them,
    /// the pins in place of the certificate verification.
    pub fn apply(&self, builder: &mut SslContextBuilder) -> Result<()> {
        self.versions.apply(builder)?;
        if let Some(pins) = &self.pins {
            pins.apply(builder);
        }
        Ok(())
    }

    /// Sets both on a QUIC client configuration: a range without TLS 1.3
    /// is refused, QUIC being TLS 1.3 only.
    #[cfg(feature = "quic")]
    pub fn apply_quic(&self, crypto: &mut quinn_btls::ClientConfig) -> Result<()> {
        self.versions.require_tls13("QUIC")?;
        if let Some(pins) = &self.pins {
            pins.apply_quic(crypto);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_range() {
        let range = TlsVersionRange::parse(None, None).unwrap();
        assert!(!range.is_set());
        assert!(range.is(Version::Tls12, Version::Tls13));
        let range = TlsVersionRange::parse(Some(""), Some("")).unwrap();
        assert!(!range.is_set());
        let range = TlsVersionRange::parse(Some("1.0"), Some("1.2")).unwrap();
        assert_eq!(range.min, Some(Version::Tls10));
        assert!(!range.has_tls13());
        assert!(TlsVersionRange::parse(Some("1.3"), None)
            .unwrap()
            .has_tls13());

        let err = TlsVersionRange::parse(Some("1.4"), None).unwrap_err();
        assert!(
            err.to_string().starts_with("min_version: unknown"),
            "{}",
            err
        );
        let err = TlsVersionRange::parse(None, Some("TLS1.2")).unwrap_err();
        assert!(
            err.to_string().starts_with("max_version: unknown"),
            "{}",
            err
        );
        // Above the default maximum, or the maximum set.
        let err = TlsVersionRange::parse(Some("1.3"), Some("1.2")).unwrap_err();
        assert!(err.to_string().contains("above max_version 1.2"), "{}", err);
        assert!(TlsVersionRange::parse(None, Some("1.1")).is_err());
        let err = TlsVersionRange::parse(None, Some("1.2"))
            .unwrap()
            .require_tls13("QUIC")
            .unwrap_err();
        assert!(err.to_string().starts_with("max_version: QUIC"), "{}", err);
    }

    #[test]
    fn test_pins_parse() {
        let hash = btls::base64::encode_block(&[7; 32]);
        let pins = PublicKeyPins::parse(std::slice::from_ref(&hash))
            .unwrap()
            .unwrap();
        assert!(pins.check(b"key").is_err());
        assert!(PublicKeyPins::parse(&[]).unwrap().is_none());

        let spki = b"a SubjectPublicKeyInfo";
        let pinned = btls::base64::encode_block(&PublicKeyPins::hash(spki));
        let pins = PublicKeyPins::parse(&[hash, pinned]).unwrap().unwrap();
        assert!(pins.check(spki).is_ok());
        let err = pins.check(b"another").unwrap_err();
        assert!(err.contains("is not pinned"), "{}", err);

        for (bad, why) in [
            ("", "not base64"),
            ("!!!!", "not base64"),
            // Unpadded, or base64url.
            ("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", "not base64"),
            ("__8=", "not base64"),
            // A SHA-1 hash, 20 bytes.
            ("AAAAAAAAAAAAAAAAAAAAAAAAAAA=", "20 bytes"),
            // The hex a Clash `fingerprint` is.
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "48 bytes",
            ),
        ] {
            let ok = btls::base64::encode_block(&[0; 32]);
            let err = PublicKeyPins::parse(&[ok, bad.to_string()]).unwrap_err();
            let err = err.to_string();
            assert!(
                err.starts_with("certificate_public_key_sha256[1]: ") && err.contains(why),
                "{:?}: {}",
                bad,
                err
            );
        }
    }
}
