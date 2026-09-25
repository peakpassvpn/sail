//! Browser ClientHello fingerprints: BoringSSL set up to send the same
//! ClientHello a browser sends, so the outer TLS layer looks like the browser.
//!
//! Each profile names the browser version and capture it matches; its test
//! compares against that capture in `tests/fixtures/tls/`.

use std::io::{self, Read, Write};

use anyhow::{anyhow, Result};
use btls::ssl::{
    CertificateCompressionAlgorithm, CertificateCompressor, ExtensionType, KeyShare,
    SslConnectorBuilder, SslOptions, SslRef, SslSignatureAlgorithm, SslVersion,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fingerprint {
    /// Chrome 153 on macOS; Edge sends the same ClientHello.
    Chrome,
    /// Firefox 156 on macOS.
    Firefox,
    /// Safari 26.3 on macOS, the same ClientHello as the system's
    /// URLSession.
    Safari,
}

impl Fingerprint {
    /// The fingerprint a config names: `chrome` (or `edge`, the same),
    /// `firefox` or `safari`.
    pub fn from_name(name: &str) -> Result<Self> {
        match name {
            "chrome" | "edge" => Ok(Self::Chrome),
            "firefox" => Ok(Self::Firefox),
            "safari" => Ok(Self::Safari),
            _ => Err(anyhow!(
                "unsupported fingerprint \"{}\", supported: chrome, edge, firefox, safari",
                name
            )),
        }
    }

    /// ALPN a browser offers when the config sets none.
    pub(crate) fn default_alpn(self) -> &'static [&'static str] {
        &["h2", "http/1.1"]
    }

    /// Settings shared by every connection of a client.
    pub(crate) fn configure(self, builder: &mut SslConnectorBuilder) -> Result<()> {
        builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        match self {
            Self::Chrome => chrome::configure(builder),
            Self::Firefox => firefox::configure(builder),
            Self::Safari => safari::configure(builder),
        }
    }

    /// Settings made per connection. `ech` says whether the connection offers
    /// real ECH; otherwise it sends ECH GREASE, as the browser does.
    pub(crate) fn configure_connection(
        self,
        ssl: &mut SslRef,
        alpn: &[String],
        ech: bool,
    ) -> Result<()> {
        match self {
            Self::Chrome => chrome::configure_connection(ssl, alpn, ech),
            Self::Firefox => firefox::configure_connection(ssl, ech),
            Self::Safari => safari::configure_connection(ssl),
        }
    }
}

mod chrome {
    use super::*;

    // TLS 1.2 suites, in Chrome's order; the three TLS 1.3 suites come first.
    const CIPHERS: &str = "ECDHE-ECDSA-AES128-GCM-SHA256:\
        ECDHE-RSA-AES128-GCM-SHA256:\
        ECDHE-ECDSA-AES256-GCM-SHA384:\
        ECDHE-RSA-AES256-GCM-SHA384:\
        ECDHE-ECDSA-CHACHA20-POLY1305:\
        ECDHE-RSA-CHACHA20-POLY1305:\
        ECDHE-RSA-AES128-SHA:\
        ECDHE-RSA-AES256-SHA:\
        AES128-GCM-SHA256:\
        AES256-GCM-SHA384:\
        AES128-SHA:\
        AES256-SHA";

    const CURVES: &str = "X25519MLKEM768:X25519:P-256:P-384";

    const SIGALGS: &[SslSignatureAlgorithm] = &[
        SslSignatureAlgorithm::ML_DSA_44,
        SslSignatureAlgorithm::ML_DSA_65,
        SslSignatureAlgorithm::ML_DSA_87,
        SslSignatureAlgorithm::ECDSA_SECP256R1_SHA256,
        SslSignatureAlgorithm::RSA_PSS_RSAE_SHA256,
        SslSignatureAlgorithm::RSA_PKCS1_SHA256,
        SslSignatureAlgorithm::ECDSA_SECP384R1_SHA384,
        SslSignatureAlgorithm::RSA_PSS_RSAE_SHA384,
        SslSignatureAlgorithm::RSA_PKCS1_SHA384,
        SslSignatureAlgorithm::RSA_PSS_RSAE_SHA512,
        SslSignatureAlgorithm::RSA_PKCS1_SHA512,
    ];

    /// The Chrome Root Store trust anchor IDs Chrome 153 requests
    /// (draft-ietf-tls-trust-anchor-ids), without the outer length.
    const TRUST_ANCHORS: &[u8] = b"\
        \x05\x82\xdf\x13\x02\x12\x08\x83\x9a\x64\x8c\x9b\x2d\x01\x0a\x08\
        \x83\x9a\x64\x8c\x9b\x2d\x01\x0d\x04\xd6\x79\x09\x05\x04\xd6\x79\
        \x09\x08\x08\x83\x9a\x64\x8c\x9b\x2d\x01\x12\x05\x82\xdf\x13\x02\
        \x06\x05\x82\xdf\x13\x02\x13\x05\x82\xdf\x13\x02\x01\x08\x83\x9a\
        \x64\x8c\x9b\x2d\x01\x13\x04\xd6\x79\x09\x0b\x04\xd6\x79\x09\x0d\
        \x04\xd6\x79\x09\x0a\x05\x82\xdf\x13\x02\x14\x05\x82\xdf\x13\x02\
        \x0e\x08\x83\x9a\x64\x8c\x9b\x2d\x01\x08\x05\x82\xdf\x13\x02\x0f\
        \x04\xd6\x79\x09\x06\x08\x83\x9a\x64\x8c\x9b\x2d\x01\x07\x05\x82\
        \xdf\x13\x02\x0d\x04\xd6\x79\x09\x07\x04\xd6\x79\x09\x0f\x04\xd6\
        \x79\x09\x01\x04\xd6\x79\x09\x04\x08\x83\x9a\x64\x8c\x9b\x2d\x01\
        \x0c\x08\x83\x9a\x64\x8c\x9b\x2d\x01\x09\x08\x83\x9a\x64\x8c\x9b\
        \x2d\x01\x0b\x04\xd6\x79\x09\x0c";

    pub(super) fn configure(builder: &mut SslConnectorBuilder) -> Result<()> {
        builder.set_cipher_list(CIPHERS)?;
        builder.set_curves_list(CURVES)?;
        builder.set_verify_algorithm_prefs(SIGALGS)?;
        builder.set_grease_enabled(true);
        builder.set_grease_sigalgs_enabled(true);
        builder.set_permute_extensions(true);
        builder.enable_ocsp_stapling();
        builder.enable_signed_cert_timestamps();
        builder.add_certificate_compression_algorithm(Brotli)?;
        builder.set_requested_trust_anchors(TRUST_ANCHORS)?;
        Ok(())
    }

    pub(crate) fn configure_connection(ssl: &mut SslRef, alpn: &[String], ech: bool) -> Result<()> {
        ssl.set_client_key_shares(&[KeyShare::X25519_MLKEM768, KeyShare::X25519])?;
        if alpn.iter().any(|p| p == "h2") {
            ssl.add_application_settings(b"h2")?;
            ssl.set_alps_use_new_codepoint(true);
        }
        if !ech {
            ssl.set_enable_ech_grease(true);
        }
        Ok(())
    }
}

mod firefox {
    use super::*;

    // TLS 1.3 suites in Firefox's order (ChaCha20 before AES-256), then TLS 1.2.
    const CIPHERS: &str = "TLS_AES_128_GCM_SHA256:\
        TLS_CHACHA20_POLY1305_SHA256:\
        TLS_AES_256_GCM_SHA384:\
        ECDHE-ECDSA-AES128-GCM-SHA256:\
        ECDHE-RSA-AES128-GCM-SHA256:\
        ECDHE-ECDSA-CHACHA20-POLY1305:\
        ECDHE-RSA-CHACHA20-POLY1305:\
        ECDHE-ECDSA-AES256-GCM-SHA384:\
        ECDHE-RSA-AES256-GCM-SHA384:\
        ECDHE-RSA-AES128-SHA:\
        ECDHE-RSA-AES256-SHA:\
        AES128-GCM-SHA256:\
        AES256-GCM-SHA384:\
        AES128-SHA:\
        AES256-SHA";

    const CURVES: &str = "X25519MLKEM768:X25519:P-256:P-384:P-521";

    const SIGALGS: &[SslSignatureAlgorithm] = &[
        SslSignatureAlgorithm::ECDSA_SECP256R1_SHA256,
        SslSignatureAlgorithm::ECDSA_SECP384R1_SHA384,
        SslSignatureAlgorithm::ECDSA_SECP521R1_SHA512,
        SslSignatureAlgorithm::RSA_PSS_RSAE_SHA256,
        SslSignatureAlgorithm::RSA_PSS_RSAE_SHA384,
        SslSignatureAlgorithm::RSA_PSS_RSAE_SHA512,
        SslSignatureAlgorithm::RSA_PKCS1_SHA256,
        SslSignatureAlgorithm::RSA_PKCS1_SHA384,
        SslSignatureAlgorithm::RSA_PKCS1_SHA512,
        SslSignatureAlgorithm::ECDSA_SHA1,
        SslSignatureAlgorithm::RSA_PKCS1_SHA1,
    ];

    const DELEGATED_CREDENTIALS: &str = "ecdsa_secp256r1_sha256:\
        ecdsa_secp384r1_sha384:\
        ecdsa_secp521r1_sha512:\
        ecdsa_sha1";

    // Firefox keeps one order; no GREASE, no permutation.
    const EXTENSIONS: &[ExtensionType] = &[
        ExtensionType::SERVER_NAME,
        ExtensionType::EXTENDED_MASTER_SECRET,
        ExtensionType::RENEGOTIATE,
        ExtensionType::SUPPORTED_GROUPS,
        ExtensionType::EC_POINT_FORMATS,
        ExtensionType::SESSION_TICKET,
        ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
        ExtensionType::STATUS_REQUEST,
        ExtensionType::DELEGATED_CREDENTIAL,
        ExtensionType::CERTIFICATE_TIMESTAMP,
        ExtensionType::KEY_SHARE,
        ExtensionType::SUPPORTED_VERSIONS,
        ExtensionType::SIGNATURE_ALGORITHMS,
        ExtensionType::PSK_KEY_EXCHANGE_MODES,
        ExtensionType::RECORD_SIZE_LIMIT,
        ExtensionType::CERT_COMPRESSION,
        ExtensionType::ENCRYPTED_CLIENT_HELLO,
    ];

    pub(super) fn configure(builder: &mut SslConnectorBuilder) -> Result<()> {
        builder.set_preserve_tls13_cipher_list(true);
        builder.set_cipher_list(CIPHERS)?;
        builder.set_curves_list(CURVES)?;
        builder.set_verify_algorithm_prefs(SIGALGS)?;
        builder.set_delegated_credentials(DELEGATED_CREDENTIALS)?;
        builder.set_record_size_limit(0x4001);
        builder.set_extension_permutation(EXTENSIONS)?;
        builder.enable_ocsp_stapling();
        builder.enable_signed_cert_timestamps();
        builder.add_certificate_compression_algorithm(Zlib)?;
        builder.add_certificate_compression_algorithm(Brotli)?;
        builder.add_certificate_compression_algorithm(Zstd)?;
        Ok(())
    }

    pub(super) fn configure_connection(ssl: &mut SslRef, ech: bool) -> Result<()> {
        ssl.set_client_key_shares(&[KeyShare::X25519_MLKEM768, KeyShare::X25519, KeyShare::P256])?;
        if !ech {
            ssl.set_enable_ech_grease(true);
            // Firefox's ECH GREASE is always ChaCha20-Poly1305 with a
            // 240-byte payload.
            set_ech_grease_shape(ssl, btls_sys::EVP_HPKE_CHACHA20_POLY1305 as u16, 240)?;
        }
        Ok(())
    }
}

mod safari {
    use super::*;

    // TLS 1.3 suites in Safari's order (AES-256 first), then TLS 1.2 down to
    // 3DES.
    const CIPHERS: &str = "TLS_AES_256_GCM_SHA384:\
        TLS_CHACHA20_POLY1305_SHA256:\
        TLS_AES_128_GCM_SHA256:\
        ECDHE-ECDSA-AES256-GCM-SHA384:\
        ECDHE-ECDSA-AES128-GCM-SHA256:\
        ECDHE-ECDSA-CHACHA20-POLY1305:\
        ECDHE-RSA-AES256-GCM-SHA384:\
        ECDHE-RSA-AES128-GCM-SHA256:\
        ECDHE-RSA-CHACHA20-POLY1305:\
        ECDHE-ECDSA-AES256-SHA:\
        ECDHE-ECDSA-AES128-SHA:\
        ECDHE-RSA-AES256-SHA:\
        ECDHE-RSA-AES128-SHA:\
        AES256-GCM-SHA384:\
        AES128-GCM-SHA256:\
        AES256-SHA:\
        AES128-SHA:\
        ECDHE-ECDSA-DES-CBC3-SHA:\
        ECDHE-RSA-DES-CBC3-SHA:\
        DES-CBC3-SHA";

    const CURVES: &str = "X25519MLKEM768:X25519:P-256:P-384:P-521";

    // rsa_pss_rsae_sha384 twice: Safari lists it twice.
    const SIGALGS: &[SslSignatureAlgorithm] = &[
        SslSignatureAlgorithm::ECDSA_SECP256R1_SHA256,
        SslSignatureAlgorithm::RSA_PSS_RSAE_SHA256,
        SslSignatureAlgorithm::RSA_PKCS1_SHA256,
        SslSignatureAlgorithm::ECDSA_SECP384R1_SHA384,
        SslSignatureAlgorithm::RSA_PSS_RSAE_SHA384,
        SslSignatureAlgorithm::RSA_PSS_RSAE_SHA384,
        SslSignatureAlgorithm::RSA_PKCS1_SHA384,
        SslSignatureAlgorithm::RSA_PSS_RSAE_SHA512,
        SslSignatureAlgorithm::RSA_PKCS1_SHA512,
        SslSignatureAlgorithm::RSA_PKCS1_SHA1,
    ];

    // Safari keeps one order, between a GREASE extension at each end.
    const EXTENSIONS: &[ExtensionType] = &[
        ExtensionType::SERVER_NAME,
        ExtensionType::EXTENDED_MASTER_SECRET,
        ExtensionType::RENEGOTIATE,
        ExtensionType::SUPPORTED_GROUPS,
        ExtensionType::EC_POINT_FORMATS,
        ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
        ExtensionType::STATUS_REQUEST,
        ExtensionType::SIGNATURE_ALGORITHMS,
        ExtensionType::CERTIFICATE_TIMESTAMP,
        ExtensionType::KEY_SHARE,
        ExtensionType::PSK_KEY_EXCHANGE_MODES,
        ExtensionType::SUPPORTED_VERSIONS,
        ExtensionType::CERT_COMPRESSION,
    ];

    pub(super) fn configure(builder: &mut SslConnectorBuilder) -> Result<()> {
        builder.set_preserve_tls13_cipher_list(true);
        builder.set_cipher_list(CIPHERS)?;
        builder.set_curves_list(CURVES)?;
        builder.set_verify_algorithm_prefs(SIGALGS)?;
        builder.set_grease_enabled(true);
        builder.set_extension_permutation(EXTENSIONS)?;
        builder.set_options(SslOptions::NO_TICKET);
        builder.enable_ocsp_stapling();
        builder.enable_signed_cert_timestamps();
        builder.add_certificate_compression_algorithm(Zlib)?;
        Ok(())
    }

    pub(super) fn configure_connection(ssl: &mut SslRef) -> Result<()> {
        ssl.set_client_key_shares(&[KeyShare::X25519_MLKEM768, KeyShare::X25519])?;
        Ok(())
    }
}

fn set_ech_grease_shape(ssl: &mut SslRef, aead_id: u16, payload_len: usize) -> Result<()> {
    use foreign_types::ForeignTypeRef;
    // SAFETY: `ssl` is a valid SSL.
    if unsafe { btls_sys::SSL_set_ech_grease_shape(ssl.as_ptr(), aead_id, payload_len) } != 1 {
        return Err(anyhow!("set ech grease shape failed"));
    }
    Ok(())
}

/// Copies `reader` to `output`.
fn drain(mut reader: impl Read, output: &mut impl Write) -> io::Result<()> {
    let mut buf = [0u8; 4096];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        output.write_all(&buf[..n])?;
    }
}

/// Zlib certificate decompression, which Firefox and Safari offer.
struct Zlib;

impl CertificateCompressor for Zlib {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::ZLIB;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        let data = miniz_oxide::inflate::decompress_to_vec_zlib(input)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{:?}", e)))?;
        output.write_all(&data)
    }
}

/// Zstandard certificate decompression, which Firefox offers.
struct Zstd;

impl CertificateCompressor for Zstd {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::ZSTD;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        let decoder = ruzstd::decoding::StreamingDecoder::new(input)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        drain(decoder, output)
    }
}

/// Brotli certificate decompression, which Chrome and Firefox offer.
struct Brotli;

impl CertificateCompressor for Brotli {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        drain(brotli_decompressor::Decompressor::new(input, 4096), output)
    }
}
