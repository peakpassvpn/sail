//! Browser ClientHello fingerprints: BoringSSL set up to send the same
//! ClientHello a browser sends, so the outer TLS layer looks like the browser.
//!
//! Each profile names the browser version and capture it matches; its test
//! compares against that capture in `tests/fixtures/tls/`.

use std::io::{self, Read, Write};

use anyhow::{anyhow, Result};
use btls::ssl::{
    CertificateCompressionAlgorithm, CertificateCompressor, KeyShare, SslConnectorBuilder, SslRef,
    SslSignatureAlgorithm, SslVersion,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fingerprint {
    /// Chrome 153 on macOS; Edge sends the same ClientHello.
    Chrome,
}

impl Fingerprint {
    /// The fingerprint a config names: `chrome`, or `edge` for the same.
    pub fn from_name(name: &str) -> Result<Self> {
        match name {
            "chrome" | "edge" => Ok(Self::Chrome),
            _ => Err(anyhow!(
                "unsupported fingerprint \"{}\", supported: chrome, edge",
                name
            )),
        }
    }

    /// ALPN a browser offers when the config sets none.
    pub(crate) fn default_alpn(self) -> &'static [&'static str] {
        match self {
            Self::Chrome => &["h2", "http/1.1"],
        }
    }

    /// Settings shared by every connection of a client.
    pub(crate) fn configure(self, builder: &mut SslConnectorBuilder) -> Result<()> {
        match self {
            Self::Chrome => chrome::configure(builder),
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
        builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
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

/// Brotli certificate decompression, which Chrome offers.
struct Brotli;

impl CertificateCompressor for Brotli {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        let mut reader = brotli_decompressor::Decompressor::new(input, 4096);
        let mut buf = [0u8; 4096];
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                return Ok(());
            }
            output.write_all(&buf[..n])?;
        }
    }
}
