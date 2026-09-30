//! TLS client settings over BoringSSL, shared by the TLS outbound, DoH and
//! health checks.

use std::fs;
use std::io;
use std::sync::OnceLock;

use anyhow::{anyhow, Result};
use btls::pkey::{PKey, Private};
use btls::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
use btls::x509::store::{X509Store, X509StoreBuilder};
use btls::x509::X509;
use tokio::io::{AsyncRead, AsyncWrite};

use super::conn::BoringConnection;
use super::fingerprint::Fingerprint;
use super::options::ClientOptions;
use crate::transport::tls_stream::TlsStream;
use crate::transport::vision::VisionState;

pub struct TlsClient {
    connector: SslConnector,
    insecure: bool,
    fingerprint: Option<Fingerprint>,
    alpn: Vec<String>,
    /// Whether the ClientHello names the server.
    sni: bool,
}

/// A certificate, its chain after it, and its key: what a client presents
/// to a server that asks for one.
pub struct Identity {
    chain: Vec<X509>,
    key: PKey<Private>,
}

impl Identity {
    /// `chain`, the certificate first, with its `key`, which must match it.
    pub fn new(chain: Vec<X509>, key: PKey<Private>) -> Result<Self> {
        let cert = chain
            .first()
            .ok_or_else(|| anyhow!("no certificate found"))?;
        let public = cert.public_key()?;
        if !public.public_eq(&key) {
            return Err(anyhow!("the key is not the certificate's"));
        }
        Ok(Self { chain, key })
    }

    /// The certificate, then its chain.
    pub fn chain(&self) -> &[X509] {
        &self.chain
    }

    pub fn key(&self) -> &PKey<Private> {
        &self.key
    }
}

impl TlsClient {
    /// `certificate`, inline PEM or a path, replaces the bundled roots as the
    /// certificates to trust. `insecure` trusts any certificate. With a
    /// `fingerprint` the ClientHello is the browser's, and an empty `alpn` is
    /// the browser's default.
    pub fn new(
        alpn: &[String],
        certificate: Option<&str>,
        insecure: bool,
        fingerprint: Option<Fingerprint>,
        roots: &super::roots::Roots,
    ) -> Result<Self> {
        Self::with_identity(alpn, certificate, insecure, fingerprint, roots, None)
    }

    /// `new`, presenting `identity` to a server that asks for a
    /// certificate.
    pub fn with_identity(
        alpn: &[String],
        certificate: Option<&str>,
        insecure: bool,
        fingerprint: Option<Fingerprint>,
        roots: &super::roots::Roots,
        identity: Option<&Identity>,
    ) -> Result<Self> {
        Self::with_options(
            alpn,
            certificate,
            insecure,
            fingerprint,
            roots,
            identity,
            &ClientOptions::default(),
        )
    }

    /// `with_identity`, with the versions and pins of `options`. A range
    /// set there replaces the fingerprint's, the ClientHello then differing
    /// from the browser's: whether it should is the caller's to settle, as
    /// `OutboundTls::stream_options` does. Pins replace the certificates
    /// trusted and `insecure`.
    pub fn with_options(
        alpn: &[String],
        certificate: Option<&str>,
        insecure: bool,
        fingerprint: Option<Fingerprint>,
        roots: &super::roots::Roots,
        identity: Option<&Identity>,
        options: &ClientOptions,
    ) -> Result<Self> {
        let mut builder = SslConnector::bare_builder(SslMethod::tls())?;
        builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        if let Some(fingerprint) = fingerprint {
            fingerprint.configure(&mut builder)?;
        }
        options.versions.apply(&mut builder)?;
        let alpn: Vec<String> = match fingerprint {
            Some(fingerprint) if alpn.is_empty() => fingerprint
                .default_alpn()
                .iter()
                .map(|p| p.to_string())
                .collect(),
            _ => alpn.to_vec(),
        };
        if let Some(pins) = &options.pins {
            pins.apply(&mut builder);
        } else if insecure {
            builder.set_verify(SslVerifyMode::NONE);
        } else {
            builder.set_verify(SslVerifyMode::PEER);
            match certificate {
                Some(certificate) => builder.set_cert_store(trust_store(certificate)?),
                None => builder.set_cert_store_ref(roots.store()),
            }
        }
        if !alpn.is_empty() {
            builder.set_alpn_protos(&alpn_wire(&alpn)?)?;
        }
        if let Some(identity) = identity {
            let mut chain = identity.chain.iter();
            if let Some(cert) = chain.next() {
                builder.set_certificate(cert)?;
            }
            for cert in chain {
                builder.add_extra_chain_cert(cert.clone())?;
            }
            builder.set_private_key(&identity.key)?;
            builder.check_private_key()?;
        }
        Ok(Self {
            connector: builder.build(),
            insecure,
            fingerprint,
            alpn,
            sni: true,
        })
    }

    /// Leaves SNI out of the ClientHello. The server's certificate is
    /// verified against the server name all the same.
    pub fn without_sni(mut self) -> Self {
        self.sni = false;
        self
    }

    /// A connection to `server_name`, a domain (sent as SNI, unless
    /// `without_sni`) or an IP address, offering ECH with `ech_config_list` when given.
    pub fn connection(
        &self,
        server_name: &str,
        ech_config_list: Option<&[u8]>,
    ) -> io::Result<BoringConnection> {
        self.connection_with(server_name, ech_config_list, |_| Ok(()))
    }

    /// `connection`, with `configure` run on the SSL before the ClientHello
    /// is made: for a protocol that hooks into it, as ShadowTLS does.
    pub(crate) fn connection_with(
        &self,
        server_name: &str,
        ech_config_list: Option<&[u8]>,
        configure: impl FnOnce(&mut btls::ssl::SslRef) -> io::Result<()>,
    ) -> io::Result<BoringConnection> {
        let mut config = self.connector.configure().map_err(io::Error::other)?;
        if self.insecure {
            config.set_verify_hostname(false);
        }
        config.set_use_server_name_indication(self.sni);
        let mut ssl = config.into_ssl(server_name).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid tls server name {}: {}", server_name, e),
            )
        })?;
        if let Some(list) = ech_config_list {
            ssl.set_ech_config_list(list).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid ech config list: {}", e),
                )
            })?;
        }
        if let Some(fingerprint) = self.fingerprint {
            fingerprint
                .configure_connection(&mut ssl, &self.alpn, ech_config_list.is_some())
                .map_err(io::Error::other)?;
        }
        configure(&mut ssl)?;
        BoringConnection::client(ssl)
    }

    /// Runs the handshake with `server_name` over `stream`.
    pub async fn connect<S>(
        &self,
        server_name: &str,
        stream: S,
        vision: Option<VisionState>,
        ech_config_list: Option<&[u8]>,
    ) -> io::Result<TlsStream<BoringConnection, S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let conn = self.connection(server_name, ech_config_list)?;
        let mut stream = TlsStream::new(conn, stream, vision);
        stream.handshake().await?;
        Ok(stream)
    }
}

/// ALPN protocols as the wire lists them: each prefixed with its length.
pub(crate) fn alpn_wire(alpn: &[String]) -> Result<Vec<u8>> {
    let mut wire = Vec::new();
    for proto in alpn {
        let len = u8::try_from(proto.len())
            .ok()
            .filter(|&n| n > 0)
            .ok_or_else(|| anyhow!("invalid alpn protocol {:?}", proto))?;
        wire.push(len);
        wire.extend_from_slice(proto.as_bytes());
    }
    Ok(wire)
}

/// Mozilla's root certificates, parsed once.
pub(crate) fn bundled_root_certs() -> Result<&'static [X509]> {
    static CERTS: OnceLock<std::result::Result<Vec<X509>, String>> = OnceLock::new();
    CERTS
        .get_or_init(|| {
            webpki_root_certs::TLS_SERVER_ROOT_CERTS
                .iter()
                .map(|der| X509::from_der(der).map_err(|e| e.to_string()))
                .collect()
        })
        .as_deref()
        .map_err(|e| anyhow!("load root certificates failed: {}", e))
}

fn trust_store(certificate: &str) -> Result<X509Store> {
    let mut store = X509StoreBuilder::new()?;
    for cert in load_certificates(certificate)? {
        store.add_cert(cert)?;
    }
    Ok(store.build())
}

/// Certificates from inline PEM, or from a PEM or DER file.
pub(crate) fn load_certificates(certificate: &str) -> Result<Vec<X509>> {
    let certs = if certificate.contains("-----BEGIN") {
        X509::stack_from_pem(certificate.as_bytes())
    } else {
        let data = fs::read(certificate)
            .map_err(|e| anyhow!("load certificates from {} failed: {}", certificate, e))?;
        if data.starts_with(b"-----BEGIN") || data.windows(10).any(|w| w == b"-----BEGIN") {
            X509::stack_from_pem(&data)
        } else {
            X509::from_der(&data).map(|cert| vec![cert])
        }
    }
    .map_err(|e| anyhow!("invalid certificate: {}", e))?;
    if certs.is_empty() {
        return Err(anyhow!("no certificate found"));
    }
    Ok(certs)
}

/// A private key (PKCS#8, PKCS#1 or SEC1) from inline PEM, or from a PEM or
/// DER (PKCS#8) file.
pub(crate) fn load_private_key(key: &str) -> Result<PKey<Private>> {
    if key.contains("-----BEGIN") {
        return PKey::private_key_from_pem(key.as_bytes())
            .map_err(|e| anyhow!("invalid private key: {}", e));
    }
    let data = fs::read(key).map_err(|e| anyhow!("load key from {} failed: {}", key, e))?;
    if data.windows(10).any(|w| w == b"-----BEGIN") {
        PKey::private_key_from_pem(&data)
    } else {
        PKey::private_key_from_der(&data)
    }
    .map_err(|e| anyhow!("invalid private key: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::tls::tests::test_roots;

    #[test]
    fn test_alpn_wire() {
        let alpn = vec!["h2".to_string(), "http/1.1".to_string()];
        assert_eq!(alpn_wire(&alpn).unwrap(), b"\x02h2\x08http/1.1");
        assert!(alpn_wire(&["".to_string()]).is_err());
    }

    #[test]
    fn test_bundled_roots_load() {}

    #[test]
    fn test_client_hello_is_ready() {
        use crate::transport::tls_stream::TlsConnection;
        let client = TlsClient::new(&[], None, false, None, &test_roots()).unwrap();
        let mut conn = client.connection("example.com", None).unwrap();
        assert!(conn.is_handshaking());
        assert!(conn.wants_write());
        let mut out = vec![];
        assert!(conn.write_tls(&mut out).unwrap() > 0);
        // A handshake record carrying a ClientHello.
        assert_eq!(out[0], 0x16);
        assert_eq!(out[5], 0x01);
        assert!(!conn.wants_write());
    }
}
