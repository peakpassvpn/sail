//! TLS client settings over BoringSSL, shared by the TLS outbound, DoH and
//! health checks.

use std::fs;
use std::io;
use std::sync::OnceLock;

use anyhow::{anyhow, Result};
use btls::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
use btls::x509::store::{X509Store, X509StoreBuilder};
use btls::x509::X509;
use tokio::io::{AsyncRead, AsyncWrite};

use super::conn::BoringConnection;
use super::fingerprint::Fingerprint;
use crate::transport::tls_stream::TlsStream;
use crate::transport::vision::VisionState;

pub struct TlsClient {
    connector: SslConnector,
    insecure: bool,
    fingerprint: Option<Fingerprint>,
    alpn: Vec<String>,
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
    ) -> Result<Self> {
        let mut builder = SslConnector::bare_builder(SslMethod::tls())?;
        builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        if let Some(fingerprint) = fingerprint {
            fingerprint.configure(&mut builder)?;
        }
        let alpn: Vec<String> = match fingerprint {
            Some(fingerprint) if alpn.is_empty() => fingerprint
                .default_alpn()
                .iter()
                .map(|p| p.to_string())
                .collect(),
            _ => alpn.to_vec(),
        };
        if insecure {
            builder.set_verify(SslVerifyMode::NONE);
        } else {
            builder.set_verify(SslVerifyMode::PEER);
            match certificate {
                Some(certificate) => builder.set_cert_store(trust_store(certificate)?),
                None => builder.set_cert_store_ref(bundled_roots()?),
            }
        }
        if !alpn.is_empty() {
            builder.set_alpn_protos(&alpn_wire(&alpn)?)?;
        }
        Ok(Self {
            connector: builder.build(),
            insecure,
            fingerprint,
            alpn,
        })
    }

    /// A connection to `server_name`, a domain (sent as SNI) or an IP address,
    /// offering ECH with `ech_config_list` when given.
    pub fn connection(
        &self,
        server_name: &str,
        ech_config_list: Option<&[u8]>,
    ) -> io::Result<BoringConnection> {
        let mut config = self.connector.configure().map_err(io::Error::other)?;
        if self.insecure {
            config.set_verify_hostname(false);
        }
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
fn bundled_roots() -> Result<&'static X509Store> {
    static ROOTS: OnceLock<std::result::Result<X509Store, String>> = OnceLock::new();
    ROOTS
        .get_or_init(|| {
            let mut store = X509StoreBuilder::new().map_err(|e| e.to_string())?;
            for der in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
                let cert = X509::from_der(der).map_err(|e| e.to_string())?;
                store.add_cert(cert).map_err(|e| e.to_string())?;
            }
            Ok(store.build())
        })
        .as_ref()
        .map_err(|e| anyhow!("load root certificates failed: {}", e))
}

fn trust_store(certificate: &str) -> Result<X509Store> {
    let mut store = X509StoreBuilder::new()?;
    for cert in load_certificates(certificate)? {
        store.add_cert(cert)?;
    }
    Ok(store.build())
}

/// Certificates from inline PEM, or from a PEM file.
pub(super) fn load_certificates(certificate: &str) -> Result<Vec<X509>> {
    let certs = if certificate.contains("-----BEGIN") {
        X509::stack_from_pem(certificate.as_bytes())
    } else {
        let pem = fs::read(certificate)
            .map_err(|e| anyhow!("load certificates from {} failed: {}", certificate, e))?;
        X509::stack_from_pem(&pem)
    }
    .map_err(|e| anyhow!("invalid certificate: {}", e))?;
    if certs.is_empty() {
        return Err(anyhow!("no certificate found"));
    }
    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alpn_wire() {
        let alpn = vec!["h2".to_string(), "http/1.1".to_string()];
        assert_eq!(alpn_wire(&alpn).unwrap(), b"\x02h2\x08http/1.1");
        assert!(alpn_wire(&["".to_string()]).is_err());
    }

    #[test]
    fn test_bundled_roots_load() {
        assert!(bundled_roots().is_ok());
    }

    #[test]
    fn test_client_hello_is_ready() {
        use crate::transport::tls_stream::TlsConnection;
        let client = TlsClient::new(&[], None, false, None).unwrap();
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
