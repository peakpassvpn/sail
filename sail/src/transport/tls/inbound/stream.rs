use anyhow::{anyhow, Result};
use async_trait::async_trait;
use btls::ssl::{Ssl, SslAcceptor, SslMethod, SslVersion};

use super::super::client::{load_certificates, load_private_key};
use super::super::conn::BoringConnection;
use crate::{
    adapter::*,
    session::Session,
    transport::{tls_stream::TlsStream, vision::VisionState},
};

pub struct Handler {
    acceptor: SslAcceptor,
}

impl Handler {
    /// `certificate` (the chain, leaf first) and `certificate_key` are inline
    /// PEM or paths.
    pub fn new(certificate: String, certificate_key: String) -> Result<Self> {
        let certs = load_certificates(&certificate)?;
        let key = load_private_key(&certificate_key)?;
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
        builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        let mut certs = certs.into_iter();
        builder.set_certificate(&certs.next().expect("load_certificates returns one or more"))?;
        for cert in certs {
            builder.add_extra_chain_cert(cert)?;
        }
        builder.set_private_key(&key)?;
        builder
            .check_private_key()
            .map_err(|e| anyhow!("private key does not match the certificate: {}", e))?;
        Ok(Self {
            acceptor: builder.build(),
        })
    }
}

#[async_trait]
impl InboundStreamHandler for Handler {
    async fn handle<'a>(
        &'a self,
        sess: Session,
        stream: AnyStream,
    ) -> std::io::Result<AnyInboundTransport> {
        tracing::trace!("handling inbound stream");
        let ssl = Ssl::new(self.acceptor.context()).map_err(std::io::Error::other)?;
        // VLESS with XTLS Vision may hand the connection over to direct copy.
        let vision = VisionState::of(&sess);
        let mut stream = TlsStream::new(BoringConnection::server(ssl)?, stream, Some(vision));
        stream.handshake().await?;
        Ok(InboundTransport::Stream(Box::new(stream), sess))
    }
}

#[cfg(test)]
mod tests {
    use super::Handler;

    #[test]
    fn test_new_with_generated_certificate() {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        assert!(Handler::new(cert.pem(), key_pair.serialize_pem()).is_ok());
    }

    #[test]
    fn test_new_with_mismatched_key_fails() {
        let a = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let b = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        assert!(Handler::new(a.cert.pem(), b.key_pair.serialize_pem()).is_err());
    }
}
