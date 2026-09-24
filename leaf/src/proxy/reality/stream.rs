use reality::{RealityConnectionState, X25519RealityGroup};
use reality_rustls::crypto::ring::default_provider;
use reality_rustls::pki_types::ServerName;
use reality_rustls::{ClientConfig, ClientConnection};
use std::sync::Arc;

use crate::common::tls_stream::ClientTlsStream;

#[derive(Debug)]
struct DebugVerifier(Arc<dyn reality_rustls::client::danger::ServerCertVerifier>);

impl reality_rustls::client::danger::ServerCertVerifier for DebugVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &reality_rustls::pki_types::CertificateDer<'_>,
        intermediates: &[reality_rustls::pki_types::CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: reality_rustls::pki_types::UnixTime,
    ) -> Result<reality_rustls::client::danger::ServerCertVerified, reality_rustls::Error> {
        self.0
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &reality_rustls::pki_types::CertificateDer<'_>,
        dss: &reality_rustls::DigitallySignedStruct,
    ) -> Result<reality_rustls::client::danger::HandshakeSignatureValid, reality_rustls::Error>
    {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &reality_rustls::pki_types::CertificateDer<'_>,
        dss: &reality_rustls::DigitallySignedStruct,
    ) -> Result<reality_rustls::client::danger::HandshakeSignatureValid, reality_rustls::Error>
    {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<reality_rustls::SignatureScheme> {
        self.0.supported_verify_schemes()
    }

    fn root_hint_subjects(&self) -> Option<&[reality_rustls::DistinguishedName]> {
        self.0.root_hint_subjects()
    }
}

pub fn create_reality_provider() -> Arc<reality_rustls::crypto::CryptoProvider> {
    let mut provider = default_provider();
    let mut new_kx_groups = vec![];
    for group in provider.kx_groups.iter() {
        if group.name() == reality_rustls::NamedGroup::X25519 {
            new_kx_groups
                .push(&X25519RealityGroup as &'static dyn reality_rustls::crypto::SupportedKxGroup);
        } else {
            new_kx_groups.push(*group);
        }
    }
    provider.kx_groups = new_kx_groups;
    Arc::new(provider)
}

pub fn build_rustls_config(
    provider_arc: Arc<reality_rustls::crypto::CryptoProvider>,
    fallback_verifier: Arc<dyn reality_rustls::client::danger::ServerCertVerifier>,
    server_public_key: [u8; 32],
    short_id: [u8; 8],
) -> Result<Arc<ClientConfig>, Box<dyn std::error::Error>> {
    let reality_state = Arc::new(RealityConnectionState::new(
        server_public_key,
        short_id,
        Arc::new(DebugVerifier(fallback_verifier)),
    ));

    let mut config = ClientConfig::builder_with_provider(provider_arc)
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(reality_state.clone())
        .with_no_client_auth();

    config.reality_callback = Some(reality_state);
    config.alpn_protocols = vec![b"h2".to_vec().into(), b"http/1.1".to_vec().into()];

    Ok(Arc::new(config))
}

/// A REALITY client stream: the generic client TLS stream over the REALITY
/// fork of rustls.
pub type RealityStream<S> = ClientTlsStream<ClientConnection, S>;
