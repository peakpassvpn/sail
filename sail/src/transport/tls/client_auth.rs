//! How an inbound checks the certificates its clients present: sing-box's
//! `client_authentication`, with the CAs (`client_certificate`,
//! `client_certificate_path`) or the pins (sing-box 1.15's
//! `client_certificate_sha256`, and `client_certificate_public_key_sha256`)
//! it verifies them by.
//!
//! The modes are sing-box's, which are Go's:
//!
//! | mode | no certificate | a certificate |
//! |---|---|---|
//! | `no` | taken | not asked for |
//! | `request` | taken | taken, unchecked |
//! | `require-any` | refused | taken, unchecked |
//! | `verify-if-given` | taken | checked |
//! | `require-and-verify` | refused | checked |
//!
//! CAs with no mode, or `no`, are `require-and-verify`, as in sing-box. A
//! certificate is checked by the CAs, as Go verifies it: chained to one of
//! them, by the intermediates the client sends, valid at the instance's
//! time and for client authentication; or by the pins, its whole DER or
//! its public key, the certificate pins looked at first and either list
//! passing, as in sing-box 1.15. Pins check the leaf alone: no CA, no
//! validity period.
//!
//! Where sing-box takes a configuration that leaves clients unchecked
//! while it looks as if it checks them, sail refuses it: pins with no mode
//! or `no`, which ask for no certificate, and CAs or pins with `request` or
//! `require-any`, which check none. What sing-box ignores beside a field it
//! prefers is ignored with a warning, its order kept: the inline CAs, then
//! the CA files, then the pins.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use btls::ssl::{SslAlert, SslContextBuilder, SslRef, SslVerifyError, SslVerifyMode};
use btls::x509::store::{X509Store, X509StoreBuilder};
use btls::x509::X509;

use super::client::load_certificates;
use super::options::{set_failure, verify_in, CertificatePins, Peer, PublicKeyPins, Purpose};

/// What a server asks of its clients' certificates, sing-box's
/// `client_authentication`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientAuthMode {
    No,
    Request,
    RequireAny,
    VerifyIfGiven,
    RequireAndVerify,
}

impl ClientAuthMode {
    const ALL: [Self; 5] = [
        Self::No,
        Self::Request,
        Self::RequireAny,
        Self::VerifyIfGiven,
        Self::RequireAndVerify,
    ];

    /// As sing-box names it.
    pub fn name(self) -> &'static str {
        match self {
            Self::No => "no",
            Self::Request => "request",
            Self::RequireAny => "require-any",
            Self::VerifyIfGiven => "verify-if-given",
            Self::RequireAndVerify => "require-and-verify",
        }
    }

    pub fn from_name(name: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|mode| mode.name() == name)
            .ok_or_else(|| {
                anyhow!(
                    "unknown value \"{}\", one of no, request, require-any, verify-if-given, \
                     require-and-verify",
                    name
                )
            })
    }

    /// Whether a certificate sent is checked.
    pub fn verifies(self) -> bool {
        matches!(self, Self::VerifyIfGiven | Self::RequireAndVerify)
    }

    /// Whether a client without a certificate is refused.
    pub fn requires(self) -> bool {
        matches!(self, Self::RequireAny | Self::RequireAndVerify)
    }
}

/// An inbound's fields that check clients' certificates, as configured:
/// the inline PEM's lines, the CA files (their paths resolved) and the
/// hashes. An empty list is unset, as is an empty mode.
#[derive(Clone, Copy, Debug, Default)]
pub struct ClientAuthFields<'a> {
    pub mode: Option<&'a str>,
    pub certificate: &'a [String],
    pub certificate_path: &'a [String],
    pub certificate_sha256: &'a [String],
    pub public_key_sha256: &'a [String],
}

/// How a TLS server takes its clients' certificates, made from an inbound's
/// [`ClientAuthFields`]; a server without it asks for none.
#[derive(Clone)]
pub struct ClientAuth {
    mode: ClientAuthMode,
    /// How a certificate is checked, in the modes that check one.
    check: Option<Check>,
    /// The sessions' context: a session is resumed only by a server that
    /// checks clients alike.
    context: [u8; 32],
}

impl std::fmt::Debug for ClientAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientAuth")
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
enum Check {
    /// By CAs, from `field`; the CAs are named to the client too.
    Cas {
        field: &'static str,
        store: Arc<X509Store>,
        cas: Arc<[X509]>,
    },
    /// By pins, the certificate pins looked at first.
    Pins {
        certificates: Option<CertificatePins>,
        keys: Option<PublicKeyPins>,
    },
}

impl ClientAuth {
    /// From `fields`: none when they ask for no certificate, and the
    /// warnings of fields ignored, as sing-box ignores them. Errors and
    /// warnings name the field, under `tls`.
    pub fn new(fields: &ClientAuthFields<'_>) -> Result<(Option<Self>, Vec<String>)> {
        let mode = fields
            .mode
            .filter(|m| !m.is_empty())
            .map(ClientAuthMode::from_name)
            .transpose()
            .map_err(|e| anyhow!("client_authentication: {}", e))?;
        // The pins are read whether or not they are used, as sing-box
        // decodes them.
        let certificates = CertificatePins::parse_field(
            Peer::CLIENT.certificate_field,
            fields.certificate_sha256,
        )?;
        let keys = PublicKeyPins::parse_field(Peer::CLIENT.key_field, fields.public_key_sha256)?;
        let cas_field = if !fields.certificate.is_empty() {
            Some("client_certificate")
        } else if !fields.certificate_path.is_empty() {
            Some("client_certificate_path")
        } else {
            None
        };
        let pins_field = match (&certificates, &keys) {
            (Some(_), Some(_)) => {
                Some("client_certificate_sha256 and client_certificate_public_key_sha256")
            }
            (Some(_), None) => Some("client_certificate_sha256"),
            (None, Some(_)) => Some("client_certificate_public_key_sha256"),
            (None, None) => None,
        };
        let mode = match mode.unwrap_or(ClientAuthMode::No) {
            ClientAuthMode::No if cas_field.is_some() => ClientAuthMode::RequireAndVerify,
            ClientAuthMode::No => {
                if let Some(field) = pins_field {
                    return Err(anyhow!(
                        "{}: without client_authentication, or with no, no client \
                         certificate is asked for, and none is checked; set it to \
                         verify-if-given or require-and-verify",
                        field
                    ));
                }
                return Ok((None, Vec::new()));
            }
            mode => mode,
        };
        if !mode.verifies() {
            if let Some(field) = cas_field.or(pins_field) {
                return Err(anyhow!(
                    "{}: client_authentication {} takes any client certificate and checks \
                     none; verify-if-given or require-and-verify check it",
                    field,
                    mode.name()
                ));
            }
            return Ok((Some(Self::of(mode, None)), Vec::new()));
        }
        let mut warnings = Vec::new();
        let check = match cas_field {
            Some(field) => {
                if field == "client_certificate" && !fields.certificate_path.is_empty() {
                    warnings.push(
                        "client_certificate_path: ignored beside client_certificate, as \
                         sing-box ignores it: clients are verified by the inline CAs alone"
                            .to_string(),
                    );
                }
                if let Some(pins) = pins_field {
                    warnings.push(format!(
                        "{}: ignored beside {}, as sing-box ignores it: clients are verified \
                         by the CAs alone",
                        pins, field
                    ));
                }
                let cas = if field == "client_certificate" {
                    X509::stack_from_pem(fields.certificate.join("\n").as_bytes())
                        .ok()
                        .filter(|cas| !cas.is_empty())
                        .ok_or_else(|| anyhow!("client_certificate: not PEM certificates"))?
                } else {
                    let mut cas = Vec::new();
                    for (i, path) in fields.certificate_path.iter().enumerate() {
                        cas.extend(
                            load_certificates(path)
                                .map_err(|e| anyhow!("client_certificate_path[{}]: {}", i, e))?,
                        );
                    }
                    cas
                };
                let mut store = X509StoreBuilder::new()?;
                for ca in &cas {
                    store
                        .add_cert(ca)
                        .map_err(|e| anyhow!("{}: {}", field, e))?;
                }
                Check::Cas {
                    field,
                    store: Arc::new(store.build()),
                    cas: cas.into(),
                }
            }
            None if pins_field.is_some() => Check::Pins { certificates, keys },
            None => {
                return Err(anyhow!(
                    "client_authentication: {} needs client_certificate, \
                     client_certificate_path, client_certificate_sha256 or \
                     client_certificate_public_key_sha256 to verify clients by",
                    mode.name()
                ))
            }
        };
        Ok((Some(Self::of(mode, Some(check))), warnings))
    }

    fn of(mode: ClientAuthMode, check: Option<Check>) -> Self {
        let mut context = btls::sha::Sha256::new();
        context.update(b"sail inbound client authentication\0");
        context.update(mode.name().as_bytes());
        match &check {
            None => {}
            Some(Check::Cas { cas, .. }) => {
                for ca in cas.iter() {
                    context.update(&btls::sha::sha256(&ca.to_der().unwrap_or_default()));
                }
            }
            Some(Check::Pins { certificates, keys }) => {
                context.update(format!("{:?} {:?}", certificates, keys).as_bytes());
            }
        }
        Self {
            mode,
            check,
            context: context.finish(),
        }
    }

    /// The mode, as taken: `require-and-verify` for CAs with none.
    pub fn mode(&self) -> ClientAuthMode {
        self.mode
    }

    /// Has the server of `builder` ask for clients' certificates and take
    /// them as the mode says, by its own verification: BoringSSL's, by the
    /// context's certificate store, plays no part, which over QUIC holds
    /// the system's roots. A client refused gets a bad_certificate alert,
    /// and the handshake's error says why.
    pub fn apply(&self, builder: &mut SslContextBuilder) -> Result<()> {
        builder.set_session_id_context(&self.context)?;
        let mut mode = SslVerifyMode::PEER;
        if self.mode.requires() {
            mode |= SslVerifyMode::FAIL_IF_NO_PEER_CERT;
        }
        let check = self.check.clone();
        let optional = !self.mode.requires();
        builder.set_custom_verify_callback(mode, move |ssl| {
            // `request` and `require-any` take any certificate.
            let Some(check) = &check else {
                return Ok(());
            };
            super::guarded(
                || Err(SslVerifyError::Invalid(SslAlert::INTERNAL_ERROR)),
                || {
                    let checked = check.verify(ssl, optional);
                    checked.map_err(|why| {
                        tracing::debug!("tls: {}", why);
                        set_failure(ssl, why);
                        SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE)
                    })
                },
            )
        });
        if let Some(Check::Cas { cas, .. }) = &self.check {
            for ca in cas.iter() {
                builder.add_client_ca(ca)?;
            }
        }
        Ok(())
    }

    /// `apply`, to a QUIC server configuration.
    #[cfg(feature = "quic")]
    pub fn apply_quic(&self, crypto: &mut quinn_btls::ServerConfig) -> Result<()> {
        super::configure_quic_server(crypto, |builder| self.apply(builder))
    }
}

impl Check {
    /// Takes the client of `ssl` or not, by the certificate it sent; one
    /// that sent none is taken if `optional`. If not, why.
    fn verify(&self, ssl: &mut SslRef, optional: bool) -> std::result::Result<(), String> {
        // BoringSSL asks only of a client that sent a certificate, but a
        // client without one is the mode's to take, as sing-box 1.15
        // takes it under verify-if-given.
        let Some(leaf) = ssl.peer_certificate() else {
            return match optional {
                true => Ok(()),
                false => Err("the client sent no certificate".to_string()),
            };
        };
        match self {
            Self::Cas { field, store, .. } => {
                // On a server, the chain the client sent leaves its leaf out.
                let intermediates: Vec<X509> = ssl
                    .peer_cert_chain()
                    .map(|chain| chain.iter().map(|c| c.to_owned()).collect())
                    .unwrap_or_default();
                verify_in(store, &leaf, &intermediates, Purpose::Client, None).map_err(|e| {
                    let hash = btls::sha::sha256(&leaf.to_der().unwrap_or_default());
                    format!(
                        "{}: the client's certificate (SHA-256 {}) is not verified by the \
                         CAs: {}",
                        field,
                        btls::base64::encode_block(&hash),
                        e
                    )
                })
            }
            Self::Pins { certificates, keys } => {
                let mut why = Vec::new();
                if let Some(pins) = certificates {
                    match pins.check_leaf(Peer::CLIENT, &leaf) {
                        Ok(()) => return Ok(()),
                        Err(e) => why.push(e),
                    }
                }
                if let Some(pins) = keys {
                    match pins.check_certificate(Peer::CLIENT, &leaf) {
                        Ok(()) => return Ok(()),
                        Err(e) => why.push(e),
                    }
                }
                Err(why.join("; "))
            }
        }
    }
}
