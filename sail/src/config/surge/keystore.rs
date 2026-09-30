//! `[Keystore]`: certificates and keys by name, read when a policy names
//! one. A `p12` item is a TLS policy's `client-cert`; an
//! `openssh-private-key` one is an SSH policy's, which sail does not
//! implement, and an item no policy names is never read.

use std::collections::HashMap;

use anyhow::{anyhow, Result};

use super::text::{self, Line};

/// The items, by name, as lines yet.
#[derive(Default)]
pub struct Keystore {
    items: HashMap<String, Line>,
}

/// A client certificate as sail's `tls` block takes it: the certificate
/// and its chain, and the key, PEM.
pub struct ClientCert {
    pub certificate: String,
    pub key: String,
}

impl Keystore {
    /// The items of the section's `lines`; a later item of a name
    /// replaces the earlier one.
    pub fn new(lines: Vec<Line>) -> Self {
        let mut items = HashMap::new();
        for line in lines {
            if let Some((name, _)) = text::key_value(&line.text) {
                items.insert(text::unquote(&name), line);
            }
        }
        Keystore { items }
    }

    /// The client certificate of the `p12` item `name`, which the
    /// parameter at `at` names.
    pub fn client_cert(&self, name: &str, at: &str) -> Result<ClientCert> {
        let line = self
            .items
            .get(name)
            .ok_or_else(|| anyhow!("{}: no [Keystore] item is named {:?}", at, name))?;
        let item = format!("{}: [Keystore] {}: {}", at, line.loc, name);
        let (_, value) = text::key_value(&line.text).unwrap_or_default();
        let (mut kind, mut base64, mut password) = (None, None, None);
        for part in text::split(&value, false) {
            match text::param(&part) {
                Some((key, value, _)) if key == "type" => kind = Some(value.to_ascii_lowercase()),
                Some((key, value, _)) if key == "base64" => base64 = Some(value),
                Some((key, value, _)) if key == "password" => password = Some(value),
                // Nothing else is an item's.
                _ => {}
            }
        }
        // Untyped, an item with a password is a PKCS#12 one.
        let kind = kind.unwrap_or_else(|| {
            if password.is_some() {
                "p12".into()
            } else {
                "openssh-private-key".into()
            }
        });
        if kind != "p12" {
            return Err(anyhow!(
                "{}: a client certificate is a p12 item, not {}",
                item,
                kind
            ));
        }
        let base64 = base64
            .filter(|b| !b.is_empty())
            .ok_or_else(|| anyhow!("{}: base64: missing", item))?;
        p12(&base64, password.as_deref().unwrap_or_default())
            .map_err(|e| anyhow!("{}: {}", item, e))
    }
}

/// The certificate, its chain and its key in the PKCS#12 file `base64`
/// holds, opened with `password`. No error echoes either.
#[cfg(feature = "tls")]
fn p12(base64: &str, password: &str) -> Result<ClientCert> {
    use base64::Engine;
    use btls::pkcs12::Pkcs12;
    let compact: String = base64.split_whitespace().collect();
    let der = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(compact.trim_end_matches('='))
        .map_err(|_| anyhow!("base64: not base64"))?;
    let p12 = Pkcs12::from_der(&der).map_err(|_| anyhow!("base64: not a PKCS#12 file"))?;
    let parsed = p12.parse2(password).map_err(|e| {
        let wrong = e
            .errors()
            .iter()
            .any(|e| e.reason() == Some("INCORRECT_PASSWORD"));
        if wrong {
            anyhow!("password: does not open the PKCS#12 file")
        } else {
            anyhow!("base64: not a PKCS#12 file")
        }
    })?;
    let (Some(cert), Some(key)) = (parsed.cert.as_ref(), parsed.pkey.as_ref()) else {
        return Err(anyhow!(
            "the PKCS#12 file holds no certificate with its key"
        ));
    };
    let mut certificate = String::from_utf8(cert.to_pem()?)?;
    for ca in parsed.chain().into_iter().flatten() {
        certificate.push_str(&String::from_utf8(ca.to_pem()?)?);
    }
    let key = String::from_utf8(key.private_key_to_pem_pkcs8()?)?;
    Ok(ClientCert { certificate, key })
}

#[cfg(not(feature = "tls"))]
fn p12(_base64: &str, _password: &str) -> Result<ClientCert> {
    Err(anyhow!("sail is built without TLS"))
}
