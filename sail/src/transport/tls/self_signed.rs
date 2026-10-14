//! The certificate an inbound with `tls.self_signed` serves: made by the
//! instance itself, once, and kept across reloads while it is for the same
//! name. No CA vouches for it: a client takes it as `insecure`, or by a
//! pin or the certificate itself, which a new certificate changes.

use anyhow::Result;
use btls::asn1::{Asn1Integer, Asn1Time};
use btls::bn::{BigNum, MsbOption};
use btls::ec::{EcGroup, EcKey};
use btls::hash::MessageDigest;
use btls::nid::Nid;
use btls::pkey::PKey;
use btls::x509::extension::SubjectAlternativeName;
use btls::x509::{X509Builder, X509NameBuilder};
use std::sync::Arc;

/// The name a certificate is made for without `tls.server_name`: under
/// `.invalid` (RFC 2606), which no host has, so none is impersonated.
pub const PLACEHOLDER_NAME: &str = "sail.invalid";

/// How long a certificate is valid for: ten years, a judgment. Mihomo's
/// (`ca.NewRandomTLSKeyPair`, as recalled, not checked) sets no validity
/// period at all, which only clients that check nothing take.
const VALID_DAYS: u32 = 3650;

/// How long before it is made a certificate is valid from, for clients
/// whose clock is behind: an hour, a judgment.
const BACKDATED_SECS: u64 = 3600;

/// The longest common name X.509 allows (ub-common-name).
const MAX_COMMON_NAME: usize = 64;

/// A certificate and its key, each inline PEM.
pub struct Pair {
    pub certificate: String,
    pub key: String,
}

/// Where an inbound keeps the certificate it made, with the name it is for:
/// one per inbound of an instance, kept across the reloads that rebuild
/// the inbound in place.
#[derive(Default)]
pub struct Slot(parking_lot::Mutex<Option<(String, Arc<Pair>)>>);

impl Slot {
    /// The certificate for `name`, or [`PLACEHOLDER_NAME`] without one: the
    /// one made for it before, or else a new one, which replaces any other.
    pub fn pair(&self, name: Option<&str>) -> Result<Arc<Pair>> {
        let name = name.unwrap_or(PLACEHOLDER_NAME);
        let mut held = self.0.lock();
        if let Some((made_for, pair)) = held.as_ref() {
            if made_for == name {
                return Ok(pair.clone());
            }
        }
        let pair = Arc::new(make(name)?);
        *held = Some((name.to_owned(), pair.clone()));
        Ok(pair)
    }

    /// The certificate held, if one was made.
    #[cfg(test)]
    pub(crate) fn certificate(&self) -> Option<String> {
        self.0.lock().as_ref().map(|(_, p)| p.certificate.clone())
    }
}

/// A new self-signed certificate for `name`, a host name or an IP address,
/// with its key: ECDSA P-256 (a judgment: Mihomo makes RSA 2048, slower to
/// make and to sign with), SHA-256, a random serial. It has no key usage
/// or basic constraints: a client trusting the certificate itself, as its
/// one CA, takes it as it takes a leaf with none, where a key usage
/// without certificate signing makes some verifiers refuse it as its own
/// issuer.
fn make(name: &str) -> Result<Pair> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let key = PKey::from_ec_key(EcKey::generate(&group)?)?;
    let mut builder = X509Builder::new()?;
    builder.set_version(2)?;
    let mut serial = BigNum::new()?;
    serial.rand(127, MsbOption::MAYBE_ZERO, false)?;
    let serial: Asn1Integer = serial.to_asn1_integer()?;
    builder.set_serial_number(&serial)?;
    // The name is the subject's common name too, where it fits; it is in
    // the alternative names either way, where clients look.
    let mut subject = X509NameBuilder::new()?;
    let named = name.len() <= MAX_COMMON_NAME;
    if named {
        subject.append_entry_by_text("CN", name)?;
    }
    let subject = subject.build();
    builder.set_subject_name(&subject)?;
    builder.set_issuer_name(&subject)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let not_before: Asn1Time = Asn1Time::from_unix(now.saturating_sub(BACKDATED_SECS) as _)?;
    builder.set_not_before(&not_before)?;
    let not_after: Asn1Time = Asn1Time::days_from_now(VALID_DAYS)?;
    builder.set_not_after(&not_after)?;
    builder.set_pubkey(&key)?;
    let mut alt_names = SubjectAlternativeName::new();
    // With no subject, the names are the only identity: critical, as
    // RFC 5280 asks.
    if !named {
        alt_names.critical();
    }
    if name.parse::<std::net::IpAddr>().is_ok() {
        alt_names.ip(name);
    } else {
        alt_names.dns(name);
    }
    let alt_names = alt_names.build(&builder.x509v3_context(None, None))?;
    builder.append_extension(&alt_names)?;
    builder.sign(&key, MessageDigest::sha256())?;
    let certificate = builder.build();
    Ok(Pair {
        certificate: String::from_utf8(certificate.to_pem()?)?,
        key: String::from_utf8(key.private_key_to_pem_pkcs8()?)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use btls::x509::X509;

    /// The names a certificate's alternative names hold, DNS and IP.
    fn alt_names(pem: &str) -> Vec<String> {
        let cert = X509::from_pem(pem.as_bytes()).unwrap();
        cert.subject_alt_names()
            .map(|names| {
                names
                    .iter()
                    .map(|n| match (n.dnsname(), n.ipaddress()) {
                        (Some(dns), _) => dns.to_owned(),
                        (None, Some(ip)) => format!("{:?}", ip),
                        _ => panic!("a DNS name or an IP address"),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// A certificate is for the name, or the placeholder; its key is its
    /// own; it is valid now and signed by itself.
    #[test]
    fn a_certificate_is_for_its_name_and_signed_by_its_key() {
        let slot = Slot::default();
        let pair = slot.pair(Some("example.com")).unwrap();
        assert_eq!(alt_names(&pair.certificate), ["example.com"]);
        let cert = X509::from_pem(pair.certificate.as_bytes()).unwrap();
        let key = PKey::private_key_from_pem(pair.key.as_bytes()).unwrap();
        assert!(cert.public_key().unwrap().public_eq(&key));
        assert!(cert.verify(&key).unwrap());
        let now = Asn1Time::days_from_now(0).unwrap();
        assert!(cert.not_before() < now && now < cert.not_after());
        let placeholder = Slot::default().pair(None).unwrap();
        assert_eq!(alt_names(&placeholder.certificate), [PLACEHOLDER_NAME]);
        let ip = Slot::default().pair(Some("192.0.2.1")).unwrap();
        assert_eq!(alt_names(&ip.certificate), ["[192, 0, 2, 1]"]);
        let long = format!("{}.example.com", "a".repeat(60));
        let pair = Slot::default().pair(Some(&long)).unwrap();
        assert_eq!(alt_names(&pair.certificate), [long]);
    }

    /// The slot keeps its certificate for the same name, and makes another
    /// for another name.
    #[test]
    fn a_slot_keeps_its_certificate_while_the_name_stays() {
        let slot = Slot::default();
        let first = slot.pair(Some("a.example")).unwrap();
        assert!(Arc::ptr_eq(&first, &slot.pair(Some("a.example")).unwrap()));
        let other = slot.pair(Some("b.example")).unwrap();
        assert_ne!(first.certificate, other.certificate);
        assert_eq!(slot.certificate(), Some(other.certificate.clone()));
    }
}
