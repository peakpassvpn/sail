//! The root certificates servers are checked against, as sing-box's
//! top-level `certificate` chooses them: the system's store (the default),
//! Mozilla's or Chrome's (each without the certificate authorities of
//! China, as sing-box documents them), or none, and certificates of one's
//! own besides.

use std::sync::{Arc, OnceLock};

use anyhow::{anyhow, Result};
use arc_swap::ArcSwapOption;
use btls::x509::store::{X509Store, X509StoreBuilder};
use btls::x509::X509;
use tracing::warn;

use super::client::{bundled_root_certs, load_certificates};
use crate::config::model::{CertificateOptions, CertificateStore};
use crate::runtime::RuntimeEnv;

/// Certificates trusted as roots, and the store made of them.
#[derive(Clone)]
pub struct Roots(Arc<Inner>);

struct Inner {
    certs: Vec<X509>,
    store: X509Store,
}

impl std::fmt::Debug for Roots {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Roots({} certificates)", self.0.certs.len())
    }
}

impl Roots {
    fn new(certs: Vec<X509>) -> Result<Self> {
        let mut store = X509StoreBuilder::new()?;
        for cert in &certs {
            store.add_cert(cert.clone())?;
        }
        Ok(Self(Arc::new(Inner {
            certs,
            store: store.build(),
        })))
    }

    pub fn certs(&self) -> &[X509] {
        &self.0.certs
    }

    pub fn store(&self) -> &X509Store {
        &self.0.store
    }

    /// One of the stores, built once per process.
    pub fn of(store: CertificateStore) -> Result<Self> {
        static SYSTEM: OnceLock<std::result::Result<Roots, String>> = OnceLock::new();
        static MOZILLA: OnceLock<std::result::Result<Roots, String>> = OnceLock::new();
        static CHROME: OnceLock<std::result::Result<Roots, String>> = OnceLock::new();
        static NONE: OnceLock<std::result::Result<Roots, String>> = OnceLock::new();
        let (cell, build): (_, fn() -> Result<Roots>) = match store {
            CertificateStore::System => (&SYSTEM, system),
            CertificateStore::Mozilla => (&MOZILLA, || pem(include_str!("roots/mozilla.pem"))),
            CertificateStore::Chrome => (&CHROME, || pem(include_str!("roots/chrome.pem"))),
            CertificateStore::None => (&NONE, || Roots::new(Vec::new())),
        };
        cell.get_or_init(|| build().map_err(|e| format!("{:#}", e)))
            .clone()
            .map_err(|e| anyhow!("certificate.store: {}", e))
    }

    /// What `options` choose: a store, and certificates of one's own
    /// besides. Paths are in the data directory, unless absolute.
    pub fn configured(options: &CertificateOptions, env: &RuntimeEnv) -> Result<Self> {
        let base = Self::of(options.store)?;
        let mut extra = Vec::new();
        if !options.certificate.is_empty() {
            extra.extend(
                load_certificates(&options.certificate.join("\n"))
                    .map_err(|e| anyhow!("certificate.certificate: {}", e))?,
            );
        }
        for path in &options.certificate_path {
            let path = env.data_path(path);
            extra.extend(
                load_certificates(&path)
                    .map_err(|e| anyhow!("certificate.certificate_path: {}: {}", path, e))?,
            );
        }
        for dir in &options.certificate_directory_path {
            let dir = env.data_path(dir);
            let entries = std::fs::read_dir(&dir)
                .map_err(|e| anyhow!("certificate.certificate_directory_path: {}: {}", dir, e))?;
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                let path = path.to_string_lossy().to_string();
                extra.extend(load_certificates(&path).map_err(|e| {
                    anyhow!("certificate.certificate_directory_path: {}: {}", path, e)
                })?);
            }
        }
        if extra.is_empty() {
            return Ok(base);
        }
        let mut certs = base.certs().to_vec();
        certs.extend(extra);
        Roots::new(certs)
    }
}

fn pem(text: &str) -> Result<Roots> {
    Roots::new(X509::stack_from_pem(text.as_bytes())?)
}

/// The system's roots. Where the system does not let them be listed (iOS,
/// and Android unless its store is found), the bundled Mozilla roots stand
/// in, as they did before there was a choice.
fn system() -> Result<Roots> {
    let loaded = rustls_native_certs::load_native_certs();
    let certs: Vec<X509> = loaded
        .certs
        .iter()
        .filter_map(|der| X509::from_der(der).ok())
        .collect();
    if certs.is_empty() {
        warn!(
            "certificate.store system: no system root certificates here ({}); \\
             the bundled Mozilla roots stand in",
            loaded
                .errors
                .first()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "none found".into())
        );
        return Roots::new(bundled_root_certs()?.to_vec());
    }
    Roots::new(certs)
}

/// The roots of an instance, as its configuration chose them; the
/// system's until it has.
#[derive(Clone, Default)]
pub struct TrustRoots(Arc<ArcSwapOption<Roots>>);

impl std::fmt::Debug for TrustRoots {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TrustRoots({:?})", self.0.load())
    }
}

impl TrustRoots {
    pub fn get(&self) -> Result<Roots> {
        match self.0.load_full() {
            Some(roots) => Ok((*roots).clone()),
            None => Roots::of(CertificateStore::System),
        }
    }

    pub fn set(&self, roots: Roots) {
        self.0.store(Some(Arc::new(roots)));
    }

    /// Puts `roots` in place until the guard is dropped, unless it is kept:
    /// a reload that fails half way leaves the roots it found.
    pub fn replace(&self, roots: Roots) -> RootsGuard {
        let previous = self.0.swap(Some(Arc::new(roots)));
        RootsGuard {
            trust: self.clone(),
            previous: Some(previous),
        }
    }
}

/// The roots a [`TrustRoots::replace`] replaced, put back on drop.
pub struct RootsGuard {
    trust: TrustRoots,
    previous: Option<Option<Arc<Roots>>>,
}

impl RootsGuard {
    /// Keeps the new roots.
    pub fn keep(mut self) {
        self.previous = None;
    }
}

impl Drop for RootsGuard {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.take() {
            self.trust.0.store(previous);
        }
    }
}

/// The roots a configuration chooses: its `certificate`, or the system's.
pub fn configured(certificate: Option<&CertificateOptions>, env: &RuntimeEnv) -> Result<Roots> {
    match certificate {
        Some(options) => Roots::configured(options, env),
        None => Roots::of(CertificateStore::System),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stores_load_and_leave_out_china() {
        let mozilla = Roots::of(CertificateStore::Mozilla).unwrap();
        let chrome = Roots::of(CertificateStore::Chrome).unwrap();
        assert!(mozilla.certs().len() > 80, "{:?}", mozilla);
        assert!(chrome.certs().len() > 80, "{:?}", chrome);
        assert!(Roots::of(CertificateStore::None)
            .unwrap()
            .certs()
            .is_empty());
        for roots in [&mozilla, &chrome] {
            for cert in roots.certs() {
                let country = cert
                    .subject_name()
                    .entries_by_nid(btls::nid::Nid::COUNTRYNAME)
                    .next()
                    .and_then(|c| c.data().as_utf8().ok().map(|s| s.to_string()));
                assert_ne!(country.as_deref(), Some("CN"), "{:?}", cert.subject_name());
            }
        }
        assert!(!Roots::of(CertificateStore::System)
            .unwrap()
            .certs()
            .is_empty());
    }

    #[test]
    fn a_replacement_not_kept_puts_the_old_roots_back() {
        let trust = TrustRoots::default();
        trust.set(Roots::of(CertificateStore::Chrome).unwrap());
        let chrome = trust.get().unwrap().certs().len();
        drop(trust.replace(Roots::of(CertificateStore::None).unwrap()));
        assert_eq!(trust.get().unwrap().certs().len(), chrome);
        trust
            .replace(Roots::of(CertificateStore::None).unwrap())
            .keep();
        assert!(trust.get().unwrap().certs().is_empty());
    }

    #[test]
    fn certificates_of_one_s_own_are_added() {
        let options = CertificateOptions {
            store: CertificateStore::None,
            certificate: vec![crate::transport::tls::tests::self_signed_pem()],
            ..Default::default()
        };
        let roots = Roots::configured(&options, &RuntimeEnv::default()).unwrap();
        assert_eq!(roots.certs().len(), 1);
    }
}
