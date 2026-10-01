//! Assets: the data files a configuration reads that sail never downloads
//! itself, the ASN database (`asn.mmdb`), the GeoIP database (`geo.mmdb`)
//! and the site lists (`site.dat`), or files the configuration names in
//! their place. The core tells which ones a configuration needs and where,
//! checks a file before it takes the place of one, and puts it there.
//! Where one is downloaded from is the host's to say
//! ([`Host::asset_sources`](crate::runtime::Host::asset_sources)): core
//! names no URL.
//!
//! Only what the configuration itself names is known: a rule-set read
//! from a file or downloaded may need `asn.mmdb` too, and says so when it
//! is loaded, naming the path.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{anyhow, Result};
use serde_derive::Serialize;

use crate::config::{external_rule, rule_set::HeadlessRule, Config, Rule};
use crate::runtime::RuntimeEnv;

/// What an asset is read as.
#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// A MaxMind database: GeoIP (`geo.mmdb`) or ASN (`asn.mmdb`).
    Mmdb,
    /// Site lists, as V2Ray's `geosite.dat`.
    Site,
}

/// A data file a configuration reads.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Asset {
    /// The file as the configuration names it, or the default one:
    /// `asn.mmdb`, `geo.mmdb` or `site.dat`.
    pub name: String,
    pub kind: Kind,
    /// Where it is read from: `name` in the data directory, unless
    /// absolute.
    pub path: String,
    /// The fields that read it, as `route.rules[3].ip_asn`.
    pub used_by: Vec<String>,
    /// Whether there is a file there.
    pub present: bool,
}

/// The assets `config` reads with `env`, one for each path, in the order
/// the configuration first names them.
pub fn required(config: &Config, env: &RuntimeEnv) -> Vec<Asset> {
    let mut found = Found::default();
    for (i, rule) in config.route.rules.iter().enumerate() {
        found.rule(rule, &format!("route.rules[{}]", i));
    }
    for (i, rule) in config.dns.rules.iter().enumerate() {
        found.rule(&rule.conditions(), &format!("dns.rules[{}]", i));
    }
    for (i, set) in config.route.rule_set.iter().enumerate() {
        for (j, rule) in set.rules.iter().enumerate() {
            found.headless(rule, &format!("route.rule_set[{}].rules[{}]", i, j));
        }
    }
    #[cfg(feature = "outbound-smart")]
    for (i, outbound) in config.outbounds.iter().enumerate() {
        if outbound.protocol != "smart" {
            continue;
        }
        if let Some(file) =
            crate::protocol::group::smart::asn_file(&outbound.tag, &outbound.options)
        {
            found.add(&file, Kind::Mmdb, format!("outbounds[{}].prefer_asn", i));
        }
    }
    let mut assets: Vec<Asset> = Vec::new();
    let mut at: BTreeMap<String, usize> = BTreeMap::new();
    for (name, kind, used_by) in found.0 {
        let path = env.data_path(&name);
        match at.get(&path) {
            Some(&i) => assets[i].used_by.push(used_by),
            None => {
                at.insert(path.clone(), assets.len());
                assets.push(Asset {
                    name,
                    kind,
                    present: Path::new(&path).is_file(),
                    path,
                    used_by: vec![used_by],
                });
            }
        }
    }
    assets
}

/// The files named, each with what reads it, in order.
#[derive(Default)]
struct Found(Vec<(String, Kind, String)>);

impl Found {
    fn add(&mut self, file: &str, kind: Kind, used_by: String) {
        self.0.push((file.to_string(), kind, used_by));
    }

    fn rule(&mut self, rule: &Rule, path: &str) {
        use crate::app::router::matcher::ASN_FILE;
        if !rule.geosite.is_empty() {
            self.add(
                external_rule::GEOSITE_FILE,
                Kind::Site,
                format!("{}.geosite", path),
            );
        }
        if !rule.geoip.is_empty() {
            self.add(
                external_rule::GEOIP_FILE,
                Kind::Mmdb,
                format!("{}.geoip", path),
            );
        }
        for (i, filter) in rule.external.iter().enumerate() {
            // One that does not parse is the load's error.
            if let Ok((kind, file, _)) = external_rule::parse(filter) {
                self.add(file, kind, format!("{}.external[{}]", path, i));
            }
        }
        if !rule.ip_asn.is_empty() {
            self.add(ASN_FILE, Kind::Mmdb, format!("{}.ip_asn", path));
        }
        for (i, rule) in rule.rules.iter().enumerate() {
            self.rule(rule, &format!("{}.rules[{}]", path, i));
        }
    }

    fn headless(&mut self, rule: &HeadlessRule, path: &str) {
        use crate::app::router::matcher::ASN_FILE;
        if !rule.ip_asn.is_empty() {
            self.add(ASN_FILE, Kind::Mmdb, format!("{}.ip_asn", path));
        }
        for (i, rule) in rule.rules.iter().enumerate() {
            self.headless(rule, &format!("{}.rules[{}]", path, i));
        }
    }
}

/// The error of an asset file `path` that does not open: one not there
/// says how to get it.
pub(crate) fn open_error(what: &str, path: &str, e: std::io::Error) -> anyhow::Error {
    let what = match what {
        "" => String::new(),
        what => format!("{} ", what),
    };
    match e.kind() {
        std::io::ErrorKind::NotFound => anyhow!(
            "open {}{} failed: {} (sail assets --fetch <config>, or place the file there)",
            what,
            path,
            e
        ),
        _ => anyhow!("open {}{} failed: {}", what, path, e),
    }
}

/// The asset `name` of `assets`: an error that lists them if there is
/// none.
pub fn find<'a>(assets: &'a [Asset], name: &str) -> Result<&'a Asset> {
    assets.iter().find(|a| a.name == name).ok_or_else(|| {
        let names: Vec<&str> = assets.iter().map(|a| a.name.as_str()).collect();
        match names.is_empty() {
            true => anyhow!("{}: the configuration reads no asset", name),
            false => anyhow!(
                "{}: not an asset the configuration reads ({})",
                name,
                names.join(", ")
            ),
        }
    })
}

/// Checks that `data` is a whole file of `kind`, as it is read.
pub fn validate(kind: Kind, data: &[u8]) -> Result<()> {
    match kind {
        Kind::Mmdb => maxminddb::Reader::from_source(data)
            .map(drop)
            .map_err(|e| anyhow!("not a MaxMind database: {}", e)),
        Kind::Site => external_rule::count_site_groups(data)
            .map(drop)
            .map_err(|e| anyhow!("not a site list: {}", e)),
    }
}

/// Puts `data` in the place of `asset`, whole, if it is a file of the
/// asset's kind; the file there stays otherwise.
#[cfg(feature = "http-client")]
pub fn install(asset: &Asset, data: &[u8]) -> Result<()> {
    validate(asset.kind, data).map_err(|e| anyhow!("{}: {}", asset.name, e))?;
    crate::fetch::write_atomically(Path::new(&asset.path), data)
        .map_err(|e| anyhow!("{}: {}", asset.path, e))
}

/// How an asset is downloaded: five minutes, for GeoLite2-ASN's 12 MB
/// (measured 2026-09-30) on a slow link; 64 MiB at most, as a rule-set.
#[cfg(feature = "http-client")]
fn download_options() -> crate::fetch::Options {
    crate::fetch::Options {
        timeout: std::time::Duration::from_secs(5 * 60),
        ..Default::default()
    }
}

/// The host of `url` alone, for errors: a URL may carry a secret.
#[cfg(feature = "http-client")]
fn host_of(url: &str) -> &str {
    crate::common::redact::host(url)
}

/// Downloads `url` directly into the place of `asset` (see [`install`]);
/// the size written.
#[cfg(feature = "http-client")]
pub async fn download(asset: &Asset, url: &str) -> Result<usize> {
    let data = crate::fetch::fetch(url, &download_options())
        .await
        .map_err(|e| anyhow!("{}: {}: {:#}", asset.name, host_of(url), e))?;
    install(asset, &data)?;
    Ok(data.len())
}

/// What an update of a running instance's asset did.
#[cfg(feature = "http-client")]
#[derive(Serialize, Debug)]
pub struct Updated {
    pub name: String,
    pub path: String,
    /// The size written.
    pub size: usize,
    /// Whether the instance reloaded, which is how the new file takes
    /// effect: the rules and groups hold the old one until then.
    pub reloaded: bool,
    /// Why it did not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reload_error: Option<String>,
}

/// Why an update of a running instance's asset failed.
#[cfg(feature = "http-client")]
#[derive(Debug)]
pub enum UpdateError {
    /// The configuration reads no asset of that name.
    Unknown(anyhow::Error),
    /// No URL given, and the host has none for it.
    NoSource(String),
    /// The download, or the file, failed.
    Failed(anyhow::Error),
}

#[cfg(feature = "http-client")]
impl std::fmt::Display for UpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpdateError::Unknown(e) | UpdateError::Failed(e) => write!(f, "{:#}", e),
            UpdateError::NoSource(name) => write!(
                f,
                "{}: no URL given, and the host has no source for it (asset_sources)",
                name
            ),
        }
    }
}

/// Downloads the asset `name` of the running instance `manager` from
/// `url`, or else from the host's source for it, through the outbound
/// `detour`, or else the default one; puts it in place, and reloads the
/// instance so that it takes effect.
#[cfg(feature = "http-client")]
pub async fn update(
    manager: &crate::RuntimeManager,
    name: &str,
    url: Option<&str>,
    detour: Option<&str>,
) -> std::result::Result<Updated, UpdateError> {
    let assets = manager.assets();
    let asset = find(&assets, name).map_err(UpdateError::Unknown)?;
    let url = url
        .or_else(|| manager.env.host.asset_sources.get(name).map(String::as_str))
        .ok_or_else(|| UpdateError::NoSource(name.to_string()))?;
    let failed = |e: anyhow::Error| UpdateError::Failed(anyhow!("{}: {:#}", asset.name, e));
    let detour = match detour {
        Some(detour) => detour.to_string(),
        None => manager
            .dispatcher
            .upgrade()
            .and_then(|d| d.default_outbound())
            .ok_or_else(|| failed(anyhow!("no outbound to download through")))?,
    };
    let data = crate::fetch::fetch_through(manager, &detour, url, &download_options())
        .await
        .map_err(|e| failed(anyhow!("{}: {:#}", host_of(url), e)))?;
    install(asset, &data).map_err(UpdateError::Failed)?;
    tracing::info!(
        "asset {} updated from {}: {} bytes",
        asset.name,
        host_of(url),
        data.len()
    );
    let reload_error = manager.reload().await.err().map(|e| e.to_string());
    Ok(Updated {
        name: asset.name.clone(),
        path: asset.path.clone(),
        size: data.len(),
        reloaded: reload_error.is_none(),
        reload_error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::router::matcher::tests::{asn_records, mmdb};

    fn env(dir: &Path) -> RuntimeEnv {
        RuntimeEnv {
            host: crate::runtime::Host {
                data_dir: Some(dir.to_path_buf()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn config(json: serde_json::Value) -> Config {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn each_kind_is_found_once_a_path_with_its_readers() {
        let dir = std::env::temp_dir().join(format!("sail-assets-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("site.dat"), b"").unwrap();
        let whole = config(serde_json::json!({
            "outbounds": [
                { "type": "direct" },
                { "type": "smart", "tag": "s", "outbounds": ["direct"], "prefer_asn": true },
                { "type": "smart", "tag": "t", "outbounds": ["direct"],
                  "prefer_asn": true, "asn_file": "/abs/other.mmdb" },
                { "type": "smart", "tag": "u", "outbounds": ["direct"] }
            ],
            "dns": { "rules": [
                { "geosite": "cn", "server": "x" },
                { "external": "site:ads.dat:ads", "server": "x" }
            ] },
            "route": {
                "rules": [
                    { "ip_asn": 13335, "outbound": "direct" },
                    { "type": "logical", "mode": "or", "rules": [
                        { "geoip": "cn" }, { "ip_asn": 1 }
                    ], "outbound": "direct" },
                    { "external": ["mmdb:us", "mmdb:my.mmdb:us", "bad"], "outbound": "direct" }
                ],
                "rule_set": [
                    { "type": "inline", "tag": "a", "rules": [
                        { "type": "logical", "mode": "and", "rules": [ { "ip_asn": 2 } ] }
                    ] }
                ]
            }
        }));
        let assets = required(&whole, &env(&dir));
        let by_name = |name: &str| assets.iter().find(|a| a.name == name).unwrap();
        let asn = by_name("asn.mmdb");
        assert_eq!(asn.kind, Kind::Mmdb);
        assert_eq!(
            Path::new(&asn.path),
            dir.join("asn.mmdb"),
            "in the data directory"
        );
        assert!(!asn.present);
        let mut expected = vec![
            "route.rules[0].ip_asn",
            "route.rules[1].rules[1].ip_asn",
            "route.rule_set[0].rules[0].rules[0].ip_asn",
        ];
        if cfg!(feature = "outbound-smart") {
            expected.push("outbounds[1].prefer_asn");
        }
        assert_eq!(asn.used_by, expected);
        assert_eq!(
            by_name("geo.mmdb").used_by,
            [
                "route.rules[1].rules[0].geoip",
                "route.rules[2].external[0]"
            ]
        );
        assert_eq!(by_name("my.mmdb").used_by, ["route.rules[2].external[1]"]);
        let site = by_name("site.dat");
        assert_eq!((site.kind, site.present), (Kind::Site, true));
        assert_eq!(site.used_by, ["dns.rules[0].geosite"]);
        assert_eq!(by_name("ads.dat").used_by, ["dns.rules[1].external[0]"]);
        if cfg!(feature = "outbound-smart") {
            let other = by_name("/abs/other.mmdb");
            assert_eq!(other.path, "/abs/other.mmdb", "absolute, as it is");
            assert_eq!(other.used_by, ["outbounds[2].prefer_asn"]);
        }
        let expected = if cfg!(feature = "outbound-smart") {
            6
        } else {
            5
        };
        assert_eq!(assets.len(), expected, "{:?}", assets);
        // Relative to the data directory, or not, the same file is one.
        #[cfg(unix)]
        {
            let absolute = dir.join("geo.mmdb").to_string_lossy().to_string();
            let same = config(serde_json::json!({ "route": { "rules": [
                { "geoip": "cn", "outbound": "direct" },
                { "external": format!("mmdb:{}:us", absolute), "outbound": "direct" }
            ] } }));
            let assets = required(&same, &env(&dir));
            assert_eq!(assets.len(), 1, "{:?}", assets);
            assert_eq!(assets[0].used_by.len(), 2);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_missing_file_says_how_to_get_it() {
        let env = env(Path::new("/nonexistent-sail"));
        let rule = config(serde_json::json!({ "route": { "rules": [
            { "ip_asn": 1, "outbound": "direct" }
        ] } }));
        let err = crate::app::router::matcher::Matcher::new(
            &rule.route.rules[0],
            &env,
            &Default::default(),
        )
        .err()
        .unwrap()
        .to_string();
        assert!(err.contains("asn.mmdb"), "{}", err);
        assert!(err.contains("sail assets --fetch"), "{}", err);
        let err = external_rule::load("site:x.dat:cn", &env)
            .err()
            .unwrap()
            .to_string();
        assert!(
            err.contains("x.dat") && err.contains("sail assets --fetch"),
            "{}",
            err
        );
    }

    #[test]
    fn a_file_not_of_its_kind_is_refused() {
        let (record, _) = asn_records(13335, "");
        assert!(validate(Kind::Mmdb, &mmdb(&[("1.0.0.0/8", record)])).is_ok());
        assert!(validate(Kind::Mmdb, b"<html>not found</html>").is_err());
        assert!(validate(Kind::Mmdb, b"").is_err());
        assert!(validate(Kind::Site, &site_list()).is_ok());
        assert!(validate(Kind::Site, b"").is_err());
        assert!(validate(Kind::Site, b"<html>not found</html>").is_err());
    }

    /// A site list of one group, `CN`, of one domain.
    pub(crate) fn site_list() -> Vec<u8> {
        use protobuf::Message;
        let mut group = crate::config::geosite::SiteGroup::new();
        group.tag = "CN".into();
        let mut domain = crate::config::geosite::Domain::new();
        domain.type_ = crate::config::geosite::domain::Type::Domain.into();
        domain.value = "example.cn".into();
        group.domain.push(domain);
        let mut list = crate::config::geosite::SiteGroupList::new();
        list.site_group.push(group);
        list.write_to_bytes().unwrap()
    }

    #[cfg(feature = "http-client")]
    #[test]
    fn a_bad_file_leaves_the_old_one() {
        let dir = std::env::temp_dir().join(format!("sail-assets-install-{}", std::process::id()));
        let asset = Asset {
            name: "site.dat".into(),
            kind: Kind::Site,
            path: dir.join("site.dat").to_string_lossy().to_string(),
            used_by: vec![],
            present: false,
        };
        install(&asset, &site_list()).unwrap();
        let err = install(&asset, b"<html>").unwrap_err().to_string();
        assert!(err.contains("site.dat: not a site list"), "{}", err);
        assert_eq!(std::fs::read(&asset.path).unwrap(), site_list());
        let domains = external_rule::load("site:cn", &env(&dir)).unwrap();
        assert!(matches!(domains, external_rule::External::Domains(d) if d.len() == 1));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A server that answers one request with `body`.
    #[cfg(feature = "http-client")]
    pub(crate) async fn serve(body: Vec<u8>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
            let _ = stream.write_all(head.as_bytes()).await;
            let _ = stream.write_all(&body).await;
        });
        format!("http://{}/asn.mmdb", addr)
    }

    #[cfg(feature = "http-client")]
    #[tokio::test]
    async fn a_download_is_what_the_rules_then_read() {
        use crate::app::router::matcher::{Facts, Matcher};
        let dir = std::env::temp_dir().join(format!("sail-assets-dl-{}", std::process::id()));
        let env = env(&dir);
        let whole = config(serde_json::json!({ "route": { "rules": [
            { "ip_asn": 13335, "outbound": "direct" }
        ] } }));
        let rule = &whole.route.rules[0];
        assert!(Matcher::new(rule, &env, &Default::default()).is_err());
        let assets = required(&whole, &env);
        assert!(!assets[0].present);

        let url = serve(b"<html>".to_vec()).await;
        assert!(download(&assets[0], &url).await.is_err());
        assert!(!Path::new(&assets[0].path).exists());

        let (record, _) = asn_records(13335, "");
        let url = serve(mmdb(&[("1.0.0.0/8", record)])).await;
        download(&assets[0], &url).await.unwrap();
        assert!(required(&whole, &env)[0].present);
        let m = Matcher::new(rule, &env, &Default::default()).unwrap();
        let to = |ip: &str| {
            Facts::new(
                &crate::session::Session {
                    destination: (ip.parse::<std::net::IpAddr>().unwrap(), 443).into(),
                    ..Default::default()
                },
                &[],
            )
        };
        assert!(m.matches(&to("1.1.1.1")));
        assert!(!m.matches(&to("9.9.9.9")));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(feature = "http-client")]
    #[test]
    fn errors_name_the_host_alone() {
        assert_eq!(
            host_of("https://u:p@example.com:8443/s3cret?k=v"),
            "example.com:8443"
        );
        assert_eq!(host_of("http://example.com"), "example.com");
    }
}
