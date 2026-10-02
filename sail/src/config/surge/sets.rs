//! The rule-sets Surge's rules name, `RULE-SET,value` and `DOMAIN-SET,value`:
//! a set built into Surge (`SYSTEM`, `LAN`), a `[Ruleset <name>]` section
//! of the profile, or a file, by URL or by path relative to the profile.
//!
//! A built-in or inline set is its rules, in place; one of them may name
//! another set, eight deep at most, as Surge has it, and a deeper one
//! matches nothing. A file is a rule-set of sail's, of Surge's text: a
//! URL's downloaded directly, as Surge downloads it, every
//! `update-interval` (a day by default); a path's read, and read again
//! when it changes. The same file is not both a `RULE-SET` and a
//! `DOMAIN-SET`, as Surge refuses it.
//!
//! And the rule-sets `GEOIP` rules name, as Clash's front-end downloads
//! them.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use indexmap::IndexMap;
use serde_json::{json, Value};

use super::text::Line;

/// How deep sets name sets.
pub const MAX_DEPTH: usize = 8;

/// `LAN`, as Surge's manual lists it (manual.nssurge.com, "Rule Set",
/// 2026-09): the `.local` names, and the private and special-purpose
/// ranges.
const LAN: &[&str] = &[
    "DOMAIN-SUFFIX,local",
    "IP-CIDR,0.0.0.0/8",
    "IP-CIDR,10.0.0.0/8",
    "IP-CIDR,100.64.0.0/10",
    "IP-CIDR,127.0.0.0/8",
    "IP-CIDR,169.254.0.0/16",
    "IP-CIDR,172.16.0.0/12",
    "IP-CIDR,192.0.0.0/24",
    "IP-CIDR,192.0.2.0/24",
    "IP-CIDR,192.168.0.0/16",
    "IP-CIDR,224.0.0.0/4",
    "IP-CIDR6,::1/128",
    "IP-CIDR6,fc00::/7",
    "IP-CIDR6,fe80::/10",
];

/// `SYSTEM`, as Surge's manual lists it (manual.nssurge.com, "Rule Set",
/// 2026-09): what macOS and iOS themselves ask for. Its two daemons,
/// `trustd` and `netbiosd`, are left out: sail tells no program on the
/// platforms they run on.
const SYSTEM: &[&str] = &[
    "DOMAIN,api.smoot.apple.com",
    "DOMAIN,captive.apple.com",
    "DOMAIN,xp.apple.com",
    "DOMAIN,configuration.apple.com",
    "DOMAIN,guzzoni.apple.com",
    "DOMAIN,smp-device-content.apple.com",
    "DOMAIN,aod.itunes.apple.com",
    "DOMAIN,mesu.apple.com",
    "DOMAIN,api.smoot.apple.cn",
    "DOMAIN,gs-loc.apple.com",
    "DOMAIN,mvod.itunes.apple.com",
    "DOMAIN,streamingaudio.itunes.apple.com",
    "DOMAIN-SUFFIX,ess.apple.com",
    "DOMAIN-SUFFIX,push-apple.com.akadns.net",
    "DOMAIN-SUFFIX,push.apple.com",
    "DOMAIN-SUFFIX,lcdn-locator.apple.com",
    "DOMAIN-SUFFIX,lcdn-registration.apple.com",
    "DOMAIN-SUFFIX,ls.apple.com",
];

/// What a set's file holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Rules, `RULE-SET`.
    Rules,
    /// Names, `DOMAIN-SET`.
    Domains,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Rules => "RULE-SET",
            Kind::Domains => "DOMAIN-SET",
        }
    }
}

/// The sets rules may name, and those they name that are made here.
pub struct Sets {
    geo: crate::config::clash::provider::Sets,
    /// The profile's directory, which paths are relative to.
    dir: Option<PathBuf>,
    /// The data directory, which a profile without one names files in.
    home: Option<PathBuf>,
    /// The `[Ruleset <name>]` sections, by name.
    inline: IndexMap<String, Vec<Line>>,
    /// The files named, by tag: what they hold, and the rule-set.
    files: IndexMap<String, (Kind, Value)>,
    /// The built-in and inline sets being read, outermost first.
    pub stack: Vec<String>,
}

impl Sets {
    pub fn new(dir: Option<&Path>, home: Option<&Path>, inline: Vec<(String, Vec<Line>)>) -> Self {
        Sets {
            geo: Default::default(),
            dir: dir.map(Path::to_path_buf),
            home: home.map(Path::to_path_buf),
            inline: inline.into_iter().collect(),
            files: IndexMap::new(),
            stack: Vec::new(),
        }
    }

    /// The tag of the rule-set of the country `code`.
    pub fn geoip(&mut self, code: &str) -> Result<String> {
        self.geo.geoip(code)
    }

    /// The rules of the set `name`, when it is built in or inline: a
    /// built-in one's first, as Surge looks for it; with where each is.
    pub fn rules_of(&self, name: &str) -> Option<Vec<(String, String)>> {
        let built_in = match name {
            "LAN" => Some(LAN),
            "SYSTEM" => Some(SYSTEM),
            _ => None,
        };
        if let Some(lines) = built_in {
            return Some(
                lines
                    .iter()
                    .map(|l| (format!("RULE-SET,{}", name), l.to_string()))
                    .collect(),
            );
        }
        let lines = self.inline.get(name)?;
        Some(
            lines
                .iter()
                .map(|l| (format!("[Ruleset {}] {}", name, l.loc), l.text.clone()))
                .collect(),
        )
    }

    /// The tag of the rule-set of the file `location`, a URL or a path,
    /// holding `kind`; downloaded every `interval` seconds, never when
    /// below 0.
    pub fn file(&mut self, kind: Kind, location: &str, interval: Option<i64>) -> Result<String> {
        let remote = location.starts_with("http://") || location.starts_with("https://");
        let tag = if remote {
            location.to_string()
        } else {
            super::local_file(
                self.dir.as_deref(),
                self.home.as_deref(),
                kind.name(),
                location,
            )?
        };
        if let Some((known, _)) = self.files.get(&tag) {
            if *known != kind {
                return Err(anyhow!(
                    "{}: {} is a {} too, which Surge refuses",
                    kind.name(),
                    location,
                    known.name()
                ));
            }
            return Ok(tag);
        }
        let behavior = match kind {
            Kind::Rules => "classical",
            Kind::Domains => "domain",
        };
        let mut set = json!({
            "tag": tag,
            "format": "surge-text",
            "behavior": behavior,
        });
        if remote {
            set["type"] = json!("remote");
            set["url"] = json!(location);
            set["download_detour"] = json!("DIRECT");
            match interval {
                Some(seconds) if seconds < 0 => set["update_interval"] = json!("87600h"),
                Some(seconds) if seconds > 0 => {
                    set["update_interval"] = json!(format!("{}s", seconds))
                }
                _ => {}
            }
        } else {
            set["type"] = json!("local");
            set["path"] = json!(tag);
        }
        self.files.insert(tag.clone(), (kind, set));
        Ok(tag)
    }

    /// The rule-sets of the files, and of the GEOIP rules.
    pub fn into_rule_sets(self) -> Vec<Value> {
        let mut sets: Vec<Value> = self.files.into_values().map(|(_, set)| set).collect();
        sets.extend(self.geo.into_geo_sets());
        sets
    }
}
