//! The outbound providers and the rule-sets: what each holds, when it was
//! last updated and is next, why its last update failed, and updating one
//! by hand, as Mihomo's proxy and rule providers. No URL is told: a
//! subscription's often carries a token.

use std::time::{Duration, SystemTime};

use super::ControlError;
use crate::RuntimeManager;

/// Where a provider or a rule-set comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SourceKind {
    /// Downloaded.
    Remote,
    /// Read from a file.
    Local,
    /// Written in the configuration.
    Inline,
}

/// An update that failed: when, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Failure {
    pub at: SystemTime,
    /// The error, which names no URL.
    pub error: String,
}

impl Failure {
    #[cfg(any(feature = "outbound-provider", feature = "rule-set"))]
    pub(crate) fn now(error: &anyhow::Error) -> Self {
        Failure {
            at: SystemTime::now(),
            error: format!("{:#}", error),
        }
    }
}

/// What a subscription says of itself, in its `subscription-userinfo`:
/// the traffic used and allowed, in bytes, and when it expires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct SubscriptionInfo {
    pub upload: u64,
    pub download: u64,
    pub total: u64,
    pub expire: Option<SystemTime>,
}

impl SubscriptionInfo {
    /// The header as Mihomo reads it: `upload=1; download=2; total=3;
    /// expire=4`, case and spaces aside, a fraction cut off, a field that
    /// is no number passed over; an expiry of 0, or none, is none.
    pub fn parse(userinfo: &str) -> Self {
        let mut info = SubscriptionInfo::default();
        let userinfo = userinfo.to_ascii_lowercase().replace(' ', "");
        for field in userinfo.split(';') {
            let Some((name, value)) = field.split_once('=') else {
                continue;
            };
            let value = match value.parse::<i64>() {
                Ok(v) => v,
                Err(_) => match value.parse::<f64>() {
                    Ok(v) if v.is_finite() => v as i64,
                    _ => continue,
                },
            };
            let value = u64::try_from(value).unwrap_or(0);
            match name {
                "upload" => info.upload = value,
                "download" => info.download = value,
                "total" => info.total = value,
                "expire" => {
                    info.expire =
                        (value > 0).then(|| SystemTime::UNIX_EPOCH + Duration::from_secs(value))
                }
                _ => {}
            }
        }
        info
    }
}

/// An outbound provider (Mihomo's proxy provider).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProviderInfo {
    pub tag: String,
    pub source: SourceKind,
    /// How many members it has; `provider_members` tells them.
    pub members: usize,
    /// When it was last downloaded, found unchanged, or its file read.
    pub updated: Option<SystemTime>,
    /// When it is next updated; none when it is not updated by itself.
    pub next_update: Option<SystemTime>,
    /// The last update's failure, until one succeeds.
    pub failure: Option<Failure>,
    /// What the subscription last said of itself, if it did.
    pub subscription: Option<SubscriptionInfo>,
}

/// A rule-set (Mihomo's rule provider).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RuleSetInfo {
    pub tag: String,
    pub source: SourceKind,
    /// Its format, as the configuration names it: `binary`, `source`,
    /// `clash-yaml`, ...; none for an inline one.
    pub format: Option<String>,
    /// A Clash format's behavior: `domain`, `ipcidr`, `classical`.
    pub behavior: Option<String>,
    /// How many rules, or entries, it holds.
    pub rules: usize,
    pub updated: Option<SystemTime>,
    pub next_update: Option<SystemTime>,
    pub failure: Option<Failure>,
}

impl RuntimeManager {
    /// The outbound providers, in the configuration's order.
    pub async fn providers(&self) -> Vec<ProviderInfo> {
        #[cfg(feature = "outbound-provider")]
        {
            let now = SystemTime::now();
            self.outbound_manager
                .load()
                .providers()
                .all()
                .iter()
                .map(|p| p.info(now))
                .collect()
        }
        #[cfg(not(feature = "outbound-provider"))]
        Vec::new()
    }

    /// The outbound provider `tag`.
    pub async fn provider(&self, tag: &str) -> Option<ProviderInfo> {
        self.providers().await.into_iter().find(|p| p.tag == tag)
    }

    /// Downloads the outbound provider `tag` again, or reads its file
    /// again, and puts in place what it now holds; done when it is.
    pub async fn update_provider(&self, tag: &str) -> Result<(), ControlError> {
        #[cfg(feature = "outbound-provider")]
        {
            let provider = self
                .find_provider(tag)
                .ok_or_else(|| ControlError::NoProvider(tag.to_string()))?;
            let dispatcher = self.dispatcher().ok_or(ControlError::Stopping)?;
            provider
                .update(&dispatcher)
                .await
                .map_err(|e| ControlError::UpdateFailed(format!("{:#}", e)))
        }
        #[cfg(not(feature = "outbound-provider"))]
        Err(ControlError::NoProvider(tag.to_string()))
    }

    /// The rule-sets, by tag.
    pub async fn rule_sets(&self) -> Vec<RuleSetInfo> {
        #[cfg(feature = "rule-set")]
        {
            use crate::config::rule_set::RuleSetKind;
            self.router()
                .rule_sets()
                .list()
                .into_iter()
                .map(|set| RuleSetInfo {
                    tag: set.tag,
                    source: match set.kind {
                        RuleSetKind::Remote => SourceKind::Remote,
                        RuleSetKind::Local => SourceKind::Local,
                        RuleSetKind::Inline => SourceKind::Inline,
                    },
                    format: set.format.map(|f| name_of(&f)),
                    behavior: set.behavior.map(|b| name_of(&b)),
                    rules: set.size,
                    updated: set.updated,
                    next_update: set.next_update,
                    failure: set.failure,
                })
                .collect()
        }
        #[cfg(not(feature = "rule-set"))]
        Vec::new()
    }

    /// Downloads the remote rule-set `tag` again; another kind is as it
    /// is. Done when it is.
    pub async fn update_rule_set(&self, tag: &str) -> Result<(), ControlError> {
        #[cfg(feature = "rule-set")]
        {
            let dispatcher = self.dispatcher().ok_or(ControlError::Stopping)?;
            match self.router().rule_sets().update(tag, &dispatcher).await {
                Ok(true) => Ok(()),
                Ok(false) => Err(ControlError::NoRuleSet(tag.to_string())),
                Err(e) => Err(ControlError::UpdateFailed(format!("{:#}", e))),
            }
        }
        #[cfg(not(feature = "rule-set"))]
        Err(ControlError::NoRuleSet(tag.to_string()))
    }
}

/// A unit enum's name as the configuration writes it.
#[cfg(feature = "rule-set")]
fn name_of<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_subscription_says_what_it_used_as_mihomo_reads_it() {
        let info = SubscriptionInfo::parse(
            "Upload=1024; download = 2048.7; total=10737418240; expire=1767225600; extra=x",
        );
        assert_eq!(info.upload, 1024);
        assert_eq!(info.download, 2048);
        assert_eq!(info.total, 10737418240);
        assert_eq!(
            info.expire,
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1767225600))
        );
        // A field that is no number is passed over; no expiry is none.
        let info = SubscriptionInfo::parse("upload=a;download=5;expire=0");
        assert_eq!((info.upload, info.download, info.expire), (0, 5, None));
        assert_eq!(
            SubscriptionInfo::parse("nothing"),
            SubscriptionInfo::default()
        );
    }
}
