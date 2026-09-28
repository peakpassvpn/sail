//! The members of a group that takes them from outbound providers too, as
//! Mihomo's proxy groups take a provider's proxies: its own outbounds,
//! then each provider's, filtered by name, and without those
//! `exclude_filter` and `exclude_type` leave out (see Mihomo's
//! `GroupBase.GetProxies`). They are merged again whenever a provider's
//! change: the group keeps members of its own, which a task republishes.
//!
//! A group that takes nothing from providers and leaves nothing out has
//! its outbounds as members, as ever, and no task.

use std::sync::Arc;

use anyhow::Result;

use super::members::{Members, Snapshot};
use crate::adapter::registry::OutboundContext;
use crate::config::model::GroupProviders;

/// Called after each merge but the first with the members merged, and
/// whether any of them is new.
pub type OnMerged = Box<dyn Fn(&Snapshot, bool) + Send + Sync>;

/// A group's members, and what merges them.
pub struct Merged {
    pub members: Arc<Members>,
    #[cfg(feature = "outbound-provider")]
    merge: Option<Arc<imp::Merge>>,
}

impl Merged {
    /// Calls `on_merged` after each merge from now on.
    #[cfg_attr(not(feature = "outbound-provider"), allow(unused_variables))]
    pub fn on_merged(&self, on_merged: OnMerged) {
        #[cfg(feature = "outbound-provider")]
        if let Some(merge) = &self.merge {
            merge.on_merged(on_merged);
        }
    }

    /// Whether providers give some of its members: members that may come
    /// later, or go.
    pub fn has_providers(&self) -> bool {
        #[cfg(feature = "outbound-provider")]
        return self.merge.as_ref().is_some_and(|m| m.has_providers());
        #[cfg(not(feature = "outbound-provider"))]
        false
    }
}

/// The members of the group `ctx` builds, which has `outbounds` of its
/// own and takes others as `providers` says.
pub fn members(
    ctx: &mut OutboundContext<'_>,
    outbounds: &[String],
    providers: &GroupProviders,
) -> Result<Merged> {
    if *providers == GroupProviders::default() {
        return Ok(Merged {
            members: Members::outbounds(outbounds, ctx.members(outbounds)?),
            #[cfg(feature = "outbound-provider")]
            merge: None,
        });
    }
    #[cfg(feature = "outbound-provider")]
    {
        let merge = imp::Merge::build(ctx, outbounds, providers)?;
        Ok(Merged {
            members: merge.members(),
            merge: Some(merge),
        })
    }
    #[cfg(not(feature = "outbound-provider"))]
    Err(anyhow::anyhow!(
        "[{}] outbound: {}: needs the outbound-provider feature, which is not compiled in",
        ctx.tag,
        providers.first_set().unwrap_or("providers")
    ))
}

/// Mihomo's name for the type of an outbound of `protocol` (constant
/// `AdapterType`), which `exclude_type` goes by. A protocol Mihomo does
/// not have keeps sail's name.
#[cfg(feature = "outbound-provider")]
pub fn mihomo_type(protocol: &str) -> &'static str {
    match protocol {
        "direct" => "Direct",
        "block" => "Reject",
        "shadowsocks" => "Shadowsocks",
        "socks" => "Socks5",
        "http" => "Http",
        "vmess" => "Vmess",
        "vless" => "Vless",
        "trojan" => "Trojan",
        "hysteria2" => "Hysteria2",
        "tuic" => "Tuic",
        "anytls" => "AnyTLS",
        "wireguard" => "WireGuard",
        "selector" => "Selector",
        "urltest" => "URLTest",
        "fallback" => "Fallback",
        "load-balance" => "LoadBalance",
        other => crate::include::OUTBOUNDS
            .name(other)
            .or_else(|| crate::include::ENDPOINTS.name(other))
            .unwrap_or("Unknown"),
    }
}

#[cfg(feature = "outbound-provider")]
mod imp {
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, Mutex, OnceLock};

    use anyhow::{anyhow, Result};
    use futures::future::{abortable, AbortHandle};
    use tokio::sync::watch;
    use tracing::{info, warn};

    use super::super::members::{Member, MemberKey, Members, Snapshot};
    use super::{mihomo_type, OnMerged};
    use crate::adapter::registry::OutboundContext;
    use crate::common::name_filter::NameFilter;
    use crate::config::model::GroupProviders;

    /// What groups take members from besides their outbounds, as the
    /// outbound manager builds them.
    #[derive(Default)]
    pub struct Sources {
        /// The members of each outbound provider, by its tag.
        pub providers: HashMap<String, Arc<Members>>,
        /// The protocol of each outbound, by tag, for `exclude_type`.
        pub protocols: HashMap<String, String>,
        /// The merges of the groups built, to merge again once the
        /// providers have their members.
        pub merges: Vec<Arc<Merge>>,
    }

    /// Merges a group's members from its outbounds and its providers'.
    pub struct Merge {
        tag: String,
        /// Its own outbounds: never filtered, as Mihomo's compatible
        /// provider is not.
        own: Vec<Member>,
        /// Its providers, each by tag.
        providers: Vec<(String, Arc<Members>)>,
        filters: Vec<NameFilter>,
        exclude: Vec<NameFilter>,
        /// Mihomo's type names, compared without case.
        exclude_types: Vec<String>,
        empty_fallback: Option<Member>,
        members: Arc<Members>,
        /// The providers' versions merged last.
        merged: Mutex<Option<Vec<u64>>>,
        on_merged: OnceLock<OnMerged>,
    }

    impl Merge {
        /// Merges the members of the group `ctx` builds a first time, and
        /// follows its providers from then on.
        pub fn build(
            ctx: &mut OutboundContext<'_>,
            outbounds: &[String],
            options: &GroupProviders,
        ) -> Result<Arc<Self>> {
            let tag = ctx.tag;
            let handlers = if options.providers.is_empty() {
                ctx.members(outbounds)?
            } else {
                ctx.actors(outbounds)?
            };
            let member = |tag: &str, handler, sources: &Sources| Member {
                key: MemberKey::outbound(tag),
                handler,
                kind: sources
                    .protocols
                    .get(tag)
                    .map(|p| mihomo_type(p))
                    .unwrap_or("Unknown"),
            };
            let own = outbounds
                .iter()
                .zip(handlers)
                .map(|(t, h)| member(t, h, ctx.providers))
                .collect();
            let providers = options
                .providers
                .iter()
                .map(|p| {
                    let members = ctx.providers.providers.get(p).cloned();
                    members.map(|m| (p.clone(), m)).ok_or_else(|| {
                        anyhow!(
                            "[{}] outbound: providers: provider [{}] does not exist",
                            tag,
                            p
                        )
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let filters = |field: &str, patterns: &[String]| {
                patterns
                    .iter()
                    .map(|p| NameFilter::new(p))
                    .collect::<Result<Vec<_>>>()
                    .map_err(|e| anyhow!("[{}] outbound: {}: {}", tag, field, e))
            };
            let empty_fallback = match &options.empty_fallback {
                Some(fallback) => Some(member(fallback, ctx.handler(fallback)?, ctx.providers)),
                None => None,
            };
            let merge = Arc::new(Merge {
                tag: tag.to_string(),
                own,
                providers,
                filters: filters("filter", &options.filter)?,
                exclude: filters("exclude_filter", &options.exclude_filter)?,
                exclude_types: options.exclude_type.clone(),
                empty_fallback,
                members: Members::of(Vec::new()),
                merged: Mutex::new(None),
                on_merged: OnceLock::new(),
            });
            merge.run();
            if !merge.providers.is_empty() {
                ctx.abort_handles.push(merge.follow());
                ctx.providers.merges.push(merge.clone());
            }
            Ok(merge)
        }

        pub fn tag(&self) -> &str {
            &self.tag
        }

        pub fn members(&self) -> Arc<Members> {
            self.members.clone()
        }

        pub fn has_providers(&self) -> bool {
            !self.providers.is_empty()
        }

        /// Its providers' members, each by the provider's tag.
        pub fn providers(&self) -> &[(String, Arc<Members>)] {
            &self.providers
        }

        pub fn on_merged(&self, on_merged: OnMerged) {
            let _ = self.on_merged.set(on_merged);
        }

        /// Merges the members again, unless no provider changed since.
        pub fn run(&self) {
            let snapshots: Vec<Arc<Snapshot>> =
                self.providers.iter().map(|(_, p)| p.load()).collect();
            let versions: Vec<u64> = snapshots.iter().map(|s| s.version).collect();
            let mut merged = self.merged.lock().unwrap_or_else(|e| e.into_inner());
            let first = merged.is_none();
            if merged.as_ref() == Some(&versions) {
                return;
            }
            *merged = Some(versions);
            let mut warnings = Vec::new();
            let mut members = self.merge(&snapshots, &mut warnings);
            if let Some(first) = warnings.first() {
                warn!(
                    "[{}] outbound: {}{}",
                    self.tag,
                    first,
                    match warnings.len() {
                        1 => String::new(),
                        n => format!(" (and {} more like it)", n - 1),
                    }
                );
            }
            if members.is_empty() {
                if let Some(fallback) = &self.empty_fallback {
                    info!(
                        "[{}] outbound: no member left; [{}] stands in",
                        self.tag, fallback.key.name
                    );
                    members.push(fallback.clone());
                }
            }
            let before = self.members.load();
            let added = members.iter().any(|m| before.position(&m.key).is_none());
            self.members.publish(members);
            if !first {
                if let Some(on_merged) = self.on_merged.get() {
                    on_merged(&self.members.load(), added);
                }
            }
        }

        /// The members, as Mihomo's `GetProxies` has them, but for the
        /// empty fallback.
        pub(super) fn merge(
            &self,
            providers: &[Arc<Snapshot>],
            warnings: &mut Vec<String>,
        ) -> Vec<Member> {
            let mut members = self.own.clone();
            for snapshot in providers {
                if self.filters.is_empty() {
                    members.extend(snapshot.members.iter().cloned());
                    continue;
                }
                // Each filter in turn, so that the members of the first
                // come first; a name once taken is not taken again.
                members.extend(by_filters(
                    &self.filters,
                    &snapshot.members,
                    false,
                    warnings,
                ));
            }
            // Mihomo reorders the whole list once more when there are
            // several providers, its own outbounds counting as one, and
            // several filters: by filter, then the rest, each name once.
            let sources = self.providers.len() + usize::from(!self.own.is_empty());
            if sources > 1 && self.filters.len() > 1 {
                members = by_filters(&self.filters, &members, true, warnings);
            }
            members.retain(|m| {
                !self
                    .exclude
                    .iter()
                    .any(|f| f.matches(&m.key.name, warnings))
            });
            members.retain(|m| {
                !self
                    .exclude_types
                    .iter()
                    .any(|t| t.eq_ignore_ascii_case(m.kind))
            });
            members
        }

        /// Merges again whenever a provider publishes, until aborted.
        fn follow(self: &Arc<Self>) -> AbortHandle {
            let merge = self.clone();
            let mut versions: Vec<watch::Receiver<u64>> =
                self.providers.iter().map(|(_, p)| p.subscribe()).collect();
            let (task, abort_handle) = abortable(async move {
                loop {
                    let changes = versions.iter_mut().map(|v| Box::pin(v.changed()));
                    let (changed, _, _) = futures::future::select_all(changes).await;
                    if changed.is_err() {
                        return;
                    }
                    merge.run();
                }
            });
            // A configuration is checked without a runtime: nothing to
            // follow then.
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(task);
            }
            abort_handle
        }
    }

    /// The members of `members` each filter matches, in turn, each name
    /// once; with `rest`, those none matches after them.
    fn by_filters(
        filters: &[NameFilter],
        members: &[Member],
        rest: bool,
        warnings: &mut Vec<String>,
    ) -> Vec<Member> {
        let mut taken = HashSet::new();
        let mut picked = Vec::new();
        for filter in filters {
            for m in members {
                if filter.matches(&m.key.name, warnings) && taken.insert(m.key.name.clone()) {
                    picked.push(m.clone());
                }
            }
        }
        if rest {
            for m in members {
                if taken.insert(m.key.name.clone()) {
                    picked.push(m.clone());
                }
            }
        }
        picked
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::protocol::group::members::tests::member;

        fn of(source: Option<&str>, name: &str, kind: &'static str) -> Member {
            Member {
                kind,
                ..member(source, name)
            }
        }

        fn provider(tag: &str, names: &[&str]) -> (String, Arc<Members>) {
            let members = names
                .iter()
                .map(|n| of(Some(tag), n, "Shadowsocks"))
                .collect();
            (tag.to_string(), Members::of(members))
        }

        fn filters(patterns: &[&str]) -> Vec<NameFilter> {
            patterns
                .iter()
                .map(|p| NameFilter::new(p).unwrap())
                .collect()
        }

        fn group(own: &[&str], providers: Vec<(String, Arc<Members>)>, filter: &[&str]) -> Merge {
            Merge {
                tag: "g".to_string(),
                own: own.iter().map(|n| of(None, n, "Direct")).collect(),
                providers,
                filters: filters(filter),
                exclude: Vec::new(),
                exclude_types: Vec::new(),
                empty_fallback: None,
                members: Members::of(Vec::new()),
                merged: Mutex::new(None),
                on_merged: OnceLock::new(),
            }
        }

        fn names(merge: &Merge) -> Vec<String> {
            merge.run();
            let snapshot = merge.members.load();
            let names = snapshot.members.iter().map(|m| match &m.key.source {
                Some(source) => format!("{}:{}", source, m.key.name),
                None => m.key.name.to_string(),
            });
            names.collect()
        }

        #[test]
        fn its_own_outbounds_come_first_and_unfiltered() {
            let merge = group(
                &["d"],
                vec![provider("p", &["HK 1", "JP 1"]), provider("q", &["HK 2"])],
                &[],
            );
            assert_eq!(names(&merge), ["d", "p:HK 1", "p:JP 1", "q:HK 2"]);
            let merge = group(
                &[],
                vec![provider("p", &["HK 1", "JP 1", "US 1", "JP 2"])],
                &["JP", "HK"],
            );
            assert_eq!(names(&merge), ["p:JP 1", "p:JP 2", "p:HK 1"]);
        }

        /// Mihomo's second pass: several providers, its own outbounds
        /// counting as one, and several filters order the whole list by
        /// filter, the rest after, each name once.
        #[test]
        fn several_providers_and_filters_order_the_whole_list() {
            let merge = group(
                &["d", "JP 0"],
                vec![
                    provider("p", &["HK 1", "JP 1"]),
                    provider("q", &["JP 1", "HK 2"]),
                ],
                &["JP", "HK"],
            );
            assert_eq!(names(&merge), ["JP 0", "p:JP 1", "p:HK 1", "q:HK 2", "d"]);
            // One provider and its own outbounds are two.
            let merge = group(
                &["d"],
                vec![provider("p", &["HK 1", "JP 1"])],
                &["JP", "HK"],
            );
            assert_eq!(names(&merge), ["p:JP 1", "p:HK 1", "d"]);
        }

        #[test]
        fn exclusions_apply_to_its_own_outbounds_too() {
            let mut merge = group(
                &["d", "HK x"],
                vec![provider("p", &["HK 1", "HK 2 IPLC"])],
                &[],
            );
            merge.exclude = filters(&["IPLC", "x$"]);
            merge.exclude_types = vec!["direct".to_string()];
            assert_eq!(names(&merge), ["p:HK 1"]);
        }

        #[test]
        fn the_empty_fallback_stands_in_for_no_member() {
            let (tag, members) = provider("p", &["HK 1"]);
            let mut merge = group(&[], vec![(tag, members.clone())], &["JP"]);
            assert!(names(&merge).is_empty());
            merge.empty_fallback = Some(of(None, "d", "Direct"));
            *merge.merged.lock().unwrap() = None;
            assert_eq!(names(&merge), ["d"]);
            members.publish(vec![of(Some("p"), "JP 1", "Vmess")]);
            assert_eq!(names(&merge), ["p:JP 1"]);
        }

        #[test]
        fn a_merge_follows_its_providers_versions() {
            let (tag, members) = provider("p", &["a"]);
            let merge = group(&[], vec![(tag, members.clone())], &[]);
            let added = Arc::new(Mutex::new(Vec::new()));
            merge.run();
            merge.on_merged({
                let added = added.clone();
                Box::new(move |_, new| added.lock().unwrap().push(new))
            });
            let version = merge.members.load().version;
            merge.run();
            assert_eq!(merge.members.load().version, version, "nothing changed");
            members.publish(vec![of(Some("p"), "a", "Http")]);
            merge.run();
            members.publish(vec![of(Some("p"), "a", "Http"), of(Some("p"), "b", "Http")]);
            merge.run();
            assert_eq!(*added.lock().unwrap(), [false, true]);
        }
    }
}

#[cfg(feature = "outbound-provider")]
pub use imp::{Merge, Sources};
