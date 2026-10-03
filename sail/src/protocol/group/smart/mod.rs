//! `smart`: picks a member per connection by how the connections through
//! each have done lately, and keeps a site on the member that works for
//! it, as Surge's smart group does. A sail extension; Surge's `smart` and
//! the Mihomo fork's `Smart` groups are read into it.
//!
//! Each member has a score, in milliseconds, lower being better: its
//! latency, a moving average over time (half-life five minutes) of the
//! time from connecting through it to the first bytes back, plus a
//! penalty for recent failures (200 ms, doubled with each failure in a
//! row, halving every ten minutes, gone with the next success), times its
//! `policy_priority` factor. A member that has not been measured yet is
//! unknown: tried after those known to work, before those that failed.
//!
//! What is measured, of real connections:
//! - the time to connect through the member, until its stream is ready;
//!   a failure to connect is a failure, and a connect much slower than
//!   the member's average costs half a failure;
//! - for a connection sniffed as TLS or QUIC, the time from the client's
//!   first bytes (its hello) leaving to the first bytes back: the round
//!   trip through the member to the server. No answer within
//!   max(3 s, three average connects) is a failure;
//! - for any other connection, the time to the first bytes back after the
//!   client's first ones, at a fifth of the weight, and never a failure:
//!   it includes the time the server takes to think, which is not the
//!   member's doing.
//!
//! The members are also probed with an HTTP request, `url`, every
//! `interval`, at less weight: those nothing told of for the interval,
//! and those that failed, so that they recover; of a group of more than
//! twelve, the most used and those probed longest ago, twelve at most.
//!
//! A connection goes to its site's member, while that member has not
//! failed and is not more than twice as slow for the site as the best
//! member is, or is within the tolerance of it; else to one picked at random among the members whose score
//! is within `tolerance` ms or `tolerance_ratio` of the best. A site
//! whose first responses through its member are more than twice the
//! member's usual tries the next member on its next connection; after
//! three members, it stays on the best of them: the site is slow, not
//! the members. Sites are kept `site_ttl` after their last use,
//! `site_capacity` at most.
//!
//! A connection that fails to connect is tried again through the next
//! members, the rest of those up by score, then the unknown, then the
//! failed, three members at most. So is a TLS or QUIC one whose hello is
//! not answered in time, or is answered by the connection closing: the
//! client's bytes so far (16 KiB at most) are sent again through the next
//! member. Nothing is tried again once any byte reached the client. When
//! every member tried fails, none is blamed: the site is taken to be
//! down, and the members tried are probed soon. A connection is never
//! closed for another's sake; with `interrupt_exist_connections`, only
//! for its member leaving the group.
//!
//! Probes pause while the network is down. When it changes, the sites
//! forget their members, and the members their failures and connect
//! times, which were of the network before; their latencies are kept, as
//! they rank the members much as before, until new samples replace them;
//! and every member is probed at once, as urltest tests them.
//!
//! Where it differs from Surge: only the handshakes of TLS and QUIC count
//! against a member, since the first response of a plain connection
//! includes the server's think time; TCP retransmissions are not
//! measured; a failure blamed on every member tried is blamed on none;
//! no two members are raced for one connection; and sites are not kept
//! across restarts.

mod datagram;
mod score;
mod site;
mod stream;

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use futures::future::{abortable, BoxFuture};
use futures::FutureExt;
use lru_time_cache::LruCache;
use serde_derive::Deserialize;
use tokio::sync::{watch, Notify, RwLock};
use tokio::time::Instant;
use tracing::debug;

use self::score::MemberStats;
use self::site::{Rank, Site, Tolerance};
use super::interrupt::Until;
use super::members::{MemberKey, MemberLatencies, Members, Snapshot, Tested};
use super::merge;
use super::tell::Attempt;
use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{
    parse_options, Options, OutboundContext, OutboundFactory, OutboundRegistry,
};
use crate::adapter::*;
use crate::app::healthcheck::HttpProbe;
use crate::app::outbound::selector::{OutboundSelector, SelectedBy, Selection};
use crate::app::SyncDnsClient;
use crate::common::name_filter::NameFilter;
use crate::config::model::GroupProviders;
use crate::net::network::Network;
use crate::session::{Session, SniffedProtocol};

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register("smart", OutboundFactory::composite(dependencies, build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SmartOutboundOptions {
    /// Its members; none may be when its providers give others.
    #[serde(default)]
    outbounds: Vec<String>,
    /// Members from outbound providers too.
    #[serde(flatten)]
    providers: GroupProviders,
    /// What is requested through each member to probe it.
    #[serde(default = "default_url")]
    url: String,
    /// How often members nothing told of lately are probed; 5 minutes.
    #[serde(default, with = "crate::config::model::duration")]
    interval: Option<Duration>,
    /// How long a probe, or a connection attempt that has a member left to
    /// try, may take before its member counts as failed; 5 seconds.
    #[serde(default, with = "crate::config::model::duration")]
    timeout: Option<Duration>,
    /// Probes pause once the group has not been used for this long; 30
    /// minutes.
    #[serde(default, with = "crate::config::model::duration")]
    idle_timeout: Option<Duration>,
    /// Milliseconds: a member whose score is within this of the best may
    /// be picked.
    #[serde(default = "default_tolerance")]
    tolerance: u16,
    /// A member whose score is within this fraction of the best may be
    /// picked too, whichever of the two is the wider.
    #[serde(default = "default_tolerance_ratio")]
    tolerance_ratio: f32,
    /// Factors of the scores of the members whose names match a regular
    /// expression, the first that matches: below 1 prefers them, above 1
    /// avoids them. 1 for the others.
    #[serde(default)]
    policy_priority: Vec<PolicyPriority>,
    /// How long a site is kept on its member after its last connection;
    /// an hour.
    #[serde(default, with = "crate::config::model::duration")]
    site_ttl: Option<Duration>,
    /// How many sites are kept at most; the least recently used goes
    /// first.
    #[serde(default = "default_site_capacity")]
    site_capacity: usize,
    /// Destinations known by address alone are sites by their autonomous
    /// system, but those of CDNs, rather than by their network. Needs an
    /// ASN database: `asn.mmdb` in the asset directory, or `asn_file`.
    #[serde(default)]
    prefer_asn: bool,
    /// The ASN database, for `prefer_asn`; relative to the asset
    /// directory.
    #[serde(default)]
    asn_file: Option<String>,
    /// The first connection waits for the first probes, `timeout` at
    /// most, rather than going through a member not measured yet.
    #[serde(default)]
    evaluate_before_use: bool,
    /// Ends the connections through a member once it leaves the group.
    #[serde(default)]
    interrupt_exist_connections: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyPriority {
    /// Matched against the member's name, as Mihomo's filters are:
    /// lookarounds included, backtracking bounded.
    regex: String,
    /// Multiplies the member's score: above 0.
    factor: f64,
}

fn default_url() -> String {
    crate::app::healthcheck::DEFAULT_URL.to_string()
}

fn default_tolerance() -> u16 {
    30
}

fn default_tolerance_ratio() -> f32 {
    0.2
}

fn default_site_capacity() -> usize {
    4096
}

const DEFAULT_INTERVAL: Duration = Duration::from_secs(5 * 60);
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const DEFAULT_SITE_TTL: Duration = Duration::from_secs(60 * 60);
/// Members probed in one round at most, of a group that has more.
const MAX_PROBED: usize = 12;
/// A failure asks for probes again, but not more often than this.
const MIN_REPROBE: Duration = Duration::from_secs(2);
/// How often the member shown as selected is worked out again at most.
const REPORT_EVERY: Duration = Duration::from_secs(1);

fn dependencies(tag: &str, options: &Options) -> Result<Vec<String>> {
    let options: SmartOutboundOptions = parse_options("outbound", tag, options)?;
    Ok(options.providers.dependencies(options.outbounds))
}

/// The ASN database the group `tag` of `options` reads, for
/// `prefer_asn`; none if it reads none, or its options do not parse.
pub(crate) fn asn_file(tag: &str, options: &Options) -> Option<String> {
    let options: SmartOutboundOptions = parse_options("outbound", tag, options).ok()?;
    options.asn_file().map(String::from)
}

impl SmartOutboundOptions {
    /// `asn_file`, or `asn.mmdb`, with `prefer_asn`: relative to the data
    /// directory.
    fn asn_file(&self) -> Option<&str> {
        use crate::app::router::matcher::ASN_FILE;
        self.prefer_asn
            .then(|| self.asn_file.as_deref().unwrap_or(ASN_FILE))
    }
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let options: SmartOutboundOptions = ctx.options()?;
    let tag = ctx.tag;
    let error = |field: &str, why: &dyn std::fmt::Display| {
        anyhow!("[{}] outbound: {}: {}", tag, field, why)
    };
    let nonzero = |field: &str, value: Option<Duration>, default: Duration| match value {
        Some(d) if d.is_zero() => Err(error(field, &"must not be zero")),
        other => Ok(other.unwrap_or(default)),
    };
    let interval = nonzero("interval", options.interval, DEFAULT_INTERVAL)?;
    let timeout = nonzero("timeout", options.timeout, DEFAULT_TIMEOUT)?;
    let idle_timeout = nonzero("idle_timeout", options.idle_timeout, DEFAULT_IDLE_TIMEOUT)?;
    let site_ttl = nonzero("site_ttl", options.site_ttl, DEFAULT_SITE_TTL)?;
    if options.site_capacity == 0 {
        return Err(error("site_capacity", &"must be at least 1"));
    }
    if !(options.tolerance_ratio >= 0.0 && options.tolerance_ratio.is_finite()) {
        return Err(error("tolerance_ratio", &"must be 0 or more"));
    }
    let priorities = options
        .policy_priority
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let field = format!("policy_priority[{}]", i);
            if !(p.factor > 0.0 && p.factor.is_finite()) {
                return Err(error(&format!("{}.factor", field), &"must be above 0"));
            }
            let regex =
                NameFilter::new(&p.regex).map_err(|e| error(&format!("{}.regex", field), &e))?;
            Ok((regex, p.factor))
        })
        .collect::<Result<Vec<_>>>()?;
    if !options.prefer_asn && options.asn_file.is_some() {
        return Err(error("asn_file", &"only with prefer_asn"));
    }
    let asn = options
        .asn_file()
        .map(|file| {
            crate::app::router::matcher::open_mmdb(ctx.env, file)
                .map_err(|e| error("prefer_asn", &format!("needs the ASN database: {}", e)))
        })
        .transpose()?;
    let probe = HttpProbe::new(&options.url, ctx.dns_client.clone(), ctx.env)
        .map_err(|e| error("url", &e))?;

    let merged = merge::members(ctx, &options.outbounds, &options.providers)?;
    let members = merged.members.clone();
    let first = members
        .load()
        .members
        .first()
        .map(|m| m.key.clone())
        .unwrap_or_else(|| MemberKey::outbound(""));
    let selected = Arc::new(Selection::new(&first.name, first.clone()));
    let latencies = MemberLatencies::default();
    let group = Arc::new(Group {
        tag: tag.to_owned(),
        members: members.clone(),
        dns_client: ctx.dns_client.clone(),
        network: ctx.env.network.clone(),
        events: ctx.env.events.clone(),
        stats: Mutex::new(HashMap::new()),
        sites: Mutex::new(LruCache::with_expiry_duration_and_capacity(
            site_ttl,
            options.site_capacity,
        )),
        priorities,
        tolerance: Tolerance {
            ms: options.tolerance.into(),
            ratio: options.tolerance_ratio.into(),
        },
        timeout,
        asn,
        interrupt: options.interrupt_exist_connections,
        selected: selected.clone(),
        latencies: latencies.clone(),
        reported: Mutex::new(None),
        probes: Probes {
            interval,
            idle: idle_timeout,
            last_used: Mutex::new(Instant::now()),
            wake: Notify::new(),
            forced: AtomicBool::new(false),
            suspects: Mutex::new(HashSet::new()),
            evaluated: watch::Sender::new(false),
            evaluate_before_use: options.evaluate_before_use,
            task: Mutex::new(None),
        },
    });
    let (task, abort_handle) = abortable(probe_loop(Arc::downgrade(&group), probe));
    if let Ok(mut slot) = group.probes.task.lock() {
        *slot = Some(task.map(|_| ()).boxed());
    }
    group.start();
    ctx.abort_handles.push(abort_handle);
    merged.on_merged({
        let group = Arc::downgrade(&group);
        Box::new(move |snapshot, added| {
            if let Some(group) = group.upgrade() {
                group.merged(snapshot, added);
            }
        })
    });

    let outbound_selector = OutboundSelector::new(
        tag.to_owned(),
        members,
        selected,
        SelectedBy::Checks,
        Some(latencies),
    );
    ctx.selectors
        .insert(tag.to_owned(), Arc::new(RwLock::new(outbound_selector)));

    let handler = Arc::new(Handler(group));
    Ok(HandlerBuilder::default()
        .is_group(true)
        .tag(tag.to_owned())
        .stream_handler(handler.clone())
        .datagram_handler(handler)
        .build())
}

/// The probe loop's state.
struct Probes {
    interval: Duration,
    /// Probes pause once the group has not been used for this long, and
    /// resume, at once, when it is used again.
    idle: Duration,
    last_used: Mutex<Instant>,
    wake: Notify,
    /// Whether the next round runs even though the group is idle: the
    /// network changed.
    forced: AtomicBool,
    /// Members to probe in the next round whatever else is known of them:
    /// those tried for a connection that failed through every member.
    suspects: Mutex<HashSet<MemberKey>>,
    /// Whether the first round is done.
    evaluated: watch::Sender<bool>,
    evaluate_before_use: bool,
    /// The loop, until there is a runtime to spawn it on.
    task: Mutex<Option<BoxFuture<'static, ()>>>,
}

pub(super) struct Group {
    tag: String,
    members: Arc<Members>,
    dns_client: SyncDnsClient,
    /// Probes pause while it is down: the members are not failed for it.
    network: Network,
    stats: Mutex<HashMap<MemberKey, MemberStats>>,
    sites: Mutex<LruCache<String, Site>>,
    priorities: Vec<(NameFilter, f64)>,
    tolerance: Tolerance,
    timeout: Duration,
    asn: Option<Arc<maxminddb::Reader<Vec<u8>>>>,
    interrupt: bool,
    /// The member shown as selected: the one used most lately.
    selected: Arc<Selection>,
    /// The latencies shown with it.
    latencies: MemberLatencies,
    reported: Mutex<Option<Instant>>,
    probes: Probes,
    /// Where its members' failures are told.
    events: crate::control::events::EventHub,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Group {
    /// Spawns the probe loop, once there is a runtime: a configuration
    /// can be built without one, to be checked.
    fn start(&self) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        if let Some(task) = lock(&self.probes.task).take() {
            runtime.spawn(task);
        }
    }

    /// The factor of the member named `name`.
    fn priority(&self, name: &str) -> f64 {
        let mut warnings = Vec::new();
        let factor = self
            .priorities
            .iter()
            .find(|(regex, _)| regex.matches(name, &mut warnings))
            .map_or(1.0, |(_, factor)| *factor);
        for w in warnings {
            debug!("smart policy_priority: {}", w);
        }
        factor
    }

    fn with_stats<R>(&self, key: &MemberKey, f: impl FnOnce(&mut MemberStats) -> R) -> R {
        let now = Instant::now();
        let mut stats = lock(&self.stats);
        let s = stats
            .entry(key.clone())
            .or_insert_with(|| MemberStats::new(self.priority(&key.name), now));
        f(s)
    }

    fn with_site<R>(&self, site: &str, f: impl FnOnce(&mut Site) -> R) -> R {
        let mut sites = lock(&self.sites);
        f(sites.entry(site.to_string()).or_insert_with(Site::default))
    }

    /// The site of `sess`'s destination.
    fn site(&self, sess: &Session) -> String {
        let asn = self.asn.as_ref().map(|reader| {
            move |ip: IpAddr| {
                reader
                    .lookup(ip)
                    .and_then(|r| r.decode::<maxminddb::geoip2::Asn>())
                    .ok()
                    .flatten()
                    .and_then(|asn| asn.autonomous_system_number)
            }
        });
        site::key(
            sess,
            asn.as_ref().map(|f| f as &dyn Fn(IpAddr) -> Option<u32>),
        )
    }

    /// The members of `snapshot` a connection to `site` is tried through,
    /// in turn.
    fn plan(&self, snapshot: &Snapshot, site: &str) -> Vec<usize> {
        let now = Instant::now();
        let ranks: Vec<Rank> = {
            let mut stats = lock(&self.stats);
            snapshot
                .members
                .iter()
                .map(|m| {
                    let s = stats
                        .entry(m.key.clone())
                        .or_insert_with(|| MemberStats::new(self.priority(&m.key.name), now));
                    Rank {
                        key: m.key.clone(),
                        score: s.score(now),
                        failed: s.is_failed(now),
                    }
                })
                .collect()
        };
        self.with_site(site, |site| {
            site.retain(|key| snapshot.position(key).is_some());
            site::order(
                &ranks,
                Some(site),
                self.tolerance,
                now,
                &mut rand::thread_rng(),
            )
        })
    }

    /// Notes that the group is being used, which resumes paused probes.
    fn used(&self) {
        self.start();
        let now = Instant::now();
        let was_idle = {
            let mut last = lock(&self.probes.last_used);
            let idle = now.duration_since(*last) > self.probes.idle;
            *last = now;
            idle
        };
        if was_idle {
            self.probes.wake.notify_one();
        }
    }

    fn is_idle(&self) -> bool {
        lock(&self.probes.last_used).elapsed() > self.probes.idle
    }

    /// The network changed: what was learnt of it is forgotten, see the
    /// module's doc, and every member probed at once, idle as the group
    /// may be; unless it is down, when the change that ends that does.
    /// Twice is as once.
    fn network_changed(&self) {
        if self.network.is_down() {
            return;
        }
        let now = Instant::now();
        lock(&self.sites).clear();
        for s in lock(&self.stats).values_mut() {
            s.network_changed(now);
        }
        let snapshot = self.members.load();
        lock(&self.probes.suspects).extend(snapshot.members.iter().map(|m| m.key.clone()));
        self.start();
        self.probes.forced.store(true, Ordering::Relaxed);
        self.probes.wake.notify_one();
    }

    /// With `evaluate_before_use`, waits for the first probes, `timeout`
    /// at most.
    async fn evaluated(&self) {
        if !self.probes.evaluate_before_use {
            return;
        }
        let mut done = self.probes.evaluated.subscribe();
        let _ = tokio::time::timeout(self.timeout, done.wait_for(|done| *done)).await;
    }

    /// A connection through `member` to `site` took `took` to be ready.
    fn connected(&self, member: &MemberKey, site: &str, took: Duration) {
        let now = Instant::now();
        self.with_stats(member, |s| {
            s.used(now);
            if s.connected(took, now) {
                debug!("[{}] [{}] was slow to connect", self.tag, member.name);
            }
        });
        self.with_site(site, |s| s.connected(member, now));
        self.report(now);
    }

    /// The first bytes sent through `member` for `site` were answered
    /// after `latency`, connecting included; `weight` says how much the
    /// sample counts.
    fn answered(&self, member: &MemberKey, site: &str, latency: Duration, weight: f64) {
        let now = Instant::now();
        let usual = self.with_stats(member, |s| {
            let usual = s.latency();
            s.answered(latency, weight, now);
            usual
        });
        // Only a handshake tells how the member does for the site: other
        // first responses include the server's think time.
        let ms = latency.as_secs_f64() * 1000.0;
        self.with_site(site, |s| match weight >= 1.0 {
            true => s.answered(member, ms, usual, now),
            false => s.connected(member, now),
        });
    }

    /// A connection through `member` got an answer without a sample to
    /// tell: it works.
    fn succeeded(&self, member: &MemberKey) {
        self.with_stats(member, |s| s.succeeded(Instant::now()));
    }

    /// `member` failed a connection to `site`: it is tried last for the
    /// site for a while, whoever is to blame.
    fn failed_site(&self, member: &MemberKey, site: &str) {
        debug!("[{}] [{}] failed [{}]", self.tag, member.name, site);
        self.with_site(site, |s| s.failed(member, Instant::now()));
    }

    /// A connection through `members` failed, and one through another
    /// member did not: they are to blame.
    fn blame(&self, members: &[MemberKey]) {
        let now = Instant::now();
        for member in members {
            self.with_stats(member, |s| s.failed(now));
        }
        if !members.is_empty() {
            self.probes.wake.notify_one();
        }
    }

    /// A connection failed through every member tried, `members`: they
    /// are probed soon rather than blamed.
    fn suspect(&self, members: &[MemberKey]) {
        if members.is_empty() {
            return;
        }
        lock(&self.probes.suspects).extend(members.iter().cloned());
        self.probes.wake.notify_one();
    }

    /// How long a TLS or QUIC hello through `member` is given to be
    /// answered.
    fn first_byte_timeout(&self, member: &MemberKey) -> Duration {
        self.with_stats(member, |s| s.first_byte_timeout())
    }

    /// Shows the member used most lately as selected, and the latencies,
    /// once a `REPORT_EVERY` at most.
    fn report(&self, now: Instant) {
        {
            let mut reported = lock(&self.reported);
            if reported.is_some_and(|at| now.duration_since(at) < REPORT_EVERY) {
                return;
            }
            *reported = Some(now);
        }
        self.report_now(now);
    }

    fn report_now(&self, now: Instant) {
        let snapshot = self.members.load();
        let (most_used, latencies) = {
            let stats = lock(&self.stats);
            let most_used = snapshot
                .members
                .iter()
                .filter_map(|m| stats.get(&m.key).map(|s| (&m.key, s.uses(now))))
                .filter(|(_, uses)| *uses > 0.0)
                .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
                .map(|(key, _)| key.clone());
            let latencies: HashMap<MemberKey, Option<Duration>> = snapshot
                .members
                .iter()
                .filter_map(|m| {
                    let s = stats.get(&m.key)?;
                    let latency = match s.is_failed(now) {
                        true => None,
                        false => Some(Duration::from_secs_f64(s.latency()? / 1000.0)),
                    };
                    Some((m.key.clone(), latency))
                })
                .collect();
            (most_used, latencies)
        };
        if let Some(key) = most_used {
            if *self.selected.get() != key {
                self.selected.set(key);
            }
        }
        // A latency is as old as its last change: one that did not change
        // keeps its time, so the history shown does not move.
        let at = std::time::SystemTime::now();
        self.latencies.update(|tested| {
            let before = std::mem::take(tested);
            *tested = latencies
                .into_iter()
                .map(|(key, latency)| {
                    let t = match before.get(&key) {
                        Some(t) if t.latency == latency => *t,
                        _ => Tested { latency, at },
                    };
                    (key, t)
                })
                .collect();
            *tested != before
        });
    }

    /// The members changed: those gone are forgotten, and new ones probed
    /// soon.
    fn merged(&self, snapshot: &Snapshot, added: bool) {
        lock(&self.stats).retain(|key, _| snapshot.position(key).is_some());
        lock(&self.probes.suspects).retain(|key| snapshot.position(key).is_some());
        self.report_now(Instant::now());
        if added {
            self.probes.wake.notify_one();
        }
    }

    /// The members to probe in a round, by index into `snapshot`: those
    /// nothing told of for `interval`, and those failed or suspected; of
    /// more than `MAX_PROBED`, the most used, then those probed longest
    /// ago.
    fn to_probe(&self, snapshot: &Snapshot) -> Vec<usize> {
        let now = Instant::now();
        let suspects = std::mem::take(&mut *lock(&self.probes.suspects));
        let stats = lock(&self.stats);
        let fresh = MemberStats::new(1.0, now);
        let wanted: Vec<(usize, &MemberStats)> = snapshot
            .members
            .iter()
            .enumerate()
            .map(|(i, m)| (i, stats.get(&m.key).unwrap_or(&fresh)))
            .filter(|(i, s)| {
                suspects.contains(&snapshot.members[*i].key)
                    || s.is_failed(now)
                    || s.is_stale(self.probes.interval, now)
            })
            .collect();
        pick_probed(wanted, now)
    }

    /// Feeds a round of probes of `snapshot`'s members `probed` into their
    /// stats.
    fn probed(&self, snapshot: &Snapshot, probed: &[usize], results: &[Option<Duration>]) {
        let now = Instant::now();
        for (&i, result) in probed.iter().zip(results) {
            self.with_stats(&snapshot.members[i].key, |s| s.probed(*result, now));
        }
        debug!(
            "[{}] probed: {}",
            self.tag,
            probed
                .iter()
                .zip(results)
                .map(|(&i, l)| match l {
                    Some(l) => format!("{}({}ms)", snapshot.members[i].key.name, l.as_millis()),
                    None => format!("{}(failed)", snapshot.members[i].key.name),
                })
                .collect::<Vec<_>>()
                .join(" ")
        );
        self.report_now(now);
    }

    /// Tries `candidates` of `snapshot` in turn, with `connect`, until one
    /// connects; each but the last has `timeout`. Returns the one that
    /// did, how long it took, and what it connected; those that failed
    /// are added to `failed`.
    #[allow(clippy::too_many_arguments)]
    async fn try_members<T, F, Fut>(
        &self,
        sess: &Session,
        snapshot: &Snapshot,
        candidates: &[usize],
        site: &str,
        failed: &mut Vec<MemberKey>,
        tell: bool,
        connect: F,
    ) -> io::Result<(usize, Duration, T)>
    where
        F: Fn(AnyOutboundHandler) -> Fut,
        Fut: Future<Output = io::Result<T>>,
    {
        let mut last_error = None;
        for (n, &i) in candidates.iter().enumerate() {
            let member = &snapshot.members[i];
            debug!(
                "[{}] handles [{}:{}] to [{}]",
                self.tag, sess.network, sess.destination, member.key.name
            );
            let more = n + 1 < candidates.len();
            let told = tell.then(|| Attempt::start(sess, &member.key.name, more));
            let start = Instant::now();
            let attempt = connect(member.handler.clone());
            let result = if more {
                tokio::time::timeout(self.timeout, attempt)
                    .await
                    .unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "timed out")))
            } else {
                attempt.await
            };
            match result {
                Ok(v) => {
                    if let Some(told) = told {
                        told.connected(sess);
                    }
                    return Ok((i, start.elapsed(), v));
                }
                Err(e) => {
                    debug!(
                        "[{}] failed to handle [{}:{}] through [{}]: {}",
                        self.tag, sess.network, sess.destination, member.key.name, e
                    );
                    if let Some(told) = told {
                        let stage = crate::control::events::DialStage::guessed(e.kind());
                        told.failed(&self.events, sess, &e, stage);
                    }
                    self.failed_site(&member.key, site);
                    failed.push(member.key.clone());
                    last_error = Some(e);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| io::Error::other("no outbound to try")))
    }

    /// What ends a connection through `member`, with
    /// `interrupt_exist_connections`.
    fn until(&self, member: &MemberKey) -> Option<Until> {
        self.interrupt
            .then(|| Until::Removed(self.members.clone(), member.clone()))
    }
}

/// Of `wanted`, the members to probe with their stats, twelve at most:
/// half of them the most used, the rest those probed longest ago.
fn pick_probed(mut wanted: Vec<(usize, &MemberStats)>, now: Instant) -> Vec<usize> {
    if wanted.len() <= MAX_PROBED {
        return wanted.into_iter().map(|(i, _)| i).collect();
    }
    wanted.sort_by(|a, b| b.1.uses(now).partial_cmp(&a.1.uses(now)).unwrap());
    let mut picked: Vec<usize> = wanted[..MAX_PROBED / 2].iter().map(|(i, _)| *i).collect();
    let mut rest = wanted.split_off(MAX_PROBED / 2);
    rest.sort_by_key(|(i, s)| (s.last_probed, *i));
    picked.extend(rest.iter().take(MAX_PROBED - picked.len()).map(|(i, _)| *i));
    picked
}

/// Probes the members, `interval` apart or sooner when woken, while the
/// group is in use and there.
async fn probe_loop(group: Weak<Group>, probe: HttpProbe) {
    loop {
        let Some(g) = group.upgrade() else {
            return;
        };
        if g.network.is_down() {
            debug!("[{}] the network is down, probes paused", g.tag);
        } else if g.probes.forced.swap(false, Ordering::Relaxed) || !g.is_idle() {
            let snapshot = g.members.load();
            let probed = g.to_probe(&snapshot);
            if !probed.is_empty() {
                let probes = probed.iter().map(|&i| {
                    let member = &snapshot.members[i].handler;
                    let probe = &probe;
                    let dns_client = g.dns_client.clone();
                    let timeout = g.timeout;
                    async move {
                        tokio::time::timeout(timeout, probe.run(dns_client, member))
                            .await
                            .ok()
                            .and_then(Result::ok)
                    }
                });
                let results = futures::future::join_all(probes).await;
                g.probed(&snapshot, &probed, &results);
            }
            g.probes.evaluated.send_replace(true);
        } else {
            debug!("[{}] not used lately, probes paused", g.tag);
        }
        let probed_at = Instant::now();
        let interval = g.probes.interval;
        // Woken early by a failure, new members, use after a pause, or a
        // change of network.
        let woken = tokio::time::timeout(interval, g.probes.wake.notified())
            .await
            .is_ok();
        // A change of network is not a failure: no wait for it.
        let forced = g.probes.forced.load(Ordering::Relaxed);
        drop(g);
        if woken && !forced {
            tokio::time::sleep_until(probed_at + MIN_REPROBE.min(interval)).await;
        }
    }
}

/// The group as the outbound manager holds it.
struct Handler(Arc<Group>);

fn is_handshake(sess: &Session) -> bool {
    matches!(
        sess.sniffed_protocol,
        Some(SniffedProtocol::Tls | SniffedProtocol::Quic)
    )
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        // The member is picked, and dialled, per connection.
        OutboundConnect::Unknown
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        _stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        stream::connect(self.0.clone(), sess).await
    }

    /// Heard here only: the datagram side is the same group. Its members
    /// hear of it themselves.
    fn network_changed(&self, _change: &crate::net::network::NetworkChange) {
        self.0.network_changed();
    }
}

#[async_trait]
impl OutboundDatagramHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Unknown
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        datagram::connect(self.0.clone(), sess).await
    }
}

/// The failures of one connection, settled once it is answered, when the
/// members that failed are blamed, or ends unanswered, when they are only
/// suspected.
pub(super) struct Verdict {
    group: Arc<Group>,
    failed: Vec<MemberKey>,
    settled: bool,
}

impl Verdict {
    fn new(group: Arc<Group>, failed: Vec<MemberKey>) -> Self {
        Self {
            group,
            failed,
            settled: false,
        }
    }

    fn add(&mut self, member: MemberKey) {
        self.failed.push(member);
    }

    /// The connection was answered.
    fn answered(&mut self) {
        if !self.settled {
            self.settled = true;
            self.group.blame(&self.failed);
        }
    }
}

impl Drop for Verdict {
    fn drop(&mut self) {
        if !self.settled {
            self.group.suspect(&self.failed);
        }
    }
}

#[cfg(test)]
mod tests;
