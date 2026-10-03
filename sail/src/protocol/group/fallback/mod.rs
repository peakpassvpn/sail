//! `fallback`: sends every connection to the first member, in the order
//! configured, that passed its last URL test, as Mihomo's fallback group
//! does. Members are tested every `interval`, through them, as `urltest`
//! tests them. When every member failed, the first takes the connections,
//! as in Mihomo.
//!
//! A connection that fails through the member selected is tried again
//! through the next members that are up, in order, a few times at most,
//! before it fails: a member can die between two tests. A failure that
//! says the member itself cannot be reached marks it down at once, see
//! `attempt::member_unreachable`, so that the next connection goes to the
//! next member without waiting for the tests, which run again to bring it
//! back up. Other failures are counted, and the members tested again after
//! `max_failed_times` of them, as Mihomo does.
//!
//! It can be pinned to a member by hand, through the API, as Mihomo's
//! can: it goes there while that member is up, and is unpinned once it is
//! down; the pin is kept across restarts in the cache file.
//!
//! Its `debounce`, a sail extension, keeps a member that flaps from
//! sending the connections back and forth: a member is left after
//! `fail_after` failed rounds in a row, taken back after `recover_after`
//! passed ones, and not left for an earlier one before the group has been
//! on it for `min_dwell`. A member marked down is left at once all the
//! same, and a pin goes by the member's last test.
//!
//! Its `url` may list several URLs, a sail extension: a member passes
//! when `any` of them answers, or, `url_policy: "all"`, every one.
//!
//! Its `dial_timeout`, a sail extension, is how long a connection attempt
//! through a member may take before the group moves on to the next, apart
//! from `timeout`, which its tests take: a member whose server does not
//! answer the dial in time is marked down.

use std::future::Future;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_derive::Deserialize;
use tokio::sync::{watch, RwLock};
use tokio::time::Instant;
use tracing::{debug, info, warn};

use super::attempt::{member_unreachable, Progress};
use super::health::{self, Checker, Debounce, Probes, UrlPolicy};
use super::members::{MemberKey, Members, Snapshot};
use super::merge;
use super::tell::Attempt;
use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{
    parse_options, Options, OutboundContext, OutboundFactory, OutboundRegistry,
};
use crate::adapter::*;
use crate::app::healthcheck::{HttpProbe, StatusRanges};
use crate::app::outbound::selector::{GroupPin, OutboundSelector, SelectedBy, Selection};
use crate::app::SyncDnsClient;
use crate::config::model::GroupProviders;
use crate::net::{connect_datagram_outbound, connect_stream_outbound, dial_domain};
use crate::runtime::cache_file::CacheFile;
use crate::session::Session;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register("fallback", OutboundFactory::composite(dependencies, build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FallbackOutboundOptions {
    /// Its members, in order; none may be when its providers give
    /// others.
    #[serde(default)]
    outbounds: Vec<String>,
    /// Members from outbound providers too, a sail extension.
    #[serde(flatten)]
    providers: GroupProviders,
    /// What is requested through each member to test it: a URL, or a
    /// list of them, a sail extension, all tested at once in each round.
    /// The latency shown is the first URL's, and the API shows it as the
    /// group's `testUrl`.
    #[serde(default = "default_url", with = "crate::config::model::listable")]
    url: Vec<String>,
    /// With several URLs, which a member must answer to pass: `any` of
    /// them, which tells a dead member from a URL blocked, or `all`; a
    /// sail extension. Under `any`, the latency shown is that of the first
    /// URL that answered.
    #[serde(default)]
    url_policy: UrlPolicy,
    /// The HTTP statuses a test must be answered with to pass, as
    /// Mihomo's `expected-status`: codes and ranges, `200/204/401-429`;
    /// any when unset. Each URL's answer must be one.
    #[serde(default)]
    expected_status: Option<String>,
    #[serde(default, with = "crate::config::model::duration")]
    interval: Option<Duration>,
    /// How long a test may take before its member counts as failed; 5s,
    /// as Mihomo's `timeout`. Also how close together `max_failed_times`
    /// failures must come, and `dial_timeout` when that is unset.
    #[serde(default, with = "crate::config::model::duration")]
    timeout: Option<Duration>,
    /// How long a connection attempt through a member, with a member left
    /// to fall back to, may take before the group moves on to the next; a
    /// sail extension, 1s at least, `timeout` when unset. One still
    /// dialling the member's server then marks it down at once; one in
    /// the member's handshake is counted toward `max_failed_times`.
    #[serde(default, with = "crate::config::model::duration")]
    dial_timeout: Option<Duration>,
    /// How many failed connections, within `timeout` of the first, have
    /// the members tested again; 5, as Mihomo's `max-failed-times`. Only
    /// failures that may be the destination's count: one that says the
    /// member's server cannot be reached marks the member down at once.
    #[serde(default)]
    max_failed_times: Option<u32>,
    /// Tests only while the group is in use: not when it was not used
    /// since the last ones.
    #[serde(default = "default_lazy")]
    lazy: bool,
    /// Ends the connections through the member left once the group
    /// switches.
    #[serde(default)]
    interrupt_exist_connections: bool,
    /// How many rounds of tests in a row have the group leave a member,
    /// or take an earlier one back, and how long it stays on a member at
    /// least; a sail extension. Unset, every round counts at once.
    #[serde(default)]
    debounce: DebounceOptions,
}

/// A fallback's `debounce`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DebounceOptions {
    /// Failed rounds in a row before the member the group is on is left,
    /// by default one. A connection that finds its server unreachable
    /// leaves it at once all the same.
    #[serde(default = "one")]
    fail_after: u32,
    /// Passed rounds in a row before a member that was down, failed or
    /// found unreachable, is up again, and taken back if it comes first,
    /// by default one.
    #[serde(default = "one")]
    recover_after: u32,
    /// The least time on a member before the group leaves it, while it is
    /// up, for an earlier member up again; 0s. The first round past it
    /// switches. A member down is left at once.
    #[serde(default, with = "crate::config::model::duration")]
    min_dwell: Option<Duration>,
}

impl Default for DebounceOptions {
    fn default() -> Self {
        Self {
            fail_after: 1,
            recover_after: 1,
            min_dwell: None,
        }
    }
}

fn one() -> u32 {
    1
}

fn default_url() -> Vec<String> {
    vec![health::DEFAULT_URL.to_string()]
}

fn default_lazy() -> bool {
    true
}

/// How many members one connection is tried through at most.
const MAX_ATTEMPTS: usize = 3;

/// The least `dial_timeout`: TCP waits 1s before it sends a lost SYN again
/// (RFC 6298's initial RTO), so a shorter one marks a member down for a
/// single lost packet.
const MIN_DIAL_TIMEOUT: Duration = Duration::from_secs(1);

fn dependencies(tag: &str, options: &Options) -> Result<Vec<String>> {
    let options: FallbackOutboundOptions = parse_options("outbound", tag, options)?;
    Ok(options.providers.dependencies(options.outbounds))
}

/// The member the group goes to, of members `up` or not: the one
/// `pinned`, while it is up; else the first up, in order; else, every
/// member down, `first`, as Mihomo's fallback takes its first
/// (adapter/outboundgroup/fallback.go, `findAliveProxy`).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Choice {
    pub member: usize,
    /// The pinned member is down: the pin goes.
    pub unpin: bool,
}

pub(crate) fn choose(up: &[bool], pinned: Option<usize>, first: usize) -> Choice {
    let unpin = pinned.is_some_and(|p| !up[p]);
    let member = pinned
        .filter(|&p| up[p])
        .or_else(|| up.iter().position(|&u| u))
        .unwrap_or(first);
    Choice { member, unpin }
}

/// What has the group choose again.
enum Cause {
    /// A round of tests.
    Round,
    /// A connection found a member down; why.
    Failed(String),
    /// Its members changed.
    Merged,
    /// It was pinned or unpinned by hand.
    Hand,
}

/// How the group chooses its member, shared by its tests, its connections
/// and its selector.
struct Choosing {
    tag: String,
    selected: Arc<Selection>,
    /// The member pinned by hand, by name, as Mihomo pins it.
    pinned: Mutex<Option<Arc<str>>>,
    /// Where the pin is kept across restarts.
    cache_file: Option<Arc<CacheFile>>,
    /// The least time on a member before the group leaves it, while it is
    /// up, for an earlier one.
    min_dwell: Duration,
    /// When the group went to the member it is on.
    since: Mutex<Instant>,
    /// Where its switches are told.
    events: crate::control::events::EventHub,
}

impl Choosing {
    fn new(
        tag: &str,
        selected: Arc<Selection>,
        pinned: Option<Arc<str>>,
        cache_file: Option<Arc<CacheFile>>,
        min_dwell: Duration,
        events: crate::control::events::EventHub,
    ) -> Self {
        Self {
            tag: tag.to_owned(),
            selected,
            pinned: Mutex::new(pinned),
            cache_file,
            min_dwell,
            since: Mutex::new(Instant::now()),
            events,
        }
    }

    fn pinned(&self) -> Option<Arc<str>> {
        self.pinned
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Sets the pin, and keeps it.
    fn set_pin(&self, name: Option<&str>) -> Option<Arc<str>> {
        let previous = std::mem::replace(
            &mut *self.pinned.lock().unwrap_or_else(|e| e.into_inner()),
            name.map(Into::into),
        );
        if let Some(cache_file) = &self.cache_file {
            if let Err(e) = cache_file.store_selected(&self.tag, name.unwrap_or_default()) {
                warn!("[{}] pin will not be kept: {}", self.tag, e);
            }
        }
        previous
    }

    /// Moves the group to the member `choose` names, of the members of
    /// `snapshot`, up or not as `checker` has them (see `chooses_up`),
    /// unless the group would leave a member up for an earlier one before
    /// `min_dwell`; drops a pin whose member is down; logs why, `cause`
    /// telling.
    fn settle(&self, checker: &Checker, snapshot: &Snapshot, cause: Cause) {
        let Some(first) = snapshot.first_up().and_then(|m| snapshot.position(&m.key)) else {
            return;
        };
        let standing = up(checker, snapshot);
        let passed: Vec<bool> = snapshot
            .members
            .iter()
            .map(|m| !m.handler.is_pass() && checker.passed(&m.key))
            .collect();
        let pinned_name = self.pinned();
        let pinned = pinned_name
            .as_ref()
            .and_then(|name| snapshot.find(name))
            .and_then(|m| snapshot.position(&m.key));
        let up = chooses_up(&standing, &passed, pinned);
        let choice = choose(&up, pinned, first);
        if choice.unpin {
            // Mihomo drops it as it finds the member down; the cache keeps
            // it, as Mihomo's does, until it is unpinned or pinned again.
            *self.pinned.lock().unwrap_or_else(|e| e.into_inner()) = None;
            if let Some(name) = &pinned_name {
                info!(
                    "[{}] is no longer pinned to [{}]: it is down",
                    self.tag, name
                );
            }
        }
        let current = self.selected.get();
        let current_at = snapshot.position(&current);
        let next = &snapshot.members[choice.member].key;
        let pin_holds = pinned == Some(choice.member);
        if *next == *current {
            if matches!(cause, Cause::Round) && !pin_holds {
                self.held_back(checker, snapshot, &up, &passed, current_at);
            }
            return;
        }
        // The group leaves a member up for an earlier one by itself: not
        // before it has been on it for `min_dwell`.
        let by_hand = choice.unpin || pin_holds || matches!(cause, Cause::Hand);
        if !by_hand && current_at.is_some_and(|i| up[i]) {
            let on_it = self
                .since
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .elapsed();
            if on_it < self.min_dwell {
                debug!(
                    "[{}] stays on [{}]: on it for {:?} of min_dwell {:?}, [{}] is up",
                    self.tag, current.name, on_it, self.min_dwell, next.name
                );
                return;
            }
        }
        let reason = {
            use crate::control::events::SwitchReason as R;
            if choice.unpin {
                R::MemberDown
            } else if pin_holds {
                R::Pinned
            } else if !up.iter().any(|&u| u) {
                R::AllDown
            } else {
                match &cause {
                    Cause::Round if current_at.is_some_and(|i| !up[i]) => R::TestFailed,
                    Cause::Round => R::Recovered,
                    Cause::Failed(_) => R::MemberDown,
                    Cause::Merged => R::MembersChanged,
                    Cause::Hand => R::Unpinned,
                }
            }
        };
        let why = if choice.unpin {
            "the member pinned is down".to_string()
        } else if pin_holds {
            format!("it is pinned to [{}]", next.name)
        } else if !up.iter().any(|&u| u) {
            "no member is up: the first takes the connections".to_string()
        } else {
            match cause {
                Cause::Round => {
                    let debounce = checker.debounce();
                    match current_at.is_some_and(|i| !up[i]) {
                        true if debounce.fail_after > 1 => format!(
                            "[{}] failed {} rounds in a row",
                            current.name, debounce.fail_after
                        ),
                        true => format!("[{}] failed its test", current.name),
                        false if debounce.recover_after > 1 || !self.min_dwell.is_zero() => {
                            format!("[{}] is up again and comes first", next.name)
                        }
                        false => format!("[{}] passed its test and comes first", next.name),
                    }
                }
                Cause::Failed(why) => why,
                Cause::Merged => "its members changed".to_string(),
                Cause::Hand => "it was unpinned".to_string(),
            }
        };
        info!(
            "[{}] switches from [{}] to [{}]: {}",
            self.tag, current.name, next.name, why
        );
        self.selected.set(next.clone());
        *self.since.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
        // TODO: the enclosing groups' tags before its own, when a group
        // knows them; its tag alone until then.
        self.events
            .group_switched(crate::control::events::GroupSwitch::new(
                self.tag.clone(),
                Some(current.name.to_string()),
                next.name.to_string(),
                reason,
            ));
    }

    /// Logs why, after a round, the group stays on the member at
    /// `current`, up, though its last test says otherwise: it failed fewer
    /// than `fail_after` rounds in a row, or an earlier member passed
    /// fewer than `recover_after`.
    fn held_back(
        &self,
        checker: &Checker,
        snapshot: &Snapshot,
        up: &[bool],
        passed: &[bool],
        current: Option<usize>,
    ) {
        let Some(at) = current.filter(|&i| up[i]) else {
            return;
        };
        let debounce = checker.debounce();
        let against = |i: usize| {
            checker
                .standing(&snapshot.members[i].key)
                .map_or(0, |s| s.against)
        };
        let name = &snapshot.members[at].key.name;
        if let Some(i) = (0..at).find(|&i| passed[i] && !up[i]) {
            debug!(
                "[{}] stays on [{}]: [{}] passed {} of {} rounds",
                self.tag,
                name,
                snapshot.members[i].key.name,
                against(i),
                debounce.recover_after
            );
        }
        if !passed[at] {
            debug!(
                "[{}] stays on [{}]: it failed {} of {} rounds",
                self.tag,
                name,
                against(at),
                debounce.fail_after
            );
        }
    }
}

/// Whether each member of `snapshot` stands up, as `checker` has them; a
/// `pass` outbound never does.
fn up(checker: &Checker, snapshot: &Snapshot) -> Vec<bool> {
    snapshot
        .members
        .iter()
        .map(|m| !m.handler.is_pass() && checker.is_up(&m.key))
        .collect()
}

/// Whether each member is up for the group to choose, of those that
/// `standing` up or not and `passed` their last test or not: as they
/// stand; but when none stands up, as their last test has it, a member
/// that passed taken over the first, down; and the member `pinned` up if
/// either says so, the pin overriding the debounce.
pub(crate) fn chooses_up(standing: &[bool], passed: &[bool], pinned: Option<usize>) -> Vec<bool> {
    let mut up = match standing.iter().any(|&u| u) {
        true => standing.to_vec(),
        false => passed.to_vec(),
    };
    if let Some(p) = pinned {
        up[p] = standing[p] || passed[p];
    }
    up
}

/// The group's pin, for its selector, which the API pins and unpins it
/// through.
struct Pin {
    choosing: Arc<Choosing>,
    checker: Arc<Checker>,
    members: Arc<Members>,
}

impl GroupPin for Pin {
    /// Pins the group there: it goes there at once if the member is up,
    /// or passed its last test, whatever the debounce; else it is tested
    /// again at once, as Mihomo tests it, and the group goes there if it
    /// passes, or drops the pin if not.
    fn pin(&self, name: &str) -> Result<()> {
        let snapshot = self.members.load();
        let Some(member) = snapshot.find(name) else {
            return Err(anyhow!(
                "[{}] has no outbound [{}]",
                self.choosing.tag,
                name
            ));
        };
        self.choosing.set_pin(Some(name));
        info!("[{}] is pinned to [{}]", self.choosing.tag, name);
        let up = !member.handler.is_pass()
            && (self.checker.is_up(&member.key) || self.checker.passed(&member.key));
        if up {
            self.choosing.settle(&self.checker, &snapshot, Cause::Hand);
        } else {
            self.checker.retest();
        }
        Ok(())
    }

    fn unpin(&self) {
        if let Some(name) = self.choosing.set_pin(None) {
            info!("[{}] is no longer pinned to [{}]", self.choosing.tag, name);
            self.choosing
                .settle(&self.checker, &self.members.load(), Cause::Hand);
        }
    }

    fn pinned(&self) -> Option<String> {
        self.choosing.pinned().map(|name| name.to_string())
    }
}

/// A pin kept across a restart in `cache_file`, if any.
fn kept_pin(tag: &str, cache_file: Option<&CacheFile>) -> Option<Arc<str>> {
    match cache_file?.load_selected(tag) {
        Ok(name) => name.filter(|n| !n.is_empty()).map(Into::into),
        Err(e) => {
            warn!(
                "[{}] outbound: pin kept in the cache file not read: {}",
                tag, e
            );
            None
        }
    }
}

/// The members a connection is tried through, in turn: the one selected,
/// then the others that are up in the order configured, or, when none is,
/// all of them, since a test can be wrong and trying beats refusing.
pub(crate) fn candidates(
    selected: usize,
    members: usize,
    is_up: impl Fn(usize) -> bool,
) -> Vec<usize> {
    let any_up = (0..members).any(&is_up);
    std::iter::once(selected)
        .chain((0..members).filter(|&i| i != selected && (!any_up || is_up(i))))
        .take(MAX_ATTEMPTS)
        .collect()
}

/// The time a member but the last one tried has to connect: the
/// `dial_timeout` configured, 1s at least, or `timeout`.
fn dial_timeout(configured: Option<Duration>, timeout: Duration) -> Result<Duration> {
    match configured {
        Some(d) if d < MIN_DIAL_TIMEOUT => Err(anyhow!(
            "must be {:?} at least: a shorter one takes a lost packet for a member down",
            MIN_DIAL_TIMEOUT
        )),
        Some(d) => Ok(d),
        None => Ok(timeout),
    }
}

/// What the group does after each round of tests: it chooses again.
fn on_tested(choosing: Arc<Choosing>) -> health::OnTested {
    Box::new(
        move |checker: &Checker, snapshot: &Snapshot, _: &[Option<Duration>]| {
            choosing.settle(checker, snapshot, Cause::Round);
        },
    )
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let options: FallbackOutboundOptions = ctx.options()?;
    let merged = merge::members(ctx, &options.outbounds, &options.providers)?;
    let members = merged.members.clone();
    let interval = options.interval.unwrap_or(health::DEFAULT_INTERVAL);
    let timeout = options.timeout.unwrap_or(health::DEFAULT_TIMEOUT);
    let max_failed_times = options
        .max_failed_times
        .unwrap_or(health::DEFAULT_MAX_FAILED_TIMES);
    if interval.is_zero() {
        return Err(anyhow!(
            "[{}] outbound: interval: must not be zero",
            ctx.tag
        ));
    }
    if timeout.is_zero() {
        return Err(anyhow!("[{}] outbound: timeout: must not be zero", ctx.tag));
    }
    if max_failed_times == 0 {
        return Err(anyhow!(
            "[{}] outbound: max_failed_times: must not be zero",
            ctx.tag
        ));
    }
    let dial_timeout = dial_timeout(options.dial_timeout, timeout)
        .map_err(|e| anyhow!("[{}] outbound: dial_timeout: {}", ctx.tag, e))?;
    let debounce = Debounce {
        fail_after: options.debounce.fail_after,
        recover_after: options.debounce.recover_after,
    };
    for (field, value) in [
        ("fail_after", debounce.fail_after),
        ("recover_after", debounce.recover_after),
    ] {
        if value == 0 {
            return Err(anyhow!(
                "[{}] outbound: debounce.{}: must not be zero",
                ctx.tag,
                field
            ));
        }
    }
    let min_dwell = options.debounce.min_dwell.unwrap_or_default();
    let expected = StatusRanges::parse(options.expected_status.as_deref().unwrap_or_default())
        .map_err(|e| anyhow!("[{}] outbound: expected_status: {}", ctx.tag, e))?;
    if options.url.is_empty() {
        return Err(anyhow!(
            "[{}] outbound: url: must name one URL at least",
            ctx.tag
        ));
    }
    let probes = options
        .url
        .iter()
        .map(|url| {
            HttpProbe::new(url, ctx.dns_client.clone(), ctx.env)
                .map(|probe| probe.expecting(expected.clone()))
                .map_err(|e| anyhow!("[{}] outbound: url: {}", ctx.tag, e))
        })
        .collect::<Result<Vec<_>>>()?;
    let probes = Probes::new(probes, options.url_policy);

    // The member pinned before the restart, if any, else the first, until
    // the first tests are done.
    let cache_file = ctx.env.cache_file.get();
    let pinned = kept_pin(ctx.tag, cache_file.as_deref());
    let snapshot = members.load();
    let first = pinned
        .as_ref()
        .and_then(|name| snapshot.find(name))
        .filter(|m| !m.handler.is_pass())
        .or_else(|| snapshot.first_up())
        .map(|m| m.key.clone())
        .unwrap_or_else(|| MemberKey::outbound(""));
    let selected = Arc::new(Selection::new(&first.name, first.clone()));
    let choosing = Arc::new(Choosing::new(
        ctx.tag,
        selected.clone(),
        pinned,
        cache_file,
        min_dwell,
        ctx.env.events.clone(),
    ));
    let on_tested = on_tested(choosing.clone());
    let (checker, abort_handle) = Checker::new(
        ctx.tag,
        members.clone(),
        probes,
        ctx.dns_client.clone(),
        ctx.env.network.clone(),
        interval,
        timeout,
        max_failed_times,
        options.lazy.then_some(interval),
        debounce,
        on_tested,
    );
    ctx.abort_handles.push(abort_handle);
    merged.on_merged({
        let choosing = choosing.clone();
        let checker = checker.clone();
        Box::new(move |snapshot, added| {
            // The first member up in the new order, new ones untested and
            // so taken to be up.
            choosing.settle(&checker, snapshot, Cause::Merged);
            if added {
                checker.retest();
            }
        })
    });

    let outbound_selector = OutboundSelector::new(
        ctx.tag.to_owned(),
        members.clone(),
        selected.clone(),
        SelectedBy::Checks,
        Some(checker.latencies()),
    )
    .with_checks(checker.clone())
    .with_pin(Arc::new(Pin {
        choosing: choosing.clone(),
        checker: checker.clone(),
        members: members.clone(),
    }));
    ctx.selectors
        .insert(ctx.tag.to_owned(), Arc::new(RwLock::new(outbound_selector)));

    let group = Arc::new(Group {
        tag: ctx.tag.to_owned(),
        members,
        interrupt: options
            .interrupt_exist_connections
            .then(|| selected.subscribe()),
        selected,
        choosing,
        checker,
        dial_timeout,
        dns_client: ctx.dns_client.clone(),
    });
    Ok(HandlerBuilder::default()
        .is_group(true)
        .tag(ctx.tag.to_owned())
        .stream_handler(group.clone())
        .datagram_handler(group)
        .build())
}

struct Group {
    tag: String,
    members: Arc<Members>,
    selected: Arc<Selection>,
    choosing: Arc<Choosing>,
    checker: Arc<Checker>,
    /// How long a member but the last one tried has to connect.
    dial_timeout: Duration,
    dns_client: SyncDnsClient,
    interrupt: Option<watch::Receiver<MemberKey>>,
}

impl Group {
    /// Connects through the members of `snapshot` in turn, see
    /// `candidates`, until one connects; returns which, and what it
    /// connected. Every member but the last one tried has `dial_timeout`
    /// to connect. `connect` tells how far it got, see `Progress`. Each
    /// member is in the session's chain while it is tried, and its
    /// failure told (`tell::Attempt`).
    async fn connect<'a, T, F, Fut>(
        &'a self,
        sess: &'a Session,
        snapshot: &'a Snapshot,
        connect: F,
    ) -> io::Result<(&'a MemberKey, T)>
    where
        F: Fn(&'a AnyOutboundHandler, Arc<Progress>) -> Fut,
        Fut: Future<Output = io::Result<T>>,
    {
        self.checker.used();
        let Some((selected, _)) = self.selected.pick(snapshot) else {
            return Err(io::Error::other("no outbound to try"));
        };
        let order = candidates(selected, snapshot.members.len(), |i| {
            let member = &snapshot.members[i];
            !member.handler.is_pass() && self.checker.is_up(&member.key)
        });
        let mut last_error = None;
        for (n, &i) in order.iter().enumerate() {
            let a = &snapshot.members[i].handler;
            debug!(
                "[{}] handles [{}:{}] to [{}]",
                self.tag,
                sess.network,
                sess.destination,
                a.tag()
            );
            let more = n + 1 < order.len();
            let attempt = Attempt::start(sess, &snapshot.members[i].key.name, more);
            let progress = Arc::new(Progress::default());
            let result = if more {
                tokio::time::timeout(self.dial_timeout, connect(a, progress.clone()))
                    .await
                    .unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "timed out")))
            } else {
                connect(a, progress.clone()).await
            };
            match result {
                Ok(v) => {
                    attempt.connected(sess);
                    self.checker.succeeded();
                    return Ok((&snapshot.members[i].key, v));
                }
                Err(e) => {
                    debug!(
                        "[{}] failed to handle [{}:{}] through [{}]: {}",
                        self.tag,
                        sess.network,
                        sess.destination,
                        a.tag(),
                        e
                    );
                    attempt.failed(
                        &self.choosing.events,
                        sess,
                        &e,
                        progress.failed_at(e.kind()),
                    );
                    // A member that cannot be reached is down now, and the
                    // next connection goes elsewhere, the tests asked to
                    // bring it back; other failures, which may be the
                    // destination's, are counted, and enough have the
                    // members tested.
                    let key = &snapshot.members[i].key;
                    if member_unreachable(progress.get(), e.kind()) {
                        if self.checker.mark_down(key) {
                            let why = format!("a connection through [{}] failed: {}", key.name, e);
                            self.choosing
                                .settle(&self.checker, snapshot, Cause::Failed(why));
                        }
                    } else {
                        self.checker.failed();
                    }
                    last_error = Some(e);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| io::Error::other("no outbound to try")))
    }

    /// The selection a connection through `member` watches, to end when
    /// the group moves off it: only one through the member selected, since
    /// one that fell back to another is already off it.
    fn interrupt(&self, member: &MemberKey) -> Option<&watch::Receiver<MemberKey>> {
        self.interrupt
            .as_ref()
            .filter(|selection| *selection.borrow() == *member)
    }
}

#[async_trait]
impl OutboundStreamHandler for Group {
    fn connect_addr(&self) -> OutboundConnect {
        // The member is picked, and dialled, per connection.
        OutboundConnect::Unknown
    }

    /// Tests the members again, as sing-box's urltest does on a change of
    /// interface. Heard here only: the datagram side is the same group.
    /// Its members hear of it themselves.
    fn network_changed(&self, _change: &crate::net::network::NetworkChange) {
        self.checker.network_changed();
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        _stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        let snapshot = self.members.load();
        let (member, stream) = self
            .connect(sess, &snapshot, |a, progress| async move {
                let connect = a.stream()?.connect_addr();
                progress.dialing(&connect);
                let at = dial_domain::session(sess, a, &connect);
                let result = async {
                    let stream = connect_stream_outbound(&at, self.dns_client.clone(), a).await?;
                    progress.dialled();
                    a.stream()?.handle(&at, None, stream).await
                }
                .await;
                dial_domain::stream_done(&at, result)
            })
            .await?;
        Ok(match self.interrupt(member) {
            Some(selection) => super::interrupt::stream(stream, selection, member.clone()),
            None => stream,
        })
    }
}

#[async_trait]
impl OutboundDatagramHandler for Group {
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
        let snapshot = self.members.load();
        let (member, datagram) = self
            .connect(sess, &snapshot, |a, progress| async move {
                let connect = a.datagram()?.connect_addr();
                progress.dialing(&connect);
                let at = dial_domain::session(sess, a, &connect);
                let result = async {
                    let transport =
                        connect_datagram_outbound(&at, self.dns_client.clone(), a).await?;
                    progress.dialled();
                    a.datagram()?.handle(&at, transport).await
                }
                .await;
                dial_domain::datagram_done(sess, &at, result)
            })
            .await?;
        Ok(match self.interrupt(member) {
            Some(selection) => super::interrupt::datagram(datagram, selection, member.clone()),
            None => datagram,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_member_up_is_chosen_whatever_its_latency() {
        let c = |up: &[bool]| choose(up, None, 0).member;
        assert_eq!(c(&[true, true]), 0);
        assert_eq!(c(&[false, true, true]), 1);
    }

    #[test]
    fn when_every_member_is_down_the_first_is_chosen() {
        assert_eq!(choose(&[false, false], None, 0).member, 0);
        // The first that is not a pass outbound.
        assert_eq!(choose(&[false, false, false], None, 1).member, 1);
    }

    #[test]
    fn a_pin_holds_while_its_member_is_up() {
        let pinned = choose(&[true, true, true], Some(2), 0);
        assert_eq!(
            pinned,
            Choice {
                member: 2,
                unpin: false
            }
        );
        // Down: unpinned, and the group goes by itself.
        let gone = choose(&[true, true, false], Some(2), 0);
        assert_eq!(
            gone,
            Choice {
                member: 0,
                unpin: true
            }
        );
        let all_down = choose(&[false, false], Some(1), 0);
        assert_eq!(
            all_down,
            Choice {
                member: 0,
                unpin: true
            }
        );
    }

    #[test]
    fn a_connection_falls_back_to_the_next_members_up_in_order() {
        assert_eq!(candidates(0, 4, |_| true), [0, 1, 2]);
        assert_eq!(candidates(1, 4, |i| i != 0), [1, 2, 3]);
        assert_eq!(candidates(1, 4, |i| i == 1 || i == 3), [1, 3]);
        // The selected member is tried first even if a test since failed
        // it: the selection moves after the round, or a failure.
        assert_eq!(candidates(0, 3, |i| i == 2), [0, 2]);
    }

    #[test]
    fn when_every_member_is_down_each_is_tried_in_order() {
        assert_eq!(candidates(1, 3, |_| false), [1, 0, 2]);
        assert_eq!(candidates(0, 5, |_| false), [0, 1, 2]);
    }

    #[test]
    fn the_members_chosen_from_are_those_that_stand_or_else_those_that_passed() {
        let (t, f) = (true, false);
        assert_eq!(chooses_up(&[f, t], &[t, t], None), [f, t]);
        // None stands: what passed its last test beats the first, down.
        assert_eq!(chooses_up(&[f, f], &[f, t], None), [f, t]);
        // The member pinned is up if either says so.
        assert_eq!(chooses_up(&[f, t, f], &[t, t, f], Some(0)), [t, t, f]);
        assert_eq!(chooses_up(&[f, t, t], &[t, t, f], Some(2)), [f, t, t]);
        assert_eq!(chooses_up(&[f, t, f], &[t, t, f], Some(2)), [f, t, f]);
    }

    /// A fallback of members `a`, `b` and `c`, its rounds and failures fed
    /// by hand; its time is tokio's, paused.
    struct Harness {
        members: Arc<Members>,
        selected: Arc<Selection>,
        choosing: Arc<Choosing>,
        checker: Arc<Checker>,
    }

    const PASS: Option<Duration> = Some(Duration::from_millis(10));
    const FAIL: Option<Duration> = None;

    impl Harness {
        fn new(fail_after: u32, recover_after: u32, min_dwell: Duration) -> Self {
            let members = crate::protocol::group::members::tests::outbounds(&["a", "b", "c"]);
            let selected = Arc::new(Selection::new("a", MemberKey::outbound("a")));
            let choosing = Arc::new(Choosing::new(
                "fb",
                selected.clone(),
                None,
                None,
                min_dwell,
                Default::default(),
            ));
            let checker = health::tests::checker(
                members.clone(),
                Debounce {
                    fail_after,
                    recover_after,
                },
                on_tested(choosing.clone()),
            );
            Self {
                members,
                selected,
                choosing,
                checker,
            }
        }

        fn round(&self, latencies: &[Option<Duration>]) -> String {
            self.checker.round(latencies);
            self.on()
        }

        /// A connection through `name` finds its server unreachable.
        fn unreachable(&self, name: &str) -> String {
            let snapshot = self.members.load();
            let key = MemberKey::outbound(name);
            if self.checker.mark_down(&key) {
                self.choosing
                    .settle(&self.checker, &snapshot, Cause::Failed("refused".into()));
            }
            self.on()
        }

        fn on(&self) -> String {
            self.selected.get().name.to_string()
        }

        /// The group, whose members but the last one tried have
        /// `dial_timeout` to connect.
        fn group(&self, dial_timeout: Duration) -> Group {
            Group {
                tag: "fb".into(),
                members: self.members.clone(),
                selected: self.selected.clone(),
                choosing: self.choosing.clone(),
                checker: self.checker.clone(),
                dial_timeout,
                dns_client: health::tests::dns(),
                interrupt: None,
            }
        }

        fn pin(&self) -> Pin {
            Pin {
                choosing: self.choosing.clone(),
                checker: self.checker.clone(),
                members: self.members.clone(),
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn by_default_each_round_and_each_failure_counts_at_once() {
        let h = Harness::new(1, 1, Duration::ZERO);
        assert_eq!(h.round(&[PASS, PASS, PASS]), "a");
        assert_eq!(h.round(&[FAIL, PASS, PASS]), "b");
        assert_eq!(h.round(&[PASS, PASS, PASS]), "a");
        assert_eq!(h.unreachable("a"), "b");
        assert_eq!(h.round(&[PASS, FAIL, PASS]), "a");
    }

    #[tokio::test(start_paused = true)]
    async fn a_member_marked_down_is_taken_back_after_recover_after_rounds_in_a_row() {
        let h = Harness::new(1, 3, Duration::ZERO);
        assert_eq!(h.round(&[PASS, PASS, PASS]), "a");
        assert_eq!(h.unreachable("a"), "b");
        assert_eq!(h.round(&[PASS, PASS, PASS]), "b");
        assert_eq!(h.round(&[PASS, PASS, PASS]), "b");
        // A failed round starts the count again.
        assert_eq!(h.round(&[FAIL, PASS, PASS]), "b");
        assert_eq!(h.round(&[PASS, PASS, PASS]), "b");
        assert_eq!(h.round(&[PASS, PASS, PASS]), "b");
        assert_eq!(h.round(&[PASS, PASS, PASS]), "a");
        // The same after failed rounds.
        assert_eq!(h.round(&[FAIL, PASS, PASS]), "b");
        assert_eq!(h.round(&[PASS, PASS, PASS]), "b");
        assert_eq!(h.round(&[PASS, PASS, PASS]), "b");
        assert_eq!(h.round(&[PASS, PASS, PASS]), "a");
    }

    #[tokio::test(start_paused = true)]
    async fn a_member_is_left_after_fail_after_rounds_in_a_row_or_once_marked_down() {
        let h = Harness::new(2, 1, Duration::ZERO);
        assert_eq!(h.round(&[PASS, PASS, PASS]), "a");
        assert_eq!(h.round(&[FAIL, PASS, PASS]), "a");
        // A pass in between forgets it.
        assert_eq!(h.round(&[PASS, PASS, PASS]), "a");
        assert_eq!(h.round(&[FAIL, PASS, PASS]), "a");
        assert_eq!(h.round(&[FAIL, PASS, PASS]), "b");
        assert_eq!(h.round(&[PASS, PASS, PASS]), "a");
        // Unreachable: left at once.
        assert_eq!(h.unreachable("a"), "b");
        // And one that failed a round, but still stood, too.
        assert_eq!(h.round(&[PASS, FAIL, PASS]), "a");
        assert_eq!(h.round(&[FAIL, PASS, PASS]), "a");
        assert_eq!(h.unreachable("a"), "b");
    }

    #[tokio::test(start_paused = true)]
    async fn an_earlier_member_is_not_taken_back_before_min_dwell() {
        let h = Harness::new(1, 1, Duration::from_secs(30));
        assert_eq!(h.round(&[PASS, PASS, PASS]), "a");
        // Down, it is left at once, on the group's first second on it.
        assert_eq!(h.unreachable("a"), "b");
        tokio::time::advance(Duration::from_secs(10)).await;
        assert_eq!(h.round(&[PASS, PASS, PASS]), "b");
        tokio::time::advance(Duration::from_secs(19)).await;
        assert_eq!(h.round(&[PASS, PASS, PASS]), "b");
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(h.round(&[PASS, PASS, PASS]), "a");
        // A member down is left at once, from a round or a connection,
        // however short the time on it.
        assert_eq!(h.round(&[FAIL, PASS, PASS]), "b");
        assert_eq!(h.round(&[PASS, FAIL, PASS]), "a");
        // [b] failed the last round.
        assert_eq!(h.unreachable("a"), "c");
    }

    #[tokio::test(start_paused = true)]
    async fn recover_after_3_and_min_dwell_30s_take_the_first_back_after_both() {
        let h = Harness::new(1, 3, Duration::from_secs(30));
        assert_eq!(h.round(&[PASS, PASS, PASS]), "a");
        assert_eq!(h.unreachable("a"), "b");
        // Three passed rounds within 30s: not back yet.
        for _ in 0..3 {
            tokio::time::advance(Duration::from_secs(5)).await;
            assert_eq!(h.round(&[PASS, PASS, PASS]), "b");
        }
        // The first round past 30s.
        tokio::time::advance(Duration::from_secs(20)).await;
        assert_eq!(h.round(&[PASS, PASS, PASS]), "a");
    }

    #[tokio::test(start_paused = true)]
    async fn a_pin_overrides_the_debounce_while_its_member_is_up() {
        let h = Harness::new(2, 3, Duration::from_secs(30));
        assert_eq!(h.round(&[PASS, PASS, PASS]), "a");
        assert_eq!(h.unreachable("a"), "b");
        assert_eq!(h.round(&[PASS, PASS, PASS]), "b");
        // [a] passed one round of three, and the group is on [b] for less
        // than min_dwell: pinned, it goes there all the same.
        h.pin().pin("a").unwrap();
        assert_eq!(h.on(), "a");
        h.pin().pin("c").unwrap();
        assert_eq!(h.on(), "c");
        // A failed round of two keeps the pin; a member down drops it.
        assert_eq!(h.round(&[PASS, PASS, FAIL]), "c");
        assert_eq!(h.pin().pinned().as_deref(), Some("c"));
        assert_eq!(h.unreachable("c"), "b");
        assert_eq!(h.pin().pinned(), None);
    }

    /// A connection through the group on [a], whose server never answers
    /// the dial, or, `handshake`, answers it and never the handshake,
    /// while [b] connects at once: how long it took, and what it reached.
    async fn past_a_silent_server(group: &Group, handshake: bool) -> (Duration, String) {
        let dialer = crate::net::DialDefaults::default()
            .dialer(&Default::default(), None)
            .unwrap();
        let server = OutboundConnect::Proxy(
            crate::session::Network::Tcp,
            "server.test".into(),
            443,
            dialer,
        );
        let sess = Session::default();
        let snapshot = group.members.load();
        let start = Instant::now();
        let (member, reached) = group
            .connect(&sess, &snapshot, |a, progress| {
                let server = server.clone();
                async move {
                    progress.dialing(&server);
                    if a.tag() == "a" {
                        if handshake {
                            progress.dialled();
                        }
                        std::future::pending::<()>().await;
                    }
                    Ok(a.tag().to_string())
                }
            })
            .await
            .unwrap();
        assert_eq!(member.name.as_ref(), reached);
        (start.elapsed(), reached)
    }

    #[tokio::test(start_paused = true)]
    async fn a_member_whose_server_does_not_answer_the_dial_is_left_after_dial_timeout() {
        let timeout = health::DEFAULT_TIMEOUT;
        let dial = Duration::from_secs(1);
        let h = Harness::new(1, 1, Duration::ZERO);
        let group = h.group(dial_timeout(Some(dial), timeout).unwrap());
        assert_eq!(
            past_a_silent_server(&group, false).await,
            (dial, "b".into())
        );
        // Timed out at the dial: [a] is down, and the group on [b].
        assert!(!h.checker.is_up(&MemberKey::outbound("a")));
        assert_eq!(h.on(), "b");

        // Unset, it is `timeout`, as before it was.
        let h = Harness::new(1, 1, Duration::ZERO);
        let group = h.group(dial_timeout(None, timeout).unwrap());
        assert_eq!(
            past_a_silent_server(&group, false).await,
            (timeout, "b".into())
        );
        assert_eq!(h.on(), "b");
    }

    #[tokio::test(start_paused = true)]
    async fn a_handshake_past_dial_timeout_is_counted_not_marked_down() {
        let dial = Duration::from_secs(2);
        let h = Harness::new(1, 1, Duration::ZERO);
        let group = h.group(dial_timeout(Some(dial), health::DEFAULT_TIMEOUT).unwrap());
        assert_eq!(past_a_silent_server(&group, true).await, (dial, "b".into()));
        // It may be the destination's doing: [a] stays up, and chosen.
        assert!(h.checker.is_up(&MemberKey::outbound("a")));
        assert_eq!(h.on(), "a");
    }

    #[test]
    fn a_dial_timeout_below_a_second_is_an_error() {
        let timeout = Duration::from_millis(500);
        assert_eq!(dial_timeout(None, timeout).unwrap(), timeout);
        assert_eq!(
            dial_timeout(Some(Duration::from_secs(1)), timeout).unwrap(),
            Duration::from_secs(1)
        );
        let e = dial_timeout(Some(Duration::from_millis(999)), timeout).unwrap_err();
        assert!(e.to_string().contains("1s at least"), "{}", e);
    }
}
