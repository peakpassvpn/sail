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

use std::future::Future;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_derive::Deserialize;
use tokio::sync::{watch, RwLock};
use tracing::{debug, info, warn};

use super::attempt::{member_unreachable, Progress};
use super::health::{self, Checker};
use super::members::{MemberKey, Members, Snapshot};
use super::merge;
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
    /// What is requested through each member to test it.
    #[serde(default = "default_url")]
    url: String,
    /// The HTTP statuses a test must be answered with to pass, as
    /// Mihomo's `expected-status`: codes and ranges, `200/204/401-429`;
    /// any when unset.
    #[serde(default)]
    expected_status: Option<String>,
    #[serde(default, with = "crate::config::model::duration")]
    interval: Option<Duration>,
    /// How long a test, or a connection attempt that has a member left to
    /// fall back to, may take before its member counts as failed; 5s.
    /// Also how close together `max_failed_times` failures must come.
    #[serde(default, with = "crate::config::model::duration")]
    timeout: Option<Duration>,
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
}

fn default_url() -> String {
    health::DEFAULT_URL.to_string()
}

fn default_lazy() -> bool {
    true
}

/// How many members one connection is tried through at most.
const MAX_ATTEMPTS: usize = 3;

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
enum Cause<'a> {
    /// A round of tests, with the latencies of `Snapshot`'s members.
    Round(&'a [Option<Duration>]),
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
}

impl Choosing {
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
    /// `snapshot`, `up` or not; drops a pin whose member is down; logs
    /// why, `cause` telling.
    fn settle(&self, snapshot: &Snapshot, up: &[bool], cause: Cause) {
        let Some(first) = snapshot.first_up().and_then(|m| snapshot.position(&m.key)) else {
            return;
        };
        let pinned_name = self.pinned();
        let pinned = pinned_name
            .as_ref()
            .and_then(|name| snapshot.find(name))
            .and_then(|m| snapshot.position(&m.key));
        let choice = choose(up, pinned, first);
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
        let next = &snapshot.members[choice.member].key;
        if *next == *current {
            return;
        }
        let why = if choice.unpin {
            "the member pinned is down".to_string()
        } else if pinned == Some(choice.member) {
            format!("it is pinned to [{}]", next.name)
        } else if !up.iter().any(|&u| u) {
            "no member is up: the first takes the connections".to_string()
        } else {
            match cause {
                Cause::Round(latencies) => {
                    let failed = snapshot
                        .position(&current)
                        .is_some_and(|i| latencies[i].is_none());
                    match failed {
                        true => format!("[{}] failed its test", current.name),
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
    }

    /// As `settle`, the members up as the checks have them now, those not
    /// tested yet taken to be up.
    fn settle_now(&self, checker: &Checker, snapshot: &Snapshot, cause: Cause) {
        self.settle(snapshot, &up(checker, snapshot), cause);
    }
}

/// Whether each member of `snapshot` is up, as `checker` has them; a
/// `pass` outbound never is.
fn up(checker: &Checker, snapshot: &Snapshot) -> Vec<bool> {
    snapshot
        .members
        .iter()
        .map(|m| !m.handler.is_pass() && checker.is_up(&m.key))
        .collect()
}

/// The group's pin, for its selector, which the API pins and unpins it
/// through.
struct Pin {
    choosing: Arc<Choosing>,
    checker: Arc<Checker>,
    members: Arc<Members>,
}

impl GroupPin for Pin {
    /// Pins the group there: it goes there at once if the member is up;
    /// else it is tested again at once, as Mihomo tests it, and the group
    /// goes there if it passes, or drops the pin if not.
    fn pin(&self, name: &str) -> Result<()> {
        let snapshot = self.members.load();
        let Some(member) = snapshot.find(name) else {
            return Err(anyhow!(
                "[{}] has no outbound [{}]",
                self.choosing.tag,
                name
            ));
        };
        let i = snapshot.position(&member.key).unwrap_or_default();
        self.choosing.set_pin(Some(name));
        info!("[{}] is pinned to [{}]", self.choosing.tag, name);
        let up = up(&self.checker, &snapshot);
        if up[i] {
            self.choosing.settle(&snapshot, &up, Cause::Hand);
        } else {
            self.checker.retest();
        }
        Ok(())
    }

    fn unpin(&self) {
        if let Some(name) = self.choosing.set_pin(None) {
            info!("[{}] is no longer pinned to [{}]", self.choosing.tag, name);
            self.choosing
                .settle_now(&self.checker, &self.members.load(), Cause::Hand);
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
    let expected = StatusRanges::parse(options.expected_status.as_deref().unwrap_or_default())
        .map_err(|e| anyhow!("[{}] outbound: expected_status: {}", ctx.tag, e))?;
    let probe = HttpProbe::new(&options.url, ctx.dns_client.clone(), ctx.env)
        .map_err(|e| anyhow!("[{}] outbound: url: {}", ctx.tag, e))?
        .expecting(expected);

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
    let choosing = Arc::new(Choosing {
        tag: ctx.tag.to_owned(),
        selected: selected.clone(),
        pinned: Mutex::new(pinned),
        cache_file,
    });
    let on_tested = {
        let choosing = choosing.clone();
        Box::new(move |snapshot: &Snapshot, latencies: &[Option<Duration>]| {
            let up: Vec<bool> = latencies.iter().map(Option::is_some).collect();
            choosing.settle(snapshot, &up, Cause::Round(latencies));
        })
    };
    let (checker, abort_handle) = Checker::new(
        ctx.tag,
        members.clone(),
        probe,
        ctx.dns_client.clone(),
        ctx.env.network.clone(),
        interval,
        timeout,
        max_failed_times,
        options.lazy.then_some(interval),
        on_tested,
    );
    ctx.abort_handles.push(abort_handle);
    merged.on_merged({
        let choosing = choosing.clone();
        let checker = checker.clone();
        Box::new(move |snapshot, added| {
            // The first member up in the new order, new ones untested and
            // so taken to be up.
            choosing.settle_now(&checker, snapshot, Cause::Merged);
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
        timeout,
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
    timeout: Duration,
    dns_client: SyncDnsClient,
    interrupt: Option<watch::Receiver<MemberKey>>,
}

impl Group {
    /// Connects through the members of `snapshot` in turn, see
    /// `candidates`, until one connects; returns which, and what it
    /// connected. Every member but the last one tried has `timeout` to
    /// connect. `connect` tells how far it got, see `Progress`.
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
            let progress = Arc::new(Progress::default());
            let result = if n + 1 < order.len() {
                tokio::time::timeout(self.timeout, connect(a, progress.clone()))
                    .await
                    .unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "timed out")))
            } else {
                connect(a, progress.clone()).await
            };
            match result {
                Ok(v) => {
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
                                .settle_now(&self.checker, snapshot, Cause::Failed(why));
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
        sess.chain.push(&member.name);
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
        sess.chain.push(&member.name);
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
}
