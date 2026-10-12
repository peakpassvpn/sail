//! `urltest`: sends every connection to the member that answered an HTTP
//! request through it fastest, as sing-box's urltest does. Members are
//! tested every `interval`; the group moves to a faster one only when it
//! is faster by more than `tolerance`, so that close latencies do not
//! make it switch back and forth.
//!
//! A connection whose network the selected member does not carry (an
//! outbound with sing-box's `network`), or that finds it down, goes to
//! the fastest member that carries it, see `takes`, as sing-box's urltest
//! selects for TCP and for UDP apart.
//!
//! A connection that fails has the members tested again: at once when the
//! member's server cannot be reached, else once `max_failed_times` failed,
//! as Mihomo's url-test does.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_derive::Deserialize;
use tokio::sync::{watch, RwLock};
use tracing::debug;

use super::attempt::{member_unreachable, Progress};
use super::health::{self, Checker};
use super::members::{Member, MemberKey, Members, Snapshot, Tested};
use super::merge;
use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{
    parse_options, Options, OutboundContext, OutboundFactory, OutboundRegistry,
};
use crate::adapter::*;
use crate::app::healthcheck::{HttpProbe, StatusRanges};
use crate::app::outbound::selector::{OutboundSelector, SelectedBy, Selection};
use crate::app::SyncDnsClient;
use crate::config::model::GroupProviders;
use crate::net::{connect_datagram_outbound, connect_stream_outbound, dial_domain};
use crate::session::Session;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register("urltest", OutboundFactory::composite(dependencies, build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UrlTestOutboundOptions {
    /// Its members; none may be when its providers give others.
    #[serde(default)]
    outbounds: Vec<String>,
    /// Members from outbound providers too, a sail extension.
    #[serde(flatten)]
    providers: GroupProviders,
    /// What is requested through each member; sing-box's default.
    #[serde(default = "default_url")]
    url: String,
    /// The HTTP statuses a test must be answered with to pass, as
    /// Mihomo's `expected-status`: codes and ranges, `200/204/401-429`;
    /// any when unset.
    #[serde(default)]
    expected_status: Option<String>,
    /// The latency of a second request on the connection the first
    /// opened, without the connect and handshakes, as Mihomo's
    /// `unified-delay`; a sail extension.
    #[serde(default)]
    unified_delay: bool,
    #[serde(default, with = "crate::config::model::duration")]
    interval: Option<Duration>,
    /// How long a test may take before its member counts as failed; 5s.
    /// Also how close together `max_failed_times` failures must come;
    /// Mihomo's `timeout`.
    #[serde(default, with = "crate::config::model::duration")]
    timeout: Option<Duration>,
    /// How many failed connections, within `timeout` of the first, have
    /// the members tested again; 5, as Mihomo's `max-failed-times`. One
    /// whose member's server cannot be reached has them tested at once.
    #[serde(default)]
    max_failed_times: Option<u32>,
    /// Milliseconds.
    #[serde(default = "default_tolerance")]
    tolerance: u16,
    /// Tests pause once the group has not been used for this long; 30m,
    /// sing-box's. A Clash `url-test` group, lazy, has it equal to its
    /// `interval`, as Mihomo's.
    #[serde(default, with = "crate::config::model::duration")]
    idle_timeout: Option<Duration>,
    /// `false`: tests never pause, used or not, as Mihomo's `lazy: false`;
    /// `idle_timeout` is then a mistake.
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

fn default_tolerance() -> u16 {
    50
}

const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);

fn dependencies(tag: &str, options: &Options) -> Result<Vec<String>> {
    let options: UrlTestOutboundOptions = parse_options("outbound", tag, options)?;
    Ok(options.providers.dependencies(options.outbounds))
}

/// The member to move to, given the one selected and the latest
/// latencies: the fastest, unless the selected one is up and no more
/// than `tolerance` slower. `None` keeps the selection, when every
/// member failed.
pub(crate) fn choose(
    current: usize,
    latencies: &[Option<Duration>],
    tolerance: Duration,
) -> Option<usize> {
    let (fastest, min) = latencies
        .iter()
        .enumerate()
        .filter_map(|(i, l)| l.map(|l| (i, l)))
        .min_by_key(|(_, l)| *l)?;
    match latencies.get(current).copied().flatten() {
        Some(l) if l <= min + tolerance => Some(current),
        _ => Some(fastest),
    }
}

/// The member to move to once the members changed, given the one
/// selected and the latencies known: none while the selected one is still
/// a member and did not fail its last test; else the fastest known, if
/// any is.
pub(crate) fn repick(
    snapshot: &Snapshot,
    current: &MemberKey,
    latencies: &HashMap<MemberKey, Option<Duration>>,
) -> Option<MemberKey> {
    if snapshot.position(current).is_some() && latencies.get(current) != Some(&None) {
        return None;
    }
    snapshot
        .members
        .iter()
        .filter_map(|m| latencies.get(&m.key).copied().flatten().map(|l| (m, l)))
        .min_by_key(|(_, l)| *l)
        .map(|(m, _)| m.key.clone())
}

/// The member of `snapshot` a connection goes to, given the one
/// `selected`, which of them carry its network, as `carries` tells, and
/// their last checks: the one selected, while it carries it and did not
/// fail its last test. Else, of those that carry it, the fastest that
/// passed theirs; else the first not known to be down, one not tested
/// being up; else, a test can be wrong and trying beats refusing, the one
/// selected if it carries it, or the first that does. When none carries
/// it, the one selected, whose error tells. As sing-box's urltest takes,
/// for TCP and for UDP apart, the lowest delay among the outbounds that
/// carry the network, else the first that does
/// (protocol/group/urltest.go, `Select`).
pub(crate) fn takes(
    snapshot: &Snapshot,
    selected: usize,
    tested: &HashMap<MemberKey, Tested>,
    carries: impl Fn(&AnyOutboundHandler) -> bool,
) -> usize {
    let latency = |m: &Member| tested.get(&m.key).map(|t| t.latency);
    let member = &snapshot.members[selected];
    let carried = carries(&member.handler);
    if carried && latency(member) != Some(None) {
        return selected;
    }
    let carrying: Vec<(usize, &Member)> = snapshot
        .members
        .iter()
        .enumerate()
        .filter(|(_, m)| !m.handler.is_pass() && carries(&m.handler))
        .collect();
    let fastest = carrying
        .iter()
        .filter_map(|(i, m)| latency(m).flatten().map(|l| (*i, l)))
        .min_by_key(|(_, l)| *l)
        .map(|(i, _)| i);
    let not_down = || carrying.iter().find(|(_, m)| latency(m) != Some(None));
    fastest
        .or_else(|| not_down().map(|(i, _)| *i))
        .or_else(|| carried.then_some(selected))
        .or_else(|| carrying.first().map(|(i, _)| *i))
        .unwrap_or(selected)
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let options: UrlTestOutboundOptions = ctx.options()?;
    let merged = merge::members(ctx, &options.outbounds, &options.providers)?;
    let members = merged.members.clone();
    let interval = options.interval.unwrap_or(health::DEFAULT_INTERVAL);
    let idle_timeout = options.idle_timeout.unwrap_or(DEFAULT_IDLE_TIMEOUT);
    let timeout = options.timeout.unwrap_or(health::DEFAULT_TIMEOUT);
    let max_failed_times = options
        .max_failed_times
        .unwrap_or(health::DEFAULT_MAX_FAILED_TIMES);
    if !options.lazy && options.idle_timeout.is_some() {
        return Err(anyhow!(
            "[{}] outbound: idle_timeout: has no use with lazy: false",
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
    if interval.is_zero() {
        return Err(anyhow!(
            "[{}] outbound: interval: must not be zero",
            ctx.tag
        ));
    }
    if idle_timeout.is_zero() {
        return Err(anyhow!(
            "[{}] outbound: idle_timeout: must not be zero",
            ctx.tag
        ));
    }
    let expected = StatusRanges::parse(options.expected_status.as_deref().unwrap_or_default())
        .map_err(|e| anyhow!("[{}] outbound: expected_status: {}", ctx.tag, e))?;
    let probe = HttpProbe::new(&options.url, ctx.dns_client.clone(), ctx.env)
        .map_err(|e| anyhow!("[{}] outbound: url: {}", ctx.tag, e))?
        .expecting(expected)
        .unified(options.unified_delay);

    // The first member until the first tests are done.
    let first = members
        .load()
        .first_up()
        .map(|m| m.key.clone())
        .unwrap_or_else(|| MemberKey::outbound(""));
    let selected = Arc::new(Selection::new(&first.name, first.clone()));
    let tolerance = Duration::from_millis(options.tolerance.into());
    let on_tested = {
        let selected = selected.clone();
        let tag = ctx.tag.to_owned();
        let events = ctx.env.events.clone();
        Box::new(
            move |_: &Checker, snapshot: &Snapshot, latencies: &[Option<Duration>]| {
                let current = selected.get();
                // A selection that is not a member is left for the fastest.
                let at = snapshot.position(&current).unwrap_or(usize::MAX);
                if let Some(next) = choose(at, latencies, tolerance) {
                    if next != at {
                        let next = &snapshot.members[next].key;
                        debug!(
                            "[{}] switches from [{}] to [{}]",
                            tag, current.name, next.name
                        );
                        selected.set(next.clone());
                        use crate::control::events::{GroupSwitch, SwitchReason as R};
                        // One left that is not tested has no latency,
                        // and did not fail.
                        let reason = match snapshot.members.get(at) {
                            None => R::MembersChanged,
                            Some(m) if latencies[at].is_none() && health::is_tested(&m.handler) => {
                                R::TestFailed
                            }
                            Some(_) => R::Faster,
                        };
                        // TODO: the enclosing groups' tags, as the fallback's.
                        events.group_switched(GroupSwitch::new(
                            tag.clone(),
                            Some(current.name.to_string()),
                            next.name.to_string(),
                            reason,
                        ));
                    }
                }
            },
        )
    };
    let (checker, abort_handle) = Checker::new(
        ctx.tag,
        members.clone(),
        probe.into(),
        ctx.dns_client.clone(),
        ctx.env.network.clone(),
        interval,
        timeout,
        max_failed_times,
        options.lazy.then_some(idle_timeout),
        Default::default(),
        on_tested,
    );
    ctx.abort_handles.push(abort_handle);
    ctx.checkers.insert(ctx.tag.to_owned(), checker.clone());
    merged.on_merged({
        let selected = selected.clone();
        let checker = checker.clone();
        let tag = ctx.tag.to_owned();
        Box::new(move |snapshot, added| {
            let current = selected.get();
            let latencies: HashMap<MemberKey, Option<Duration>> =
                checker.latencies().read(|tested| {
                    tested
                        .iter()
                        .map(|(key, t)| (key.clone(), t.latency))
                        .collect()
                });
            let next = repick(snapshot, &current, &latencies);
            if let Some(next) = next {
                debug!(
                    "[{}] switches from [{}] to [{}], as its members changed",
                    tag, current.name, next.name
                );
                selected.set(next);
            }
            // The new members are tested soon rather than an interval on.
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
    .with_checks(checker.clone());
    ctx.selectors
        .insert(ctx.tag.to_owned(), Arc::new(RwLock::new(outbound_selector)));

    let group = Arc::new(Group {
        members,
        interrupt: options
            .interrupt_exist_connections
            .then(|| selected.subscribe()),
        selected,
        checker,
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
    members: Arc<Members>,
    selected: Arc<Selection>,
    checker: Arc<Checker>,
    dns_client: SyncDnsClient,
    interrupt: Option<watch::Receiver<MemberKey>>,
}

impl Group {
    /// The member of `snapshot` for a new connection, which is also a use
    /// of the group, and, for `interrupt_exist_connections`, the
    /// selection it went by: the member selected, or, when that one does
    /// not carry the connection's network, as `carries` tells, or is
    /// down, another that does, see `takes`. A connection through another
    /// than the one selected ends as the others do, once the selection
    /// moves.
    fn pick<'s>(
        &self,
        snapshot: &'s Snapshot,
        carries: impl Fn(&AnyOutboundHandler) -> bool,
    ) -> io::Result<(&'s Member, Option<MemberKey>)> {
        self.checker.used();
        let (selected, by) = self
            .selected
            .pick(snapshot)
            .ok_or_else(|| io::Error::other("no outbound to select"))?;
        let by = self.interrupt.as_ref().map(|_| MemberKey::clone(&by));
        let i = self
            .checker
            .latencies()
            .read(|tested| takes(snapshot, selected, tested, carries));
        Ok((&snapshot.members[i], by))
    }

    /// A connection through `member` that failed, at the stage `progress`
    /// tells, is reason to test again rather than wait out the interval:
    /// at once if the member's server cannot be reached, as Mihomo tests
    /// at once after a refusal; else once enough failed, see
    /// `Checker::failed`. Not through a member that is not tested, see
    /// `health::is_tested`: the tests would say nothing of it, and each
    /// of its failures would run them again.
    fn failed<T>(
        &self,
        member: &Member,
        result: io::Result<T>,
        progress: &Progress,
    ) -> io::Result<T> {
        match &result {
            Ok(_) => self.checker.succeeded(),
            Err(_) if !health::is_tested(&member.handler) => {}
            Err(e) if member_unreachable(progress.get(), e.kind()) => self.checker.retest(),
            Err(_) => self.checker.failed(),
        }
        result
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
        let (member, by) = self.pick(&snapshot, |m| m.stream().is_ok())?;
        let a = &member.handler;
        debug!("urltest handles [{}] to [{}]", sess.destination, a.tag());
        let progress = Progress::default();
        // In the chain before it is dialled: a failure names it.
        sess.chain.push(&member.key.name);
        let stream = self.failed(
            member,
            async {
                let connect = a.stream()?.connect_addr();
                progress.dialing(&connect);
                let at = dial_domain::session(sess, a, &connect);
                let stream = dial_domain::stream_done(
                    &at,
                    async {
                        let stream =
                            connect_stream_outbound(&at, self.dns_client.clone(), a).await?;
                        progress.dialled();
                        a.stream()?.handle(&at, None, stream).await
                    }
                    .await,
                )?;
                Ok(stream)
            }
            .await,
            &progress,
        )?;
        Ok(match (&self.interrupt, by) {
            (Some(selection), Some(by)) => super::interrupt::stream(stream, selection, by),
            _ => stream,
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
        let (member, by) = self.pick(&snapshot, |m| m.datagram().is_ok())?;
        let a = &member.handler;
        debug!("urltest handles [{}] to [{}]", sess.destination, a.tag());
        let progress = Progress::default();
        // In the chain before it is dialled: a failure names it.
        sess.chain.push(&member.key.name);
        let datagram = self.failed(
            member,
            async {
                let connect = a.datagram()?.connect_addr();
                progress.dialing(&connect);
                let at = dial_domain::session(sess, a, &connect);
                let datagram = dial_domain::datagram_done(
                    sess,
                    &at,
                    async {
                        let transport =
                            connect_datagram_outbound(&at, self.dns_client.clone(), a).await?;
                        progress.dialled();
                        a.datagram()?.handle(&at, transport).await
                    }
                    .await,
                )?;
                Ok(datagram)
            }
            .await,
            &progress,
        )?;
        Ok(match (&self.interrupt, by) {
            (Some(selection), Some(by)) => super::interrupt::datagram(datagram, selection, by),
            _ => datagram,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(v: u64) -> Option<Duration> {
        Some(Duration::from_millis(v))
    }

    #[test]
    fn the_fastest_member_is_chosen() {
        assert_eq!(
            choose(0, &[ms(300), ms(20), ms(90)], Duration::ZERO),
            Some(1)
        );
    }

    #[test]
    fn the_selected_member_is_kept_within_the_tolerance() {
        let t = Duration::from_millis(50);
        assert_eq!(choose(0, &[ms(60), ms(20)], t), Some(0));
        assert_eq!(choose(0, &[ms(70), ms(20)], t), Some(0));
        assert_eq!(choose(0, &[ms(71), ms(20)], t), Some(1));
    }

    #[test]
    fn a_failed_member_is_left_whatever_the_tolerance() {
        let t = Duration::from_secs(10);
        assert_eq!(choose(0, &[None, ms(500)], t), Some(1));
    }

    #[test]
    fn nothing_changes_when_every_member_failed() {
        assert_eq!(choose(1, &[None, None], Duration::ZERO), None);
    }

    /// A urltest of `members`, on the first, whose rounds are fed by hand.
    fn group(members: Vec<Member>) -> Group {
        let first = members[0].key.clone();
        let members = Members::of(members);
        let selected = Arc::new(Selection::new(&first.name, first.clone()));
        let on_tested: health::OnTested = Box::new({
            let selected = selected.clone();
            move |_: &Checker, snapshot: &Snapshot, latencies: &[Option<Duration>]| {
                let at = snapshot.position(&selected.get()).unwrap();
                if let Some(next) = choose(at, latencies, Duration::ZERO) {
                    selected.set(snapshot.members[next].key.clone());
                }
            }
        });
        Group {
            checker: health::tests::checker(members.clone(), Default::default(), on_tested),
            members,
            selected,
            dns_client: health::tests::dns(),
            interrupt: None,
        }
    }

    /// The members a TCP and a UDP connection through `group` go to.
    fn goes(group: &Group) -> (String, String) {
        let snapshot = group.members.load();
        let to = |carries: fn(&AnyOutboundHandler) -> bool| {
            let (member, _) = group.pick(&snapshot, carries).unwrap();
            member.key.name.to_string()
        };
        (to(|m| m.stream().is_ok()), to(|m| m.datagram().is_ok()))
    }

    #[tokio::test]
    async fn a_member_that_carries_udp_alone_takes_udp_once_the_selected_one_is_down() {
        use crate::protocol::group::members::tests::{member, one};
        let group = group(vec![member(None, "a"), one("u", false)]);
        let both = |a: &str, b: &str| (a.to_string(), b.to_string());
        assert_eq!(goes(&group), both("a", "a"));
        // [u] is not tested: [a], selected and up, takes both.
        group.checker.round(&[ms(20), None]);
        assert_eq!(goes(&group), both("a", "a"));
        // [a] down, it is still the one selected, and takes TCP as it
        // did; UDP goes to the member that carries it and is not down.
        for _ in 0..3 {
            group.checker.round(&[None, None]);
            assert_eq!(group.selected.get().name.as_ref(), "a");
            assert_eq!(goes(&group), both("a", "u"));
        }
    }

    #[tokio::test]
    async fn a_connection_the_selected_member_does_not_carry_goes_to_the_fastest_that_does() {
        use crate::protocol::group::members::tests::{member, one};
        let group = group(vec![
            one("t", true),
            one("u", false),
            member(None, "b"),
            member(None, "c"),
        ]);
        let both = |a: &str, b: &str| (a.to_string(), b.to_string());
        // Before the tests, the first that carries it.
        assert_eq!(goes(&group), both("t", "u"));
        // [t], the fastest, is selected, and carries TCP alone: UDP goes
        // to the fastest that passed, of those that carry it.
        group.checker.round(&[ms(10), None, ms(90), ms(30)]);
        assert_eq!(group.selected.get().name.as_ref(), "t");
        assert_eq!(goes(&group), both("t", "c"));
        group.checker.round(&[ms(10), None, ms(30), ms(90)]);
        assert_eq!(goes(&group), both("t", "b"));
        // None passed: the one not tested, which is not down.
        group.checker.round(&[ms(10), None, None, None]);
        assert_eq!(goes(&group), both("t", "u"));
        // The member selected carries UDP: it takes both.
        group.checker.round(&[ms(50), None, ms(20), None]);
        assert_eq!(group.selected.get().name.as_ref(), "b");
        assert_eq!(goes(&group), both("b", "b"));
    }

    #[test]
    fn when_every_member_is_down_the_selected_one_is_still_tried() {
        use crate::protocol::group::members::tests::{member, one, outbounds};
        let members = outbounds(&[]);
        members.publish(vec![one("t", true), member(None, "b"), member(None, "c")]);
        let snapshot = members.load();
        let at = std::time::SystemTime::now();
        let tested = |latencies: [Option<Duration>; 3]| -> HashMap<MemberKey, Tested> {
            snapshot
                .members
                .iter()
                .zip(latencies)
                .map(|(m, latency)| (m.key.clone(), Tested { latency, at }))
                .collect()
        };
        let tcp = |m: &AnyOutboundHandler| m.stream().is_ok();
        let udp = |m: &AnyOutboundHandler| m.datagram().is_ok();
        let down = tested([None, None, None]);
        // As it was: the one selected, down as every member is.
        assert_eq!(takes(&snapshot, 2, &down, tcp), 2);
        assert_eq!(takes(&snapshot, 2, &down, udp), 2);
        // It does not carry the network: the first that does.
        assert_eq!(takes(&snapshot, 0, &down, udp), 1);
        // Down, it is left for one that passed, or was not tested yet.
        assert_eq!(takes(&snapshot, 1, &tested([None, None, ms(9)]), udp), 2);
        let untested: HashMap<_, _> = tested([None, None, None])
            .into_iter()
            .filter(|(key, _)| &*key.name != "c")
            .collect();
        assert_eq!(takes(&snapshot, 1, &untested, tcp), 2);
        // No member carries it: the one selected, whose error tells.
        assert_eq!(takes(&snapshot, 1, &down, |_| false), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_failure_through_a_member_not_tested_asks_for_no_tests() {
        use crate::protocol::group::members::tests::{member, one};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let members = Members::of(vec![member(None, "a"), one("u", false)]);
        let rounds = Arc::new(AtomicUsize::new(0));
        let checker = health::tests::running(
            members.clone(),
            Box::new({
                let rounds = rounds.clone();
                move |_, _, _| {
                    rounds.fetch_add(1, Ordering::Relaxed);
                }
            }),
        );
        let group = Group {
            checker,
            members: members.clone(),
            selected: Arc::new(Selection::new("a", MemberKey::outbound("a"))),
            dns_client: health::tests::dns(),
            interrupt: None,
        };
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert_eq!(rounds.load(Ordering::Relaxed), 1);
        let snapshot = members.load();
        let refused = || -> io::Result<()> { Err(io::ErrorKind::ConnectionRefused.into()) };
        let dialer = crate::net::DialDefaults::default()
            .dialer(&Default::default(), None)
            .unwrap();
        let progress = Progress::default();
        progress.dialing(&OutboundConnect::Proxy(
            crate::session::Network::Udp,
            "server.test".into(),
            443,
            dialer,
        ));
        // Through [u], which the tests say nothing of.
        for _ in 0..20 {
            let _ = group.failed(&snapshot.members[1], refused(), &progress);
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert_eq!(rounds.load(Ordering::Relaxed), 1);
        // Through [a], whose server cannot be reached: tested at once.
        let _ = group.failed(&snapshot.members[0], refused(), &progress);
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert_eq!(rounds.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn a_change_of_members_keeps_the_pick_while_it_is_a_member_and_up() {
        use crate::protocol::group::members::tests::{member, outbounds};
        let key = |source: Option<&str>, name: &str| MemberKey {
            source: source.map(Into::into),
            name: name.into(),
        };
        let members = outbounds(&[]);
        members.publish(vec![
            member(None, "a"),
            member(Some("p"), "b"),
            member(Some("p"), "c"),
        ]);
        let snapshot = members.load();
        let latencies: HashMap<MemberKey, Option<Duration>> = [
            (key(None, "a"), ms(90)),
            (key(Some("p"), "b"), None),
            (key(Some("p"), "c"), ms(30)),
        ]
        .into();
        // Kept, slower or untested as it may be.
        assert_eq!(repick(&snapshot, &key(None, "a"), &latencies), None);
        let mut untested = latencies.clone();
        untested.remove(&key(None, "a"));
        assert_eq!(repick(&snapshot, &key(None, "a"), &untested), None);
        // Failed, or gone: the fastest known.
        assert_eq!(
            repick(&snapshot, &key(Some("p"), "b"), &latencies),
            Some(key(Some("p"), "c"))
        );
        assert_eq!(
            repick(&snapshot, &key(Some("q"), "c"), &latencies),
            Some(key(Some("p"), "c"))
        );
        // Nothing known: left for the next tests.
        assert_eq!(
            repick(&snapshot, &key(Some("q"), "c"), &HashMap::new()),
            None
        );
    }
}
