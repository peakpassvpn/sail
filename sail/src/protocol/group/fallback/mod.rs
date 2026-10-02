//! `fallback`: sends every connection to the first member, in the order
//! configured, that passed its last URL test, as Mihomo's fallback group
//! does. Members are tested every `interval`, through them, as `urltest`
//! tests them.
//!
//! A connection that fails through the member selected is tried again
//! through the next members that are up, in order, a few times at most,
//! before it fails: a member can die between two tests. A failure that
//! says the member itself cannot be reached marks it down at once, see
//! `member_unreachable`, so that the next connection goes to the next
//! member without waiting for the tests, which run again to bring it
//! back up.

use std::future::Future;
use std::io;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_derive::Deserialize;
use tokio::sync::{watch, RwLock};
use tracing::{debug, info};

use super::health::{self, Checker};
use super::members::{MemberKey, Members, Snapshot};
use super::merge;
use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{
    parse_options, Options, OutboundContext, OutboundFactory, OutboundRegistry,
};
use crate::adapter::*;
use crate::app::healthcheck::HttpProbe;
use crate::app::outbound::selector::{OutboundSelector, SelectedBy, Selection};
use crate::app::SyncDnsClient;
use crate::config::model::GroupProviders;
use crate::net::{connect_datagram_outbound, connect_stream_outbound};
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
    #[serde(default, with = "crate::config::model::duration")]
    interval: Option<Duration>,
    /// How long a test, or a connection attempt that has a member left to
    /// fall back to, may take before its member counts as failed.
    #[serde(default, with = "crate::config::model::duration")]
    timeout: Option<Duration>,
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

/// The member to select after a round of tests: the first that passed.
/// `None` keeps the selection, when every member failed.
pub(crate) fn choose(latencies: &[Option<Duration>]) -> Option<usize> {
    latencies.iter().position(Option::is_some)
}

/// How far an attempt through a member got when it failed, which tells
/// what the failure says of the member.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Stage {
    /// Dialling something else than the member's own server: the
    /// destination (a direct member), or nothing (a member that dials by
    /// itself, a group, a QUIC protocol), whose failures cannot be told
    /// from the destination's.
    Elsewhere = 0,
    /// Dialling the member's server.
    DialingServer = 1,
    /// Its server dialled, the member's handshake over it.
    Handshake = 2,
}

/// The stage an attempt is at, as it moves on.
#[derive(Default)]
struct Progress(AtomicU8);

impl Progress {
    fn set(&self, stage: Stage) {
        self.0.store(stage as u8, Ordering::Relaxed);
    }

    fn get(&self) -> Stage {
        match self.0.load(Ordering::Relaxed) {
            1 => Stage::DialingServer,
            2 => Stage::Handshake,
            _ => Stage::Elsewhere,
        }
    }

    /// Before the member dials `connect`.
    fn dialing(&self, connect: &OutboundConnect) {
        self.set(match connect {
            OutboundConnect::Proxy(..) => Stage::DialingServer,
            _ => Stage::Elsewhere,
        });
    }

    /// The dial done, before the member's handshake.
    fn dialled(&self) {
        if self.get() == Stage::DialingServer {
            self.set(Stage::Handshake);
        }
    }
}

/// Whether a connection through a member that failed at `stage` with
/// `kind` says the member itself cannot be reached, which marks it down
/// at once rather than at the next round of tests.
///
/// Conservatively: only what can only be the member's server's doing.
/// Its server refusing the dial, not answering it in time, or being out
/// of reach; then, the dial done, the server ending or garbling the
/// handshake (a TLS failure is `InvalidData`). Not what the destination
/// causes through a working server: a refusal the protocol reports (a
/// SOCKS reply, an HTTP proxy's status, a mux stream refused) comes as
/// another kind, `Other` or `ConnectionRefused` after the dial, and a
/// handshake that times out may be waiting on the destination, as SOCKS
/// waits for its connect. Nor anything a member that dials by itself or
/// dials the destination meets, which cannot be told apart. Those only
/// ask for the tests to run again.
pub(crate) fn member_unreachable(stage: Stage, kind: io::ErrorKind) -> bool {
    use io::ErrorKind::*;
    match stage {
        Stage::DialingServer => matches!(
            kind,
            ConnectionRefused
                | TimedOut
                | HostUnreachable
                | NetworkUnreachable
                | ConnectionReset
                | ConnectionAborted
        ),
        Stage::Handshake => matches!(kind, InvalidData | UnexpectedEof | ConnectionReset),
        Stage::Elsewhere => false,
    }
}

/// Moves the group to the first member up, in the order configured,
/// members not tested yet taken to be up, unless it is there already or
/// none is; logs why.
fn reselect(tag: &str, selected: &Selection, checker: &Checker, snapshot: &Snapshot, why: &str) {
    let current = selected.get();
    let Some(next) = snapshot
        .members
        .iter()
        .find(|m| !m.handler.is_pass() && checker.is_up(&m.key))
    else {
        return;
    };
    if next.key != *current {
        info!(
            "[{}] switches from [{}] to [{}]: {}",
            tag, current.name, next.key.name, why
        );
        selected.set(next.key.clone());
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
    if interval.is_zero() {
        return Err(anyhow!(
            "[{}] outbound: interval: must not be zero",
            ctx.tag
        ));
    }
    if timeout.is_zero() {
        return Err(anyhow!("[{}] outbound: timeout: must not be zero", ctx.tag));
    }
    let probe = HttpProbe::new(&options.url, ctx.dns_client.clone(), ctx.env)
        .map_err(|e| anyhow!("[{}] outbound: url: {}", ctx.tag, e))?;

    // The first member until the first tests are done.
    let first = members
        .load()
        .first_up()
        .map(|m| m.key.clone())
        .unwrap_or_else(|| MemberKey::outbound(""));
    let selected = Arc::new(Selection::new(&first.name, first.clone()));
    let on_tested = {
        let selected = selected.clone();
        let tag = ctx.tag.to_owned();
        Box::new(move |snapshot: &Snapshot, latencies: &[Option<Duration>]| {
            let current = selected.get();
            if let Some(next) = choose(latencies) {
                let next = &snapshot.members[next].key;
                if *next != *current {
                    let failed = snapshot
                        .position(&current)
                        .is_some_and(|i| latencies[i].is_none());
                    let why = match failed {
                        true => format!("[{}] failed its test", current.name),
                        false => format!("[{}] passed its test and comes first", next.name),
                    };
                    info!(
                        "[{}] switches from [{}] to [{}]: {}",
                        tag, current.name, next.name, why
                    );
                    selected.set(next.clone());
                }
            }
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
        options.lazy.then_some(interval),
        on_tested,
    );
    ctx.abort_handles.push(abort_handle);
    merged.on_merged({
        let selected = selected.clone();
        let checker = checker.clone();
        let tag = ctx.tag.to_owned();
        Box::new(move |snapshot, added| {
            // The first member up in the new order, new ones untested and
            // so taken to be up.
            reselect(&tag, &selected, &checker, snapshot, "its members changed");
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
        tag: ctx.tag.to_owned(),
        members,
        interrupt: options
            .interrupt_exist_connections
            .then(|| selected.subscribe()),
        selected,
        checker,
        timeout,
        dns_client: ctx.dns_client.clone(),
    });
    Ok(HandlerBuilder::default()
        .tag(ctx.tag.to_owned())
        .stream_handler(group.clone())
        .datagram_handler(group)
        .build())
}

struct Group {
    tag: String,
    members: Arc<Members>,
    selected: Arc<Selection>,
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
                Ok(v) => return Ok((&snapshot.members[i].key, v)),
                Err(e) => {
                    debug!(
                        "[{}] failed to handle [{}:{}] through [{}]: {}",
                        self.tag,
                        sess.network,
                        sess.destination,
                        a.tag(),
                        e
                    );
                    // A member failed between tests: test again rather
                    // than wait out the interval; and if it cannot be
                    // reached, the next connection goes elsewhere now.
                    let key = &snapshot.members[i].key;
                    if member_unreachable(progress.get(), e.kind()) {
                        if self.checker.mark_down(key) {
                            let why = format!("a connection through [{}] failed: {}", key.name, e);
                            reselect(&self.tag, &self.selected, &self.checker, snapshot, &why);
                        }
                    } else {
                        self.checker.retest();
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
                progress.dialing(&a.stream()?.connect_addr());
                let stream = connect_stream_outbound(sess, self.dns_client.clone(), a).await?;
                progress.dialled();
                let stream = a.stream()?.handle(sess, None, stream).await?;
                Ok(stream)
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
                progress.dialing(&a.datagram()?.connect_addr());
                let transport = connect_datagram_outbound(sess, self.dns_client.clone(), a).await?;
                progress.dialled();
                let datagram = a.datagram()?.handle(sess, transport).await?;
                Ok(datagram)
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

    fn ms(v: u64) -> Option<Duration> {
        Some(Duration::from_millis(v))
    }

    #[test]
    fn the_first_member_up_is_chosen_whatever_its_latency() {
        assert_eq!(choose(&[ms(900), ms(10)]), Some(0));
        assert_eq!(choose(&[None, ms(900), ms(10)]), Some(1));
    }

    #[test]
    fn nothing_changes_when_every_member_failed() {
        assert_eq!(choose(&[None, None]), None);
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
    fn only_failures_of_the_members_server_mark_it_down() {
        use io::ErrorKind::*;
        for kind in [
            ConnectionRefused,
            TimedOut,
            HostUnreachable,
            ConnectionReset,
        ] {
            assert!(member_unreachable(Stage::DialingServer, kind), "{:?}", kind);
        }
        assert!(member_unreachable(Stage::Handshake, InvalidData));
        assert!(member_unreachable(Stage::Handshake, UnexpectedEof));
        // A refusal the protocol reports, a handshake waiting on the
        // destination, a DNS failure: not the server's.
        assert!(!member_unreachable(Stage::Handshake, Other));
        assert!(!member_unreachable(Stage::Handshake, ConnectionRefused));
        assert!(!member_unreachable(Stage::Handshake, TimedOut));
        assert!(!member_unreachable(Stage::DialingServer, Other));
        // The destination's, or what cannot be told from it.
        assert!(!member_unreachable(Stage::Elsewhere, ConnectionRefused));
        assert!(!member_unreachable(Stage::Elsewhere, TimedOut));
    }

    #[test]
    fn when_every_member_is_down_each_is_tried_in_order() {
        assert_eq!(candidates(1, 3, |_| false), [1, 0, 2]);
        assert_eq!(candidates(0, 5, |_| false), [0, 1, 2]);
    }
}
