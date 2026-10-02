//! `urltest`: sends every connection to the member that answered an HTTP
//! request through it fastest, as sing-box's urltest does. Members are
//! tested every `interval`; the group moves to a faster one only when it
//! is faster by more than `tolerance`, so that close latencies do not
//! make it switch back and forth.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_derive::Deserialize;
use tokio::sync::{watch, RwLock};
use tracing::debug;

use super::health::{self, Checker};
use super::members::{Member, MemberKey, Members, Snapshot};
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
    #[serde(default, with = "crate::config::model::duration")]
    interval: Option<Duration>,
    /// Milliseconds.
    #[serde(default = "default_tolerance")]
    tolerance: u16,
    /// Tests pause once the group has not been used for this long.
    #[serde(default, with = "crate::config::model::duration")]
    idle_timeout: Option<Duration>,
    /// Ends the connections through the member left once the group
    /// switches.
    #[serde(default)]
    interrupt_exist_connections: bool,
}

fn default_url() -> String {
    health::DEFAULT_URL.to_string()
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

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let options: UrlTestOutboundOptions = ctx.options()?;
    let merged = merge::members(ctx, &options.outbounds, &options.providers)?;
    let members = merged.members.clone();
    let interval = options.interval.unwrap_or(health::DEFAULT_INTERVAL);
    let idle_timeout = options.idle_timeout.unwrap_or(DEFAULT_IDLE_TIMEOUT);
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
    let probe = HttpProbe::new(&options.url, ctx.dns_client.clone(), ctx.env)
        .map_err(|e| anyhow!("[{}] outbound: url: {}", ctx.tag, e))?;

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
        Box::new(move |snapshot: &Snapshot, latencies: &[Option<Duration>]| {
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
        health::DEFAULT_TIMEOUT,
        Some(idle_timeout),
        on_tested,
    );
    ctx.abort_handles.push(abort_handle);
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
    /// selection it went by.
    fn pick<'s>(&self, snapshot: &'s Snapshot) -> io::Result<(&'s Member, Option<MemberKey>)> {
        self.checker.used();
        let (i, by) = self
            .selected
            .pick(snapshot)
            .ok_or_else(|| io::Error::other("no outbound to select"))?;
        let by = self.interrupt.as_ref().map(|_| MemberKey::clone(&by));
        Ok((&snapshot.members[i], by))
    }

    /// A connection through the selected member that failed is reason to
    /// test again rather than wait out the interval.
    fn failed<T>(&self, result: io::Result<T>) -> io::Result<T> {
        if result.is_err() {
            self.checker.retest();
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
        let (member, by) = self.pick(&snapshot)?;
        let a = &member.handler;
        debug!("urltest handles [{}] to [{}]", sess.destination, a.tag());
        let stream = self.failed(
            async {
                let stream = connect_stream_outbound(sess, self.dns_client.clone(), a).await?;
                let stream = a.stream()?.handle(sess, None, stream).await?;
                sess.chain.push(&member.key.name);
                Ok(stream)
            }
            .await,
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
        let (member, by) = self.pick(&snapshot)?;
        let a = &member.handler;
        debug!("urltest handles [{}] to [{}]", sess.destination, a.tag());
        let datagram = self.failed(
            async {
                let transport = connect_datagram_outbound(sess, self.dns_client.clone(), a).await?;
                let datagram = a.datagram()?.handle(sess, transport).await?;
                sess.chain.push(&member.key.name);
                Ok(datagram)
            }
            .await,
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
