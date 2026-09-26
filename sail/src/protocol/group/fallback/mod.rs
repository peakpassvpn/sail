//! `fallback`: sends every connection to the first member, in the order
//! configured, that passed its last URL test, as Mihomo's fallback group
//! does. Members are tested every `interval`, through them, as `urltest`
//! tests them.
//!
//! A connection that fails through the member selected is tried again
//! through the next members that are up, in order, a few times at most,
//! before it fails: a member can die between two tests.

use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_derive::Deserialize;
use tokio::sync::{watch, RwLock};
use tracing::debug;

use super::health::{self, Checker};
use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{
    parse_options, Options, OutboundContext, OutboundFactory, OutboundRegistry,
};
use crate::adapter::*;
use crate::app::healthcheck::HttpProbe;
use crate::app::outbound::selector::{OutboundSelector, SelectedBy, Selection};
use crate::app::SyncDnsClient;
use crate::net::{connect_datagram_outbound, connect_stream_outbound};
use crate::session::Session;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register("fallback", OutboundFactory::composite(dependencies, build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FallbackOutboundOptions {
    outbounds: Vec<String>,
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
    Ok(options.outbounds)
}

/// The member to select after a round of tests: the first that passed.
/// `None` keeps the selection, when every member failed.
pub(crate) fn choose(latencies: &[Option<Duration>]) -> Option<usize> {
    latencies.iter().position(Option::is_some)
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
    let actors = ctx.members(&options.outbounds)?;
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
    let probe = HttpProbe::new(&options.url, ctx.dns_client.clone())
        .map_err(|e| anyhow!("[{}] outbound: url: {}", ctx.tag, e))?;

    // The first member until the first tests are done.
    let selected = Arc::new(Selection::new(0));
    let on_tested = {
        let selected = selected.clone();
        let tag = ctx.tag.to_owned();
        let members = options.outbounds.clone();
        Box::new(move |latencies: &[Option<Duration>]| {
            let current = selected.get();
            if let Some(next) = choose(latencies) {
                if next != current {
                    debug!(
                        "[{}] switches from [{}] to [{}]",
                        tag, members[current], members[next]
                    );
                    selected.set(next);
                }
            }
        })
    };
    let (checker, abort_handle) = Checker::new(
        ctx.tag,
        actors.clone(),
        probe,
        ctx.dns_client.clone(),
        interval,
        timeout,
        options.lazy.then_some(interval),
        on_tested,
    );
    ctx.abort_handles.push(abort_handle);

    let outbound_selector = OutboundSelector::new(
        ctx.tag.to_owned(),
        options.outbounds.clone(),
        selected.clone(),
        SelectedBy::Checks,
        Some(checker.latencies()),
    );
    ctx.selectors
        .insert(ctx.tag.to_owned(), Arc::new(RwLock::new(outbound_selector)));

    let group = Arc::new(Group {
        tag: ctx.tag.to_owned(),
        actors,
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
    actors: Vec<AnyOutboundHandler>,
    selected: Arc<Selection>,
    checker: Arc<Checker>,
    timeout: Duration,
    dns_client: SyncDnsClient,
    interrupt: Option<watch::Receiver<usize>>,
}

impl Group {
    /// Connects through the members in turn, see `candidates`, until one
    /// connects; returns which, and what it connected. Every member but the
    /// last one tried has `timeout` to connect.
    async fn connect<'a, T, F, Fut>(
        &'a self,
        sess: &'a Session,
        connect: F,
    ) -> io::Result<(usize, T)>
    where
        F: Fn(&'a AnyOutboundHandler) -> Fut,
        Fut: Future<Output = io::Result<T>>,
    {
        self.checker.used();
        let order = candidates(self.selected.get(), self.actors.len(), |i| {
            self.checker.is_up(i)
        });
        let mut last_error = None;
        for (n, &i) in order.iter().enumerate() {
            let a = &self.actors[i];
            debug!(
                "[{}] handles [{}:{}] to [{}]",
                self.tag,
                sess.network,
                sess.destination,
                a.tag()
            );
            let result = if n + 1 < order.len() {
                tokio::time::timeout(self.timeout, connect(a))
                    .await
                    .unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "timed out")))
            } else {
                connect(a).await
            };
            match result {
                Ok(v) => return Ok((i, v)),
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
                    // than wait out the interval.
                    self.checker.retest();
                    last_error = Some(e);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| io::Error::other("no outbound to try")))
    }

    /// The selection a connection through member `i` watches, to end when
    /// the group moves off `i`: only one through the member selected, since
    /// one that fell back to another is already off it.
    fn interrupt(&self, i: usize) -> Option<&watch::Receiver<usize>> {
        self.interrupt
            .as_ref()
            .filter(|selection| *selection.borrow() == i)
    }
}

#[async_trait]
impl OutboundStreamHandler for Group {
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
        let (i, stream) = self
            .connect(sess, |a| async move {
                let stream = connect_stream_outbound(sess, self.dns_client.clone(), a).await?;
                a.stream()?.handle(sess, None, stream).await
            })
            .await?;
        Ok(match self.interrupt(i) {
            Some(selection) => super::interrupt::stream(stream, selection, i),
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
        let (i, datagram) = self
            .connect(sess, |a| async move {
                let transport = connect_datagram_outbound(sess, self.dns_client.clone(), a).await?;
                a.datagram()?.handle(sess, transport).await
            })
            .await?;
        Ok(match self.interrupt(i) {
            Some(selection) => super::interrupt::datagram(datagram, selection, i),
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
        // it: the selection moves only on a round of tests.
        assert_eq!(candidates(0, 3, |i| i == 2), [0, 2]);
    }

    #[test]
    fn when_every_member_is_down_each_is_tried_in_order() {
        assert_eq!(candidates(1, 3, |_| false), [1, 0, 2]);
        assert_eq!(candidates(0, 5, |_| false), [0, 1, 2]);
    }
}
