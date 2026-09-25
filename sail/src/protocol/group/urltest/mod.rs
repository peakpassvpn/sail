//! `urltest`: sends every connection to the member that answered an HTTP
//! request through it fastest, as sing-box's urltest does. Members are
//! tested every `interval`; the group moves to a faster one only when it
//! is faster by more than `tolerance`, so that close latencies do not
//! make it switch back and forth.

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
    registry.register("urltest", OutboundFactory::composite(dependencies, build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UrlTestOutboundOptions {
    outbounds: Vec<String>,
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
    Ok(options.outbounds)
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

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let options: UrlTestOutboundOptions = ctx.options()?;
    let actors = ctx.members(&options.outbounds)?;
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
    let probe = HttpProbe::new(&options.url, ctx.dns_client.clone())
        .map_err(|e| anyhow!("[{}] outbound: url: {}", ctx.tag, e))?;

    // The first member until the first tests are done.
    let selected = Arc::new(Selection::new(0));
    let tolerance = Duration::from_millis(options.tolerance.into());
    let on_tested = {
        let selected = selected.clone();
        let tag = ctx.tag.to_owned();
        let members = options.outbounds.clone();
        Box::new(move |latencies: &[Option<Duration>]| {
            let current = selected.get();
            if let Some(next) = choose(current, latencies, tolerance) {
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
        Some(idle_timeout),
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
        actors,
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
    actors: Vec<AnyOutboundHandler>,
    selected: Arc<Selection>,
    checker: Arc<Checker>,
    dns_client: SyncDnsClient,
    interrupt: Option<watch::Receiver<usize>>,
}

impl Group {
    /// The member for a new connection, which is also a use of the group.
    fn pick(&self) -> (usize, &AnyOutboundHandler) {
        self.checker.used();
        let i = self.selected.get();
        (i, &self.actors[i])
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

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        _stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        let (i, a) = self.pick();
        debug!("urltest handles [{}] to [{}]", sess.destination, a.tag());
        let stream = self.failed(
            async {
                let stream = connect_stream_outbound(sess, self.dns_client.clone(), a).await?;
                a.stream()?.handle(sess, None, stream).await
            }
            .await,
        )?;
        Ok(match &self.interrupt {
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
        let (i, a) = self.pick();
        debug!("urltest handles [{}] to [{}]", sess.destination, a.tag());
        let datagram = self.failed(
            async {
                let transport = connect_datagram_outbound(sess, self.dns_client.clone(), a).await?;
                a.datagram()?.handle(sess, transport).await
            }
            .await,
        )?;
        Ok(match &self.interrupt {
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
}
