use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::Result;

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{
    parse_options, Options, OutboundContext, OutboundFactory, OutboundRegistry,
};
use crate::adapter::AnyOutboundHandler;
use crate::control::events::{DialStage, EventHub};
use crate::session::{Chain, Session};
use serde_derive::Deserialize;

pub mod datagram;
pub mod stream;

pub use datagram::Handler as DatagramHandler;
pub use stream::Handler as StreamHandler;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register("tryall", OutboundFactory::composite(dependencies, build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TryAllOutboundOptions {
    outbounds: Vec<String>,
    /// Milliseconds to wait before trying each next outbound.
    #[serde(default)]
    delay_base: u32,
}

fn dependencies(tag: &str, options: &Options) -> Result<Vec<String>> {
    let options: TryAllOutboundOptions = parse_options("outbound", tag, options)?;
    Ok(options.outbounds)
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let options: TryAllOutboundOptions = ctx.options()?;
    let actors = ctx.members(&options.outbounds)?;
    let stream = Arc::new(StreamHandler {
        actors: actors.clone(),
        tags: options.outbounds.clone(),
        delay_base: options.delay_base,
        dns_client: ctx.dns_client.clone(),
        events: ctx.env.events.clone(),
    });
    let datagram = Arc::new(DatagramHandler {
        actors,
        tags: options.outbounds,
        delay_base: options.delay_base,
        dns_client: ctx.dns_client.clone(),
        events: ctx.env.events.clone(),
    });
    Ok(HandlerBuilder::default()
        .is_group(true)
        .tag(ctx.tag.to_owned())
        .stream_handler(stream)
        .datagram_handler(datagram)
        .build())
}

/// The members' attempts of one connection, side by side: each in a chain
/// of its own (`Chain::fork`), the member in it before it is dialled, its
/// failure told as a fallback's are, and the chain of the one that
/// connected, or else failed last, the session's in the end.
pub(super) struct Attempts {
    forks: Vec<Chain>,
    /// Whether a group around this one goes on if it gives up.
    outer: bool,
    /// The attempts not failed yet.
    pending: AtomicUsize,
    last_failed: AtomicUsize,
}

impl Attempts {
    pub(super) fn new(sess: &Session, members: usize) -> Self {
        let outer = sess.chain.more();
        let forks = (0..members)
            .map(|_| {
                let fork = sess.chain.fork();
                fork.set_more(members > 1 || outer);
                fork
            })
            .collect();
        Attempts {
            forks,
            outer,
            pending: AtomicUsize::new(members),
            last_failed: AtomicUsize::new(0),
        }
    }

    /// The session attempt `i` goes in, through `member`.
    pub(super) fn session(&self, sess: &Session, i: usize, member: &str) -> Session {
        let at = Session {
            chain: self.forks[i].clone(),
            ..sess.clone()
        };
        at.chain.push(member);
        at
    }

    /// Attempt `i`, in `at`, failed with `e`: told, unless it was a group
    /// that gave up having told it.
    pub(super) fn failed(&self, events: &EventHub, i: usize, at: &Session, e: &io::Error) {
        let left = self.pending.fetch_sub(1, Ordering::SeqCst) - 1;
        self.last_failed.store(i, Ordering::SeqCst);
        // Those still trying: whether any other is.
        for fork in &self.forks {
            fork.set_more(left > 1 || self.outer);
        }
        if at.chain.ended() == 0 {
            super::tell::member_failed(
                events,
                at,
                e,
                DialStage::guessed(e.kind()),
                left > 0 || self.outer,
            );
        }
        if left == 0 {
            at.chain.end();
        }
    }

    /// Done, attempt `won` connected or none did: the session's chain is
    /// that attempt's, or the last that failed.
    pub(super) fn done(&self, sess: &Session, won: Option<usize>) {
        let taken = won.unwrap_or_else(|| self.last_failed.load(Ordering::SeqCst));
        for (i, fork) in self.forks.iter().enumerate() {
            sess.chain.join(fork, i == taken);
        }
    }
}
