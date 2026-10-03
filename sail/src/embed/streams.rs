//! What a host shows of a running instance, on a timer: its traffic, its
//! connections, its outbounds. Snapshots, not events: each item is the
//! whole picture then. They go on through stops and starts, quiet while it
//! does not run, until dropped. They need a tokio runtime to run on.

use std::time::Duration;

use futures::Stream;

use super::{ConnectionInfo, Instance, OutboundInfo};

/// Intervals shorter are taken as this: a host cannot ask for a busy loop.
const INTERVAL_MIN: Duration = Duration::from_millis(100);

/// The traffic now, and its rate since the item before.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Status {
    /// Bytes a second, up and down, since the item before; 0 in the first.
    pub up: u64,
    pub down: u64,
    pub up_total: u64,
    pub down_total: u64,
    pub connections: usize,
    /// The process's resident memory, in bytes.
    pub memory: u64,
}

fn ticker(every: Duration) -> tokio::time::Interval {
    let mut ticker = tokio::time::interval(every.max(INTERVAL_MIN));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    ticker
}

impl Instance {
    /// The traffic each `every` (100 ms at least), with its rate, while it
    /// runs.
    pub fn status(&self, every: Duration) -> impl Stream<Item = Status> + Send + 'static {
        let inner = self.inner().clone();
        futures::stream::unfold(
            (inner, ticker(every), None),
            |(inner, mut ticker, mut last): (_, _, Option<(tokio::time::Instant, u64, u64)>)| async move {
                loop {
                    ticker.tick().await;
                    let Ok(manager) = inner.manager() else {
                        last = None;
                        continue;
                    };
                    let traffic = manager.traffic().await;
                    let now = tokio::time::Instant::now();
                    let (up, down) = match last {
                        Some((then, up0, down0)) => {
                            let secs = now.duration_since(then).as_secs_f64().max(f64::EPSILON);
                            (
                                (traffic.up_total.saturating_sub(up0) as f64 / secs) as u64,
                                (traffic.down_total.saturating_sub(down0) as f64 / secs) as u64,
                            )
                        }
                        None => (0, 0),
                    };
                    let status = Status {
                        up,
                        down,
                        up_total: traffic.up_total,
                        down_total: traffic.down_total,
                        connections: traffic.connections,
                        memory: crate::control::resident_memory(),
                    };
                    let last = Some((now, traffic.up_total, traffic.down_total));
                    return Some((status, (inner, ticker, last)));
                }
            },
        )
    }

    /// The connections open, each `every`, while it runs.
    pub fn watch_connections(
        &self,
        every: Duration,
    ) -> impl Stream<Item = Vec<ConnectionInfo>> + Send + 'static {
        let inner = self.inner().clone();
        futures::stream::unfold((inner, ticker(every)), |(inner, mut ticker)| async move {
            loop {
                ticker.tick().await;
                let Ok(manager) = inner.manager() else {
                    continue;
                };
                let connections = manager.connections().await;
                return Some((connections, (inner, ticker)));
            }
        })
    }

    /// The outbounds (or the groups alone), when they change: at once when
    /// a group's selection or a member's checks do, else as looked at each
    /// `every`, while it runs.
    pub fn watch_outbounds(
        &self,
        every: Duration,
        groups_only: bool,
    ) -> impl Stream<Item = Vec<OutboundInfo>> + Send + 'static {
        let inner = self.inner().clone();
        let state = (inner, ticker(every), None::<String>, None);
        futures::stream::unfold(
            state,
            move |(inner, mut ticker, mut last, mut changes)| async move {
                loop {
                    match changes.take() {
                        Some(changes) => {
                            let changes: crate::control::GroupChanges = changes;
                            tokio::select! {
                                _ = ticker.tick() => {}
                                _ = changes.changed() => {}
                            }
                        }
                        None => {
                            ticker.tick().await;
                        }
                    }
                    let Ok(manager) = inner.manager() else {
                        last = None;
                        continue;
                    };
                    // Before the groups are read: a change after is not missed.
                    changes = Some(manager.group_changes().await);
                    let list = if groups_only {
                        manager.groups().await
                    } else {
                        manager.outbounds().await
                    };
                    let now = format!("{:?}", list);
                    if last.as_ref() != Some(&now) {
                        last = Some(now);
                        return Some((list, (inner, ticker, last, changes)));
                    }
                }
            },
        )
    }
}
