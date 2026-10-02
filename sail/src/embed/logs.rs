//! An instance's log, as a host follows it: the lines kept, then those
//! logged, in batches.

use std::sync::Arc;

use futures::Stream;
use tokio::sync::broadcast::error::{RecvError, TryRecvError};

use super::Instance;
use crate::app::logger::{InstanceLog, LogEvent};

pub use crate::app::logger::LogLine;

/// Lines to a batch, at most.
const BATCH: usize = 256;

/// Which lines to follow.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct LogFilter {
    /// The least severe level taken.
    pub level: tracing::Level,
    /// Whether the lines kept before come first.
    pub backlog: bool,
}

impl Default for LogFilter {
    /// Every level, the lines kept first.
    fn default() -> Self {
        Self {
            level: tracing::Level::TRACE,
            backlog: true,
        }
    }
}

impl LogFilter {
    pub fn level(mut self, level: tracing::Level) -> Self {
        self.level = level;
        self
    }

    pub fn backlog(mut self, backlog: bool) -> Self {
        self.backlog = backlog;
        self
    }
}

/// Lines of the log, in the order logged.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct LogBatch {
    /// Drop the lines had so far: the first batch, and after
    /// `clear_logs`.
    pub reset: bool,
    pub lines: Vec<Arc<LogLine>>,
    /// Lines left out since the last batch: this follower fell behind.
    pub dropped: u64,
}

impl Instance {
    /// Follows the log: the lines kept (with `backlog`), then each batch
    /// logged, through stops and starts, until dropped. A follower too
    /// slow misses lines, counted in `dropped`, rather than hold them.
    pub fn logs(&self, filter: LogFilter) -> impl Stream<Item = LogBatch> + Send + 'static {
        follow(self.log().clone(), filter)
    }
}

pub(super) fn follow(
    log: Arc<InstanceLog>,
    filter: LogFilter,
) -> impl Stream<Item = LogBatch> + Send + 'static {
    let least = filter.level;
    let wanted = move |line: &LogLine| line.level <= least;
    let (kept, events) = log.follow();
    let first = LogBatch {
        reset: true,
        lines: if filter.backlog {
            kept.into_iter().filter(|l| wanted(l)).collect()
        } else {
            Vec::new()
        },
        dropped: 0,
    };
    futures::stream::unfold(
        (Some(first), events, 0u64),
        move |(first, mut events, mut dropped)| async move {
            if let Some(first) = first {
                return Some((first, (None, events, dropped)));
            }
            loop {
                let mut lines = Vec::new();
                let mut reset = false;
                let take = |event: LogEvent, lines: &mut Vec<Arc<LogLine>>, reset: &mut bool| {
                    match event {
                        LogEvent::Line(line) if wanted(&line) => lines.push(line),
                        LogEvent::Line(_) => {}
                        LogEvent::Cleared => {
                            lines.clear();
                            *reset = true;
                        }
                    }
                };
                match events.recv().await {
                    Ok(event) => take(event, &mut lines, &mut reset),
                    Err(RecvError::Lagged(n)) => dropped += n,
                    Err(RecvError::Closed) => return None,
                }
                while lines.len() < BATCH {
                    match events.try_recv() {
                        Ok(event) => take(event, &mut lines, &mut reset),
                        Err(TryRecvError::Lagged(n)) => dropped += n,
                        Err(TryRecvError::Empty) | Err(TryRecvError::Closed) => break,
                    }
                }
                if lines.is_empty() && !reset && dropped == 0 {
                    continue;
                }
                let batch = LogBatch {
                    reset,
                    lines,
                    dropped: std::mem::take(&mut dropped),
                };
                return Some((batch, (None, events, dropped)));
            }
        },
    )
}
