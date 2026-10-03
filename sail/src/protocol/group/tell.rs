//! The failures of a group's members, told (control::events) by the groups
//! that try members in turn, each its own `DialFailure`.

use std::io;

use crate::control::events::{DialFailure, DialStage, EventHub};
use crate::session::Session;

/// Tells that the member last in `sess`'s chain failed with `e` at
/// `stage`, `more_to_try` as `DialFailure` has it: nothing when the
/// connection's failures are not told (a health check, a DNS detour).
pub(crate) fn member_failed(
    events: &EventHub,
    sess: &Session,
    e: &io::Error,
    stage: DialStage,
    more_to_try: bool,
) {
    if !sess.chain.tells() {
        return;
    }
    let chain = std::iter::once(sess.outbound_tag.clone())
        .chain(sess.chain.get())
        .collect::<Vec<_>>()
        .join(">");
    events.dial_failed(
        DialFailure::new(
            chain,
            crate::app::logger::destination(&sess.destination),
            e.kind(),
            stage,
        )
        .with_more_to_try(more_to_try),
    );
}

/// A member a group tries, one after another: in the chain from before
/// it is dialled, and out again if it fails and the group goes on.
#[cfg(any(feature = "outbound-fallback", feature = "outbound-smart"))]
pub(crate) struct Attempt {
    /// The chain before the member.
    mark: usize,
    /// The groups that had given up before it.
    ended: usize,
    /// Whether a group around this one goes on if this one gives up.
    outer: bool,
    /// Whether this group goes on to another member if this one fails.
    more: bool,
}

#[cfg(any(feature = "outbound-fallback", feature = "outbound-smart"))]
impl Attempt {
    /// Before `member` is dialled; `more` if the group has another member
    /// to try after it. A group in the member sees that someone goes on.
    pub(crate) fn start(sess: &Session, member: &str, more: bool) -> Self {
        let chain = &sess.chain;
        let mark = chain.mark();
        let ended = chain.ended();
        let outer = chain.more();
        chain.set_more(more || outer);
        chain.push(member);
        Attempt {
            mark,
            ended,
            outer,
            more,
        }
    }

    /// The member connected: it stays in the chain.
    pub(crate) fn connected(self, sess: &Session) {
        sess.chain.set_more(self.outer);
    }

    /// The member failed with `e` at `stage`: told, unless it is a group
    /// that told already, having given up. The chain is put back when the
    /// group goes on; when it gives up, it keeps the member that failed
    /// last.
    pub(crate) fn failed(self, events: &EventHub, sess: &Session, e: &io::Error, stage: DialStage) {
        let chain = &sess.chain;
        chain.set_more(self.outer);
        if chain.ended() == self.ended {
            member_failed(events, sess, e, stage, self.more || self.outer);
        }
        if self.more {
            chain.truncate(self.mark);
        } else {
            chain.end();
        }
    }
}
