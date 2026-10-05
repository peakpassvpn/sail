//! A reload's recheck of the connections open (`RecheckOpen::CloseRejected`):
//! each the rules routed is matched again against the routing the reload
//! leaves, with no side effect (`Router::recheck`). Those the rules now
//! reject or drop are closed as the connections of a removed inbound are;
//! those they send to another outbound are told, and go on.

use std::sync::Arc;

use super::outbound::manager::OutboundManager;
use super::router::{Decision, Passes, Router};
use super::stat_manager::StatManager;
use crate::control::{RecheckClosed, RecheckDiffer, RecheckReport};
use crate::session::Session;

/// What a recheck finds of a connection.
enum Verdict {
    /// The rules reject or drop it, by the rule of this index.
    Close(Option<u32>),
    /// They send it to the outbound of this tag, as the connections list
    /// the one it goes to.
    Goes(String),
}

/// Where the rules of `router` send the connection whose session is
/// `sess`, the outbound as the dispatcher would take it: the handler of the
/// tag picked, the default one, or the implicit direct. Behind a captive
/// portal the dispatcher sends every connection direct; a recheck goes by
/// the rules alone. None when there is no outbound to send it to.
async fn judge(router: &Router, outbounds: &OutboundManager, sess: &Session) -> Option<Verdict> {
    let recheck = router.recheck(sess, outbounds).await;
    let tag = match recheck.decision {
        Decision::Reject { .. } => return Some(Verdict::Close(recheck.rule)),
        Decision::HijackDns => return Some(Verdict::Goes("hijack-dns".to_string())),
        Decision::Route(Some(tag)) => Some(tag),
        Decision::Route(None) => {
            let tag = outbounds.default_handler()?;
            match outbounds.passes(&tag).await {
                true => None,
                false => Some(tag),
            }
        }
        Decision::Direct => None,
    };
    outbounds
        .handler(tag.as_deref())
        .map(|h| Verdict::Goes(h.tag().clone()))
}

/// Rechecks each connection open the rules routed against `router`: closes
/// those it rejects or drops, and tells those it sends to another outbound
/// than theirs. Those closed already, as the reload closed the connections
/// of the inbounds it removed or replaced, are passed over.
pub(crate) async fn pass(
    stats: &StatManager,
    router: &Router,
    outbounds: &OutboundManager,
) -> RecheckReport {
    let mut report = RecheckReport::default();
    for counter in stats.connections() {
        if counter.sess.routed_by == 0 || counter.closer.is_closed() {
            continue;
        }
        match judge(router, outbounds, &counter.sess).await {
            Some(Verdict::Close(rule)) => {
                if stats.close(counter.id) {
                    report.closed.push(RecheckClosed {
                        id: counter.id,
                        rule,
                    });
                }
            }
            Some(Verdict::Goes(tag)) if tag != counter.sess.outbound_tag => {
                report.differ.push(RecheckDiffer {
                    id: counter.id,
                    old: counter.sess.outbound_tag.clone(),
                    new: tag,
                });
            }
            Some(Verdict::Goes(_)) | None => {}
        }
    }
    report
}

/// The connection `id`, listed with the session `sess` after a reload's
/// recheck went by, an older router having routed it: rechecked as the
/// recheck would have, against the router now, and closed if its rules
/// reject or drop it.
pub(crate) async fn late(
    stats: &StatManager,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
    sess: &Session,
    id: u64,
) {
    if let Some(Verdict::Close(rule)) = judge(&router, &outbounds, sess).await {
        tracing::debug!(
            "connection {} routed before the reload: rule {:?} rejects it now, closed",
            id,
            rule
        );
        stats.close(id);
    }
}

#[cfg(test)]
mod tests;
