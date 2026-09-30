//! auto_redirect's pre-match: the first packet of a flow, queued by the
//! ruleset through NFQUEUE, is judged by the router before the flow is
//! redirected, and the verdict marks it for the rules the chain runs again
//! (sing-tun v0.9.6's `NF_REPEAT` verdicts).

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::Semaphore;
use tracing::{debug, warn};

use crate::app::dispatcher::Dispatcher;
use crate::app::router::PreMatch;
use crate::net::accept::AcceptBackoff;
use crate::platform::nfqueue::{Protocol, Queue, Verdict};
use crate::session::{Network, Session, SocksAddr};

/// The marks a verdict sets.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Marks {
    pub input: u32,
    pub output: u32,
    pub reset: u32,
}

/// How many packets may wait on the router at once; past that, a packet is
/// let through unjudged rather than held.
const IN_FLIGHT: usize = 1024;

/// The verdict on a flow's packet of `protocol` that the router judged
/// `decision`: a bypassed flow is marked as sail's own, which every rule
/// lets go; a TCP connection refused is marked for the kernel to reset; a
/// UDP or ICMP flow otherwise goes into the TUN, whose router refuses it or
/// carries it.
pub(crate) fn verdict(protocol: Protocol, decision: PreMatch, marks: Marks) -> Verdict {
    match (decision, protocol) {
        (PreMatch::Bypass, _) => Verdict::Repeat { mark: marks.output },
        (PreMatch::Reject { drop: true }, _) => Verdict::Drop,
        (PreMatch::Reject { drop: false }, Protocol::Tcp) => Verdict::Repeat { mark: marks.reset },
        (PreMatch::Proceed, Protocol::Tcp) => Verdict::Accept,
        (_, Protocol::Udp | Protocol::Icmp) => Verdict::Repeat { mark: marks.input },
    }
}

/// Judges the queued packets, until the queue fails for good.
pub(crate) async fn serve(queue: Queue, tag: String, dispatcher: Arc<Dispatcher>, marks: Marks) {
    let queue = Arc::new(queue);
    let in_flight = Arc::new(Semaphore::new(IN_FLIGHT));
    let mut backoff = AcceptBackoff::new("auto_redirect: nfqueue");
    loop {
        let queued = match queue.recv().await {
            Ok(queued) => {
                backoff.succeeded();
                queued
            }
            // Overrun: the kernel let the packets through (FAIL_OPEN).
            // Reading on at once is what catches up.
            Err(e) if e.raw_os_error() == Some(libc::ENOBUFS) => {
                debug!("auto_redirect: nfqueue overrun: {}", e);
                continue;
            }
            // One datagram the kernel cut or garbled: the next is read.
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                debug!("auto_redirect: nfqueue: {}", e);
                continue;
            }
            Err(e) => {
                if backoff.failed(e).await.is_err() {
                    // The queue's `bypass` flag lets the kernel accept
                    // what nothing reads: the traffic goes on unjudged.
                    warn!("auto_redirect: pre-match stops; bypass rules no longer apply");
                    return;
                }
                continue;
            }
        };
        let id = queued.id;
        let unjudged = |protocol| match protocol {
            Protocol::Tcp => Verdict::Accept,
            _ => Verdict::Repeat { mark: marks.input },
        };
        let Some(flow) = queued.flow else {
            give(&queue, id, Verdict::Accept);
            continue;
        };
        // ICMP has no network a rule can name: it goes into the TUN.
        let network = match flow.protocol {
            _ if !flow.first_packet => None,
            Protocol::Tcp => Some(Network::Tcp),
            Protocol::Udp => Some(Network::Udp),
            Protocol::Icmp => None,
        };
        let Some(network) = network else {
            give(&queue, id, unjudged(flow.protocol));
            continue;
        };
        let Ok(permit) = in_flight.clone().try_acquire_owned() else {
            give(&queue, id, unjudged(flow.protocol));
            continue;
        };
        let (queue, dispatcher, tag) = (queue.clone(), dispatcher.clone(), tag.clone());
        tokio::spawn(async move {
            let _permit = permit;
            let decision = judge(&dispatcher, network, flow.source, flow.destination, tag).await;
            give(&queue, id, verdict(flow.protocol, decision, marks));
        });
    }
}

async fn judge(
    dispatcher: &Dispatcher,
    network: Network,
    source: SocketAddr,
    destination: SocketAddr,
    inbound_tag: String,
) -> PreMatch {
    let mut sess = Session {
        network,
        source,
        destination: SocksAddr::Ip(destination),
        inbound_tag,
        ..Default::default()
    };
    dispatcher.pre_match(&mut sess).await
}

fn give(queue: &Queue, id: u32, verdict: Verdict) {
    if let Err(e) = queue.verdict(id, verdict) {
        warn!("auto_redirect: nfqueue verdict: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdicts_as_sing_tun_gives_them() {
        let marks = Marks {
            input: 1,
            output: 2,
            reset: 3,
        };
        let repeat = |mark| Verdict::Repeat { mark };
        for (protocol, decision, expected) in [
            (Protocol::Tcp, PreMatch::Bypass, repeat(2)),
            (Protocol::Tcp, PreMatch::Reject { drop: false }, repeat(3)),
            (
                Protocol::Tcp,
                PreMatch::Reject { drop: true },
                Verdict::Drop,
            ),
            (Protocol::Tcp, PreMatch::Proceed, Verdict::Accept),
            (Protocol::Udp, PreMatch::Bypass, repeat(2)),
            (Protocol::Udp, PreMatch::Reject { drop: false }, repeat(1)),
            (
                Protocol::Udp,
                PreMatch::Reject { drop: true },
                Verdict::Drop,
            ),
            (Protocol::Udp, PreMatch::Proceed, repeat(1)),
            (Protocol::Icmp, PreMatch::Proceed, repeat(1)),
        ] {
            assert_eq!(
                verdict(protocol, decision, marks),
                expected,
                "{:?} {:?}",
                protocol,
                decision
            );
        }
    }
}
