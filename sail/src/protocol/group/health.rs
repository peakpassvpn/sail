//! The URL tests `urltest`, `load-balance` and `fallback` check their
//! members with: every member at once, through it, every `interval`, while
//! the group is in use and the network is up, and at once when the network
//! changes, as sing-box's urltest does.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use futures::future::{abortable, AbortHandle, BoxFuture};
use futures::FutureExt;
use tokio::sync::Notify;
use tokio::time::Instant;
use tracing::debug;

use super::members::{MemberKey, MemberLatencies, Members, Snapshot};
use crate::app::healthcheck::HttpProbe;
use crate::app::SyncDnsClient;
use crate::net::network::Network;

/// How long one test may take, by default, before its member counts as
/// failed.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// A failed connection asks for the members to be tested again, but not
/// more often than this.
const MIN_RETEST: Duration = Duration::from_secs(2);

pub use crate::app::healthcheck::DEFAULT_URL;
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(3 * 60);

/// Called after every round of tests with the members tested and their
/// latencies, in the same order.
pub type OnTested = Box<dyn Fn(&Snapshot, &[Option<Duration>]) + Send + Sync>;

pub struct Checker {
    tag: String,
    members: Arc<Members>,
    probe: HttpProbe,
    dns_client: SyncDnsClient,
    /// Tests pause while it is down: the members are not failed for it.
    network: Network,
    interval: Duration,
    /// How long one test may take before its member counts as failed.
    timeout: Duration,
    /// Tests pause once the group has not been used for this long, and
    /// resume, at once, when it is used again.
    idle: Option<Duration>,
    /// A member is taken to be up until it is tested.
    latencies: MemberLatencies,
    last_used: Mutex<Instant>,
    wake: Notify,
    /// Whether the next round runs even though the group is idle: the
    /// network changed.
    forced: AtomicBool,
    on_tested: OnTested,
    /// The test loop, until there is a runtime to spawn it on.
    task: Mutex<Option<BoxFuture<'static, ()>>>,
}

impl Checker {
    /// A checker of `members`, and the handle that stops its tests.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tag: &str,
        members: Arc<Members>,
        probe: HttpProbe,
        dns_client: SyncDnsClient,
        network: Network,
        interval: Duration,
        timeout: Duration,
        idle: Option<Duration>,
        on_tested: OnTested,
    ) -> (Arc<Self>, AbortHandle) {
        let checker = Arc::new(Self {
            tag: tag.to_string(),
            members,
            probe,
            dns_client,
            network,
            interval,
            timeout,
            idle,
            latencies: Default::default(),
            last_used: Mutex::new(Instant::now()),
            wake: Notify::new(),
            forced: AtomicBool::new(false),
            on_tested,
            task: Mutex::new(None),
        });
        // The loop holds the checker weakly: a checker that is dropped
        // before its loop was ever spawned is not kept alive by it.
        let (task, abort_handle) = abortable(test_loop(Arc::downgrade(&checker)));
        if let Ok(mut slot) = checker.task.lock() {
            *slot = Some(task.map(|_| ()).boxed());
        }
        checker.start();
        (checker, abort_handle)
    }

    /// Spawns the test loop, once there is a runtime: a configuration can
    /// be built without one, to be checked.
    fn start(&self) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let task = self.task.lock().ok().and_then(|mut slot| slot.take());
        if let Some(task) = task {
            runtime.spawn(task);
        }
    }

    /// For the selector, which shows them.
    #[cfg(any(feature = "outbound-urltest", feature = "outbound-fallback"))]
    pub fn latencies(&self) -> MemberLatencies {
        self.latencies.clone()
    }

    /// Whether `member` passed its last test, or was not tested yet. A
    /// `pass` outbound is never up, see `Snapshot::first_up`; this goes by
    /// the tests only.
    #[cfg(any(feature = "outbound-load-balance", feature = "outbound-fallback"))]
    pub fn is_up(&self, member: &MemberKey) -> bool {
        self.latencies
            .read()
            .map(|l| is_up(&l, member))
            .unwrap_or(true)
    }

    /// Notes that the group is being used, which resumes paused tests.
    pub fn used(&self) {
        self.start();
        let now = Instant::now();
        let was_idle = match self.last_used.lock() {
            Ok(mut last) => {
                let idle = self
                    .idle
                    .is_some_and(|idle| now.duration_since(*last) > idle);
                *last = now;
                idle
            }
            Err(_) => false,
        };
        if was_idle {
            self.wake.notify_one();
        }
    }

    /// Asks for the members to be tested again soon, after a connection
    /// through one failed.
    pub fn retest(&self) {
        self.wake.notify_one();
    }

    /// The network changed: the members are tested again at once, idle
    /// as the group may be, unless it is down, when the change that ends
    /// that tests them. The latencies known are kept until then, as
    /// sing-box keeps its history. Twice is as once.
    pub fn network_changed(&self) {
        if self.network.is_down() {
            return;
        }
        self.start();
        self.forced.store(true, Ordering::Relaxed);
        self.wake.notify_one();
    }

    fn is_idle(&self) -> bool {
        let Some(idle) = self.idle else {
            return false;
        };
        self.last_used
            .lock()
            .map(|last| last.elapsed() > idle)
            .unwrap_or(false)
    }

    async fn test_all(&self) {
        let snapshot = self.members.load();
        let tests = snapshot
            .members
            .iter()
            .map(|m| &m.handler)
            .map(|member| async move {
                // A pass outbound fails any connection: it is down, and
                // not tested.
                if member.is_pass() {
                    return None;
                }
                match tokio::time::timeout(
                    self.timeout,
                    self.probe.run(self.dns_client.clone(), member),
                )
                .await
                {
                    Ok(Ok(latency)) => Some(latency),
                    Ok(Err(e)) => {
                        debug!("[{}] test of [{}] failed: {}", self.tag, member.tag(), e);
                        None
                    }
                    Err(_) => {
                        debug!("[{}] test of [{}] timed out", self.tag, member.tag());
                        None
                    }
                }
            });
        let latencies = futures::future::join_all(tests).await;
        debug!(
            "[{}] tested: {}",
            self.tag,
            snapshot
                .members
                .iter()
                .zip(&latencies)
                .map(|(m, l)| match l {
                    Some(l) => format!("{}({}ms)", m.key.name, l.as_millis()),
                    None => format!("{}(failed)", m.key.name),
                })
                .collect::<Vec<_>>()
                .join(" ")
        );
        if let Ok(mut current) = self.latencies.write() {
            *current = measured(&snapshot, &latencies);
        }
        (self.on_tested)(&snapshot, &latencies);
    }
}

/// The latencies of a round of tests of `snapshot`, by member: those of
/// members since gone are dropped.
fn measured(
    snapshot: &Snapshot,
    latencies: &[Option<Duration>],
) -> HashMap<MemberKey, Option<Duration>> {
    snapshot
        .members
        .iter()
        .zip(latencies)
        .map(|(m, l)| (m.key.clone(), *l))
        .collect()
}

#[cfg(any(feature = "outbound-load-balance", feature = "outbound-fallback"))]
fn is_up(latencies: &HashMap<MemberKey, Option<Duration>>, member: &MemberKey) -> bool {
    latencies.get(member).is_none_or(Option::is_some)
}

async fn test_loop(checker: Weak<Checker>) {
    loop {
        let Some(c) = checker.upgrade() else {
            return;
        };
        if c.network.is_down() {
            debug!("[{}] the network is down, tests paused", c.tag);
        } else if c.forced.swap(false, Ordering::Relaxed) || !c.is_idle() {
            c.test_all().await;
        } else {
            debug!("[{}] not used lately, tests paused", c.tag);
        }
        let tested = Instant::now();
        let interval = c.interval;
        // Woken early by a failure, by use after a pause, or by a change of
        // network.
        let woken = tokio::time::timeout(interval, c.wake.notified())
            .await
            .is_ok();
        // A change of network is not a failure: no wait for it.
        let forced = c.forced.load(Ordering::Relaxed);
        drop(c);
        if woken && !forced {
            tokio::time::sleep_until(tested + MIN_RETEST.min(interval)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::network::{ChangeReason, NetworkState};
    use crate::protocol::group::members::tests::{member, outbounds};
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn a_round_keeps_the_members_tested_and_only_them() {
        let ms = |v| Some(Duration::from_millis(v));
        let members = outbounds(&["a", "b", "c"]);
        let before = measured(&members.load(), &[ms(10), None, ms(30)]);
        assert_eq!(before.len(), 3);

        members.publish(vec![member(None, "c"), member(Some("p"), "d")]);
        let snapshot = members.load();
        let after = measured(&snapshot, &[None, ms(40)]);
        assert_eq!(after.len(), 2);
        assert!(!after.contains_key(&MemberKey::outbound("a")));
        assert_eq!(after[&snapshot.members[0].key], None);
        assert_eq!(after[&snapshot.members[1].key], ms(40));
    }

    #[cfg(any(feature = "outbound-load-balance", feature = "outbound-fallback"))]
    #[test]
    fn a_member_is_up_until_it_fails_a_test() {
        let members = outbounds(&["a", "b"]);
        let latencies = measured(&members.load(), &[Some(Duration::from_millis(10)), None]);
        assert!(is_up(&latencies, &MemberKey::outbound("a")));
        assert!(!is_up(&latencies, &MemberKey::outbound("b")));
        // One new since the round is not tested yet.
        assert!(is_up(&latencies, &MemberKey::outbound("c")));
    }

    /// A checker of no members, which counts its rounds, on `network`.
    fn counting(network: &Network, idle: Option<Duration>) -> (Arc<Checker>, Arc<AtomicUsize>) {
        let dns_client = crate::app::dns::DnsClient::new(
            &Default::default(),
            Arc::new(crate::net::DialDefaults::default()),
            &Default::default(),
        )
        .unwrap()
        .into_shared();
        let probe = HttpProbe::new(
            "http://example.com/",
            dns_client.clone(),
            &Default::default(),
        )
        .unwrap();
        let rounds = Arc::new(AtomicUsize::new(0));
        let (checker, _) = Checker::new(
            "t",
            outbounds(&[]),
            probe,
            dns_client,
            network.clone(),
            DEFAULT_INTERVAL,
            DEFAULT_TIMEOUT,
            idle,
            Box::new({
                let rounds = rounds.clone();
                move |_, _| {
                    rounds.fetch_add(1, Ordering::Relaxed);
                }
            }),
        );
        (checker, rounds)
    }

    fn on(interface: &str) -> NetworkState {
        NetworkState {
            interface: Some(interface.into()),
            ..Default::default()
        }
    }

    async fn settle() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_change_of_network_tests_at_once_idle_as_the_group_is() {
        let network = Network::default();
        network.detected(on("en0"), ChangeReason::State);
        let (checker, rounds) = counting(&network, Some(Duration::from_secs(1)));
        settle().await;
        assert_eq!(rounds.load(Ordering::Relaxed), 1);
        tokio::time::sleep(Duration::from_secs(10)).await;
        // Idle: the tick passes it by.
        tokio::time::sleep(DEFAULT_INTERVAL).await;
        assert_eq!(rounds.load(Ordering::Relaxed), 1);
        network.detected(on("en1"), ChangeReason::State);
        checker.network_changed();
        // Twice, as a group that is both stream and datagram hears it.
        checker.network_changed();
        settle().await;
        assert_eq!(rounds.load(Ordering::Relaxed), 2);
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert_eq!(rounds.load(Ordering::Relaxed), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn nothing_is_tested_while_the_network_is_down() {
        let network = Network::default();
        network.detected(on("en0"), ChangeReason::State);
        let (checker, rounds) = counting(&network, None);
        settle().await;
        assert_eq!(rounds.load(Ordering::Relaxed), 1);
        network.detected(NetworkState::default(), ChangeReason::State);
        checker.network_changed();
        checker.retest();
        // Between two ticks: only the change can test before the next.
        tokio::time::sleep(DEFAULT_INTERVAL * 3 + Duration::from_secs(30)).await;
        assert_eq!(rounds.load(Ordering::Relaxed), 1);
        // Back: tested at once.
        network.detected(on("en0"), ChangeReason::State);
        checker.network_changed();
        settle().await;
        assert_eq!(rounds.load(Ordering::Relaxed), 2);
    }
}
