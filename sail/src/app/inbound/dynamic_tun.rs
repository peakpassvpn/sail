//! One opt-in attachment, owned by a run rather than a host handle.
use std::sync::{Arc, Mutex, MutexGuard};

use crate::embed::tun::{PacketBridge, PreparedTun, TunPacketFlow, TunState};
use crate::embed::{Error, ErrorKind};
use crate::net::netstack::NativeRuntimeControl;
use crate::protocol::tun::inbound::TunRunner;
use crate::runtime::scope::{StopReport, TaskScope};
use crate::runtime::teardown::Teardown;
use crate::RuntimeManager;
use futures::FutureExt;

#[derive(Default)]
pub(crate) struct DynamicTun(Mutex<State>);
#[derive(Default)]
struct State {
    closed: bool,
    next: u64,
    phase: Phase,
}
#[derive(Default)]
enum Phase {
    #[default]
    Empty,
    Prepared {
        token: u64,
        tag: String,
        source: PreparedSource,
        scope: TaskScope,
    },
    Committing {
        token: u64,
        tag: String,
    },
    Active {
        tag: String,
        control: NativeRuntimeControl,
        scope: TaskScope,
        teardown: Teardown,
    },
    Draining {
        tag: String,
        scope: TaskScope,
        teardown: Teardown,
    },
}
enum PreparedSource {
    Packets(TunRunner),
}
impl DynamicTun {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn control(&self) -> Option<NativeRuntimeControl> {
        match &self.lock().phase {
            Phase::Active { control, scope, .. } if scope.failure().is_none() => {
                Some(control.clone())
            }
            _ => None,
        }
    }
}
impl Drop for DynamicTun {
    fn drop(&mut self) {
        // Fallback if run() unwinds before its explicit drain, particularly
        // on a host-owned runtime that will keep running after Sail stops.
        let state = self.lock();
        if let Phase::Active { scope, .. } | Phase::Draining { scope, .. } = &state.phase {
            scope.abort_all();
        }
    }
}
impl RuntimeManager {
    /// A reload/add cannot claim the attachment's tag or add a static TUN
    /// while any dynamic transaction owns the slot.
    pub(crate) fn check_dynamic_inbounds(
        &self,
        inbounds: &[crate::config::Inbound],
    ) -> Result<(), crate::Error> {
        let state = self.dynamic_tun.lock();
        let tag = match &state.phase {
            Phase::Empty => return Ok(()),
            Phase::Prepared { tag, .. }
            | Phase::Committing { tag, .. }
            | Phase::Active { tag, .. }
            | Phase::Draining { tag, .. } => tag,
        };
        if inbounds
            .iter()
            .any(|i| i.tag == *tag || i.protocol == "tun")
        {
            return Err(crate::Error::Config(anyhow::anyhow!(
                "dynamic TUN reserves tag [{}] and the TUN slot; detach it first",
                tag
            )));
        }
        Ok(())
    }
    pub(crate) fn current_tun_control(&self) -> Option<NativeRuntimeControl> {
        self.dynamic_tun
            .control()
            .or_else(|| self.tun_control.clone())
    }
    pub(crate) fn dynamic_tun_state(&self) -> TunState {
        match &self.dynamic_tun.lock().phase {
            Phase::Empty => TunState::Detached,
            Phase::Prepared { tag, .. } => TunState::Prepared { tag: tag.clone() },
            Phase::Committing { tag, .. } => TunState::Committing { tag: tag.clone() },
            Phase::Active { tag, scope, .. } if scope.failure().is_none() => {
                TunState::Attached { tag: tag.clone() }
            }
            Phase::Active { tag, scope, .. } => TunState::Failed {
                tag: tag.clone(),
                reason: scope.failure().unwrap_or_else(|| "TUN ended".to_string()),
            },
            Phase::Draining { tag, .. } => TunState::Draining { tag: tag.clone() },
        }
    }
    pub(crate) fn cancel_prepared_tun(&self, token: u64) {
        let old = {
            let mut state = self.dynamic_tun.lock();
            if matches!(state.phase, Phase::Prepared { token: current, .. } if current == token) {
                std::mem::take(&mut state.phase)
            } else {
                Phase::Empty
            }
        };
        // Drops the unpolled runner/packet bridge outside the mutex.
        drop(old);
    }
    fn check_dynamic_tun(&self, tag: &str) -> Result<(), Error> {
        if !self.env.host.dynamic_tun {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "dynamic TUN is not enabled",
            ));
        }
        let inbounds = self
            .inbound_manager
            .lock()
            .map_err(|_| Error::state("inbound manager poisoned"))?;
        if inbounds
            .configs()
            .iter()
            .any(|i| i.protocol == "tun" || i.tag == tag)
        {
            return Err(Error::state(
                "a static TUN or an inbound with this tag already exists",
            ));
        }
        Ok(())
    }
    pub(crate) async fn prepare_tun_packets(
        self: &Arc<Self>,
        json: &str,
        capacity: usize,
    ) -> Result<(PreparedTun, TunPacketFlow), Error> {
        let _update = self.update.lock().await;
        let config = crate::config::from_string(&format!("{{\"inbounds\":[{json}]}}"))
            .map_err(|e| Error::new(ErrorKind::Config, format!("{e:#}")))?;
        if config.inbounds.len() != 1 {
            return Err(Error::new(
                ErrorKind::InvalidArgument,
                "exactly one TUN inbound required",
            ));
        }
        let inbound =
            config.inbounds.into_iter().next().ok_or_else(|| {
                Error::new(ErrorKind::InvalidArgument, "one TUN inbound required")
            })?;
        if inbound.protocol != "tun"
            || inbound.tag.is_empty()
            || inbound.listen.is_some()
            || inbound.listen_port.is_some()
        {
            return Err(Error::new(
                ErrorKind::InvalidArgument,
                "one named TUN inbound without a listen address is required",
            ));
        }
        self.check_dynamic_tun(&inbound.tag)?;
        {
            let state = self.dynamic_tun.lock();
            if state.closed {
                return Err(Error::not_running());
            }
            if !matches!(state.phase, Phase::Empty) {
                return Err(Error::state(
                    "a TUN is already prepared, attached or draining",
                ));
            }
        }
        let settings = crate::protocol::tun::inbound::options(&inbound, &self.env.host)
            .map_err(|e| Error::new(ErrorKind::Config, format!("{e:#}")))?;
        if settings.auto_route || settings.auto_redirect.is_some() {
            return Err(Error::new(ErrorKind::Unsupported, "dynamic packet TUN leaves OS routes and DNS to the host; auto_route/auto_redirect must be off"));
        }
        let (io, flow) = PacketBridge::pair(capacity)?;
        let dispatcher = self.dispatcher.upgrade().ok_or_else(Error::not_running)?;
        let nat = Arc::new(crate::app::nat_manager::NatManager::new(
            dispatcher.clone(),
            std::slice::from_ref(&inbound),
        ));
        let scope = self.env.scope.isolated();
        let tag = inbound.tag.clone();
        let tun = scope
            .enter(async {
                crate::protocol::tun::inbound::run(
                    inbound,
                    dispatcher,
                    nat,
                    vec![io],
                    usize::from(settings.mtu),
                    &self.env.options.netstack,
                    settings.endpoint_independent_nat,
                )
            })
            .await
            .map_err(|e| Error::new(ErrorKind::Failed, format!("{e:#}")))?;
        let token = {
            let mut state = self.dynamic_tun.lock();
            if state.closed {
                return Err(Error::not_running());
            }
            state.next = state
                .next
                .checked_add(1)
                .ok_or_else(|| Error::state("TUN generation exhausted"))?;
            let token = state.next;
            state.phase = Phase::Prepared {
                token,
                tag,
                source: PreparedSource::Packets(tun),
                scope,
            };
            token
        };
        Ok((
            PreparedTun {
                manager: Arc::downgrade(self),
                token,
                armed: true,
            },
            flow,
        ))
    }
    pub(crate) async fn commit_prepared_tun(&self, token: u64) -> Result<(), Error> {
        let _update = self.update.lock().await;
        let (tag, source, scope) = {
            let mut state = self.dynamic_tun.lock();
            if state.closed {
                return Err(Error::not_running());
            }
            let Phase::Prepared {
                token: current,
                tag,
                ..
            } = &state.phase
            else {
                return Err(Error::state("TUN preparation is no longer current"));
            };
            if *current != token {
                return Err(Error::state("stale TUN preparation"));
            }
            self.check_dynamic_tun(tag)?;
            let Phase::Prepared {
                tag, source, scope, ..
            } = std::mem::take(&mut state.phase)
            else {
                unreachable!()
            };
            state.phase = Phase::Committing {
                token,
                tag: tag.clone(),
            };
            (tag, source, scope)
        };
        let teardown = Teardown::default();
        let opened = std::panic::AssertUnwindSafe(scope.enter(async {
            match source {
                PreparedSource::Packets(tun) => Ok::<TunRunner, anyhow::Error>(tun),
            }
        }))
        .catch_unwind()
        .await;
        let result = match opened {
            Ok(Ok(tun)) => Ok(tun),
            Ok(Err(e)) => Err(Error::new(ErrorKind::Failed, format!("{e:#}"))),
            Err(_) => Err(Error::new(
                ErrorKind::Failed,
                "opening the dynamic TUN panicked",
            )),
        };
        let tun = match result {
            Ok(tun) => tun,
            Err(error) => {
                teardown.run_all();
                teardown.check_all();
                let left = teardown.left();
                let mut state = self.dynamic_tun.lock();
                state.phase = if left.is_empty() {
                    Phase::Empty
                } else {
                    Phase::Draining {
                        tag,
                        scope,
                        teardown,
                    }
                };
                return Err(error.with_left(left));
            }
        };
        let mut state = self.dynamic_tun.lock();
        if state.closed
            || !matches!(state.phase, Phase::Committing { token: current, .. } if current == token)
        {
            drop(state);
            drop(tun);
            teardown.run_all();
            teardown.check_all();
            let left = teardown.left();
            self.dynamic_tun.lock().phase = if left.is_empty() {
                Phase::Empty
            } else {
                Phase::Draining {
                    tag,
                    scope,
                    teardown,
                }
            };
            return Err(Error::not_running().with_left(left));
        }
        if let Some(dispatcher) = self.dispatcher.upgrade() {
            dispatcher.set_inbound_type(&tag, Some("tun"));
        }
        let control = tun.control;
        let observed = scope.clone();
        scope.spawn_essential("dynamic tun runner", async move {
            tun.runner.await;
            observed.fail("dynamic TUN runner ended".to_string());
        });
        state.phase = Phase::Active {
            tag,
            control,
            scope,
            teardown,
        };
        Ok(())
    }
    pub(crate) async fn detach_dynamic_tun(&self) -> Result<StopReport, Error> {
        let _update = self.update.lock().await;
        self.detach_dynamic_tun_locked().await
    }
    async fn detach_dynamic_tun_locked(&self) -> Result<StopReport, Error> {
        let old = {
            let mut state = self.dynamic_tun.lock();
            match std::mem::take(&mut state.phase) {
                Phase::Empty => return Ok(StopReport::default()),
                Phase::Prepared { .. } => return Ok(StopReport::default()),
                Phase::Committing { .. } => return Err(Error::state("TUN commit did not finish")),
                Phase::Active {
                    tag,
                    scope,
                    teardown,
                    ..
                }
                | Phase::Draining {
                    tag,
                    scope,
                    teardown,
                } => {
                    state.phase = Phase::Draining {
                        tag: tag.clone(),
                        scope: scope.clone(),
                        teardown: teardown.clone(),
                    };
                    (tag, scope, teardown)
                }
            }
        };
        let (tag, scope, teardown) = old;
        teardown.run_all();
        let mut report = scope
            .stop(
                self.env
                    .host
                    .stop_within
                    .unwrap_or(crate::runtime::scope::STOP_WITHIN),
            )
            .await;
        if report.tasks.is_empty() {
            teardown.check_all();
        }
        report.left = teardown.left();
        if report.clean() {
            if let Some(dispatcher) = self.dispatcher.upgrade() {
                dispatcher.set_inbound_type(&tag, None);
            }
            self.dynamic_tun.lock().phase = Phase::Empty;
        }
        Ok(report)
    }
    pub(crate) async fn stop_dynamic_tun(&self) {
        self.dynamic_tun.lock().closed = true;
        let _update = self.update.lock().await;
        match self.detach_dynamic_tun_locked().await {
            Ok(report) if !report.clean() => {
                for left in report.left {
                    let mut step =
                        crate::runtime::teardown::Step::new(left.kind, left.resource, move || {
                            Err(std::io::Error::other(left.why))
                        });
                    if let Some(clear) = left.clear {
                        step = step.clear(clear);
                    }
                    self.env.teardown.push_check(step);
                }
                for (name, count) in report.tasks {
                    self.env
                        .teardown
                        .push_check(crate::runtime::teardown::Step::new(
                            crate::runtime::teardown::LeftKind::Task,
                            format!("{count} dynamic TUN tasks: {name}"),
                            || {
                                Err(std::io::Error::other(
                                    "attachment did not drain before instance stop",
                                ))
                            },
                        ));
                }
            }
            Err(e) => tracing::warn!("stopping dynamic TUN: {e}"),
            _ => {}
        }
    }
}

#[cfg(all(test, feature = "outbound-direct"))]
mod tests {
    use super::*;
    use crate::embed::{Config, Instance, Options, Runtime};
    use std::time::Duration;
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn incomplete_drain_quarantines_the_generation_until_a_later_detach() {
        let instance = Instance::new(
            Options::new()
                .dynamic_tun(true)
                .stop_within(Duration::from_millis(100))
                .runtime(Runtime::Host(tokio::runtime::Handle::current())),
        )
        .unwrap();
        instance
            .start(Config::Json(
                r#"{"outbounds":[{"type":"direct","tag":"direct"}]}"#.into(),
            ))
            .await
            .unwrap();
        let manager = instance.manager().unwrap();
        let json = r#"{"type":"tun","tag":"capture","address":["10.19.0.1/24"]}"#;
        let (p, _flow) = instance.prepare_tun_packets(json, 1).await.unwrap();
        p.commit().await.unwrap();
        let scope = match &manager.dynamic_tun.lock().phase {
            Phase::Active { scope, .. } => scope.clone(),
            _ => unreachable!(),
        };
        let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        struct Release(Arc<(Mutex<bool>, std::sync::Condvar)>);
        impl Drop for Release {
            fn drop(&mut self) {
                *self.0 .0.lock().unwrap() = true;
                self.0 .1.notify_all();
            }
        }
        let release = Release(gate.clone());
        let (started_tx, started) = tokio::sync::oneshot::channel();
        let blocked = scope.spawn_blocking("test pinned TUN resource", move || {
            started_tx.send(()).unwrap();
            let mut open = gate.0.lock().unwrap();
            while !*open {
                open = gate.1.wait(open).unwrap();
            }
        });
        started.await.unwrap();
        let report = instance.detach_tun().await.unwrap();
        assert!(!report.clean());
        assert!(report
            .tasks
            .iter()
            .any(|(name, _)| *name == "test pinned TUN resource"));
        assert!(matches!(
            instance.tun_state().unwrap(),
            TunState::Draining { .. }
        ));
        assert_eq!(
            instance
                .prepare_tun_packets(json, 1)
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::State
        );
        drop(release);
        blocked.await.unwrap();
        assert!(instance.detach_tun().await.unwrap().clean());
        let (p, _next_flow) = instance.prepare_tun_packets(json, 1).await.unwrap();
        p.commit().await.unwrap();
        instance.stop().await.unwrap();
    }
}
