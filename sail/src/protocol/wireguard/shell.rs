//! An async shell around the sans-IO [`Device`]: a task receiving
//! datagrams from a [`Transport`], a task running the timers, and
//! [`WireGuard::send`] for IP packets going out. Once either task ends,
//! however it ends, the device is dead: [`WireGuard::ended`] says so.
//!
//! The transport is a trait so that WireGuard's UDP can later go through a
//! sail outbound (a detour) instead of a socket of its own.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::sync::{mpsc, watch, Notify};
use tokio::task::JoinHandle;

use super::device::{Device, Error, Incoming, PeerId, Transmit};
use crate::net::accept::AcceptBackoff;
use crate::runtime::scope::TaskClass;

/// Where WireGuard's datagrams go and come from.
#[async_trait]
pub trait Transport: Send + Sync + 'static {
    async fn send_to(&self, datagram: &[u8], dst: SocketAddr) -> io::Result<()>;
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;

    /// Opens it anew, on the network the host is on now, as wireguard-go's
    /// BindUpdate: the device's sessions go on over it, as WireGuard
    /// roams. A receive pending meanwhile goes on on the new one.
    async fn rebind(&self) -> io::Result<()> {
        Ok(())
    }

    /// Lets go of what it sends on at once, for good: a stopped endpoint's
    /// port is free again while its tasks are still being ended.
    fn close(&self) {}
}

#[async_trait]
impl Transport for tokio::net::UdpSocket {
    async fn send_to(&self, datagram: &[u8], dst: SocketAddr) -> io::Result<()> {
        tokio::net::UdpSocket::send_to(self, datagram, dst)
            .await
            .map(|_| ())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        tokio::net::UdpSocket::recv_from(self, buf).await
    }
}

/// An IP packet that came out of the tunnel.
#[derive(Debug)]
pub struct InboundPacket {
    pub peer: PeerId,
    pub packet: Vec<u8>,
}

/// Packets out of the tunnel queue up to this many; beyond, they drop, as
/// a network interface's would.
const INBOUND_QUEUE: usize = 1024;
/// The largest UDP payload.
const MAX_DATAGRAM: usize = 65535;

struct Inner {
    device: Mutex<Device>,
    transport: Arc<dyn Transport>,
    /// Wakes the timer task when a timer moved earlier.
    timer: Notify,
}

fn now() -> std::time::Instant {
    // tokio's clock, so that paused-time tests drive the timers.
    tokio::time::Instant::now().into_std()
}

impl Inner {
    /// Runs `f` on the device, then wakes the timer task if `f` armed a
    /// timer earlier than it sleeps for.
    fn with_device<R>(&self, f: impl FnOnce(&mut Device) -> R) -> R {
        let (r, moved) = {
            let mut d = self.device.lock();
            let r = f(&mut d);
            (r, d.take_deadline_moved())
        };
        if moved {
            self.timer.notify_one();
        }
        r
    }

    async fn transmit(&self, t: Transmit) {
        if let Err(e) = self.transport.send_to(&t.payload, t.dst).await {
            tracing::debug!("wireguard: sending to {} failed: {}", t.dst, e);
        }
    }

    async fn recv_loop(self: Arc<Self>, tx: mpsc::Sender<InboundPacket>) {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        let mut backoff = AcceptBackoff::new("wireguard: receive");
        loop {
            let (n, src) = match self.transport.recv_from(&mut buf).await {
                Ok(r) => {
                    backoff.succeeded();
                    r
                }
                Err(e) => {
                    // ICMP errors surface here on some systems; keep going,
                    // but do not spin on a transport that keeps failing,
                    // and stop on a socket that is gone.
                    if backoff.failed(e).await.is_err() {
                        return;
                    }
                    continue;
                }
            };
            let (incoming, extra) = self.with_device(|d| {
                let incoming = d.handle_incoming(now(), src, &buf[..n]);
                let extra: Vec<Transmit> = std::iter::from_fn(|| d.poll_transmit()).collect();
                (incoming, extra)
            });
            match incoming {
                Incoming::WriteBack(t) => self.transmit(t).await,
                Incoming::Deliver { peer, packet } => {
                    match tx.try_send(InboundPacket { peer, packet }) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            tracing::debug!("wireguard: the inbound queue is full; a packet drops");
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => return,
                    }
                }
                Incoming::Nothing => {}
            }
            for t in extra {
                self.transmit(t).await;
            }
        }
    }

    async fn timer_loop(self: Arc<Self>) {
        loop {
            let deadline = self.device.lock().next_deadline();
            match deadline {
                Some(d) => {
                    tokio::select! {
                        _ = tokio::time::sleep_until(tokio::time::Instant::from_std(d)) => {}
                        _ = self.timer.notified() => continue,
                    }
                }
                None => {
                    self.timer.notified().await;
                    continue;
                }
            }
            let out = self.device.lock().tick(now());
            for t in out {
                self.transmit(t).await;
            }
        }
    }
}

/// Tells that its task ended when dropped: returned, panicked or aborted.
struct Ending(Arc<watch::Sender<bool>>);

impl Drop for Ending {
    fn drop(&mut self) {
        self.0.send_replace(true);
    }
}

/// A running WireGuard device.
pub struct WireGuard {
    inner: Arc<Inner>,
    tasks: Vec<JoinHandle<()>>,
    ended: Arc<watch::Sender<bool>>,
}

impl WireGuard {
    /// Starts the receive and timer tasks, of `class`. Packets out of the
    /// tunnel arrive on the returned receiver.
    pub fn spawn(
        device: Device,
        transport: Arc<dyn Transport>,
        class: TaskClass,
    ) -> (Self, mpsc::Receiver<InboundPacket>) {
        let inner = Arc::new(Inner {
            device: Mutex::new(device),
            transport,
            timer: Notify::new(),
        });
        let (tx, rx) = mpsc::channel(INBOUND_QUEUE);
        let ended = Arc::new(watch::Sender::new(false));
        let recv = {
            let ending = Ending(ended.clone());
            let recv = inner.clone().recv_loop(tx);
            async move {
                let _ending = ending;
                recv.await
            }
        };
        let timer = {
            let ending = Ending(ended.clone());
            let timer = inner.clone().timer_loop();
            async move {
                let _ending = ending;
                timer.await
            }
        };
        let tasks = vec![
            crate::runtime::scope::spawn_of(class, "wireguard recv", recv),
            crate::runtime::scope::spawn_of(class, "wireguard timer", timer),
        ];
        (
            WireGuard {
                inner,
                tasks,
                ended,
            },
            rx,
        )
    }

    /// Resolves once its receive or timer task has ended, however: a
    /// transport gone, a panic caught, an abort. The device does not work
    /// without either.
    pub fn ended(&self) -> impl std::future::Future<Output = ()> + Send + 'static {
        let mut ended = self.ended.subscribe();
        async move {
            let _ = ended.wait_for(|ended| *ended).await;
        }
    }

    /// Sends an IP packet into the tunnel, to the peer its destination
    /// routes to. Transport errors are logged, as a lost datagram would be.
    pub async fn send(&self, packet: &[u8]) -> Result<(), Error> {
        let out = self.inner.with_device(|d| d.encapsulate(now(), packet))?;
        for t in out {
            self.inner.transmit(t).await;
        }
        Ok(())
    }

    /// Runs `f` on the device: adding peers, reading stats. Datagrams `f`
    /// returns are sent.
    pub async fn with_device<R>(
        &self,
        f: impl FnOnce(&mut Device, std::time::Instant) -> (R, Vec<Transmit>),
    ) -> R {
        let (r, out) = self.inner.with_device(|d| f(d, now()));
        for t in out {
            self.inner.transmit(t).await;
        }
        r
    }
}

impl Drop for WireGuard {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}
