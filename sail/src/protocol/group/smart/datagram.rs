//! Datagrams through the smart group, measured: the time from the first
//! datagram sent to the first received. A QUIC session whose first
//! datagrams are not answered in time is a failure of its member; the
//! session is not moved to another one.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use futures::future::Either;
use tokio::sync::Notify;
use tokio::time::Instant;

use super::score::PLAIN_WEIGHT;
use super::{is_handshake, lock, Group, Verdict};
use crate::adapter::*;
use crate::net::connect_datagram_outbound;
use crate::protocol::group::interrupt;
use crate::protocol::group::members::MemberKey;
use crate::session::{Session, SocksAddr};

/// Datagrams for `sess` through the member of `group` its site goes to,
/// or the next that connects.
pub async fn connect(group: Arc<Group>, sess: &Session) -> io::Result<AnyOutboundDatagram> {
    group.evaluated().await;
    group.used();
    let snapshot = group.members.load();
    if snapshot.members.is_empty() {
        return Err(io::Error::other("no outbound to try"));
    }
    let site = group.site(sess);
    let order = group.plan(&snapshot, &site);
    let mut failed = Vec::new();
    let dns_client = group.dns_client.clone();
    let result = group
        .try_members(sess, &snapshot, &order, &site, &mut failed, |a| {
            let dns_client = dns_client.clone();
            async move {
                let transport = connect_datagram_outbound(sess, dns_client, &a).await?;
                a.datagram()?.handle(sess, transport).await
            }
        })
        .await;
    let verdict = Verdict::new(group.clone(), failed);
    let (i, took, datagram) = result?;
    let key = snapshot.members[i].key.clone();
    sess.chain.push(&key.name);
    group.connected(&key, &site, took);
    let until = group.until(&key);
    let measured = Box::new(MeasuredDatagram {
        inner: datagram,
        shared: Arc::new(Shared {
            timeout: group.first_byte_timeout(&key),
            group,
            member: key,
            site,
            connect: took,
            handshake: is_handshake(sess),
            first_sent: Mutex::new(None),
            sent: Notify::new(),
            answered: AtomicBool::new(false),
            timed_out: AtomicBool::new(false),
            verdict: Mutex::new(verdict),
        }),
    });
    Ok(match until {
        Some(until) => interrupt::datagram_until(measured, until),
        None => measured,
    })
}

/// What the two halves share.
struct Shared {
    group: Arc<Group>,
    member: MemberKey,
    site: String,
    connect: Duration,
    /// Whether the session is QUIC, whose first datagrams must be
    /// answered.
    handshake: bool,
    timeout: Duration,
    first_sent: Mutex<Option<Instant>>,
    /// Wakes a receive waiting before anything was sent.
    sent: Notify,
    answered: AtomicBool,
    timed_out: AtomicBool,
    verdict: Mutex<Verdict>,
}

impl Shared {
    fn on_sent(&self) {
        let mut first = lock(&self.first_sent);
        if first.is_none() {
            *first = Some(Instant::now());
            self.sent.notify_waiters();
        }
    }

    /// When the member's time to answer is up, while it is running.
    fn deadline(&self) -> Option<Instant> {
        if !self.handshake || self.timed_out.load(Ordering::Relaxed) {
            return None;
        }
        lock(&self.first_sent).map(|sent| sent + self.timeout)
    }

    fn on_timeout(&self) {
        self.timed_out.store(true, Ordering::Relaxed);
        self.group.failed_site(&self.member, &self.site);
        lock(&self.verdict).add(self.member.clone());
    }

    fn on_answer(&self) {
        if self.answered.swap(true, Ordering::Relaxed) {
            return;
        }
        let sent = *lock(&self.first_sent);
        match sent {
            Some(sent) => {
                let latency = self.connect + sent.elapsed();
                let weight = if self.handshake { 1.0 } else { PLAIN_WEIGHT };
                self.group
                    .answered(&self.member, &self.site, latency, weight);
            }
            None => self.group.succeeded(&self.member),
        }
        lock(&self.verdict).answered();
    }
}

struct MeasuredDatagram {
    inner: AnyOutboundDatagram,
    shared: Arc<Shared>,
}

impl OutboundDatagram for MeasuredDatagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let (recv, send) = self.inner.split();
        (
            Box::new(RecvHalf {
                inner: recv,
                shared: self.shared.clone(),
            }),
            Box::new(SendHalf {
                inner: send,
                shared: self.shared,
            }),
        )
    }
}

struct RecvHalf {
    inner: Box<dyn OutboundDatagramRecvHalf>,
    shared: Arc<Shared>,
}

#[async_trait]
impl OutboundDatagramRecvHalf for RecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        if self.shared.answered.load(Ordering::Relaxed) {
            return self.inner.recv_from(buf).await;
        }
        let shared = self.shared.clone();
        let recv = self.inner.recv_from(buf);
        futures::pin_mut!(recv);
        let result = loop {
            // Made before the deadline is looked at, so that a first send
            // in between wakes it.
            let sent = shared.sent.notified();
            let deadline = shared.deadline();
            let waiting = lock(&shared.first_sent).is_none();
            let wait = async {
                match deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None if waiting => sent.await,
                    None => std::future::pending().await,
                }
            };
            futures::pin_mut!(wait);
            match futures::future::select(recv.as_mut(), wait).await {
                Either::Left((result, _)) => break result,
                Either::Right(((), _)) => {
                    if deadline.is_some() {
                        shared.on_timeout();
                    }
                }
            }
        };
        if result.is_ok() {
            shared.on_answer();
        }
        result
    }
}

struct SendHalf {
    inner: Box<dyn OutboundDatagramSendHalf>,
    shared: Arc<Shared>,
}

#[async_trait]
impl OutboundDatagramSendHalf for SendHalf {
    async fn send_to(&mut self, buf: &[u8], dst_addr: &SocksAddr) -> io::Result<usize> {
        let n = self.inner.send_to(buf, dst_addr).await?;
        self.shared.on_sent();
        Ok(n)
    }

    async fn close(&mut self) -> io::Result<()> {
        self.inner.close().await
    }
}
