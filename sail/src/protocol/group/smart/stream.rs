//! Streams through the smart group: measured, and tried again through the
//! next member while nothing has reached the client.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll, Waker};
use std::time::Duration;

use futures::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::{Instant, Sleep};
use tracing::debug;

use super::score::PLAIN_WEIGHT;
use super::{is_handshake, Group, Verdict};
use crate::adapter::{AnyOutboundHandler, AnyStream};
use crate::app::SyncDnsClient;
use crate::protocol::group::interrupt;
use crate::protocol::group::members::{MemberKey, Snapshot};
use crate::session::Session;

/// What the client sent before any answer is kept, to be sent again
/// through the next member, up to this much.
pub const MAX_REPLAY: usize = 16 * 1024;

/// A stream through `member`, ready to carry the session's data.
async fn dial(
    sess: &Session,
    dns_client: SyncDnsClient,
    member: &AnyOutboundHandler,
) -> io::Result<AnyStream> {
    crate::net::dial_domain::stream(sess, dns_client, member).await
}

/// A stream for `sess` through the member of `group` its site goes to, or
/// the next that connects.
pub async fn connect(group: Arc<Group>, sess: &Session) -> io::Result<AnyStream> {
    group.evaluated().await;
    group.used();
    let snapshot = group.members.load();
    if snapshot.members.is_empty() {
        return Err(io::Error::other("no outbound to try"));
    }
    let site: Arc<str> = group.site(sess).into();
    let order = group.plan(&snapshot, &site);
    let mut failed = Vec::new();
    let dns_client = group.dns_client.clone();
    let result = group
        .try_members(sess, &snapshot, &order, &site, &mut failed, true, |a| {
            let dns_client = dns_client.clone();
            async move { dial(sess, dns_client, &a).await }
        })
        .await;
    let verdict = Verdict::new(group.clone(), failed);
    let (i, took, stream) = result?;
    // In the chain since it was tried.
    let key = snapshot.members[i].key.clone();
    group.connected(&key, &site, took);
    let handshake = is_handshake(sess);
    let next = order
        .iter()
        .position(|&m| m == i)
        .map_or(order.len(), |p| p + 1);
    let until = group.until(&key);
    let stream = SmartStream {
        remaining: order[next..].to_vec(),
        group,
        snapshot,
        sess: handshake.then(|| Arc::new(sess.clone())),
        chain: sess.chain.clone(),
        site,
        member: i,
        connect: took,
        handshake,
        state: State::Ready(stream),
        replay: handshake.then(Vec::new),
        sent_at: None,
        answered: false,
        deadline: None,
        verdict,
        read_waker: None,
        write_waker: None,
    };
    Ok(match until {
        Some(until) => interrupt::stream_until(Box::new(stream), until),
        None => Box::new(stream),
    })
}

/// Another member for a stream: which, how long it took to connect, the
/// stream with the client's bytes sent again, and the members left.
type Reconnected = io::Result<(usize, Duration, AnyStream, Vec<usize>)>;

enum State {
    Ready(AnyStream),
    /// Going over to the next member; the lock only makes it `Sync`.
    Reconnecting(Mutex<BoxFuture<'static, (Vec<MemberKey>, Reconnected)>>),
    /// No member answered.
    Failed,
}

pub struct SmartStream {
    group: Arc<Group>,
    snapshot: Arc<Snapshot>,
    /// For another member, while one may be tried.
    sess: Option<Arc<Session>>,
    /// The session's chain, where a change of member is written.
    chain: crate::session::Chain,
    site: Arc<str>,
    /// The member it goes through, by index into `snapshot`.
    member: usize,
    /// How long the member took to connect.
    connect: Duration,
    /// Whether it carries TLS or QUIC: a handshake the member must answer
    /// in time.
    handshake: bool,
    state: State,
    /// The members it may still go over to, in turn.
    remaining: Vec<usize>,
    /// What the client sent before any answer, while it is kept: of a
    /// handshake only, and up to `MAX_REPLAY`.
    replay: Option<Vec<u8>>,
    /// When the client's first bytes through the member left.
    sent_at: Option<Instant>,
    /// Whether any byte reached the client.
    answered: bool,
    /// When the member's time to answer the handshake is up.
    deadline: Option<Pin<Box<Sleep>>>,
    verdict: Verdict,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
}

fn no_answer() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "no member of the group answered the handshake",
    )
}

impl SmartStream {
    fn key(&self) -> &MemberKey {
        &self.snapshot.members[self.member].key
    }

    /// Whether the client's bytes wait for an answer.
    fn waiting(&self) -> bool {
        self.sent_at.is_some() && !self.answered
    }

    /// Starts the member's time to answer the handshake.
    fn arm(&mut self) {
        if self.handshake && !self.answered {
            let timeout = self.group.first_byte_timeout(self.key());
            self.deadline = Some(Box::pin(tokio::time::sleep(timeout)));
        }
    }

    /// The member failed the handshake: it is blamed, unless no member
    /// does better.
    fn member_failed(&mut self) {
        let key = self.key().clone();
        self.group.failed_site(&key, &self.site);
        self.verdict.add(key);
    }

    /// Goes over to the next member, if nothing reached the client, what
    /// it sent is all kept, and a member is left. Returns whether it
    /// does.
    fn reconnect(&mut self) -> bool {
        if self.answered || self.remaining.is_empty() {
            return false;
        }
        let (Some(replay), Some(sess)) = (self.replay.clone(), self.sess.clone()) else {
            return false;
        };
        self.member_failed();
        debug!(
            "[{}] [{}] did not answer [{}]; {} bytes go through the next member",
            self.group.tag,
            self.key().name,
            sess.destination,
            replay.len()
        );
        let candidates = std::mem::take(&mut self.remaining);
        let group = self.group.clone();
        let snapshot = self.snapshot.clone();
        let site = self.site.clone();
        let task = async move {
            let mut failed = Vec::new();
            let dns_client = group.dns_client.clone();
            let result = group
                // Up already: what fails now is not told, and the member
                // taken replaces the one before in the chain.
                .try_members(
                    &sess,
                    &snapshot,
                    &candidates,
                    &site,
                    &mut failed,
                    false,
                    |a| {
                        let dns_client = dns_client.clone();
                        let (sess, replay) = (&sess, &replay);
                        async move {
                            let mut stream = dial(sess, dns_client, &a).await?;
                            stream.write_all(replay).await?;
                            stream.flush().await?;
                            Ok(stream)
                        }
                    },
                )
                .await
                .map(|(i, took, stream)| {
                    let next = candidates
                        .iter()
                        .position(|&m| m == i)
                        .map_or(candidates.len(), |p| p + 1);
                    (i, took, stream, candidates[next..].to_vec())
                });
            (failed, result)
        };
        self.state = State::Reconnecting(Mutex::new(Box::pin(task)));
        self.sent_at = None;
        self.deadline = None;
        true
    }

    /// Drives a change of member to its end.
    fn poll_reconnect(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let task = match &mut self.state {
            State::Reconnecting(task) => task.get_mut().unwrap_or_else(|e| e.into_inner()),
            State::Ready(_) => return Poll::Ready(Ok(())),
            State::Failed => return Poll::Ready(Err(no_answer())),
        };
        let (failed, result) = ready!(task.as_mut().poll(cx));
        for key in failed {
            self.verdict.add(key);
        }
        let result = match result {
            Ok((i, took, stream, remaining)) => {
                self.chain.replace(
                    &self.snapshot.members[self.member].key.name,
                    &self.snapshot.members[i].key.name,
                );
                self.member = i;
                self.connect = took;
                self.remaining = remaining;
                self.state = State::Ready(stream);
                let key = self.key().clone();
                self.group.connected(&key, &self.site, took);
                if self.replay.as_ref().is_some_and(|r| !r.is_empty()) {
                    self.sent_at = Some(Instant::now());
                    self.arm();
                }
                Ok(())
            }
            Err(e) => {
                debug!("[{}] no member answered: {}", self.group.tag, e);
                self.state = State::Failed;
                Err(no_answer())
            }
        };
        for waker in [self.read_waker.take(), self.write_waker.take()]
            .into_iter()
            .flatten()
        {
            waker.wake();
        }
        Poll::Ready(result)
    }

    /// The first bytes came back.
    fn on_answer(&mut self) {
        self.answered = true;
        self.replay = None;
        self.sess = None;
        self.deadline = None;
        let key = self.key().clone();
        match self.sent_at {
            Some(sent_at) => {
                let latency = self.connect + sent_at.elapsed();
                let weight = if self.handshake { 1.0 } else { PLAIN_WEIGHT };
                self.group.answered(&key, &self.site, latency, weight);
            }
            // The server spoke first.
            None => self.group.succeeded(&key),
        }
        self.verdict.answered();
    }

    /// The client's bytes `sent` left through the member.
    fn on_sent(&mut self, sent: &[u8]) {
        if self.answered || sent.is_empty() {
            return;
        }
        if self.sent_at.is_none() {
            self.sent_at = Some(Instant::now());
            self.arm();
        }
        if let Some(replay) = &mut self.replay {
            if replay.len() + sent.len() > MAX_REPLAY {
                self.replay = None;
            } else {
                replay.extend_from_slice(sent);
            }
        }
    }
}

impl AsyncRead for SmartStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if this.poll_reconnect(cx)?.is_pending() {
                this.read_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            let State::Ready(stream) = &mut this.state else {
                return Poll::Ready(Err(no_answer()));
            };
            let before = buf.filled().len();
            match Pin::new(stream).poll_read(cx, buf) {
                Poll::Ready(Ok(())) if buf.filled().len() > before => {
                    if !this.answered {
                        this.on_answer();
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(result) => {
                    // Closed, or failed, before the handshake was
                    // answered.
                    if this.waiting() && this.handshake {
                        if this.reconnect() {
                            continue;
                        }
                        this.member_failed();
                        this.sent_at = None;
                        this.deadline = None;
                    }
                    return Poll::Ready(result);
                }
                Poll::Pending => {
                    let timed_out = this
                        .deadline
                        .as_mut()
                        .is_some_and(|d| d.as_mut().poll(cx).is_ready());
                    if timed_out {
                        this.deadline = None;
                        if this.reconnect() {
                            continue;
                        }
                        // Nothing to go over to: it is a failure, once, and
                        // the stream waits on.
                        this.member_failed();
                        this.sent_at = None;
                    }
                    return Poll::Pending;
                }
            }
        }
    }
}

impl AsyncWrite for SmartStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        loop {
            if this.poll_reconnect(cx)?.is_pending() {
                this.write_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            let State::Ready(stream) = &mut this.state else {
                return Poll::Ready(Err(no_answer()));
            };
            match Pin::new(stream).poll_write(cx, buf) {
                Poll::Ready(Ok(n)) => {
                    this.on_sent(&buf[..n]);
                    return Poll::Ready(Ok(n));
                }
                Poll::Ready(Err(e)) => {
                    if this.handshake && this.reconnect() {
                        continue;
                    }
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.poll_reconnect(cx)?.is_pending() {
            this.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        match &mut this.state {
            State::Ready(stream) => Pin::new(stream).poll_flush(cx),
            _ => Poll::Ready(Err(no_answer())),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        match this.poll_reconnect(cx) {
            Poll::Pending => {
                this.write_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            Poll::Ready(Err(_)) => return Poll::Ready(Ok(())),
            Poll::Ready(Ok(())) => {}
        }
        match &mut this.state {
            State::Ready(stream) => Pin::new(stream).poll_shutdown(cx),
            _ => Poll::Ready(Ok(())),
        }
    }
}
