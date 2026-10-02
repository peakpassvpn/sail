//! How many proxied sessions live at once: `inbound.max_connections`. Every
//! connection, UDP session and stream of a multiplexed or QUIC inbound
//! holds one place while it lives; one more waits for a place, and is
//! refused when none comes. Memory, which each session takes 24 to 39 KiB
//! of (measured), is what the limit keeps within a small router's budget.

use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::adapter::{
    AnyOutboundDatagram, OutboundDatagram, OutboundDatagramRecvHalf, OutboundDatagramSendHalf,
};
use crate::session::SocksAddr;

/// How long a session over the limit waits for a place (judged: a burst
/// of new connections passes, a sustained excess is refused soon).
pub const MAX_CONNECTIONS_WAIT: Duration = Duration::from_secs(1);

/// The refusals are logged at most this often, with their count since.
const WARN_EVERY: Duration = Duration::from_secs(10);

/// The places, when there is a limit.
pub struct Sessions {
    places: Arc<Semaphore>,
    limit: usize,
    refused: AtomicUsize,
    warned: Mutex<Option<Instant>>,
}

/// A session's place, given back when it is dropped.
pub struct Place(#[allow(dead_code)] OwnedSemaphorePermit);

impl Sessions {
    /// None for 0, no limit.
    pub fn new(limit: usize) -> Option<Self> {
        (limit > 0).then(|| Self {
            places: Arc::new(Semaphore::new(limit)),
            limit,
            refused: AtomicUsize::new(0),
            warned: Mutex::new(None),
        })
    }

    /// A place for one more session, waiting `wait` at most; none, and the
    /// session is refused.
    pub async fn enter(&self, wait: Duration) -> Option<Place> {
        match tokio::time::timeout(wait, self.places.clone().acquire_owned()).await {
            Ok(Ok(permit)) => Some(Place(permit)),
            _ => {
                self.refused();
                None
            }
        }
    }

    /// The sessions living now.
    pub fn live(&self) -> usize {
        self.limit - self.places.available_permits()
    }

    fn refused(&self) {
        let refused = self.refused.fetch_add(1, Ordering::Relaxed) + 1;
        let mut warned = self.warned.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        if warned.is_none_or(|at| now.duration_since(at) >= WARN_EVERY) {
            *warned = Some(now);
            self.refused.store(0, Ordering::Relaxed);
            tracing::warn!(
                "{} session(s) refused: {} live, the limit of inbound.max_connections",
                refused,
                self.limit
            );
        }
    }
}

/// A UDP session's datagram, which holds its place until both its halves
/// are dropped.
pub struct Held {
    inner: AnyOutboundDatagram,
    place: Place,
}

impl Held {
    pub fn new(inner: AnyOutboundDatagram, place: Place) -> AnyOutboundDatagram {
        Box::new(Self { inner, place })
    }
}

impl OutboundDatagram for Held {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let place = Arc::new(self.place);
        let (recv, send) = self.inner.split();
        (
            Box::new(RecvHalf(recv, place.clone())),
            Box::new(SendHalf(send, place)),
        )
    }
}

struct RecvHalf(
    Box<dyn OutboundDatagramRecvHalf>,
    #[allow(dead_code)] Arc<Place>,
);

#[async_trait]
impl OutboundDatagramRecvHalf for RecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        self.0.recv_from(buf).await
    }
}

struct SendHalf(
    Box<dyn OutboundDatagramSendHalf>,
    #[allow(dead_code)] Arc<Place>,
);

#[async_trait]
impl OutboundDatagramSendHalf for SendHalf {
    async fn send_to(&mut self, buf: &[u8], dst_addr: &SocksAddr) -> io::Result<usize> {
        self.0.send_to(buf, dst_addr).await
    }

    async fn close(&mut self) -> io::Result<()> {
        self.0.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_session_over_the_limit_waits_and_is_then_refused() {
        assert!(Sessions::new(0).is_none(), "0 is no limit");
        let sessions = Sessions::new(2).unwrap();
        let a = sessions.enter(Duration::from_millis(50)).await.unwrap();
        let _b = sessions.enter(Duration::from_millis(50)).await.unwrap();
        assert_eq!(sessions.live(), 2);
        // A third is refused once its wait is over.
        let started = Instant::now();
        assert!(sessions.enter(Duration::from_millis(50)).await.is_none());
        assert!(started.elapsed() >= Duration::from_millis(50));
        // One that waits gets the place a session gives back.
        let give_back = async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            drop(a);
        };
        let (place, ()) = tokio::join!(sessions.enter(Duration::from_secs(1)), give_back);
        assert!(place.is_some());
        assert_eq!(sessions.live(), 2);
    }

    struct Quiet;

    #[async_trait]
    impl OutboundDatagramRecvHalf for Quiet {
        async fn recv_from(&mut self, _: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
            std::future::pending().await
        }
    }

    #[async_trait]
    impl OutboundDatagramSendHalf for Quiet {
        async fn send_to(&mut self, buf: &[u8], _: &SocksAddr) -> io::Result<usize> {
            Ok(buf.len())
        }

        async fn close(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl OutboundDatagram for Quiet {
        fn split(
            self: Box<Self>,
        ) -> (
            Box<dyn OutboundDatagramRecvHalf>,
            Box<dyn OutboundDatagramSendHalf>,
        ) {
            (Box::new(Quiet), Box::new(Quiet))
        }
    }

    /// A UDP session holds its place until both its halves are dropped.
    #[tokio::test]
    async fn a_udp_session_holds_its_place_while_either_half_lives() {
        let sessions = Sessions::new(1).unwrap();
        let place = sessions.enter(Duration::from_millis(10)).await.unwrap();
        let (recv, send) = Held::new(Box::new(Quiet), place).split();
        assert_eq!(sessions.live(), 1);
        drop(send);
        assert_eq!(sessions.live(), 1, "the receive half still lives");
        drop(recv);
        assert_eq!(sessions.live(), 0);
    }
}
