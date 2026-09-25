use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use futures::stream::Stream as FuturesStream;
use tokio::sync::mpsc;
use tracing::debug;

use crate::adapter::*;
use crate::session::{Session as ProxySession, SocksAddr, SocksAddrWireType, StreamId};
use crate::transport::uot;

use super::super::padding::PaddingScheme;
use super::super::session::{read_auth, Session, Stream, MAX_STREAMS};

/// Streams handshaken and waiting for the listener to take them.
const INCOMING_QUEUE: usize = 64;

pub struct Handler {
    /// Users by the SHA-256 of their password, with their names.
    users: HashMap<[u8; 32], Option<Arc<str>>>,
    padding: Arc<PaddingScheme>,
    /// How long a stream has to name its destination.
    handshake_timeout: Duration,
}

impl Handler {
    pub fn new(
        users: HashMap<[u8; 32], Option<Arc<str>>>,
        padding: Arc<PaddingScheme>,
        handshake_timeout: Duration,
    ) -> Self {
        Handler {
            users,
            padding,
            handshake_timeout,
        }
    }
}

#[async_trait]
impl InboundStreamHandler for Handler {
    async fn handle<'a>(
        &'a self,
        mut sess: ProxySession,
        mut stream: AnyStream,
    ) -> io::Result<AnyInboundTransport> {
        tracing::trace!("handling inbound stream");
        let hash = read_auth(&mut stream).await?;
        let Some(user) = self.users.get(&hash) else {
            return Err(io::Error::other("anytls: unknown user"));
        };
        sess.user = user.clone();
        let (tx, rx) = mpsc::channel(INCOMING_QUEUE);
        let handshake_timeout = self.handshake_timeout;
        let session = Session::server(
            stream,
            self.padding.clone(),
            Box::new(move |stream| {
                tokio::spawn(accept(stream, sess.clone(), tx.clone(), handshake_timeout));
            }),
        );
        Ok(InboundTransport::Incoming(Box::new(Incoming {
            rx,
            _session: session,
        })))
    }
}

/// Reads what a new stream asks for, and passes it on to be routed.
async fn accept(
    mut stream: Stream,
    mut sess: ProxySession,
    tx: mpsc::Sender<AnyBaseInboundTransport>,
    handshake_timeout: Duration,
) {
    let sid = stream.id();
    // A stream for UDP over TCP is handed on like any other, and served
    // where every inbound's are; version 1 is refused here, where the
    // client can be told.
    let handshake = async {
        let destination = SocksAddr::read_from(&mut stream, SocksAddrWireType::PortLast).await?;
        if uot::version(&destination) == Some(1) {
            return Err(io::Error::other("udp-over-tcp version 1 is not supported"));
        }
        Ok::<_, io::Error>(destination)
    };
    let destination = match tokio::time::timeout(handshake_timeout, handshake).await {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            debug!("anytls stream {}: {}", sid, e);
            let _ = stream.report(Some(&e.to_string())).await;
            return;
        }
        Err(_) => {
            debug!("anytls stream {}: handshake timed out", sid);
            return;
        }
    };
    if stream.report(None).await.is_err() {
        return;
    }
    // Unique with the source, which is this connection's.
    sess.stream_id = Some(StreamId::U64(sid as u64));
    sess.destination = destination;
    let _ = tx
        .send(AnyBaseInboundTransport::Stream(Box::new(stream), sess))
        .await;
}

/// The streams of one session, as they are opened.
struct Incoming {
    rx: mpsc::Receiver<AnyBaseInboundTransport>,
    /// Kept for as long as streams may come.
    _session: Arc<Session>,
}

impl FuturesStream for Incoming {
    type Item = AnyBaseInboundTransport;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

// The session refuses streams beyond this many, so the queue of those
// waiting for their destination is bounded by it too.
const _: () = assert!(INCOMING_QUEUE <= MAX_STREAMS);
