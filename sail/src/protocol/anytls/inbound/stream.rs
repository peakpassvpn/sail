use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use futures::stream::Stream as FuturesStream;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::debug;

use crate::adapter::*;
use crate::protocol::fallback::{Fallback, HEADER_TIMEOUT};
use crate::session::{Session as ProxySession, SocksAddr, SocksAddrWireType, StreamId};
use crate::transport::uot;

use super::super::padding::PaddingScheme;
use super::super::session::{read_auth_padding, Session, Stream, AUTH_HASH_LEN, MAX_STREAMS};

/// Streams handshaken and waiting for the listener to take them.
const INCOMING_QUEUE: usize = 64;

pub struct Handler {
    /// Users by the SHA-256 of their password, with their names.
    users: HashMap<[u8; 32], Option<Arc<str>>>,
    padding: Arc<PaddingScheme>,
    /// How long a stream has to name its destination.
    handshake_timeout: Duration,
    /// Where what fails to authenticate goes; closed without one.
    fallback: Option<Fallback>,
}

impl Handler {
    pub fn new(
        users: HashMap<[u8; 32], Option<Arc<str>>>,
        padding: Arc<PaddingScheme>,
        handshake_timeout: Duration,
        fallback: Option<Fallback>,
    ) -> Self {
        Handler {
            users,
            padding,
            handshake_timeout,
            fallback,
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
        // The password's hash, and no more: what is read here is what the
        // fallback is given if it is not a user's. Nothing tells a hash from
        // anything else before all of it is in.
        let mut hash = [0u8; AUTH_HASH_LEN];
        let mut read = 0;
        let reading = async {
            while read < AUTH_HASH_LEN {
                let n = stream.read(&mut hash[read..]).await?;
                if n == 0 {
                    return Ok(false);
                }
                read += n;
            }
            Ok::<_, io::Error>(true)
        };
        let complete = match self.fallback {
            // A peer that sends part of a hash and waits is not a client.
            Some(_) => timeout(HEADER_TIMEOUT, reading)
                .await
                .unwrap_or(Ok(false))?,
            None => reading.await?,
        };
        let user = match complete {
            true => self.users.get(&hash).ok_or("anytls: unknown user"),
            false => Err("anytls: not an AnyTLS request"),
        };
        let user = match user {
            Ok(user) => user,
            Err(why) => {
                return Err(match &self.fallback {
                    Some(fallback) => fallback.relay(&sess, stream, hash[..read].to_vec(), why),
                    None => io::Error::new(io::ErrorKind::PermissionDenied, why),
                })
            }
        };
        // The padding after it is a user's to send, and the handshake's
        // deadline bounds it.
        read_auth_padding(&mut stream).await?;
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
