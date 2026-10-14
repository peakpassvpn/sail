use std::convert::TryFrom;
use std::io;
use std::sync::{Arc, Weak};
use std::time::Duration;

use async_trait::async_trait;
use futures::future::BoxFuture;
use futures::future::{abortable, AbortHandle};
use futures::FutureExt;
use rand::prelude::SliceRandom;
use rand::rngs::StdRng;
use rand::SeedableRng;
use tokio::sync::Mutex;
use tracing::{debug, Instrument};

use crate::{
    adapter::*,
    app::SyncDnsClient,
    net::dial::BoundInterface,
    net::*,
    session::{Session, SocksAddr},
    transport::idle::Idle,
    transport::muxcore::Tuning,
};

use super::MuxConnector;
use super::MuxSession;
use super::MuxStream;

/// A session, and what its dial recorded, which the streams on it after
/// the first are given: they go out where it does.
pub struct Pooled {
    connector: MuxConnector,
    bound: BoundInterface,
    /// Since when its session has had no streams, as last checked.
    idle: Idle,
}

/// Drops the connectors that are done, and closes and drops those whose
/// session has had no streams for `idle_timeout` (`transport::idle`):
/// their connection would otherwise stay for as long as the outbound.
fn check(connectors: &mut Vec<Pooled>, idle_timeout: Duration, now: tokio::time::Instant) {
    connectors.retain_mut(|c| {
        if c.connector.is_done() {
            return false;
        }
        if !c.idle.expired(c.connector.num_streams(), now, idle_timeout) {
            return true;
        }
        debug!("closing an idle amux session");
        c.connector.close();
        false
    });
}

pub struct MuxManager {
    pub address: String,
    pub port: u16,
    pub actors: Vec<AnyOutboundHandler>,
    pub max_accepts: usize,
    pub concurrency: usize,
    pub max_recv_bytes: usize,
    pub max_lifetime: u64,
    pub dns_client: SyncDnsClient,
    pub dialer: Dialer,
    pub tuning: Tuning,
    /// Who the sessions serve, in their logs.
    pub label: String,
    /// Sessions that may take more streams. One dropped, by the monitor or
    /// with the manager on a reload, ends once its streams are done; one
    /// the monitor finds idle is closed.
    pub connectors: Arc<Mutex<Vec<Pooled>>>,
    pub monitor_task: Mutex<Option<BoxFuture<'static, ()>>>,
}

impl MuxManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        address: String,
        port: u16,
        actors: Vec<AnyOutboundHandler>,
        max_accepts: usize,
        concurrency: usize,
        max_recv_bytes: usize,
        max_lifetime: u64,
        dns_client: SyncDnsClient,
        dialer: Dialer,
        tuning: Tuning,
        label: String,
    ) -> (Self, Vec<AbortHandle>) {
        let mut abort_handles = Vec::new();
        let connectors: Arc<Mutex<Vec<Pooled>>> = Arc::new(Mutex::new(Vec::new()));
        let watched: Weak<Mutex<Vec<Pooled>>> = Arc::downgrade(&connectors);
        let idle_timeout = tuning.idle_timeout;
        // A task to remove completed connectors and close idle ones, until
        // the manager is gone.
        let fut = async move {
            loop {
                let Some(connectors) = watched.upgrade() else {
                    return;
                };
                check(
                    &mut *connectors.lock().await,
                    idle_timeout,
                    tokio::time::Instant::now(),
                );
                drop(connectors);
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        };
        let (abortable, abort_handle) = abortable(fut);
        abort_handles.push(abort_handle);
        let monitor_task: BoxFuture<'static, ()> = Box::pin(abortable.map(|_| ()));
        (
            MuxManager {
                address,
                port,
                actors,
                max_accepts,
                concurrency,
                max_recv_bytes,
                max_lifetime,
                dns_client,
                dialer,
                tuning,
                label,
                connectors,
                monitor_task: Mutex::new(Some(monitor_task)),
            },
            abort_handles,
        )
    }

    pub async fn new_stream(&self, sess: &Session) -> io::Result<MuxStream> {
        // Run the cleanup task, if it's not already running.
        if self.monitor_task.lock().await.is_some() {
            if let Some(task) = self.monitor_task.lock().await.take() {
                crate::runtime::scope::spawn_essential("amux idle check", task);
            }
        }

        if !sess.new_conn_once {
            // Try to create the stream from existing connections.
            let mut conns = self.connectors.lock().await;
            conns.shuffle(&mut StdRng::from_entropy());
            for c in conns.iter_mut() {
                if let Some(s) = c
                    .connector
                    .new_stream()
                    .instrument(tracing::Span::current())
                    .await
                {
                    c.bound.onto(sess);
                    return Ok(s);
                }
            }
        }

        // Create a new connection.

        // Create the underlying connection, TCP or through a detour.
        let mut sess = sess.clone();
        sess.destination = SocksAddr::try_from((&self.address, self.port))?;
        sess.forget_sniffed();
        let mut conn: AnyStream = self
            .dialer
            .stream(&self.dns_client, Some(&sess), &sess.destination)
            .instrument(tracing::Span::current())
            .await?;

        // Pass it through all sub-transports, e.g. TLS, WebSocket.
        for a in self.actors.iter() {
            conn = a
                .stream()?
                .handle(&sess, None, Some(conn))
                .instrument(tracing::Span::current())
                .await?;
        }

        // Create the stream over this new connection.
        let mut connector = {
            if sess.new_conn_once {
                MuxSession::connector(conn, 1, 1, 0, 0, self.tuning, &self.label)
            } else {
                MuxSession::connector(
                    conn,
                    self.max_accepts,
                    self.concurrency,
                    self.max_recv_bytes,
                    self.max_lifetime,
                    self.tuning,
                    &self.label,
                )
            }
        };
        let s = match connector
            .new_stream()
            .instrument(tracing::Span::current())
            .await
        {
            Some(s) => s,
            None => return Err(io::Error::other("new stream failed")),
        };
        let mut conns = self.connectors.lock().await;
        conns.push(Pooled {
            connector,
            bound: BoundInterface::of(&sess),
            idle: Idle::default(),
        });
        debug!("created new amux conn, total: {}", conns.len());
        Ok(s)
    }
}

pub struct Handler {
    manager: MuxManager,
}

impl Handler {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        address: String,
        port: u16,
        actors: Vec<AnyOutboundHandler>,
        max_accepts: usize,
        concurrency: usize,
        max_recv_bytes: usize,
        max_lifetime: u64,
        dns_client: SyncDnsClient,
        dialer: Dialer,
        tuning: Tuning,
        label: String,
    ) -> (Self, Vec<AbortHandle>) {
        let (manager, abort_handles) = MuxManager::new(
            address,
            port,
            actors,
            max_accepts,
            concurrency,
            max_recv_bytes,
            max_lifetime,
            dns_client,
            dialer,
            tuning,
            label,
        );
        (Handler { manager }, abort_handles)
    }
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        _stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        tracing::trace!("handling outbound stream");
        Ok(Box::new(
            self.manager
                .new_stream(sess)
                .instrument(tracing::Span::current())
                .await?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;
    use tokio::net::TcpListener;

    use super::*;
    use crate::net::dial::Egress;

    /// A stream on a session another stream made goes out where the
    /// session does, from and to its addresses.
    #[tokio::test]
    async fn a_stream_on_a_session_another_made_goes_out_where_it_does() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = listener.local_addr().unwrap();
        // Takes one session's streams, and keeps them.
        tokio::spawn(async move {
            let (conn, _) = listener.accept().await.unwrap();
            let mut acceptor = MuxSession::acceptor(conn, Tuning::default(), "test");
            let mut kept = Vec::new();
            while let Some(stream) = acceptor.next().await {
                kept.push(stream);
            }
        });
        let dns = crate::app::dns::DnsClient::new(
            &Default::default(),
            Default::default(),
            &Default::default(),
        )
        .unwrap()
        .into_shared();
        let (manager, _) = MuxManager::new(
            server.ip().to_string(),
            server.port(),
            Vec::new(),
            128,
            16,
            0,
            0,
            dns,
            Dialer::system(),
            Tuning::default(),
            "test".into(),
        );
        let (first, second) = (Session::default(), Session::default());
        let _made = manager.new_stream(&first).await.unwrap();
        let _given = manager.new_stream(&second).await.unwrap();
        assert_eq!(manager.connectors.lock().await.len(), 1);
        let (made, given) = (
            first.state.get::<BoundInterface>(),
            second.state.get::<BoundInterface>(),
        );
        assert_eq!(made.peer(), Some(server));
        assert_eq!(given.get(), Some(Egress::DefaultRoute));
        assert_eq!(given.local(), made.local());
        assert_eq!(given.peer(), Some(server));
    }

    /// A server that answers each stream with its end once the client's
    /// has come: the port, and a message for each session that ended.
    async fn finishing_server() -> (u16, tokio::sync::mpsc::UnboundedReceiver<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (ended, ends) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((conn, _)) = listener.accept().await {
                let ended = ended.clone();
                tokio::spawn(async move {
                    let mut acceptor = MuxSession::acceptor(conn, Tuning::default(), "test");
                    while let Some(mut stream) = acceptor.next().await {
                        tokio::spawn(async move {
                            let _ = stream.read_to_end(&mut Vec::new()).await;
                            let _ = stream.shutdown().await;
                        });
                    }
                    let _ = ended.send(());
                });
            }
        });
        (port, ends)
    }

    fn manager_to(port: u16) -> MuxManager {
        let dns = crate::app::dns::DnsClient::new(
            &Default::default(),
            Default::default(),
            &Default::default(),
        )
        .unwrap()
        .into_shared();
        MuxManager::new(
            "127.0.0.1".into(),
            port,
            Vec::new(),
            128,
            16,
            0,
            0,
            dns,
            Dialer::system(),
            Tuning::default(),
            "test".into(),
        )
        .0
    }

    /// A stream through `manager`, ended both ways: its session takes more.
    async fn finished_stream(manager: &MuxManager) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = manager.new_stream(&Session::default()).await.unwrap();
        stream.write_all(b"once").await.unwrap();
        stream.shutdown().await.unwrap();
        stream.read_to_end(&mut Vec::new()).await.unwrap();
    }

    /// A session whose streams have ended is closed once the idle timeout
    /// has passed, which the server sees; the next stream makes another.
    /// Time paused.
    #[tokio::test(start_paused = true)]
    async fn a_session_with_no_stream_is_closed() {
        let idle = Tuning::default().idle_timeout;
        let (port, mut ended) = finishing_server().await;
        let manager = manager_to(port);
        finished_stream(&manager).await;
        tokio::time::sleep(idle + Duration::from_secs(15)).await;
        assert!(manager.connectors.lock().await.is_empty(), "kept idle");
        let seen = tokio::time::timeout(Duration::from_secs(5), ended.recv()).await;
        assert!(matches!(seen, Ok(Some(()))), "the server saw no end");
        let _stream = manager.new_stream(&Session::default()).await.unwrap();
        assert_eq!(manager.connectors.lock().await.len(), 1);
    }

    /// An open stream keeps its session past the idle timeout. Time paused.
    #[tokio::test(start_paused = true)]
    async fn an_open_stream_keeps_the_session() {
        let idle = Tuning::default().idle_timeout;
        let (port, mut ended) = finishing_server().await;
        let manager = manager_to(port);
        let open = manager.new_stream(&Session::default()).await.unwrap();
        tokio::time::sleep(idle * 3).await;
        assert_eq!(manager.connectors.lock().await.len(), 1);
        assert!(ended.try_recv().is_err(), "the server saw an end");
        drop(open);
    }
}
