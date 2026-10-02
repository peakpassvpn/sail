//! The command service an instance serves, on its events thread: while it
//! is idle or failed too, as libbox's command server serves before and
//! between its service's runs.

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::time::Duration;

use futures::Stream;
use tokio::sync::{mpsc, watch};
use tonic::{Request, Response, Status};

use super::proto::{self, managed_server::Managed, started_server::Started};
use super::{status_of, Address, SECRET};
use crate::events::{self, Emit};
use crate::instance::Instance;
use crate::{json, Failure};

/// How many messages a stream holds for a slow client before its producer
/// waits; a log batch, or a status, each.
const STREAM_BUFFER: usize = 16;

/// A command service running. Dropping it closes it: its streams end, its
/// listener goes, and its socket file is removed.
pub(crate) struct Server {
    closed: watch::Sender<bool>,
    socket: Option<std::path::PathBuf>,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.closed.send(true);
        if let Some(path) = &self.socket {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Serves `instance` at `address`, on its events thread.
pub(crate) fn serve(instance: &Arc<Instance>, address: Address) -> Result<Server, Failure> {
    let handle = instance.events.handle().clone();
    let listener = {
        let _runtime = handle.enter();
        sail::control::listen::bind(&address).map_err(super::listen_failure)?
    };
    let (closed, closed_rx) = watch::channel(false);
    let secret = address.secret().map(str::to_owned);
    let started = proto::started_server::StartedServer::new(StartedService {
        instance: Arc::downgrade(instance),
        closed: closed_rx.clone(),
    });
    let managed = proto::managed_server::ManagedServer::new(ManagedService {
        instance: Arc::downgrade(instance),
    });
    let router = tower::service_fn(move |req: http::Request<hyper::body::Incoming>| {
        let (mut started, mut managed, secret) = (started.clone(), managed.clone(), secret.clone());
        async move {
            use tower::Service;
            if let Some(secret) = &secret {
                let given = req
                    .headers()
                    .get(SECRET)
                    .map(|v| v.as_bytes())
                    .unwrap_or_default();
                if !sail::control::listen::same_secret(given, secret.as_bytes()) {
                    return Ok::<_, Infallible>(
                        Status::unauthenticated("invalid authentication secret").into_http(),
                    );
                }
            }
            let path = req.uri().path();
            if path.starts_with("/sail.command.v1.Started/") {
                started.call(req).await
            } else if path.starts_with("/sail.command.v1.Managed/") {
                managed.call(req).await
            } else {
                Ok(Status::unimplemented("no such service").into_http())
            }
        }
    });
    handle.spawn(accept(listener, router, closed_rx));
    Ok(Server {
        closed,
        socket: match address {
            Address::Unix(path) => Some(path),
            _ => None,
        },
    })
}

async fn accept<S>(
    listener: sail::control::listen::Listener,
    router: S,
    mut closed: watch::Receiver<bool>,
) where
    S: tower::Service<
            http::Request<hyper::body::Incoming>,
            Response = http::Response<tonic::body::Body>,
            Error = Infallible,
        > + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    loop {
        let stream: Box<dyn Connection> = tokio::select! {
            accepted = async {
                use sail::control::listen::Listener;
                match &listener {
                    #[cfg(unix)]
                    Listener::Unix(l) => l.accept().await.map(|(s, _)| Box::new(s) as Box<dyn Connection>),
                    Listener::Tcp(l) => l.accept().await.map(|(s, _)| Box::new(s) as Box<dyn Connection>),
                }
            } => match accepted {
                Ok(stream) => stream,
                Err(_) => continue,
            },
            _ = closed.changed() => return,
        };
        let router = router.clone();
        let mut closed = closed.clone();
        tokio::spawn(async move {
            let connection =
                hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection(
                        hyper_util::rt::TokioIo::new(stream),
                        hyper_util::service::TowerToHyperService::new(router),
                    );
            tokio::pin!(connection);
            tokio::select! {
                _ = connection.as_mut() => {}
                _ = closed.changed() => {
                    // The streams end with OK; then the connection.
                    connection.as_mut().graceful_shutdown();
                    let _ = tokio::time::timeout(Duration::from_secs(1), connection).await;
                }
            }
        });
    }
}

trait Connection: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> Connection for T {}

type Streamed<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;

/// A stream's producer's end: what it sends goes to the client.
struct Out<P>(mpsc::Sender<Result<P, Status>>);

struct StartedService {
    instance: Weak<Instance>,
    closed: watch::Receiver<bool>,
}

impl StartedService {
    fn instance(&self) -> Result<Arc<Instance>, Status> {
        self.instance
            .upgrade()
            .ok_or_else(|| Status::unavailable("the instance was freed"))
    }

    fn manager(&self) -> Result<Arc<sail::RuntimeManager>, Status> {
        self.instance()?.manager().map_err(status_of)
    }

    /// Runs `task` on the instance's runtime, not this thread's.
    async fn on_instance<T: Send + 'static>(
        &self,
        task: impl FnOnce(Arc<sail::RuntimeManager>) -> futures::future::BoxFuture<'static, T>,
    ) -> Result<T, Status> {
        let manager = self.manager()?;
        let runtime = manager.handle().clone();
        runtime
            .spawn(task(manager))
            .await
            .map_err(|_| Status::unavailable("the instance stopped"))
    }

    /// A stream `produce` fills, ending when the service closes.
    fn stream<P: Send + 'static>(
        &self,
        produce: impl FnOnce(Out<P>) -> futures::future::BoxFuture<'static, ()>,
    ) -> Response<Streamed<P>> {
        let (tx, rx) = mpsc::channel(STREAM_BUFFER);
        let producer = produce(Out(tx));
        let mut closed = self.closed.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = producer => {}
                _ = closed.wait_for(|c| *c) => {}
            }
        });
        Response::new(Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx)))
    }
}

fn ok<T>(value: T) -> Result<Response<T>, Status> {
    Ok(Response::new(value))
}

#[tonic::async_trait]
impl Started for StartedService {
    async fn get_version(
        &self,
        _: Request<proto::Empty>,
    ) -> Result<Response<proto::Version>, Status> {
        let instance = self.instance()?;
        let mut version = proto::Version {
            version: env!("CARGO_PKG_VERSION").into(),
            features: sail::control::features()
                .into_iter()
                .map(Into::into)
                .collect(),
            ..Default::default()
        };
        if let Ok(manager) = instance.manager() {
            let (opens_tun, protects_sockets) = instance.host_callbacks();
            version.has_tun = manager.has_tun();
            version.opens_tun = opens_tun && manager.has_tun();
            version.protects_sockets = protects_sockets;
            version.needs_network = manager.needs_network();
            version.has_modes = manager.mode().is_some();
        }
        ok(version)
    }

    type SubscribeServiceStatusStream = Streamed<proto::ServiceStatus>;

    async fn subscribe_service_status(
        &self,
        _: Request<proto::Empty>,
    ) -> Result<Response<Self::SubscribeServiceStatusStream>, Status> {
        let state = self.instance()?.states();
        Ok(self.stream(move |out: Out<proto::ServiceStatus>| {
            Box::pin(events::follow_state(RefOut(out), state))
        }))
    }

    async fn get_service_status(
        &self,
        _: Request<proto::Empty>,
    ) -> Result<Response<proto::ServiceStatus>, Status> {
        ok((&self.instance()?.state()).into())
    }

    type SubscribeLogStream = Streamed<proto::Log>;

    async fn subscribe_log(
        &self,
        request: Request<proto::SubscribeLogRequest>,
    ) -> Result<Response<Self::SubscribeLogStream>, Status> {
        let request = request.into_inner();
        let least = events::level(Some(&request.level)).map_err(status_of)?;
        let log = self.instance()?.log.clone();
        Ok(self.stream(move |out: Out<proto::Log>| {
            Box::pin(events::follow_log(
                RefOut(out),
                log,
                least,
                !request.no_backlog,
            ))
        }))
    }

    async fn clear_logs(&self, _: Request<proto::Empty>) -> Result<Response<proto::Empty>, Status> {
        self.instance()?.log.clear();
        ok(proto::Empty {})
    }

    type SubscribeStatusStream = Streamed<proto::Status>;

    async fn subscribe_status(
        &self,
        request: Request<proto::IntervalRequest>,
    ) -> Result<Response<Self::SubscribeStatusStream>, Status> {
        let every = events::interval(
            Some(request.into_inner().interval_ms),
            Duration::from_secs(1),
        );
        let instance = self.instance.clone();
        Ok(self.stream(move |out: Out<proto::Status>| {
            Box::pin(events::follow_status(RefOut(out), instance, every))
        }))
    }

    async fn get_traffic(
        &self,
        _: Request<proto::Empty>,
    ) -> Result<Response<proto::Traffic>, Status> {
        let traffic = self
            .on_instance(|m| Box::pin(async move { m.traffic().await }))
            .await?;
        ok((&json::Traffic::of(&traffic)).into())
    }

    type SubscribeConnectionsStream = Streamed<proto::ConnectionEvents>;

    async fn subscribe_connections(
        &self,
        request: Request<proto::IntervalRequest>,
    ) -> Result<Response<Self::SubscribeConnectionsStream>, Status> {
        let every = events::interval(
            Some(request.into_inner().interval_ms),
            Duration::from_secs(1),
        );
        let instance = self.instance.clone();
        Ok(self.stream(move |out| Box::pin(connection_events(out, instance, every))))
    }

    async fn get_connections(
        &self,
        _: Request<proto::Empty>,
    ) -> Result<Response<proto::Connections>, Status> {
        let connections = self
            .on_instance(|m| Box::pin(async move { m.connections().await }))
            .await?;
        ok(proto::Connections {
            connections: connections
                .iter()
                .map(|c| (&json::Connection::of(c)).into())
                .collect(),
        })
    }

    async fn close_connection(
        &self,
        request: Request<proto::CloseConnectionRequest>,
    ) -> Result<Response<proto::CloseConnectionReply>, Status> {
        let id = request.into_inner().id;
        let closed = self
            .on_instance(move |m| Box::pin(async move { m.close_connection(id).await }))
            .await?;
        ok(proto::CloseConnectionReply { closed })
    }

    async fn close_all_connections(
        &self,
        _: Request<proto::Empty>,
    ) -> Result<Response<proto::CloseAllConnectionsReply>, Status> {
        let count = self
            .on_instance(|m| Box::pin(async move { m.close_all_connections().await }))
            .await?;
        ok(proto::CloseAllConnectionsReply {
            count: count as u64,
        })
    }

    type SubscribeOutboundsStream = Streamed<proto::Outbounds>;

    async fn subscribe_outbounds(
        &self,
        request: Request<proto::IntervalRequest>,
    ) -> Result<Response<Self::SubscribeOutboundsStream>, Status> {
        let every = events::interval(
            Some(request.into_inner().interval_ms),
            Duration::from_millis(250),
        );
        let instance = self.instance.clone();
        Ok(self.stream(move |out: Out<proto::Outbounds>| {
            Box::pin(events::follow_outbounds(
                RefOut(out),
                instance,
                every,
                false,
            ))
        }))
    }

    async fn get_outbounds(
        &self,
        request: Request<proto::OutboundsRequest>,
    ) -> Result<Response<proto::Outbounds>, Status> {
        let groups = request.into_inner().groups;
        let list = self
            .on_instance(move |m| {
                Box::pin(async move {
                    if groups {
                        m.groups().await
                    } else {
                        m.outbounds().await
                    }
                })
            })
            .await?;
        ok(outbounds_of(&json::Outbounds {
            outbounds: list.iter().map(json::Outbound::of).collect(),
        }))
    }

    async fn select_outbound(
        &self,
        request: Request<proto::SelectOutboundRequest>,
    ) -> Result<Response<proto::Empty>, Status> {
        let request = request.into_inner();
        self.on_instance(move |m| {
            Box::pin(async move { m.select(&request.group, &request.member).await })
        })
        .await?
        .map_err(|e| status_of(e.into()))?;
        ok(proto::Empty {})
    }

    async fn get_providers(
        &self,
        _: Request<proto::Empty>,
    ) -> Result<Response<proto::Providers>, Status> {
        let list = self
            .on_instance(|m| Box::pin(async move { m.providers().await }))
            .await?;
        ok(proto::Providers {
            providers: list
                .iter()
                .map(|p| (&json::Provider::of(p)).into())
                .collect(),
        })
    }

    async fn update_provider(
        &self,
        request: Request<proto::TagRequest>,
    ) -> Result<Response<proto::Empty>, Status> {
        let tag = request.into_inner().tag;
        self.on_instance(move |m| Box::pin(async move { m.update_provider(&tag).await }))
            .await?
            .map_err(|e| status_of(e.into()))?;
        ok(proto::Empty {})
    }

    async fn get_rule_sets(
        &self,
        _: Request<proto::Empty>,
    ) -> Result<Response<proto::RuleSets>, Status> {
        let list = self
            .on_instance(|m| Box::pin(async move { m.rule_sets().await }))
            .await?;
        ok(proto::RuleSets {
            rule_sets: list
                .iter()
                .map(|r| (&json::RuleSet::of(r)).into())
                .collect(),
        })
    }

    async fn update_rule_set(
        &self,
        request: Request<proto::TagRequest>,
    ) -> Result<Response<proto::Empty>, Status> {
        let tag = request.into_inner().tag;
        self.on_instance(move |m| Box::pin(async move { m.update_rule_set(&tag).await }))
            .await?
            .map_err(|e| status_of(e.into()))?;
        ok(proto::Empty {})
    }

    async fn url_test(
        &self,
        request: Request<proto::UrlTestRequest>,
    ) -> Result<Response<proto::Empty>, Status> {
        let request = request.into_inner();
        let timeout = timeout(request.timeout_ms)?;
        let manager = self.manager()?;
        let group = self
            .on_instance({
                let tag = request.tag.clone();
                move |m| Box::pin(async move { m.outbound(&tag).await })
            })
            .await?
            .ok_or_else(|| {
                status_of(sail::control::ControlError::NotFound(request.tag.clone()).into())
            })?
            .group
            .is_some();
        let url = Some(request.url).filter(|u| !u.is_empty());
        let runtime = manager.handle().clone();
        // As libbox's: returns before the test runs.
        runtime.spawn(async move {
            if group {
                let _ = manager
                    .url_test_members(&request.tag, url.as_deref(), timeout)
                    .await;
            } else {
                let _ = manager
                    .url_test(&request.tag, url.as_deref(), timeout)
                    .await;
            }
        });
        ok(proto::Empty {})
    }

    async fn delay(
        &self,
        request: Request<proto::UrlTestRequest>,
    ) -> Result<Response<proto::DelayReply>, Status> {
        let request = request.into_inner();
        let timeout = timeout(request.timeout_ms)?;
        let url = Some(request.url).filter(|u| !u.is_empty());
        let tag = request.tag;
        let delay = self
            .on_instance(move |m| {
                Box::pin(async move { m.url_test(&tag, url.as_deref(), timeout).await })
            })
            .await?
            .map_err(|e| status_of(e.into()))?;
        ok(proto::DelayReply {
            delay_ms: delay.as_millis().max(1) as u64,
        })
    }

    async fn get_clash_mode_status(
        &self,
        _: Request<proto::Empty>,
    ) -> Result<Response<proto::ClashModeStatus>, Status> {
        let mode = self
            .manager()?
            .mode()
            .ok_or_else(|| status_of(sail::control::ControlError::NoModes.into()))?;
        ok(proto::ClashModeStatus {
            modes: mode.modes,
            mode: mode.current,
        })
    }

    type SubscribeClashModeStream = Streamed<proto::ClashMode>;

    async fn subscribe_clash_mode(
        &self,
        _: Request<proto::Empty>,
    ) -> Result<Response<Self::SubscribeClashModeStream>, Status> {
        let instance = self.instance.clone();
        Ok(self.stream(move |out| Box::pin(clash_mode(out, instance))))
    }

    async fn set_clash_mode(
        &self,
        request: Request<proto::ClashMode>,
    ) -> Result<Response<proto::Empty>, Status> {
        self.manager()?
            .set_mode(&request.into_inner().mode)
            .map_err(|e| status_of(e.into()))?;
        ok(proto::Empty {})
    }

    async fn get_deprecated_warnings(
        &self,
        _: Request<proto::Empty>,
    ) -> Result<Response<proto::Warnings>, Status> {
        ok(proto::Warnings {
            warnings: self.manager()?.take_warnings(),
        })
    }
}

fn timeout(timeout_ms: u32) -> Result<Duration, Status> {
    match timeout_ms {
        0 => Err(Status::invalid_argument("the timeout is 0")),
        ms => Ok(Duration::from_millis(u64::from(ms))),
    }
}

fn outbounds_of(outbounds: &json::Outbounds) -> proto::Outbounds {
    proto::Outbounds {
        outbounds: outbounds.outbounds.iter().map(Into::into).collect(),
    }
}

/// Emits what is followed to the client, as protobuf.
struct RefOut<P>(Out<P>);

impl<T, P> Emit<T> for RefOut<P>
where
    T: Send + 'static,
    P: for<'a> From<&'a T> + Send + 'static,
{
    async fn emit(&mut self, value: T) -> bool {
        self.0 .0.send(Ok(P::from(&value))).await.is_ok()
    }

    fn open(&self) -> bool {
        !self.0 .0.is_closed()
    }
}

impl From<&json::Outbounds> for proto::Outbounds {
    fn from(o: &json::Outbounds) -> Self {
        outbounds_of(o)
    }
}

/// The connections as libbox sends them: those open (reset), then each
/// interval what changed: the new, what the others sent and received since,
/// and the closed.
async fn connection_events(
    out: Out<proto::ConnectionEvents>,
    instance: Weak<Instance>,
    every: Duration,
) {
    use proto::connection_event::Type;
    use std::collections::HashMap;
    let mut ticker = events::ticker(every);
    // Each connection's totals as last sent; none until the first.
    let mut known: Option<HashMap<u64, (u64, u64)>> = None;
    while !out.0.is_closed() {
        let Some(manager) = events::tick(&mut ticker, &instance).await else {
            return;
        };
        let Some(manager) = manager else {
            continue;
        };
        let now = manager.connections().await;
        let mut message = proto::ConnectionEvents::default();
        let mut next = HashMap::with_capacity(now.len());
        let reset = known.is_none();
        let previous = known.take().unwrap_or_default();
        for c in &now {
            next.insert(c.id, (c.upload, c.download));
            match previous.get(&c.id) {
                Some((up, down)) if (*up, *down) == (c.upload, c.download) => {}
                Some((up, down)) => message.events.push(proto::ConnectionEvent {
                    r#type: Type::Update as i32,
                    id: c.id,
                    connection: None,
                    upload_delta: c.upload.saturating_sub(*up),
                    download_delta: c.download.saturating_sub(*down),
                }),
                None => message.events.push(proto::ConnectionEvent {
                    r#type: Type::New as i32,
                    id: c.id,
                    connection: Some((&json::Connection::of(c)).into()),
                    upload_delta: 0,
                    download_delta: 0,
                }),
            }
        }
        for id in previous.keys().filter(|id| !next.contains_key(id)) {
            message.events.push(proto::ConnectionEvent {
                r#type: Type::Closed as i32,
                id: *id,
                ..Default::default()
            });
        }
        known = Some(next);
        message.reset = reset;
        if (reset || !message.events.is_empty()) && out.0.send(Ok(message)).await.is_err() {
            return;
        }
    }
}

/// The mode, then each change, looked at every 250 ms (libbox pushes its
/// outbounds no more often).
async fn clash_mode(out: Out<proto::ClashMode>, instance: Weak<Instance>) {
    let mut ticker = events::ticker(Duration::from_millis(250));
    let mut last: Option<String> = None;
    while !out.0.is_closed() {
        let Some(manager) = events::tick(&mut ticker, &instance).await else {
            return;
        };
        // Not running: the empty mode, as libbox sends.
        let mode = manager
            .and_then(|m| m.mode())
            .map(|m| m.current)
            .unwrap_or_default();
        if last.as_ref() != Some(&mode) {
            last = Some(mode.clone());
            if out.0.send(Ok(proto::ClashMode { mode })).await.is_err() {
                return;
            }
        }
    }
}

struct ManagedService {
    instance: Weak<Instance>,
}

#[tonic::async_trait]
impl Managed for ManagedService {
    async fn stop_service(
        &self,
        _: Request<proto::Empty>,
    ) -> Result<Response<proto::Empty>, Status> {
        let instance = self
            .instance
            .upgrade()
            .ok_or_else(|| Status::unavailable("the instance was freed"))?;
        run_blocking(move || instance.service_stop()).await?;
        ok(proto::Empty {})
    }

    async fn reload_service(
        &self,
        _: Request<proto::Empty>,
    ) -> Result<Response<proto::Empty>, Status> {
        let instance = self
            .instance
            .upgrade()
            .ok_or_else(|| Status::unavailable("the instance was freed"))?;
        run_blocking(move || instance.service_reload()).await?;
        ok(proto::Empty {})
    }
}

/// Runs `f`, which may wait on the instance, off the events thread: the
/// host's callback it calls may call back in.
async fn run_blocking(
    f: impl FnOnce() -> Result<(), Failure> + Send + 'static,
) -> Result<(), Status> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| Status::internal("the call failed"))?
        .map_err(status_of)
}
