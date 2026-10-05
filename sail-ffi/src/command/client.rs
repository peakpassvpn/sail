//! A command service's client: what an app's UI process holds of the
//! instance its tunnel process serves. It answers the C functions an
//! instance does, through the service, on a thread of its own.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;

use super::proto::{self, managed_client::ManagedClient, started_client::StartedClient};
use super::{failure_of, Address, SECRET};
use crate::events::{Emit, Events};
use crate::handles::{Table, CLIENT_TAG};
use crate::{json, Failure};

static CLIENTS: Mutex<Table<Client>> = Mutex::new(Table::tagged(CLIENT_TAG));

fn clients() -> std::sync::MutexGuard<'static, Table<Client>> {
    CLIENTS.lock().unwrap_or_else(|e| e.into_inner())
}

pub(crate) fn client(handle: u64) -> Option<Arc<Client>> {
    clients().get(handle)
}

pub(crate) fn remove(handle: u64) -> Option<Arc<Client>> {
    clients().remove(handle)
}

/// How a client tries to reach the service at first, as libbox's does:
/// ten tries, each given 100 ms and 50 ms more than the last.
const PROBES: u32 = 10;
const PROBE_FIRST: Duration = Duration::from_millis(100);
const PROBE_MORE: Duration = Duration::from_millis(50);

/// Adds the secret, when there is one, to each call.
#[derive(Clone)]
pub(crate) struct WithSecret(Option<tonic::metadata::MetadataValue<tonic::metadata::Ascii>>);

impl tonic::service::Interceptor for WithSecret {
    fn call(
        &mut self,
        mut request: tonic::Request<()>,
    ) -> Result<tonic::Request<()>, tonic::Status> {
        if let Some(secret) = &self.0 {
            request.metadata_mut().insert(SECRET, secret.clone());
        }
        Ok(request)
    }
}

type Service = InterceptedService<Channel, WithSecret>;

pub(crate) struct Client {
    pub started: StartedClient<Service>,
    pub managed: ManagedClient<Service>,
    /// The channel itself, for a test to call what no client here has.
    #[cfg(test)]
    pub raw: Service,
    pub events: Events,
}

/// A connection, as the service's socket is: unix, TCP, or the host's.
trait Connection: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> Connection for T {}

impl Client {
    fn connect(address: Address) -> Result<Arc<Self>, Failure> {
        static NEXT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);
        // Off Unix the service listens on loopback TCP only.
        #[cfg(not(unix))]
        if !matches!(address, Address::Tcp(..)) {
            return Err(super::off_unix());
        }
        let events = Events::new(NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed))?;
        let secret = match &address {
            Address::Tcp(_, secret) => Some(
                secret
                    .parse()
                    .map_err(|_| Failure::invalid("the secret is not ASCII"))?,
            ),
            _ => None,
        };
        #[cfg(unix)]
        let fd = match &address {
            Address::Fd(fd) => Some(
                // SAFETY: the host gives the descriptor, which the client
                // owns from now on.
                Arc::new(Mutex::new(Some(unsafe {
                    <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(*fd)
                }))),
            ),
            _ => None,
        };
        let connector = tower::service_fn(move |_: http::Uri| {
            let address = address.clone();
            #[cfg(unix)]
            let fd = fd.clone();
            async move {
                let stream: Box<dyn Connection> = match address {
                    #[cfg(unix)]
                    Address::Unix(path) => Box::new(tokio::net::UnixStream::connect(path).await?),
                    Address::Tcp(port, _) => {
                        Box::new(tokio::net::TcpStream::connect(("127.0.0.1", port)).await?)
                    }
                    #[cfg(unix)]
                    Address::Fd(_) => {
                        // One connection: the socket the host gave.
                        let fd = fd
                            .and_then(|fd| fd.lock().ok()?.take())
                            .ok_or_else(|| std::io::Error::other("the socket given is used"))?;
                        let stream = std::os::unix::net::UnixStream::from(fd);
                        stream.set_nonblocking(true)?;
                        Box::new(tokio::net::UnixStream::from_std(stream)?)
                    }
                    #[cfg(not(unix))]
                    Address::Unix(_) | Address::Fd(_) => {
                        return Err(std::io::Error::other("not on this system"))
                    }
                };
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        });
        let channel = {
            let _runtime = events.handle().enter();
            tonic::transport::Endpoint::from_static("http://sail.command")
                .connect_with_connector_lazy(connector)
        };
        let interceptor = WithSecret(secret);
        let client = Arc::new(Client {
            started: StartedClient::with_interceptor(channel.clone(), interceptor.clone()),
            #[cfg(test)]
            raw: InterceptedService::new(channel.clone(), interceptor.clone()),
            managed: ManagedClient::with_interceptor(channel, interceptor),
            events,
        });
        client.probe()?;
        Ok(client)
    }

    /// Asks the service its version until it answers, as libbox's client
    /// does. Another release than this one is no refusal: a call it lacks
    /// answers SAIL_ERR_UNSUPPORTED, a field it lacks is absent. It is
    /// warned of, and the host reads it in the instance's capabilities (an
    /// app updated while its old system extension still runs).
    fn probe(&self) -> Result<(), Failure> {
        let mut started = self.started.clone();
        self.block(async move {
            let mut last = None;
            for n in 0..PROBES {
                let wait = PROBE_FIRST + PROBE_MORE * n;
                match tokio::time::timeout(wait, started.get_version(proto::Empty {})).await {
                    Ok(Ok(answer)) => {
                        let theirs = answer.into_inner().version;
                        if theirs != env!("CARGO_PKG_VERSION") {
                            tracing::warn!(
                                "the command service runs sail {}, this is {}: calls one lacks \
                                 answer that they are unsupported",
                                theirs,
                                env!("CARGO_PKG_VERSION")
                            );
                        }
                        return Ok(());
                    }
                    Ok(Err(status)) if status.code() == tonic::Code::Unauthenticated => {
                        return Err(failure_of(status))
                    }
                    Ok(Err(status)) => last = Some(failure_of(status).message),
                    Err(_) => last = Some("no answer".into()),
                }
            }
            Err(Failure::new(
                crate::SAIL_ERR_IO,
                format!("no command service answers: {}", last.unwrap_or_default()),
            ))
        })?
    }

    /// Runs `call` on the client's thread, and waits for it; on that thread
    /// itself (a callback), it would wait on itself.
    pub fn block<T: Send + 'static>(
        &self,
        call: impl std::future::Future<Output = T> + Send + 'static,
    ) -> Result<T, Failure> {
        if self.events.is_current() {
            return Err(Failure::new(
                crate::SAIL_ERR_WRONG_THREAD,
                "called on the client's own thread, where it would wait on itself",
            ));
        }
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        self.events.handle().spawn(async move {
            let _ = tx.send(call.await);
        });
        rx.recv()
            .map_err(|_| Failure::state("the client is closed"))
    }

    /// Calls `rpc` with a clone of the service, and waits for its answer.
    pub fn unary<T: Send + 'static, F>(
        &self,
        rpc: impl FnOnce(StartedClient<Service>) -> F,
    ) -> Result<T, Failure>
    where
        F: std::future::Future<Output = Result<tonic::Response<T>, tonic::Status>> + Send + 'static,
    {
        let call = rpc(self.started.clone());
        self.block(call)?
            .map(tonic::Response::into_inner)
            .map_err(failure_of)
    }

    pub fn managed<F>(&self, rpc: impl FnOnce(ManagedClient<Service>) -> F) -> Result<(), Failure>
    where
        F: std::future::Future<Output = Result<tonic::Response<proto::Empty>, tonic::Status>>
            + Send
            + 'static,
    {
        let call = rpc(self.managed.clone());
        self.block(call)?.map(|_| ()).map_err(failure_of)
    }
}

/// What a connection lost tells a subscription, once, before it ends.
pub(crate) struct Disconnected {
    pub error: Option<String>,
}

/// Follows the stream `open` opens: each message, as `convert` makes it,
/// to `out`; then, once the stream ends, `disconnected`.
async fn follow<M, J, S>(
    mut out: S,
    open: impl std::future::Future<Output = Result<tonic::Response<tonic::Streaming<M>>, tonic::Status>>,
    mut convert: impl FnMut(M) -> Option<J>,
) where
    S: Emit<J> + Emit<Disconnected>,
    J: Send + 'static,
{
    let error = match open.await {
        Err(status) => Some(status.message().to_string()),
        Ok(stream) => {
            let mut stream = stream.into_inner();
            loop {
                match stream.next().await {
                    Some(Ok(message)) => {
                        if let Some(event) = convert(message) {
                            if !<S as Emit<J>>::emit(&mut out, event).await {
                                return;
                            }
                        }
                    }
                    Some(Err(status)) => break Some(status.message().to_string()),
                    None => break None,
                }
            }
        }
    };
    let _ = <S as Emit<Disconnected>>::emit(&mut out, Disconnected { error }).await;
}

/// What follows `kind` through `client`, as a subscription to an instance
/// does, given the sink its events go to.
pub(crate) fn produce(
    kind: u32,
    options: &crate::events::Options,
    client: &Arc<Client>,
) -> Result<crate::events::Producer, Failure> {
    use crate::events::*;
    let mut started = client.started.clone();
    let interval_ms = options.interval_ms.unwrap_or(0);
    Ok(match kind {
        SAIL_EVENT_STATE => Box::new(move |sink| {
            Box::pin(async move {
                follow(
                    sink,
                    started.subscribe_service_status(proto::Empty {}),
                    |m| Some(json::State::from(m)),
                )
                .await
            })
        }),
        SAIL_EVENT_LOG => {
            level(options.level.as_deref())?;
            let request = proto::SubscribeLogRequest {
                level: options.level.clone().unwrap_or_default(),
                no_backlog: !options.backlog.unwrap_or(true),
            };
            Box::new(move |sink| {
                Box::pin(async move {
                    follow(sink, started.subscribe_log(request), |m| {
                        Some(json::Log::from(m))
                    })
                    .await
                })
            })
        }
        SAIL_EVENT_STATUS => Box::new(move |sink| {
            Box::pin(async move {
                follow(
                    sink,
                    started.subscribe_status(proto::IntervalRequest { interval_ms }),
                    |m| Some(json::Status::from(m)),
                )
                .await
            })
        }),
        SAIL_EVENT_CONNECTIONS => Box::new(move |sink| {
            Box::pin(async move {
                // The connections, as their events tell them.
                let mut open: BTreeMap<u64, json::Connection> = BTreeMap::new();
                follow(
                    sink,
                    started.subscribe_connections(proto::IntervalRequest { interval_ms }),
                    move |events: proto::ConnectionEvents| {
                        use proto::connection_event::Type;
                        if events.reset {
                            open.clear();
                        }
                        for event in events.events {
                            match Type::try_from(event.r#type) {
                                Ok(Type::New) => {
                                    if let Some(c) = event.connection {
                                        open.insert(event.id, c.into());
                                    }
                                }
                                Ok(Type::Update) => {
                                    if let Some(c) = open.get_mut(&event.id) {
                                        c.upload += event.upload_delta;
                                        c.download += event.download_delta;
                                    }
                                }
                                Ok(Type::Closed) => {
                                    open.remove(&event.id);
                                }
                                Err(_) => {}
                            }
                        }
                        Some(json::Connections {
                            connections: open.values().cloned().collect(),
                        })
                    },
                )
                .await
            })
        }),
        SAIL_EVENT_OUTBOUNDS => Box::new(move |sink| {
            Box::pin(async move {
                follow(
                    sink,
                    started.subscribe_outbounds(proto::IntervalRequest { interval_ms }),
                    |m: proto::Outbounds| {
                        Some(json::Outbounds {
                            outbounds: m.outbounds.into_iter().map(Into::into).collect(),
                        })
                    },
                )
                .await
            })
        }),
        SAIL_EVENT_NETWORK => {
            return Err(Failure::new(
                crate::SAIL_ERR_UNSUPPORTED,
                "the network is followed in the tunnel process, as libbox's apps follow it",
            ))
        }
        SAIL_EVENT_FAULT | SAIL_EVENT_ROUTED | SAIL_EVENT_DNS | SAIL_EVENT_GROUP
        | SAIL_EVENT_DIAL | SAIL_EVENT_USER | SAIL_EVENT_SYSTEM => {
            return Err(Failure::new(
                crate::SAIL_ERR_UNSUPPORTED,
                "this kind of event is followed in the tunnel process",
            ))
        }
        other => return Err(Failure::invalid(format!("no event kind {}", other))),
    })
}

/// Connects to the service at `options`, giving the client's handle.
pub(crate) fn connect(options: &str) -> Result<crate::SailInstance, Failure> {
    let client = Client::connect(Address::read(options, true).map_err(super::listen_failure)?)?;
    Ok(clients().insert(client))
}
