//! Streams to a magic destination, which are served here rather than
//! routed, whatever inbound they came in through: that is how sing-box's
//! clients ask for what their protocols do not carry themselves.
//!
//! - `sp.mux.sing-box.arpa`: a sing-mux connection. Each of its streams is
//!   a session of its own, with the inbound tag and user of the connection
//!   that carries it. Only an inbound whose `multiplex` block enables it
//!   lets one through, padded only with `padding`, as sing-box's do; the
//!   others refuse it before it gets here (`transport::mux::inbound`).
//!   A stream to `_BrutalBwExchange` is not routed: on it the client
//!   negotiates TCP Brutal (`transport::mux::brutal`).
//! - `sp.v2.udp-over-tcp.arpa` and `sp.udp-over-tcp.arpa`: UDP over TCP,
//!   versions 2 and 1, a UDP session of its own; on a mux stream too.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::timeout;
use tracing::debug;

use crate::adapter::AnyStream;
use crate::app::dispatcher::Dispatcher;
use crate::app::nat_manager::NatManager;
use crate::session::{DatagramSource, Network, Session, SocksAddr, StreamId};
use crate::transport::uot;

use super::network_listener::handle_inbound_datagram;

/// Serves a stream an inbound accepted: routes it, or serves it if it asks
/// for a magic destination.
pub async fn serve_stream(
    mut sess: Session,
    stream: AnyStream,
    inbound_tag: String,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
) {
    // What is served here rather than routed, a mux connection or UDP
    // over TCP, is past its handshake: what it carries takes places among
    // the sessions, each its own.
    if uot::version(&sess.destination).is_some() {
        sess.handshake = None;
    }
    #[cfg(feature = "mux")]
    if crate::transport::mux::is_magic(&sess.destination) {
        sess.handshake = None;
        serve_mux(sess, stream, inbound_tag, dispatcher, nat_manager).await;
        return;
    }
    serve_unmuxed(sess, stream, inbound_tag, dispatcher, nat_manager).await;
}

/// Serves a stream, UoT or routed, that cannot be a mux connection.
async fn serve_unmuxed(
    sess: Session,
    stream: AnyStream,
    inbound_tag: String,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
) {
    match uot::version(&sess.destination) {
        // Routed in a task of its own: the layers that brought the stream
        // here end, and their state with them, which an idle connection
        // would otherwise keep for as long as it lives. What counts and
        // closes it, its place, its user's admission, its counter, its
        // span, goes with the session.
        None => {
            crate::runtime::scope::spawn("inbound stream", async move {
                dispatcher.dispatch_stream(sess, stream).await
            });
        }
        Some(2) => {
            let handshake_timeout = dispatcher.env().options.inbound.handshake_timeout;
            serve_uot(sess, stream, inbound_tag, nat_manager, handshake_timeout).await
        }
        Some(_) => serve_legacy_uot(sess, stream, inbound_tag, nat_manager).await,
    }
}

/// UoT version 1: no request, and every packet names its address. The
/// session goes to `0.0.0.0:0`, as sing-box routes it
/// (common/uot/router.go:42).
async fn serve_legacy_uot(
    mut sess: Session,
    stream: AnyStream,
    inbound_tag: String,
    nat_manager: Arc<NatManager>,
) {
    sess.destination = SocksAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0));
    let source = udp_session(&mut sess);
    let datagram = uot::InboundDatagram::new(stream, None, source);
    handle_inbound_datagram(
        inbound_tag,
        Box::new(datagram),
        Some(sess),
        nat_manager,
        crate::runtime::scope::TaskClass::Contained,
    )
    .await;
}

async fn serve_uot(
    mut sess: Session,
    mut stream: AnyStream,
    inbound_tag: String,
    nat_manager: Arc<NatManager>,
    handshake_timeout: Duration,
) {
    let (is_connect, destination) =
        match timeout(handshake_timeout, uot::read_request(&mut stream)).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                debug!("udp-over-tcp from {}: {}", sess.source, e);
                return;
            }
            Err(_) => {
                debug!("udp-over-tcp from {}: request timed out", sess.source);
                return;
            }
        };
    sess.destination = destination.clone();
    let source = udp_session(&mut sess);
    let connected = is_connect.then_some(destination);
    let datagram = uot::InboundDatagram::new(stream, connected, source);
    handle_inbound_datagram(
        inbound_tag,
        Box::new(datagram),
        Some(sess),
        nat_manager,
        crate::runtime::scope::TaskClass::Contained,
    )
    .await;
}

/// A session of its own for a stream of `sess`'s connection.
#[cfg(feature = "mux")]
fn stream_session(sess: &Session) -> Session {
    let mut sess = sess.clone();
    sess.new_span();
    sess.forget_sniffed();
    sess
}

/// Makes `sess` a UDP session of its own, and returns the source its
/// datagrams are reported from: one NAT session per stream.
fn udp_session(sess: &mut Session) -> DatagramSource {
    sess.network = Network::Udp;
    // Unique among the streams of one connection, which share its source.
    sess.stream_id = Some(StreamId::Uuid(uuid::Uuid::new_v4()));
    DatagramSource::new(sess.source, sess.stream_id).with_user(sess.user.clone())
}

#[cfg(feature = "mux")]
async fn serve_mux(
    sess: Session,
    stream: AnyStream,
    inbound_tag: String,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
) {
    use crate::transport::mux::{self, packet::ServerDatagram, server, StreamRequest};
    use tracing::Instrument;

    let handshake_timeout = dispatcher.env().options.inbound.handshake_timeout;
    let tuning = (&dispatcher.env().options.mux).into();
    let label = format!(
        "inbound={} user={}",
        inbound_tag,
        crate::user::name(&sess.user).unwrap_or("-")
    );
    let started = server::Server::start(stream, tuning, &label);
    let mut server = match timeout(handshake_timeout, started).await {
        Ok(Ok(server)) => server,
        Ok(Err(e)) => {
            debug!("mux connection from {}: {}", sess.source, e);
            return;
        }
        Err(_) => {
            debug!("mux connection from {}: handshake timed out", sess.source);
            return;
        }
    };
    debug!("mux connection from {}", sess.source);
    // Closed with its user's connections, when the user is shut out or
    // taken out of the inbound.
    let closer = server.closer();
    let _carrier = sess
        .user
        .as_ref()
        .map(|user| user.carry(&inbound_tag, closer));
    while let Some(stream) = server.accept().await {
        let mut sess = stream_session(&sess);
        let inbound_tag = inbound_tag.clone();
        let dispatcher = dispatcher.clone();
        let nat_manager = nat_manager.clone();
        let span = sess.span();
        crate::runtime::scope::spawn(
            "inbound mux stream",
            async move {
                let (request, stream) =
                    match timeout(handshake_timeout, server::read_stream(stream)).await {
                        Ok(Ok(v)) => v,
                        Ok(Err(e)) => {
                            debug!("mux stream: {}", e);
                            return;
                        }
                        Err(_) => {
                            debug!("mux stream: request timed out");
                            return;
                        }
                    };
                sess.destination = request.destination().clone();
                match request {
                    StreamRequest::Tcp(destination) => {
                        if mux::is_magic(&destination) {
                            debug!("mux stream: a mux connection inside one is refused");
                            return;
                        }
                        if mux::brutal::is_exchange(&destination) {
                            if let Err(e) = mux::brutal::serve_exchange(stream, &sess).await {
                                debug!("mux stream: brutal exchange: {}", e);
                            }
                            return;
                        }
                        serve_unmuxed(sess, stream, inbound_tag, dispatcher, nat_manager).await;
                    }
                    StreamRequest::Udp(destination) => {
                        let source = udp_session(&mut sess);
                        let datagram = ServerDatagram::new(stream, Some(destination), source);
                        handle_inbound_datagram(
                            inbound_tag,
                            Box::new(datagram),
                            Some(sess),
                            nat_manager,
                            crate::runtime::scope::TaskClass::Contained,
                        )
                        .await;
                    }
                    StreamRequest::UdpAddr(_) => {
                        let source = udp_session(&mut sess);
                        let datagram = ServerDatagram::new(stream, None, source);
                        handle_inbound_datagram(
                            inbound_tag,
                            Box::new(datagram),
                            Some(sess),
                            nat_manager,
                            crate::runtime::scope::TaskClass::Contained,
                        )
                        .await;
                    }
                }
            }
            .instrument(span),
        );
    }
}
