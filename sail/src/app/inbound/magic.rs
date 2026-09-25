//! Streams to a magic destination, which are served here rather than
//! routed, whatever inbound they came in through: that is how sing-box's
//! clients ask for what their protocols do not carry themselves.
//!
//! - `sp.mux.sing-box.arpa`: a sing-mux connection. Each of its streams is
//!   a session of its own, with the inbound tag and user of the connection
//!   that carries it.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::timeout;
use tracing::{debug, Instrument};

use crate::adapter::AnyStream;
use crate::app::dispatcher::Dispatcher;
use crate::app::nat_manager::NatManager;
use crate::session::{DatagramSource, Network, Session, StreamId};

use super::network_listener::handle_inbound_datagram;

/// Serves a stream an inbound accepted: routes it, or serves it if it asks
/// for a magic destination.
pub async fn serve_stream(
    sess: Session,
    stream: AnyStream,
    inbound_tag: String,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
) {
    #[cfg(feature = "mux")]
    if crate::transport::mux::is_magic(&sess.destination) {
        serve_mux(sess, stream, inbound_tag, dispatcher, nat_manager).await;
        return;
    }
    let _ = (inbound_tag, nat_manager);
    dispatcher.dispatch_stream(sess, stream).await;
}

/// A session of its own for a stream of `sess`'s connection.
#[cfg(feature = "mux")]
fn stream_session(sess: &Session) -> Session {
    let mut sess = sess.clone();
    sess.new_span();
    sess.sniffed = None;
    sess
}

/// Makes `sess` a UDP session of its own, and returns the source its
/// datagrams are reported from: one NAT session per stream.
#[cfg_attr(not(feature = "mux"), allow(dead_code))]
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

    let handshake_timeout: Duration = dispatcher.env().options.inbound.handshake_timeout;
    let mut server = match timeout(handshake_timeout, server::Server::start(stream)).await {
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
    while let Some(stream) = server.accept().await {
        let mut sess = stream_session(&sess);
        let inbound_tag = inbound_tag.clone();
        let dispatcher = dispatcher.clone();
        let nat_manager = nat_manager.clone();
        let span = sess.span();
        tokio::spawn(
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
                        dispatcher.dispatch_stream(sess, stream).await;
                    }
                    StreamRequest::Udp(destination) => {
                        let source = udp_session(&mut sess);
                        let datagram = ServerDatagram::new(stream, Some(destination), source);
                        handle_inbound_datagram(
                            inbound_tag,
                            Box::new(datagram),
                            Some(sess),
                            nat_manager,
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
                        )
                        .await;
                    }
                }
            }
            .instrument(span),
        );
    }
}
