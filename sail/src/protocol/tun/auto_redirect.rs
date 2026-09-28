//! `auto_redirect` (Linux): the kernel sends the system's TCP to a local
//! listener with nftables' `redirect`, and its UDP and ICMP into the TUN by
//! a mark and the policy routing; a connection's first packet can be
//! judged by the router first, through NFQUEUE, so that a bypassed one never
//! reaches sail at all.
//!
//! Set up after the TUN device exists, and undone, in the reverse order,
//! when the instance stops: see [`AutoRedirect`].

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use tracing::{debug, info, warn};

use super::inbound::{AutoRedirectSettings, TunSettings};
use crate::app::dispatcher::Dispatcher;
use crate::platform::original_dst::{original_destination, unmapped};
use crate::platform::policy_route::PolicyRoutes;
use crate::session::{Network, Session, SocksAddr};
use crate::Runner;

/// What auto_redirect set up; dropping it undoes it.
pub(crate) struct AutoRedirect {
    routes: PolicyRoutes,
}

impl Drop for AutoRedirect {
    fn drop(&mut self) {
        self.routes.cleanup();
        info!("auto_redirect removed");
    }
}

/// How long an idle redirected connection goes before the kernel probes
/// it, as sing-tun's listener has it.
const KEEPALIVE: Duration = Duration::from_secs(10 * 60);

impl AutoRedirect {
    /// Sets it up for the TUN inbound `tag`, and returns what serves it.
    pub(crate) fn start(
        tag: &str,
        settings: &TunSettings,
        options: &AutoRedirectSettings,
        dispatcher: Arc<Dispatcher>,
    ) -> Result<(AutoRedirect, Runner)> {
        let routes = policy_routes(settings, options);
        let listener = listen(settings.ipv6.is_some())?;
        let port = listener.local_addr()?.port();
        routes.setup()?;
        let this = AutoRedirect { routes };
        info!("auto_redirect: TCP redirected to port {}", port);
        let tag = tag.to_owned();
        let runner = Box::pin(async move {
            let listener = match tokio::net::TcpListener::from_std(listener) {
                Ok(listener) => listener,
                Err(e) => {
                    warn!("auto_redirect: listener: {}", e);
                    return;
                }
            };
            serve(listener, tag, dispatcher).await;
        });
        Ok((this, runner))
    }
}

fn policy_routes(settings: &TunSettings, options: &AutoRedirectSettings) -> PolicyRoutes {
    PolicyRoutes {
        tun: settings.name.clone(),
        ipv4: settings.ipv4.is_some(),
        ipv6: settings.ipv6.is_some(),
        table: options.table_index,
        rule_index: options.rule_index,
        fallback_rule_index: options.fallback_rule_index,
        input_mark: options.input_mark,
        output_mark: options.output_mark,
        route_address: options.route_address.clone(),
        route_exclude_address: options.route_exclude_address.clone(),
    }
}

/// A TCP listener on every address and a port of the kernel's choosing:
/// `redirect` rewrites a connection's destination to an address of the
/// interface it came in on, or to loopback for the host's own. Dual stack
/// when the TUN has IPv6.
fn listen(ipv6: bool) -> Result<std::net::TcpListener> {
    let addr: SocketAddr = if ipv6 {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    if ipv6 {
        socket.set_only_v6(false)?;
    }
    socket.set_nonblocking(true)?;
    socket
        .bind(&addr.into())
        .and_then(|()| socket.listen(1024))
        .map_err(|e| anyhow!("auto_redirect: listen on {}: {}", addr, e))?;
    Ok(socket.into())
}

/// Takes the redirected connections, each to be routed as the TUN's.
async fn serve(listener: tokio::net::TcpListener, tag: String, dispatcher: Arc<Dispatcher>) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                // Out of descriptors, say: wait rather than spin.
                warn!("auto_redirect: accept: {}", e);
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let sess = match session(&stream, peer, &tag) {
            Ok(sess) => sess,
            Err(e) => {
                // Reached directly, not redirected: reset it.
                debug!("auto_redirect: {} from {}", e, peer);
                let _ = socket2::SockRef::from(&stream).set_linger(Some(Duration::ZERO));
                continue;
            }
        };
        let dispatcher = dispatcher.clone();
        tokio::spawn(async move { dispatcher.dispatch_stream(sess, stream).await });
    }
}

fn session(
    stream: &tokio::net::TcpStream,
    peer: SocketAddr,
    tag: &str,
) -> std::io::Result<Session> {
    let socket = socket2::SockRef::from(stream);
    let destination = original_destination(&socket, peer)?;
    let keepalive = socket2::TcpKeepalive::new().with_time(KEEPALIVE);
    if let Err(e) = socket.set_tcp_keepalive(&keepalive) {
        debug!("auto_redirect: keepalive: {}", e);
    }
    Ok(Session {
        network: Network::Tcp,
        source: unmapped(peer),
        local_addr: unmapped(stream.local_addr()?),
        destination: SocksAddr::Ip(destination),
        inbound_tag: tag.to_owned(),
        ..Default::default()
    })
}
