//! The QUIC glue everything on quinn shares: the quic transport, Hysteria2,
//! TUIC and the DNS upstreams over QUIC.
//!
//! TLS configurations from the `tls` blocks, transport parameters, the
//! endpoint and the socket under it, and a proxied stream. What a protocol
//! does on top, such as Hysteria2's Brutal and Salamander or TUIC's
//! heartbeats, stays with the protocol.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{anyhow, Result};
use quinn::congestion::ControllerFactory;
use quinn::{AsyncUdpSocket, Runtime};
use serde_derive::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::net::DialOptions;
use crate::runtime::options::Quic as Tuning;
use crate::runtime::RuntimeEnv;
use crate::transport::layers::{trusted_certificate, InboundTls, Listable, OutboundTls};
use crate::transport::tls::client::{bundled_root_certs, load_certificates, load_private_key};

/// The ALPNs of a `tls` block's `alpn`, or `default` when it lists none.
pub fn alpn_protocols(alpn: Option<&Listable>, default: &[&str]) -> Vec<Vec<u8>> {
    match alpn.map(|a| a.clone().into_vec()) {
        Some(list) if !list.is_empty() => list.into_iter().map(String::into_bytes).collect(),
        _ => default.iter().map(|a| a.as_bytes().to_vec()).collect(),
    }
}

/// A client TLS configuration trusting `certificate` (inline PEM or a
/// path) instead of the bundled roots, or any server if `insecure`, and
/// offering `alpns`, if any.
pub fn client_crypto(
    certificate: Option<&str>,
    insecure: bool,
    alpns: &[Vec<u8>],
) -> Result<quinn_btls::ClientConfig> {
    use quinn_btls::QuicSslContext;
    let mut crypto =
        quinn_btls::ClientConfig::new().map_err(|e| anyhow!("quic client config: {}", e))?;
    if insecure {
        crypto.verify_peer(false);
    } else {
        let certs = match certificate {
            Some(certificate) => load_certificates(certificate)?,
            None => bundled_root_certs()?.to_vec(),
        };
        let store = crypto.ctx_mut().cert_store_mut();
        for cert in certs {
            store.add_cert(cert)?;
        }
    }
    if !alpns.is_empty() {
        crypto
            .set_alpn(alpns)
            .map_err(|e| anyhow!("quic alpn: {}", e))?;
    }
    Ok(crypto)
}

/// What a client dials with, from its `tls` block.
pub struct ClientTls {
    /// The name the server is verified by: `server_name`, or the server's
    /// address.
    pub server_name: String,
    pub crypto: quinn_btls::ClientConfig,
}

impl ClientTls {
    /// From `tls`, for the server at `server`, offering `default_alpn`
    /// unless `alpn` is set. Whatever `unsupported` finds is the caller's
    /// to refuse; this reads none of it.
    pub fn new(
        tls: &OutboundTls,
        server: &str,
        default_alpn: &[&str],
        env: &RuntimeEnv,
    ) -> Result<Self> {
        let crypto = client_crypto(
            trusted_certificate(tls, env).as_deref(),
            tls.insecure,
            &alpn_protocols(tls.alpn.as_ref(), default_alpn),
        )?;
        Ok(Self {
            server_name: tls.server_name.clone().unwrap_or_else(|| server.to_owned()),
            crypto,
        })
    }
}

/// The first of `tls.reality`, `tls.ech` and `tls.utls` that the block
/// enables: none of them works over QUIC.
pub fn unsupported(tls: &OutboundTls) -> Option<&'static str> {
    [
        ("reality", tls.reality.as_ref().is_some_and(|r| r.enabled)),
        ("ech", tls.ech.as_ref().is_some_and(|e| e.enabled)),
        ("utls", tls.utls.as_ref().is_some_and(|u| u.enabled)),
    ]
    .into_iter()
    .find_map(|(field, on)| on.then_some(field))
}

/// A server TLS configuration presenting `certificate` with `key`, each
/// inline PEM or a path, and accepting `alpns`, if any.
pub fn server_crypto(
    certificate: &str,
    key: &str,
    alpns: &[Vec<u8>],
) -> Result<quinn_btls::ServerConfig> {
    use quinn_btls::QuicSslContext;
    let mut certs = load_certificates(certificate)?.into_iter();
    let key = load_private_key(key)?;

    let mut crypto =
        quinn_btls::ServerConfig::new().map_err(|e| anyhow!("quic server config: {}", e))?;
    let ctx = crypto.ctx_mut();
    let leaf = certs
        .next()
        .ok_or_else(|| anyhow!("no certificate found"))?;
    ctx.set_certificate(leaf)?;
    for cert in certs {
        ctx.add_to_cert_chain(cert)?;
    }
    ctx.set_private_key(key)?;
    ctx.check_private_key()
        .map_err(|e| anyhow!("private key does not match the certificate: {}", e))?;
    if !alpns.is_empty() {
        crypto
            .set_alpn(alpns)
            .map_err(|e| anyhow!("quic alpn: {}", e))?;
    }
    Ok(crypto)
}

/// [`server_crypto`] from an inbound's `tls` block, its errors as the
/// inbound `tag`'s.
pub fn inbound_crypto(
    tag: &str,
    tls: &InboundTls,
    env: &RuntimeEnv,
    alpns: &[Vec<u8>],
) -> Result<quinn_btls::ServerConfig> {
    let certificate = tls.certificate(tag, env)?;
    let key = tls.key(tag, env)?;
    server_crypto(&certificate, &key, alpns).map_err(|e| anyhow!("[{}] inbound: tls: {}", tag, e))
}

/// The server configuration of `crypto`, with quinn's transport defaults.
pub fn server_config(crypto: quinn_btls::ServerConfig) -> Result<quinn::ServerConfig> {
    quinn_btls::helpers::server_config(Arc::new(crypto))
        .map_err(|e| anyhow!("quic server config: {}", e))
}

/// The congestion controllers quinn has, named as in sing-box.
#[derive(Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CongestionControl {
    /// sing-box's default.
    #[default]
    Cubic,
    NewReno,
    Bbr,
}

impl CongestionControl {
    pub fn factory(self) -> Arc<dyn ControllerFactory + Send + Sync> {
        match self {
            Self::Cubic => Arc::new(quinn::congestion::CubicConfig::default()),
            Self::NewReno => Arc::new(quinn::congestion::NewRenoConfig::default()),
            Self::Bbr => Arc::new(quinn::congestion::BbrConfig::default()),
        }
    }
}

/// Which end of connections a transport configuration is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Client,
    Server,
}

/// The transport parameters the `quic` options set for `side`: concurrent
/// bidirectional streams, the idle timeout and keep-alives, none if the
/// interval is zero. Congestion is controlled as `congestion` makes it:
/// [`CongestionControl::factory`], or a protocol's own.
pub fn transport_config(
    tuning: &Tuning,
    side: Side,
    congestion: Arc<dyn ControllerFactory + Send + Sync>,
) -> quinn::TransportConfig {
    let (idle, keep_alive) = match side {
        Side::Client => (
            tuning.client_idle_timeout,
            tuning.client_keep_alive_interval,
        ),
        Side::Server => (
            tuning.server_idle_timeout,
            tuning.server_keep_alive_interval,
        ),
    };
    let mut config = quinn::TransportConfig::default();
    config
        .max_concurrent_bidi_streams(quinn::VarInt::from_u32(tuning.max_concurrent_streams))
        .max_idle_timeout(quinn::IdleTimeout::try_from(idle).ok())
        .keep_alive_interval((!keep_alive.is_zero()).then_some(keep_alive))
        .congestion_controller_factory(congestion);
    config
}

/// A UDP socket for talking to `peer`, bound as `dial` says.
pub async fn bind(peer: IpAddr, dial: &DialOptions) -> io::Result<std::net::UdpSocket> {
    let unspecified = match peer {
        IpAddr::V4(_) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
        IpAddr::V6(_) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
    };
    crate::net::new_udp_socket(&unspecified, dial)
        .await?
        .into_std()
}

/// `socket` as quinn takes it, for wrapping further.
pub fn wrap_socket(socket: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
    socket.set_nonblocking(true)?;
    quinn::TokioRuntime.wrap_udp_socket(socket)
}

/// An endpoint on `socket`, serving with `server` if set.
pub fn endpoint(
    socket: std::net::UdpSocket,
    server: Option<quinn::ServerConfig>,
) -> io::Result<quinn::Endpoint> {
    endpoint_on(wrap_socket(socket)?, server)
}

/// [`endpoint`] on a socket of quinn's.
pub fn endpoint_on(
    socket: Arc<dyn AsyncUdpSocket>,
    server: Option<quinn::ServerConfig>,
) -> io::Result<quinn::Endpoint> {
    quinn::Endpoint::new_with_abstract_socket(
        quinn_btls::helpers::default_endpoint_config(),
        server,
        socket,
        Arc::new(quinn::TokioRuntime),
    )
}

/// A proxied TCP connection: one bidirectional QUIC stream, and `G`, kept
/// as long as the stream (TUIC counts its relays by it).
///
/// Reads and writes are quinn's own: the peer's FIN reads as the end of
/// the stream, a reset or a STOP_SENDING fails with `ConnectionReset`, a
/// lost connection with `NotConnected`. Shutting down finishes our side,
/// and so does dropping the stream.
pub struct QuicStream<G = ()> {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    _guard: G,
}

impl QuicStream {
    pub fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self::guarded(send, recv, ())
    }
}

impl<G> QuicStream<G> {
    pub fn guarded(send: quinn::SendStream, recv: quinn::RecvStream, guard: G) -> Self {
        Self {
            send,
            recv,
            _guard: guard,
        }
    }
}

impl<G: Unpin> AsyncRead for QuicStream<G> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl<G: Unpin> AsyncWrite for QuicStream<G> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // quinn's own `poll_write` fails with a `WriteError`.
        Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map_err(io::Error::from)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_defaults_when_unset_or_empty() {
        let h3 = vec![b"h3".to_vec()];
        assert_eq!(alpn_protocols(None, &["h3"]), h3);
        assert_eq!(alpn_protocols(Some(&Listable::Many(vec![])), &["h3"]), h3);
        assert!(alpn_protocols(None, &[]).is_empty());
        assert_eq!(
            alpn_protocols(Some(&Listable::One("doq".into())), &["h3"]),
            vec![b"doq".to_vec()]
        );
    }

    #[test]
    fn congestion_controls_are_named_as_in_sing_box() {
        let parse = |s: &str| serde_json::from_str::<CongestionControl>(&format!("\"{}\"", s));
        assert_eq!(parse("new_reno").unwrap(), CongestionControl::NewReno);
        assert_eq!(parse("bbr").unwrap(), CongestionControl::Bbr);
        assert_eq!(parse("cubic").unwrap(), CongestionControl::Cubic);
        assert!(parse("reno").is_err());
    }
}
