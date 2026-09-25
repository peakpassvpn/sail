//! The QUIC glue both ends share: TLS configurations from the `tls` field,
//! the transport parameters Hysteria2 runs with, the socket stack under
//! quinn and a proxied stream.
//!
//! Much of it is what `transport::quic` does for the quic transport, kept
//! here so that the two can change apart until they are merged.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{anyhow, Result};
use quinn::{AsyncUdpSocket, Runtime};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::congestion::CongestionHandle;
use super::salamander::{Salamander, SalamanderSocket};
use crate::transport::layers::Listable;

/// The ALPN Hysteria2 speaks unless configured otherwise: it is HTTP/3.
pub const DEFAULT_ALPN: &str = "h3";

/// Flow control windows, the reference implementation's defaults.
const STREAM_RECEIVE_WINDOW: u32 = 8 * 1024 * 1024;
const CONNECTION_RECEIVE_WINDOW: u32 = 20 * 1024 * 1024;
/// Unidirectional streams a peer may open: HTTP/3 needs three at most.
const MAX_UNI_STREAMS: u32 = 16;

/// The ALPNs to offer or accept: those configured, or h3.
pub fn alpns(alpn: Option<Listable>) -> Vec<Vec<u8>> {
    match alpn.map(Listable::into_vec) {
        Some(list) if !list.is_empty() => list.into_iter().map(String::into_bytes).collect(),
        _ => vec![DEFAULT_ALPN.as_bytes().to_vec()],
    }
}

/// A client TLS configuration trusting `certificate` (inline PEM or a
/// path), or the bundled roots, or anything if `insecure`.
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
            Some(certificate) => crate::transport::tls::client::load_certificates(certificate)?,
            None => crate::transport::tls::client::bundled_root_certs()?.to_vec(),
        };
        let store = crypto.ctx_mut().cert_store_mut();
        for cert in certs {
            store.add_cert(cert)?;
        }
    }
    crypto
        .set_alpn(alpns)
        .map_err(|e| anyhow!("quic alpn: {}", e))?;
    Ok(crypto)
}

/// A server configuration presenting `certificate` with `key`, each inline
/// PEM or a path.
pub fn server_config(
    certificate: &str,
    key: &str,
    alpns: &[Vec<u8>],
) -> Result<quinn::ServerConfig> {
    use crate::transport::tls::client::{load_certificates, load_private_key};
    use quinn_btls::QuicSslContext;
    let mut certs = load_certificates(certificate)?.into_iter();
    let key = load_private_key(key)?;

    let mut crypto =
        quinn_btls::ServerConfig::new().map_err(|e| anyhow!("quic server config: {}", e))?;
    let ctx = crypto.ctx_mut();
    let first = certs
        .next()
        .ok_or_else(|| anyhow!("no certificate found"))?;
    ctx.set_certificate(first)?;
    for cert in certs {
        ctx.add_to_cert_chain(cert)?;
    }
    ctx.set_private_key(key)?;
    ctx.check_private_key()
        .map_err(|e| anyhow!("private key does not match the certificate: {}", e))?;
    crypto
        .set_alpn(alpns)
        .map_err(|e| anyhow!("quic alpn: {}", e))?;
    quinn_btls::helpers::server_config(Arc::new(crypto))
        .map_err(|e| anyhow!("quic server config: {}", e))
}

/// The transport parameters of one connection, its congestion controller
/// selected by `congestion`.
pub fn transport_config(
    tuning: &crate::runtime::options::Quic,
    server: bool,
    congestion: &CongestionHandle,
) -> quinn::TransportConfig {
    let mut config = quinn::TransportConfig::default();
    let (idle, keep_alive) = if server {
        (
            tuning.server_idle_timeout,
            tuning.server_keep_alive_interval,
        )
    } else {
        (
            tuning.client_idle_timeout,
            tuning.client_keep_alive_interval,
        )
    };
    config
        .max_concurrent_bidi_streams(quinn::VarInt::from_u32(tuning.max_concurrent_streams))
        .max_concurrent_uni_streams(quinn::VarInt::from_u32(MAX_UNI_STREAMS))
        .stream_receive_window(quinn::VarInt::from_u32(STREAM_RECEIVE_WINDOW))
        .receive_window(quinn::VarInt::from_u32(CONNECTION_RECEIVE_WINDOW))
        .send_window(CONNECTION_RECEIVE_WINDOW as u64)
        .max_idle_timeout(quinn::IdleTimeout::try_from(idle).ok())
        .keep_alive_interval((!keep_alive.is_zero()).then_some(keep_alive))
        .congestion_controller_factory(congestion.factory());
    config
}

/// `socket` under quinn, obfuscated if `obfs` is set.
pub fn wrap_socket(
    socket: std::net::UdpSocket,
    obfs: Option<&Salamander>,
) -> io::Result<Arc<dyn AsyncUdpSocket>> {
    socket.set_nonblocking(true)?;
    let socket = quinn::TokioRuntime.wrap_udp_socket(socket)?;
    Ok(match obfs {
        Some(obfs) => Arc::new(SalamanderSocket::new(socket, obfs.clone())),
        None => socket,
    })
}

/// A proxied TCP stream: one bidirectional QUIC stream.
pub struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl QuicStream {
    pub fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self { send, recv }
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
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

/// Opens our HTTP/3 control stream. It must stay open as long as the
/// connection: a peer closes the connection when it ends.
pub async fn open_control_stream(conn: &quinn::Connection) -> io::Result<quinn::SendStream> {
    let mut send = conn.open_uni().await.map_err(io::Error::other)?;
    send.write_all(&super::h3::control_stream_preface())
        .await
        .map_err(io::Error::other)?;
    Ok(send)
}

/// Accepts the peer's unidirectional streams, its HTTP/3 control stream
/// among them, and reads them to nothing, holding them open, until the
/// connection closes.
pub async fn drain_uni_streams(conn: quinn::Connection) {
    while let Ok(mut recv) = conn.accept_uni().await {
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            while let Ok(Some(_)) = recv.read(&mut buf).await {}
        });
    }
}
