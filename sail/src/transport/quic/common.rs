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

use super::recv_backoff::RecvBackoff;
use crate::net::Dialer;
use crate::runtime::options::Quic as Tuning;
use crate::runtime::RuntimeEnv;
use crate::transport::layers::{trusted_certificate, InboundTls, Listable, OutboundTls};
use crate::transport::muxcore::stall::{Guarded, Stallable, STALL_TIMEOUT};
use crate::transport::tls::client::{load_certificates, load_private_key, Identity};

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
    roots: &crate::transport::tls::roots::Roots,
) -> Result<quinn_btls::ClientConfig> {
    use quinn_btls::QuicSslContext;
    let mut crypto =
        quinn_btls::ClientConfig::new().map_err(|e| anyhow!("quic client config: {}", e))?;
    if insecure {
        crypto.verify_peer(false);
    } else {
        let certs = match certificate {
            Some(certificate) => load_certificates(certificate)?,
            None => roots.certs().to_vec(),
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
    /// unless `alpn` is set, presenting the client certificate if set, and
    /// taking the server by the pinned keys if set. A version range without
    /// TLS 1.3 is an error: QUIC is TLS 1.3 only. Whatever `unsupported`
    /// finds is the caller's to refuse; this reads none of it.
    pub fn new(
        tls: &OutboundTls,
        server: &str,
        default_alpn: &[&str],
        env: &RuntimeEnv,
    ) -> Result<Self> {
        // quinn-btls sets the SNI of every name but an IP address.
        if tls.disable_sni {
            return Err(anyhow!("disable_sni: not over QUIC yet"));
        }
        let mut crypto = client_crypto(
            trusted_certificate(tls, env).as_deref(),
            tls.insecure,
            &alpn_protocols(tls.alpn.as_ref(), default_alpn),
            &env.tls_roots.get()?,
        )?;
        if let Some(identity) = tls.client_identity(env)? {
            present(&mut crypto, &identity)?;
        }
        tls.client_options()?.apply_quic(&mut crypto)?;
        Ok(Self {
            server_name: tls.server_name.clone().unwrap_or_else(|| server.to_owned()),
            crypto,
        })
    }
}

/// Presents `identity` to a server that asks for a certificate.
pub fn present(crypto: &mut quinn_btls::ClientConfig, identity: &Identity) -> Result<()> {
    use quinn_btls::QuicSslContext;
    let ctx = crypto.ctx_mut();
    let mut chain = identity.chain().iter();
    if let Some(cert) = chain.next() {
        ctx.set_certificate(cert.clone())?;
    }
    for cert in chain {
        ctx.add_to_cert_chain(cert.clone())?;
    }
    ctx.set_private_key(identity.key().clone())?;
    ctx.check_private_key()
        .map_err(|e| anyhow!("client_key: not the certificate's: {}", e))?;
    Ok(())
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
/// inbound `tag`'s. A version range without TLS 1.3 is an error: QUIC is
/// TLS 1.3 only. So is REALITY, which is TCP-only: sing-box takes it in the
/// configuration and refuses it at start ("unsupported usage for
/// reality", its REALITY server's STDConfig); here, at once.
pub fn inbound_crypto(
    tag: &str,
    tls: &InboundTls,
    env: &RuntimeEnv,
    alpns: &[Vec<u8>],
) -> Result<quinn_btls::ServerConfig> {
    if tls.reality.as_ref().is_some_and(|r| r.enabled) {
        return Err(anyhow!(
            "[{}] inbound: tls.reality: REALITY is TCP-only, not for QUIC",
            tag
        ));
    }
    // Only REALITY uses `server_name`; as over TCP, it is ignored aloud.
    if tls.server_name.is_some() {
        tracing::warn!(
            "[{}] inbound: tls.server_name: a server does not use it; ignored, as sing-box",
            tag
        );
    }
    tls.versions(tag)?
        .require_tls13("QUIC")
        .map_err(|e| anyhow!("[{}] inbound: tls.{}", tag, e))?;
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

/// The streams of each kind a Hysteria2 or TUIC client may open at once
/// before it authenticates: quinn's default, and what HTTP/3 servers
/// commonly allow, so that a client that has not authenticated cannot
/// hold more. More wait their turn rather than fail.
pub const STREAMS_BEFORE_AUTH: u32 = 100;

/// The most streams of one kind an authenticated client may hold open at
/// once on one connection.
pub const STREAMS_CEILING: u64 = 65536;

/// How many streams of one kind a client of a Hysteria2 or TUIC server may
/// hold open at once: `STREAMS_BEFORE_AUTH` until it authenticates, then
/// twice as many each time three quarters are open, up to
/// `STREAMS_CEILING`. sing-box's servers allow 1<<60 (sing-quic's
/// services), but quinn sets aside room for every stream it allows, so
/// the limit follows the streams actually open; it counts those open at
/// once, not how many a connection has had. A client past it waits for
/// one to close, as for any QUIC credit; `user_limits.max_connections`
/// bounds a user. Making quinn allocate as quic-go does, lazily, would
/// do without it.
pub struct StreamLimit {
    open: std::sync::atomic::AtomicU64,
    limit: std::sync::atomic::AtomicU64,
    grows: std::sync::atomic::AtomicBool,
    raise: Box<dyn Fn(u64) + Send + Sync>,
}

impl StreamLimit {
    /// A limit of `STREAMS_BEFORE_AUTH`, which `raise` raises to the value
    /// it is given.
    pub fn new(raise: impl Fn(u64) + Send + Sync + 'static) -> Arc<StreamLimit> {
        Arc::new(StreamLimit {
            open: Default::default(),
            limit: u64::from(STREAMS_BEFORE_AUTH).into(),
            grows: Default::default(),
            raise: Box::new(raise),
        })
    }

    /// The bidirectional streams of `conn`.
    pub fn bidi(conn: &quinn::Connection) -> Arc<StreamLimit> {
        let conn = conn.clone();
        Self::new(move |n| {
            conn.set_max_concurrent_bi_streams(quinn::VarInt::from_u32(
                u32::try_from(n).unwrap_or(u32::MAX),
            ))
        })
    }

    /// The unidirectional streams of `conn`.
    pub fn uni(conn: &quinn::Connection) -> Arc<StreamLimit> {
        let conn = conn.clone();
        Self::new(move |n| {
            conn.set_max_concurrent_uni_streams(quinn::VarInt::from_u32(
                u32::try_from(n).unwrap_or(u32::MAX),
            ))
        })
    }

    /// The client authenticated: the limit grows from now on.
    pub fn authenticated(&self) {
        self.grows.store(true, std::sync::atomic::Ordering::Relaxed);
        self.grow();
    }

    /// A stream the client opened, counted until the guard is dropped.
    pub fn opened(self: &Arc<Self>) -> StreamGuard {
        self.open.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.grow();
        StreamGuard(self.clone())
    }

    /// The limit now.
    pub fn limit(&self) -> u64 {
        self.limit.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn grow(&self) {
        use std::sync::atomic::Ordering::Relaxed;
        if !self.grows.load(Relaxed) {
            return;
        }
        let open = self.open.load(Relaxed);
        let mut limit = self.limit.load(Relaxed);
        while open * 4 >= limit * 3 && limit < STREAMS_CEILING {
            let next = (limit * 2).min(STREAMS_CEILING);
            match self.limit.compare_exchange(limit, next, Relaxed, Relaxed) {
                Ok(_) => {
                    (self.raise)(next);
                    limit = next;
                }
                Err(now) => limit = now,
            }
        }
    }
}

/// A stream counted as open until dropped.
pub struct StreamGuard(Arc<StreamLimit>);

/// `S`, counted as an open stream for as long as it lives.
pub struct Counted<S> {
    inner: S,
    _guard: StreamGuard,
}

impl<S> Counted<S> {
    pub fn new(inner: S, guard: StreamGuard) -> Self {
        Counted {
            inner,
            _guard: guard,
        }
    }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Counted<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Counted<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.0
            .open
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// A UDP socket for talking to `peer`, opened by `dialer`.
pub async fn bind(peer: IpAddr, dialer: &Dialer) -> io::Result<std::net::UdpSocket> {
    let unspecified = match peer {
        IpAddr::V4(_) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
        IpAddr::V6(_) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
    };
    dialer.udp_socket(&unspecified).await?.into_std()
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

/// [`endpoint`] on a socket of quinn's. Every endpoint is made here: its
/// socket waits out transient receive errors, which would otherwise end
/// the endpoint and every connection on it ([`RecvBackoff`]).
pub fn endpoint_on(
    socket: Arc<dyn AsyncUdpSocket>,
    server: Option<quinn::ServerConfig>,
) -> io::Result<quinn::Endpoint> {
    quinn::Endpoint::new_with_abstract_socket(
        quinn_btls::helpers::default_endpoint_config(),
        server,
        Arc::new(RecvBackoff::new(socket)),
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
///
/// A stream whose reader has not come back for data for the stall timeout
/// is reset both ways, alone (`muxcore::stall`): what it holds would
/// otherwise count against its connection's window for as long.
pub struct QuicStream<G = ()> {
    io: Guarded<Halves>,
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
            io: Guarded::new(Halves { send, recv }, "quic", STALL_TIMEOUT, "".into()),
            _guard: guard,
        }
    }
}

/// A QUIC stream's two halves.
struct Halves {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl Stallable for Halves {
    fn id(&mut self) -> u64 {
        self.send.id().index()
    }

    /// quinn does not say.
    fn buffered(&mut self) -> Option<usize> {
        None
    }

    /// STOP_SENDING and RESET_STREAM: what the stream holds is dropped,
    /// and its credit goes back to the connection.
    fn reset(&mut self) {
        let _ = self.recv.stop(0u32.into());
        let _ = self.send.reset(0u32.into());
    }
}

impl AsyncRead for Halves {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for Halves {
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

impl<G: Unpin> AsyncRead for QuicStream<G> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl<G: Unpin> AsyncWrite for QuicStream<G> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
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

    /// A server whose certificate has only the IP SAN 127.0.0.1, and a
    /// client trusting that certificate.
    fn ip_san_pair() -> (quinn::Endpoint, quinn_btls::ClientConfig) {
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let pem = cert.cert.pem();
        let server = server_crypto(&pem, &cert.key_pair.serialize_pem(), &[]).unwrap();
        let server = endpoint(
            std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
            Some(server_config(server).unwrap()),
        )
        .unwrap();
        (
            server,
            client_crypto(
                Some(&pem),
                false,
                &[],
                &crate::transport::tls::tests::test_roots(),
            )
            .unwrap(),
        )
    }

    /// Dials `server` as `server_name`: the SNI the server saw, if the
    /// handshake succeeds.
    async fn dial(
        server: &quinn::Endpoint,
        crypto: quinn_btls::ClientConfig,
        server_name: &str,
    ) -> Result<Option<String>> {
        let client = endpoint(
            std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
            None,
        )
        .unwrap();
        let config = quinn::ClientConfig::new(Arc::new(crypto));
        let accept = async {
            let conn = server.accept().await.unwrap().await?;
            let data = conn.handshake_data().unwrap();
            let data = data.downcast::<quinn_btls::HandshakeData>().unwrap();
            Ok::<_, quinn::ConnectionError>(data.server_name)
        };
        let connect = async {
            let connecting =
                client.connect_with(config, server.local_addr().unwrap(), server_name)?;
            Ok::<_, anyhow::Error>(connecting.await?)
        };
        let (sni, conn) = tokio::join!(accept, connect);
        conn?;
        Ok(sni?)
    }

    #[tokio::test]
    async fn client_certificate_when_the_server_asks() {
        use quinn_btls::QuicSslContext;
        let pki = crate::transport::tls::tests::client_pki();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let pem = cert.cert.pem();
        let mut server = server_crypto(&pem, &cert.key_pair.serialize_pem(), &[]).unwrap();
        let ctx = server.ctx_mut();
        ctx.cert_store_mut()
            .add_cert(btls::x509::X509::from_pem(pki.ca.as_bytes()).unwrap())
            .unwrap();
        ctx.verify_peer(true);
        let server = endpoint(
            std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
            Some(server_config(server).unwrap()),
        )
        .unwrap();
        let roots = crate::transport::tls::tests::test_roots();
        let tls: OutboundTls = serde_json::from_value(serde_json::json!({
            "enabled": true, "certificate": pem,
            "client_certificate": pki.cert, "client_key": pki.key
        }))
        .unwrap();
        let env = RuntimeEnv::default();
        let with = ClientTls::new(&tls, "localhost", &["h3"], &env).unwrap();
        assert_eq!(
            dial(&server, with.crypto, "localhost").await.unwrap(),
            Some("localhost".into())
        );
        let without = client_crypto(Some(&pem), false, &[b"h3".to_vec()], &roots).unwrap();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            dial(&server, without, "localhost"),
        )
        .await
        .expect("the handshake fails, not hangs");
        assert!(result.is_err(), "{:?}", result);
    }

    // The pins take a server as over TCP: by its key, in place of the
    // roots, the name and `insecure`.
    #[tokio::test]
    async fn pinned_keys_over_quic() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server = server_crypto(&cert.cert.pem(), &cert.key_pair.serialize_pem(), &[]).unwrap();
        let server = endpoint(
            std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
            Some(server_config(server).unwrap()),
        )
        .unwrap();
        let pin = crate::transport::tls::tests::spki_pin(&cert.key_pair.public_key_der());
        let other = btls::base64::encode_block(&[9; 32]);
        let env = RuntimeEnv::default();
        let crypto = |pins: &[&str], insecure: bool| {
            let tls: OutboundTls = serde_json::from_value(serde_json::json!({
                "enabled": true, "insecure": insecure,
                "certificate_public_key_sha256": pins,
            }))
            .unwrap();
            ClientTls::new(&tls, "example.com", &["h3"], &env)
                .unwrap()
                .crypto
        };
        for insecure in [false, true] {
            let sni = dial(&server, crypto(&[&other, &pin], insecure), "example.com").await;
            assert_eq!(sni.unwrap(), Some("example.com".into()));
            let refused = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                dial(&server, crypto(&[&other], insecure), "example.com"),
            )
            .await
            .expect("the handshake fails, not hangs");
            assert!(refused.is_err(), "insecure {}: {:?}", insecure, refused);
        }
    }

    // Pinned certificates take a server as over TCP: the leaf's for any
    // name, a CA's for the name the leaf is for; `insecure` or not.
    #[tokio::test]
    async fn pinned_certificates_over_quic() {
        let chain = crate::transport::tls::tests::cert_chain();
        let pem = format!("{}{}{}", chain.leaf, chain.intermediate, chain.root);
        let server = server_crypto(&pem, &chain.leaf_key, &[]).unwrap();
        let server = endpoint(
            std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
            Some(server_config(server).unwrap()),
        )
        .unwrap();
        let env = RuntimeEnv::default();
        let crypto = |pins: &[&str], insecure: bool, name: &str| {
            let tls: OutboundTls = serde_json::from_value(serde_json::json!({
                "enabled": true, "insecure": insecure, "certificate_sha256": pins,
            }))
            .unwrap();
            ClientTls::new(&tls, name, &["h3"], &env).unwrap().crypto
        };
        for insecure in [false, true] {
            for (pin, name, taken) in [
                (&chain.leaf_pin, "localhost", true),
                (&chain.leaf_pin, "example.com", true),
                (&chain.root_pin, "localhost", true),
                (&chain.root_pin, "example.com", false),
                (&chain.unrelated_pin, "localhost", false),
            ] {
                let result = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    dial(&server, crypto(&[pin.as_str()], insecure, name), name),
                )
                .await
                .expect("the handshake ends, not hangs");
                assert_eq!(
                    result.is_ok(),
                    taken,
                    "{} {} {}: {:?}",
                    pin,
                    name,
                    insecure,
                    result
                );
            }
        }
    }

    #[test]
    fn versions_over_quic() {
        let client = |json: serde_json::Value| {
            let tls: OutboundTls = serde_json::from_value(json).unwrap();
            ClientTls::new(&tls, "localhost", &[], &RuntimeEnv::default())
                .map(|_| ())
                .map_err(|e| e.to_string())
        };
        assert!(client(serde_json::json!({"enabled": true, "min_version": "1.3"})).is_ok());
        assert!(client(serde_json::json!({"enabled": true, "min_version": "1.0"})).is_ok());
        assert_eq!(
            client(serde_json::json!({"enabled": true, "max_version": "1.2"})),
            Err("max_version: QUIC is TLS 1.3 only, and 1.2 leaves it out".into())
        );
        let tls: InboundTls = serde_json::from_value(serde_json::json!({
            "enabled": true, "max_version": "1.2", "certificate": "x", "key": "y",
        }))
        .unwrap();
        let err = inbound_crypto("i", &tls, &RuntimeEnv::default(), &[])
            .err()
            .unwrap();
        assert_eq!(
            err.to_string(),
            "[i] inbound: tls.max_version: QUIC is TLS 1.3 only, and 1.2 leaves it out"
        );
    }

    /// REALITY on a QUIC inbound is an error, which sing-box only finds at
    /// start.
    #[test]
    fn no_reality_over_quic() {
        let tls: InboundTls = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "reality": {
                "enabled": true,
                "private_key": "x",
                "short_id": ["0123"],
                "handshake": { "server": "example.com", "server_port": 443 },
            },
        }))
        .unwrap();
        let err = inbound_crypto("i", &tls, &RuntimeEnv::default(), &[])
            .err()
            .unwrap();
        assert_eq!(
            err.to_string(),
            "[i] inbound: tls.reality: REALITY is TCP-only, not for QUIC"
        );
    }

    /// The limit grows with the streams open at once after authentication,
    /// not before, and not with how many have come and gone.
    #[test]
    fn the_limit_follows_the_streams_open_at_once() {
        use std::sync::Mutex;
        let raised = Arc::new(Mutex::new(Vec::new()));
        let limit = {
            let raised = raised.clone();
            StreamLimit::new(move |n| raised.lock().unwrap().push(n))
        };
        // Before authentication, however many are open.
        let held: Vec<_> = (0..STREAMS_BEFORE_AUTH).map(|_| limit.opened()).collect();
        assert_eq!(limit.limit(), u64::from(STREAMS_BEFORE_AUTH));
        drop(held);
        limit.authenticated();
        // One at a time, far more than any limit: it stays.
        for _ in 0..10_000 {
            drop(limit.opened());
        }
        assert_eq!(limit.limit(), u64::from(STREAMS_BEFORE_AUTH));
        assert!(raised.lock().unwrap().is_empty());
        // Many at once: it doubles as three quarters are open, to the
        // ceiling and no further.
        let held: Vec<_> = (0..100_000).map(|_| limit.opened()).collect();
        assert_eq!(limit.limit(), STREAMS_CEILING);
        assert_eq!(
            *raised.lock().unwrap(),
            [200, 400, 800, 1600, 3200, 6400, 12800, 25600, 51200, 65536]
        );
        drop(held);
    }

    /// Not a test: what one server connection costs with
    /// `SAIL_MEASURE_STREAMS` streams of each kind allowed (100 unset),
    /// 200 connections from clients that allow none, in RSS.
    /// `cargo test -p sail --lib measure_connection_memory -- --ignored --nocapture`
    #[tokio::test]
    #[ignore]
    async fn measure_connection_memory() {
        const CONNECTIONS: u64 = 200;
        let rss_kb = || {
            let out = std::process::Command::new("ps")
                .args(["-o", "rss=", "-p", &std::process::id().to_string()])
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout)
                .trim()
                .parse::<u64>()
                .unwrap()
        };
        let streams: u32 = std::env::var("SAIL_MEASURE_STREAMS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100);
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut server_config = server_config(
            server_crypto(&cert.cert.pem(), &cert.key_pair.serialize_pem(), &[]).unwrap(),
        )
        .unwrap();
        let mut transport = quinn::TransportConfig::default();
        transport
            .max_concurrent_bidi_streams(streams.into())
            .max_concurrent_uni_streams(streams.into());
        server_config.transport_config(Arc::new(transport));
        let server = endpoint(
            std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
            Some(server_config),
        )
        .unwrap();
        let client = endpoint(
            std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
            None,
        )
        .unwrap();
        let roots = crate::transport::tls::tests::test_roots();
        let mut client_config =
            quinn::ClientConfig::new(Arc::new(client_crypto(None, true, &[], &roots).unwrap()));
        let mut none = quinn::TransportConfig::default();
        none.max_concurrent_bidi_streams(0u32.into())
            .max_concurrent_uni_streams(0u32.into());
        client_config.transport_config(Arc::new(none));
        let before = rss_kb();
        let mut held = Vec::new();
        for _ in 0..CONNECTIONS {
            let connecting = client
                .connect_with(
                    client_config.clone(),
                    server.local_addr().unwrap(),
                    "localhost",
                )
                .unwrap();
            let (accepted, connected) = tokio::join!(
                async { server.accept().await.unwrap().await.unwrap() },
                connecting
            );
            held.push((accepted, connected.unwrap()));
        }
        let after = rss_kb();
        println!(
            "MEASURE streams={} rss_before={}KB rss_after={}KB per_connection={}KB",
            streams,
            before,
            after,
            (after.saturating_sub(before)) / CONNECTIONS
        );
    }

    #[test]
    fn no_disable_sni_over_quic_yet() {
        let tls: OutboundTls =
            serde_json::from_value(serde_json::json!({"enabled": true, "disable_sni": true}))
                .unwrap();
        let err = ClientTls::new(&tls, "localhost", &[], &RuntimeEnv::default())
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "disable_sni: not over QUIC yet");
    }

    #[tokio::test]
    async fn ip_server_name_sends_no_sni_and_verifies_ip_san() {
        let (server, crypto) = ip_san_pair();
        // RFC 6066 forbids IP literals in SNI.
        assert_eq!(dial(&server, crypto, "127.0.0.1").await.unwrap(), None);
    }

    #[tokio::test]
    async fn ip_server_name_not_in_certificate_fails() {
        let (server, crypto) = ip_san_pair();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            dial(&server, crypto, "127.0.0.2"),
        )
        .await
        .expect("the handshake fails, not hangs");
        assert!(result.is_err(), "{:?}", result);
    }
}
