//! DNS over QUIC (RFC 9250) and over HTTP/3: one QUIC connection per
//! upstream, kept while it lives, and a stream per query.

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::sync::Mutex as TokioMutex;
use tokio::time::timeout;
use tracing::debug;

use super::{Upstream, MAX_MESSAGE_LEN};
use crate::app::dns::DnsClient;
use crate::transport::quic::{bind, client_crypto, endpoint, endpoint_on};

/// How long a connection without queries is kept. Neither side sends
/// keep-alives: a connection that went idle is dropped, and the next query
/// makes a new one.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    /// DNS over QUIC.
    Doq,
    /// DNS over HTTP/3.
    #[cfg(feature = "dns-h3")]
    H3,
}

impl Kind {
    fn alpn(self) -> &'static [u8] {
        match self {
            Self::Doq => b"doq",
            #[cfg(feature = "dns-h3")]
            Self::H3 => b"h3",
        }
    }
}

/// The connection of one upstream.
pub(super) struct Pool {
    kind: Kind,
    /// Built on first use, with the certificates the client trusts.
    client_config: OnceLock<std::result::Result<quinn::ClientConfig, String>>,
    /// Locked while a connection is made, so that queries at once make one.
    live: TokioMutex<Option<Live>>,
}

/// A QUIC connection, with what runs on it.
struct Live {
    /// Kept with its connection: the endpoint owns the socket.
    _endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    #[cfg(feature = "dns-h3")]
    h3: Option<H3>,
}

#[cfg(feature = "dns-h3")]
struct H3 {
    send_request: h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    /// Drives the HTTP/3 connection; stopped with it.
    driver: tokio::task::AbortHandle,
}

#[cfg(feature = "dns-h3")]
impl Drop for H3 {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

impl Live {
    fn is_alive(&self) -> bool {
        self.conn.close_reason().is_none()
    }
}

impl Pool {
    pub fn new(kind: Kind) -> Self {
        Self {
            kind,
            client_config: OnceLock::new(),
            live: TokioMutex::new(None),
        }
    }

    fn client_config(&self, certificate: Option<&str>) -> Result<quinn::ClientConfig> {
        self.client_config
            .get_or_init(|| build_client_config(self.kind, certificate).map_err(|e| e.to_string()))
            .clone()
            .map_err(|e| anyhow!("quic client config: {}", e))
    }
}

fn build_client_config(kind: Kind, certificate: Option<&str>) -> Result<quinn::ClientConfig> {
    // As for TLS: the bundled roots, or `certificate` instead, and the
    // server verified.
    let crypto = client_crypto(certificate, false, &[kind.alpn().to_vec()])?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(quinn::IdleTimeout::try_from(IDLE_TIMEOUT).ok());
    transport.keep_alive_interval(None);
    client_config.transport_config(Arc::new(transport));
    Ok(client_config)
}

impl DnsClient {
    pub(super) async fn exchange_quic(
        &self,
        upstream: &Upstream,
        pool: &Pool,
        addr: SocketAddr,
        is_direct: bool,
        request: &[u8],
    ) -> Result<Vec<u8>> {
        // DoQ requires ID 0 (RFC 9250 §4.2.1), and DoH asks for it so that
        // answers can be cached (RFC 8484 §4.1). The caller checks the ID
        // of the answer against the query's, so it is given back here.
        let id = [request[0], request[1]];
        let mut request = request.to_vec();
        request[..2].copy_from_slice(&[0, 0]);

        let mut response = None;
        // Once on the kept connection, which may be dead without being
        // known to be, then once on a new one.
        for fresh in [false, true] {
            let live = self
                .quic_connection(upstream, pool, addr, is_direct, fresh)
                .await?;
            let res = match pool.kind {
                Kind::Doq => exchange_doq(&live.conn, &request).await,
                #[cfg(feature = "dns-h3")]
                Kind::H3 => match &live.h3 {
                    Some(h3) => exchange_h3(upstream, h3, &request).await,
                    None => Err(anyhow!("no http/3 connection")),
                },
            };
            match res {
                Ok(r) => {
                    response = Some(r);
                    break;
                }
                Err(e) if !fresh && live.reused => {
                    debug!("{}: kept connection failed: {}", upstream, e);
                    pool.invalidate(&live.conn).await;
                }
                Err(e) => {
                    pool.invalidate(&live.conn).await;
                    return Err(e);
                }
            }
        }
        let mut response = response.ok_or_else(|| anyhow!("no answer"))?;
        if response.len() < 2 || response[..2] != [0, 0] {
            return Err(anyhow!("dns response with a non-zero id"));
        }
        response[..2].copy_from_slice(&id);
        Ok(response)
    }

    /// The upstream's connection, made now if there is none alive or if
    /// `fresh`.
    async fn quic_connection(
        &self,
        upstream: &Upstream,
        pool: &Pool,
        addr: SocketAddr,
        is_direct: bool,
        fresh: bool,
    ) -> Result<Handle> {
        let mut live = pool.live.lock().await;
        if let Some(l) = live.as_ref() {
            if l.is_alive() && !fresh {
                return Ok(Handle::of(l, true));
            }
        }
        *live = None;
        let l = self.connect_quic(upstream, pool, addr, is_direct).await?;
        let handle = Handle::of(&l, false);
        *live = Some(l);
        Ok(handle)
    }

    async fn connect_quic(
        &self,
        upstream: &Upstream,
        pool: &Pool,
        addr: SocketAddr,
        is_direct: bool,
    ) -> Result<Live> {
        let client_config = pool.client_config(self.upstream_certificate.as_deref())?;
        let mut endpoint = if is_direct {
            endpoint(bind(addr.ip(), &self.dial).await?, None)?
        } else {
            // QUIC over the datagrams of the outbound the router picks.
            let datagram = self.dial_datagram(addr).await?;
            endpoint_on(
                Arc::new(super::socket::DatagramSocket::new(datagram, addr)),
                None,
            )?
        };
        endpoint.set_default_client_config(client_config);
        let connecting = endpoint
            .connect(addr, &upstream.host)
            .map_err(|e| anyhow!("connect quic failed: {}", e))?;
        let conn = timeout(self.dial.connect_timeout, connecting)
            .await
            .map_err(|_| anyhow!("quic handshake timed out"))?
            .map_err(|e| anyhow!("quic handshake failed: {}", e))?;
        debug!("{}: connected over quic to {}", upstream, addr);
        #[cfg(feature = "dns-h3")]
        let h3 = match pool.kind {
            Kind::H3 => Some(connect_h3(conn.clone()).await?),
            Kind::Doq => None,
        };
        Ok(Live {
            _endpoint: endpoint,
            conn,
            #[cfg(feature = "dns-h3")]
            h3,
        })
    }
}

impl Pool {
    /// Drops the kept connection if it is still `conn`.
    async fn invalidate(&self, conn: &quinn::Connection) {
        let mut live = self.live.lock().await;
        if live
            .as_ref()
            .is_some_and(|l| l.conn.stable_id() == conn.stable_id())
        {
            if let Some(l) = live.take() {
                l.conn.close(0u32.into(), b"");
            }
        }
    }
}

/// What a query needs of the kept connection, taken without holding the
/// pool's lock.
struct Handle {
    conn: quinn::Connection,
    #[cfg(feature = "dns-h3")]
    h3: Option<H3Handle>,
    /// Whether the connection was made for an earlier query.
    reused: bool,
}

#[cfg(feature = "dns-h3")]
struct H3Handle {
    send_request: h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
}

impl Handle {
    fn of(live: &Live, reused: bool) -> Self {
        Self {
            conn: live.conn.clone(),
            #[cfg(feature = "dns-h3")]
            h3: live.h3.as_ref().map(|h3| H3Handle {
                send_request: h3.send_request.clone(),
            }),
            reused,
        }
    }
}

/// A query on its own stream, each message prefixed with its length
/// (RFC 9250 §4.2).
async fn exchange_doq(conn: &quinn::Connection, request: &[u8]) -> Result<Vec<u8>> {
    let len = u16::try_from(request.len()).map_err(|_| anyhow!("dns query too long"))?;
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| anyhow!("open quic stream failed: {}", e))?;
    let mut buf = Vec::with_capacity(2 + request.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(request);
    send.write_all(&buf)
        .await
        .map_err(|e| anyhow!("write doq query failed: {}", e))?;
    // The query ends the client's side of the stream (RFC 9250 §4.2).
    send.finish()
        .map_err(|e| anyhow!("finish doq query failed: {}", e))?;
    let data = recv
        .read_to_end(2 + MAX_MESSAGE_LEN)
        .await
        .map_err(|e| anyhow!("read doq answer failed: {}", e))?;
    let (len, response) = match data.split_first_chunk::<2>() {
        Some((len, response)) => (u16::from_be_bytes(*len) as usize, response),
        None => return Err(anyhow!("doq answer too short")),
    };
    if response.len() != len {
        return Err(anyhow!(
            "doq answer of {} bytes, {} announced",
            response.len(),
            len
        ));
    }
    Ok(response.to_vec())
}

#[cfg(feature = "dns-h3")]
async fn connect_h3(conn: quinn::Connection) -> Result<H3> {
    let (mut driver, send_request) = h3::client::new(h3_quinn::Connection::new(conn))
        .await
        .map_err(|e| anyhow!("http/3 connection failed: {}", e))?;
    let driver = tokio::spawn(async move {
        let e = futures::future::poll_fn(|cx| driver.poll_close(cx)).await;
        debug!("http/3 connection closed: {}", e);
    })
    .abort_handle();
    Ok(H3 {
        send_request,
        driver,
    })
}

/// A POST of the query to the upstream's path (RFC 8484 §4.1).
#[cfg(feature = "dns-h3")]
async fn exchange_h3(upstream: &Upstream, h3: &H3Handle, request: &[u8]) -> Result<Vec<u8>> {
    use bytes::Buf;
    use http::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE};

    const DNS_MESSAGE: &str = "application/dns-message";
    let authority = match upstream.host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(ip)) => format!("[{}]", ip),
        _ => upstream.host.clone(),
    };
    let uri = if upstream.port == 443 {
        format!("https://{}{}", authority, upstream.path)
    } else {
        format!("https://{}:{}{}", authority, upstream.port, upstream.path)
    };
    let req = http::Request::post(uri)
        .header(CONTENT_TYPE, DNS_MESSAGE)
        .header(ACCEPT, DNS_MESSAGE)
        .header(CONTENT_LENGTH, request.len())
        .body(())
        .map_err(|e| anyhow!("invalid http/3 request: {}", e))?;
    let mut send_request = h3.send_request.clone();
    let mut stream = send_request
        .send_request(req)
        .await
        .map_err(|e| anyhow!("send http/3 request failed: {}", e))?;
    stream
        .send_data(bytes::Bytes::copy_from_slice(request))
        .await
        .map_err(|e| anyhow!("send http/3 body failed: {}", e))?;
    stream
        .finish()
        .await
        .map_err(|e| anyhow!("finish http/3 request failed: {}", e))?;
    let resp = stream
        .recv_response()
        .await
        .map_err(|e| anyhow!("read http/3 response failed: {}", e))?;
    if resp.status() != http::StatusCode::OK {
        return Err(anyhow!(
            "doh3 server returned http status {}",
            resp.status().as_u16()
        ));
    }
    let mut body = Vec::new();
    while let Some(mut chunk) = stream
        .recv_data()
        .await
        .map_err(|e| anyhow!("read http/3 body failed: {}", e))?
    {
        if body.len() + chunk.remaining() > MAX_MESSAGE_LEN {
            return Err(anyhow!("doh3 answer too long"));
        }
        while chunk.has_remaining() {
            let part = chunk.chunk();
            body.extend_from_slice(part);
            let n = part.len();
            chunk.advance(n);
        }
    }
    Ok(body)
}
