//! DNS over TLS (RFC 7858): each message is prefixed with its length, on a
//! TLS connection that is kept for the next query (RFC 7858 §3.4).

use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tracing::debug;

use super::Upstream;
use crate::adapter::AnyStream;
use crate::app::dns::DnsClient;

/// Idle connections kept per upstream: as many as queries that ran at once,
/// up to this.
const MAX_IDLE: usize = 4;
/// How long a connection is kept idle. Servers close theirs after some
/// seconds (RFC 7766 §6.2.3 suggests 10), and a connection they closed
/// costs a failed query before a new one.
const IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// The idle connections of one upstream.
#[derive(Default)]
pub(super) struct Pool {
    idle: Mutex<Vec<(AnyStream, Instant)>>,
}

impl Pool {
    /// The connection idle for the least time, if one is still fresh.
    fn take(&self) -> Option<AnyStream> {
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        idle.retain(|(_, since)| now.saturating_duration_since(*since) < IDLE_TIMEOUT);
        idle.pop().map(|(stream, _)| stream)
    }

    fn put(&self, stream: AnyStream) {
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        if idle.len() >= MAX_IDLE {
            idle.remove(0);
        }
        idle.push((stream, Instant::now()));
    }
}

impl DnsClient {
    pub(super) async fn exchange_dot(
        &self,
        upstream: &Upstream,
        pool: &Pool,
        addr: SocketAddr,
        is_direct: bool,
        request: &[u8],
    ) -> Result<Vec<u8>> {
        if let Some(mut stream) = pool.take() {
            match timeout(
                self.reused_connection_timeout(),
                exchange(&mut stream, request),
            )
            .await
            {
                Ok(Ok(response)) => {
                    pool.put(stream);
                    return Ok(response);
                }
                Ok(Err(e)) => debug!("{}: kept connection failed: {}", upstream, e),
                Err(_) => debug!("{}: kept connection timed out", upstream),
            }
        }
        let stream = self.dial_stream(is_direct, addr).await?;
        let tls = self.upstream_tls_client()?;
        let mut stream: AnyStream = Box::new(
            tls.connect(&upstream.host, stream, None, None)
                .await
                .map_err(|e| anyhow!("tls handshake failed: {}", e))?,
        );
        let response = exchange(&mut stream, request).await?;
        pool.put(stream);
        Ok(response)
    }
}

/// Writes `request` and reads the answer that follows, each prefixed with
/// its length.
async fn exchange(stream: &mut AnyStream, request: &[u8]) -> Result<Vec<u8>> {
    let len = u16::try_from(request.len()).map_err(|_| anyhow!("dns query too long"))?;
    let mut buf = Vec::with_capacity(2 + request.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(request);
    stream.write_all(&buf).await?;
    stream.flush().await?;
    let len = stream.read_u16().await? as usize;
    let mut response = vec![0u8; len];
    stream.read_exact(&mut response).await?;
    Ok(response)
}
