//! DNS over TLS (RFC 7858): each message is prefixed with its length, on a
//! TLS connection that is kept for the next query (RFC 7858 §3.4).

use std::net::SocketAddr;

use anyhow::{anyhow, Result};
use tokio::time::timeout;
use tracing::debug;

use super::{exchange_framed, kept_timed_out, kept_wait, StreamPool, Upstream};
use crate::adapter::AnyStream;
use crate::app::dns::DnsClient;

impl DnsClient {
    pub(super) async fn exchange_dot(
        &self,
        upstream: &Upstream,
        pool: &StreamPool,
        addr: SocketAddr,
        request: &[u8],
    ) -> Result<Vec<u8>> {
        let kept =
            kept_wait(self.reused_connection_timeout()).and_then(|wait| Some((wait, pool.take()?)));
        if let Some((wait, mut stream)) = kept {
            match timeout(wait, exchange_framed(&mut stream, request)).await {
                Ok(Ok(response)) => {
                    pool.put(stream);
                    return Ok(response);
                }
                Ok(Err(e)) => debug!("{}: kept connection failed: {}", upstream, e),
                Err(_) => {
                    debug!("{}: kept connection timed out", upstream);
                    if kept_timed_out() {
                        return Err(anyhow!("{}: kept connection timed out", upstream));
                    }
                }
            }
        }
        let stream = self.dial_stream(&upstream.dialer, addr).await?;
        let mut stream: AnyStream = Box::new(
            upstream
                .tls_client()?
                .connect(&upstream.server_name, stream, None, None)
                .await
                .map_err(|e| anyhow!("tls handshake failed: {}", e))?,
        );
        let response = exchange_framed(&mut stream, request).await?;
        pool.put(stream);
        Ok(response)
    }
}
