//! DNS over HTTPS (RFC 8484) over TLS on TCP. The ClientHello is Chrome's,
//! offering h2 and http/1.1 as Chrome does: on HTTP/2, the connection is
//! kept and each query is a stream on it; on HTTP/1.1, the connection is
//! kept alive and taken again by the next query, as DoT's are.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex as TokioMutex;
use tokio::time::timeout;
use tracing::debug;

use super::{Upstream, MAX_MESSAGE_LEN};
use crate::adapter::AnyStream;
use crate::app::dns::DnsClient;

const DNS_MESSAGE: &str = "application/dns-message";
/// The most an HTTP/1.1 response head, or a chunk-size line, may take.
const MAX_HEAD_LEN: usize = 16 * 1024;
/// How long a queryless HTTP/2 connection is kept: dropped past that,
/// rather than found dead by the next query.
const H2_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// The connections of one upstream.
#[derive(Default)]
pub(super) struct Pool {
    /// Locked while a connection is made, so that queries at once make one
    /// when the server speaks HTTP/2.
    h2: TokioMutex<Option<H2>>,
    /// Idle HTTP/1.1 connections, for a server that does not speak HTTP/2.
    http1: super::StreamPool,
}

/// An HTTP/2 connection.
struct H2 {
    send_request: h2::client::SendRequest<Bytes>,
    /// Drives the connection; stopped with it.
    driver: tokio::task::AbortHandle,
    /// When a query last took it.
    used: Instant,
}

impl Drop for H2 {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

impl H2 {
    fn is_alive(&self) -> bool {
        !self.driver.is_finished() && self.used.elapsed() < H2_IDLE_TIMEOUT
    }

    /// The connection, for one more query.
    fn take(&mut self) -> h2::client::SendRequest<Bytes> {
        self.used = Instant::now();
        self.send_request.clone()
    }
}

impl Pool {
    /// The kept HTTP/2 connection, if it is alive.
    async fn kept_h2(&self) -> Option<h2::client::SendRequest<Bytes>> {
        let mut h2 = self.h2.lock().await;
        match h2.as_mut() {
            Some(l) if l.is_alive() => Some(l.take()),
            _ => {
                *h2 = None;
                None
            }
        }
    }

    async fn drop_h2(&self) {
        *self.h2.lock().await = None;
    }
}

/// A new connection, as the server's ALPN made it.
enum Connection {
    H2(H2),
    Http1(AnyStream),
}

impl DnsClient {
    pub(super) async fn exchange_doh(
        &self,
        upstream: &Upstream,
        pool: &Pool,
        addr: SocketAddr,
        request: &[u8],
    ) -> Result<Vec<u8>> {
        // RFC 8484 §4.1 asks for ID 0, so that answers can be cached. The
        // caller checks the ID of the answer against the query's, so it is
        // given back here.
        let id = [request[0], request[1]];
        let mut zeroed = request.to_vec();
        zeroed[..2].copy_from_slice(&[0, 0]);
        let mut response = self
            .exchange_doh_zero_id(upstream, pool, addr, Bytes::from(zeroed))
            .await?;
        if response.len() < 2 || response[..2] != [0, 0] {
            return Err(anyhow!("dns response with a non-zero id"));
        }
        response[..2].copy_from_slice(&id);
        Ok(response)
    }

    async fn exchange_doh_zero_id(
        &self,
        upstream: &Upstream,
        pool: &Pool,
        addr: SocketAddr,
        request: Bytes,
    ) -> Result<Vec<u8>> {
        // On a kept connection first, which may have died without a word:
        // for half the query's time, the rest left for a new connection.
        if let Some(send_request) = pool.kept_h2().await {
            match timeout(
                self.reused_connection_timeout(),
                exchange_h2(upstream, send_request, request.clone()),
            )
            .await
            {
                Ok(Ok(response)) => return Ok(response),
                // An answer that is not one is the server's, not the
                // connection's: another connection would not change it.
                Ok(Err(Failure::Answer(e))) => return Err(e),
                Ok(Err(Failure::Connection(e))) => {
                    debug!("{}: kept connection failed: {}", upstream, e)
                }
                Err(_) => debug!("{}: kept connection timed out", upstream),
            }
            pool.drop_h2().await;
        }
        if let Some(mut stream) = pool.http1.take() {
            match timeout(
                self.reused_connection_timeout(),
                exchange_http1(upstream, &mut stream, &request),
            )
            .await
            {
                Ok(Ok((response, keep_alive))) => {
                    if keep_alive {
                        pool.http1.put(stream);
                    }
                    return Ok(response);
                }
                Ok(Err(Failure::Answer(e))) => return Err(e),
                Ok(Err(Failure::Connection(e))) => {
                    debug!("{}: kept connection failed: {}", upstream, e)
                }
                Err(_) => debug!("{}: kept connection timed out", upstream),
            }
        }

        let mut h2 = pool.h2.lock().await;
        // Another query may have connected while this one waited.
        if let Some(l) = h2.as_mut().filter(|l| l.is_alive()) {
            let send_request = l.take();
            drop(h2);
            return exchange_h2(upstream, send_request, request)
                .await
                .map_err(Failure::into_inner);
        }
        match self.connect_doh(upstream, addr).await? {
            Connection::H2(mut l) => {
                let send_request = l.take();
                *h2 = Some(l);
                drop(h2);
                let res = exchange_h2(upstream, send_request, request).await;
                if let Err(Failure::Connection(_)) = res {
                    pool.drop_h2().await;
                }
                res.map_err(Failure::into_inner)
            }
            Connection::Http1(mut stream) => {
                drop(h2);
                let (response, keep_alive) = exchange_http1(upstream, &mut stream, &request)
                    .await
                    .map_err(Failure::into_inner)?;
                if keep_alive {
                    pool.http1.put(stream);
                }
                Ok(response)
            }
        }
    }

    async fn connect_doh(&self, upstream: &Upstream, addr: SocketAddr) -> Result<Connection> {
        let stream = self.dial_stream(&upstream.dialer, addr).await?;
        let tls = upstream
            .tls_client()?
            .connect(&upstream.server_name, stream, None, None)
            .await
            .map_err(|e| anyhow!("tls handshake failed: {}", e))?;
        let is_h2 = tls.conn().ssl().selected_alpn_protocol() == Some(b"h2");
        let stream: AnyStream = Box::new(tls);
        if !is_h2 {
            debug!("{}: connected over http/1.1 to {}", upstream, addr);
            return Ok(Connection::Http1(stream));
        }
        let (send_request, conn) = h2::client::Builder::new()
            .enable_push(false)
            .handshake::<_, Bytes>(stream)
            .await
            .map_err(|e| anyhow!("http/2 handshake failed: {}", e))?;
        let driver = tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!("doh http/2 connection closed: {}", e);
            }
        })
        .abort_handle();
        debug!("{}: connected over http/2 to {}", upstream, addr);
        Ok(Connection::H2(H2 {
            send_request,
            driver,
            used: Instant::now(),
        }))
    }
}

/// Why an exchange failed: the connection, which a new one may fix, or an
/// answer that is not one, which it would not.
enum Failure {
    Connection(anyhow::Error),
    Answer(anyhow::Error),
}

impl Failure {
    fn into_inner(self) -> anyhow::Error {
        match self {
            Self::Connection(e) | Self::Answer(e) => e,
        }
    }
}

fn conn_err(e: impl std::fmt::Display, what: &str) -> Failure {
    Failure::Connection(anyhow!("{}: {}", what, e))
}

/// A POST of the query as a stream of the HTTP/2 connection.
async fn exchange_h2(
    upstream: &Upstream,
    send_request: h2::client::SendRequest<Bytes>,
    request: Bytes,
) -> std::result::Result<Vec<u8>, Failure> {
    use http::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE};

    let req = http::Request::post(upstream.uri())
        .header(CONTENT_TYPE, DNS_MESSAGE)
        .header(ACCEPT, DNS_MESSAGE)
        .header(CONTENT_LENGTH, request.len())
        .body(())
        .map_err(|e| Failure::Answer(anyhow!("invalid http/2 request: {}", e)))?;
    let mut send_request = send_request
        .ready()
        .await
        .map_err(|e| conn_err(e, "http/2 connection not ready"))?;
    let (response, mut body) = send_request
        .send_request(req, false)
        .map_err(|e| conn_err(e, "send http/2 request failed"))?;
    body.send_data(request, true)
        .map_err(|e| conn_err(e, "send http/2 body failed"))?;
    let response = response
        .await
        .map_err(|e| conn_err(e, "read http/2 response failed"))?;
    let status = response.status();
    if status != http::StatusCode::OK {
        return Err(Failure::Answer(anyhow!(
            "doh server returned http status {}",
            status.as_u16()
        )));
    }
    let mut recv = response.into_body();
    let mut answer = Vec::new();
    while let Some(chunk) = recv.data().await {
        let chunk = chunk.map_err(|e| conn_err(e, "read http/2 body failed"))?;
        let _ = recv.flow_control().release_capacity(chunk.len());
        if answer.len() + chunk.len() > MAX_MESSAGE_LEN {
            return Err(Failure::Answer(anyhow!("doh answer too long")));
        }
        answer.extend_from_slice(&chunk);
    }
    Ok(answer)
}

/// A POST of the query on an HTTP/1.1 connection, and whether the
/// connection may be kept for the next one.
async fn exchange_http1(
    upstream: &Upstream,
    stream: &mut AnyStream,
    request: &[u8],
) -> std::result::Result<(Vec<u8>, bool), Failure> {
    let mut out = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: {}\r\nAccept: {}\r\nContent-Length: {}\r\n\r\n",
        upstream.path,
        upstream.authority(),
        DNS_MESSAGE,
        DNS_MESSAGE,
        request.len()
    )
    .into_bytes();
    out.extend_from_slice(request);
    stream
        .write_all(&out)
        .await
        .map_err(|e| conn_err(e, "write doh request failed"))?;
    stream
        .flush()
        .await
        .map_err(|e| conn_err(e, "write doh request failed"))?;

    let mut reader = Reader {
        stream,
        buf: Vec::with_capacity(1024),
    };
    let head_len = loop {
        if let Some(i) = find(&reader.buf, b"\r\n\r\n") {
            break i + 4;
        }
        if reader.buf.len() > MAX_HEAD_LEN {
            return Err(Failure::Answer(anyhow!("doh response head too long")));
        }
        reader.fill().await?;
    };
    let head = Head::parse(&reader.buf[..head_len - 4]).map_err(Failure::Answer)?;
    reader.buf.drain(..head_len);
    if head.status != 200 {
        return Err(Failure::Answer(anyhow!(
            "doh server returned http status {}",
            head.status
        )));
    }
    let too_long = || Failure::Answer(anyhow!("doh answer too long"));
    let (answer, mut keep_alive) = if head.chunked {
        (reader.chunked().await?, head.keep_alive)
    } else if let Some(len) = head.content_length {
        if len > MAX_MESSAGE_LEN {
            return Err(too_long());
        }
        while reader.buf.len() < len {
            reader.fill().await?;
        }
        let keep_alive = head.keep_alive && reader.buf.len() == len;
        reader.buf.truncate(len);
        (std::mem::take(&mut reader.buf), keep_alive)
    } else {
        // The body runs to the end of the connection.
        loop {
            if reader.buf.len() > MAX_MESSAGE_LEN {
                return Err(too_long());
            }
            if !reader.try_fill().await? {
                break;
            }
        }
        (std::mem::take(&mut reader.buf), false)
    };
    // Bytes past the answer: the connection is not where the next response
    // would start.
    if !reader.buf.is_empty() {
        keep_alive = false;
    }
    Ok((answer, keep_alive))
}

/// What a response head says.
struct Head {
    status: u16,
    content_length: Option<usize>,
    chunked: bool,
    keep_alive: bool,
}

impl Head {
    fn parse(head: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(head).map_err(|e| anyhow!("invalid http headers: {}", e))?;
        let mut lines = text.split("\r\n");
        let status_line = lines.next().unwrap_or_default();
        let mut parts = status_line.split_whitespace();
        let version = parts.next().unwrap_or_default();
        if !version.starts_with("HTTP/1.") {
            return Err(anyhow!("invalid status line {:?}", status_line));
        }
        let status = parts
            .next()
            .and_then(|s| s.parse::<u16>().ok())
            .ok_or_else(|| anyhow!("invalid status line {:?}", status_line))?;
        let mut head = Self {
            status,
            content_length: None,
            chunked: false,
            // HTTP/1.1 keeps the connection unless told otherwise; 1.0 does not.
            keep_alive: version == "HTTP/1.1",
        };
        for line in lines {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            let name = name.trim();
            let value = value.trim();
            if name.eq_ignore_ascii_case("content-length") {
                head.content_length = Some(
                    value
                        .parse::<usize>()
                        .map_err(|e| anyhow!("invalid content-length: {}", e))?,
                );
            } else if name.eq_ignore_ascii_case("transfer-encoding") {
                head.chunked = value
                    .rsplit(',')
                    .next()
                    .is_some_and(|v| v.trim().eq_ignore_ascii_case("chunked"));
            } else if name.eq_ignore_ascii_case("connection") {
                for token in value.split(',') {
                    let token = token.trim();
                    if token.eq_ignore_ascii_case("close") {
                        head.keep_alive = false;
                    } else if token.eq_ignore_ascii_case("keep-alive") {
                        head.keep_alive = true;
                    }
                }
            }
        }
        Ok(head)
    }
}

/// Reads a response off a stream, holding what came beyond what was
/// asked for.
struct Reader<'a> {
    stream: &'a mut AnyStream,
    buf: Vec<u8>,
}

impl Reader<'_> {
    /// Reads more; false at the end of the stream.
    async fn try_fill(&mut self) -> std::result::Result<bool, Failure> {
        let mut chunk = [0u8; 4096];
        let n = self
            .stream
            .read(&mut chunk)
            .await
            .map_err(|e| conn_err(e, "read doh response failed"))?;
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(n > 0)
    }

    async fn fill(&mut self) -> std::result::Result<(), Failure> {
        if self.try_fill().await? {
            Ok(())
        } else {
            Err(Failure::Connection(anyhow!(
                "doh connection closed before the response ended"
            )))
        }
    }

    /// A line, without its CRLF.
    async fn line(&mut self) -> std::result::Result<Vec<u8>, Failure> {
        loop {
            if let Some(i) = find(&self.buf, b"\r\n") {
                let line = self.buf[..i].to_vec();
                self.buf.drain(..i + 2);
                return Ok(line);
            }
            if self.buf.len() > MAX_HEAD_LEN {
                return Err(Failure::Answer(anyhow!("doh chunk line too long")));
            }
            self.fill().await?;
        }
    }

    /// A chunked body, and the trailers after it.
    async fn chunked(&mut self) -> std::result::Result<Vec<u8>, Failure> {
        let mut body = Vec::new();
        loop {
            let line = self.line().await?;
            let size = std::str::from_utf8(&line)
                .ok()
                .and_then(|l| l.split(';').next())
                .and_then(|s| usize::from_str_radix(s.trim(), 16).ok())
                .ok_or_else(|| Failure::Answer(anyhow!("invalid chunk size")))?;
            if size == 0 {
                // Trailers, up to an empty line.
                while !self.line().await?.is_empty() {}
                return Ok(body);
            }
            if body.len() + size > MAX_MESSAGE_LEN {
                return Err(Failure::Answer(anyhow!("doh answer too long")));
            }
            while self.buf.len() < size + 2 {
                self.fill().await?;
            }
            if &self.buf[size..size + 2] != b"\r\n" {
                return Err(Failure::Answer(anyhow!("invalid chunk terminator")));
            }
            body.extend_from_slice(&self.buf[..size]);
            self.buf.drain(..size + 2);
        }
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::Head;

    #[test]
    fn head_keep_alive() {
        let head = Head::parse(b"HTTP/1.1 200 OK\r\nContent-Length: 4").unwrap();
        assert_eq!(head.status, 200);
        assert_eq!(head.content_length, Some(4));
        assert!(head.keep_alive && !head.chunked);
        let head = Head::parse(b"HTTP/1.1 200 OK\r\nConnection: close").unwrap();
        assert!(!head.keep_alive);
        let head = Head::parse(b"HTTP/1.0 200 OK\r\nContent-Length: 4").unwrap();
        assert!(!head.keep_alive);
        let head = Head::parse(b"HTTP/1.1 503 Busy\r\nTransfer-Encoding: gzip, chunked").unwrap();
        assert_eq!(head.status, 503);
        assert!(head.chunked);
        assert!(Head::parse(b"SPDY 200").is_err());
    }
}
