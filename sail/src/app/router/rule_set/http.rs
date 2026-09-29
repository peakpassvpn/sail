//! A GET over HTTP/1.1, through an outbound or directly: what downloading a rule-set
//! takes, and no more. It is what `crate::fetch` downloads with too, without an
//! instance where it dials directly.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::adapter::AnyStream;
use crate::app::dispatcher::Dispatcher;
use crate::app::SyncDnsClient;
use crate::net::DialOptions;
use crate::runtime::RuntimeEnv;
use crate::session::{Network, Session, SocksAddr};

/// The most a download may be: well past the largest published rule-sets.
pub(crate) const MAX_BODY: usize = 64 << 20;
const MAX_HEAD: usize = 64 << 10;
const MAX_REDIRECTS: usize = 5;
/// How long a download may take, redirects and all.
pub(crate) const TIMEOUT: Duration = Duration::from_secs(60);

/// What a download is made with: an HTTP client, or `download_detour`.
#[derive(Clone, Default)]
pub(crate) struct Client {
    /// None: through the default outbound.
    pub via: Option<Via>,
    pub headers: Vec<(String, String)>,
}

/// How a download connects.
#[derive(Clone)]
pub(crate) enum Via {
    /// Through the outbound of this tag.
    Outbound(String),
    /// Straight to the server, as an HTTP client without a detour does.
    Direct(Arc<DialOptions>),
}

pub(crate) enum Response {
    /// Unchanged since the ETag given.
    NotModified,
    Body {
        data: Vec<u8>,
        etag: Option<String>,
    },
}

/// What a GET connects with: the instance's dispatcher, where there is
/// one, else what a direct connection takes.
pub(crate) struct Conn<'a> {
    /// Needed to go through an outbound.
    pub dispatcher: Option<&'a Dispatcher>,
    pub dns: SyncDnsClient,
    pub env: &'a RuntimeEnv,
}

/// How long a GET may take, redirects and all, and how large its body may
/// be.
#[derive(Clone, Copy)]
pub(crate) struct Limits {
    pub timeout: Duration,
    pub max_body: usize,
}

/// A rule-set's.
const LIMITS: Limits = Limits {
    timeout: TIMEOUT,
    max_body: MAX_BODY,
};

/// GETs `url` `via` an outbound or directly, following redirects; with
/// `etag`, asks for it only if changed.
pub(crate) async fn get(
    dispatcher: &Dispatcher,
    via: &Via,
    headers: &[(String, String)],
    url: &str,
    etag: Option<&str>,
) -> Result<Response> {
    let conn = Conn {
        dispatcher: Some(dispatcher),
        dns: dispatcher.dns_client(),
        env: dispatcher.env(),
    };
    get_with(&conn, via, headers, url, etag, LIMITS).await
}

/// `get`, with `conn` and within `limits`.
pub(crate) async fn get_with(
    conn: &Conn<'_>,
    via: &Via,
    headers: &[(String, String)],
    url: &str,
    etag: Option<&str>,
    limits: Limits,
) -> Result<Response> {
    tokio::time::timeout(
        limits.timeout,
        get_following(conn, via, headers, url, etag, limits.max_body),
    )
    .await
    .map_err(|_| anyhow!("timed out after {:?}", limits.timeout))?
}

async fn get_following(
    conn: &Conn<'_>,
    via: &Via,
    headers: &[(String, String)],
    url: &str,
    etag: Option<&str>,
    max_body: usize,
) -> Result<Response> {
    let mut url = url::Url::parse(url).map_err(|e| anyhow!("url: {}", e))?;
    for _ in 0..=MAX_REDIRECTS {
        match get_once(conn, via, headers, &url, etag, max_body).await? {
            Step::Done(response) => return Ok(response),
            Step::Redirect(location) => {
                url = url
                    .join(&location)
                    .map_err(|e| anyhow!("redirect to {:?}: {}", location, e))?;
            }
        }
    }
    Err(anyhow!("more than {} redirects", MAX_REDIRECTS))
}

enum Step {
    Done(Response),
    Redirect(String),
}

async fn get_once(
    conn: &Conn<'_>,
    via: &Via,
    headers: &[(String, String)],
    url: &url::Url,
    etag: Option<&str>,
    max_body: usize,
) -> Result<Step> {
    let tls = match url.scheme() {
        "https" => true,
        "http" => false,
        other => return Err(anyhow!("{}: not an http(s) URL", other)),
    };
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("{}: no host", url))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let port = url.port_or_known_default().unwrap_or(443);
    let destination = match host.parse::<IpAddr>() {
        Ok(ip) => SocksAddr::Ip((ip, port).into()),
        Err(_) => SocksAddr::Domain(host.clone(), port),
    };
    let sess = Session {
        network: Network::Tcp,
        destination,
        inbound_tag: "rule-set".to_string(),
        ..Default::default()
    };
    let stream = match via {
        Via::Outbound(detour) => conn
            .dispatcher
            .ok_or_else(|| anyhow!("connect {} through [{}]: no instance runs", host, detour))?
            .stream_via(detour, sess)
            .await
            .map_err(|e| anyhow!("connect {} through [{}]: {}", host, detour, e))?,
        Via::Direct(dial) => crate::net::new_tcp_stream(conn.dns.clone(), &host, &port, dial)
            .await
            .map_err(|e| anyhow!("connect {}: {}", host, e))?,
    };
    let mut stream = if tls {
        handshake(&host, stream, conn.env).await?
    } else {
        stream
    };

    let mut path = url.path().to_string();
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    let authority = match url.port() {
        Some(port) => format!("{}:{}", url.host_str().unwrap_or_default(), port),
        None => url.host_str().unwrap_or_default().to_string(),
    };
    let mut request = format!("GET {} HTTP/1.1\r\nConnection: close\r\n", path);
    let user_agent = format!("sail/{}", env!("CARGO_PKG_VERSION"));
    for (name, value) in [
        ("Host", authority.as_str()),
        ("User-Agent", user_agent.as_str()),
        ("Accept", "*/*"),
    ] {
        if !headers.iter().any(|(n, _)| n.eq_ignore_ascii_case(name)) {
            request.push_str(&format!("{}: {}\r\n", name, value));
        }
    }
    for (name, value) in headers {
        request.push_str(&format!("{}: {}\r\n", name, value));
    }
    if let Some(etag) = etag {
        request.push_str(&format!("If-None-Match: {}\r\n", etag));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let (head, mut rest) = read_head(&mut stream).await?;
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    response
        .parse(&head)
        .map_err(|e| anyhow!("invalid response: {}", e))?;
    let code = response.code.unwrap_or_default();
    let header = |name: &str| {
        response
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .and_then(|h| std::str::from_utf8(h.value).ok())
            .map(str::trim)
    };
    match code {
        200 => {}
        304 => return Ok(Step::Done(Response::NotModified)),
        301 | 302 | 303 | 307 | 308 => {
            let location =
                header("location").ok_or_else(|| anyhow!("{} without Location", code))?;
            return Ok(Step::Redirect(location.to_string()));
        }
        _ => return Err(anyhow!("http status {}", code)),
    }
    let etag = header("etag").map(str::to_string);
    let chunked = header("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked"));
    let length = header("content-length")
        .map(|v| {
            v.parse::<usize>()
                .map_err(|_| anyhow!("invalid Content-Length"))
        })
        .transpose()?;
    if length.is_some_and(|l| l > max_body) {
        return Err(anyhow!("larger than {} bytes", max_body));
    }
    let data = if chunked {
        read_chunked(&mut stream, rest, max_body).await?
    } else {
        read_rest(&mut stream, &mut rest, max_body).await?;
        if let Some(length) = length {
            if rest.len() < length {
                return Err(anyhow!(
                    "body cut short: {} of {} bytes",
                    rest.len(),
                    length
                ));
            }
            rest.truncate(length);
        }
        rest
    };
    Ok(Step::Done(Response::Body { data, etag }))
}

#[cfg(feature = "tls")]
async fn handshake(
    host: &str,
    stream: AnyStream,
    env: &crate::runtime::RuntimeEnv,
) -> Result<AnyStream> {
    use crate::transport::tls::{Fingerprint, TlsClient};
    let client = TlsClient::new(
        &["http/1.1".to_string()],
        None,
        false,
        Some(Fingerprint::Chrome),
        &env.tls_roots.get()?,
    )?;
    let stream = client
        .connect(host, stream, None, None)
        .await
        .map_err(|e| anyhow!("tls handshake with {}: {}", host, e))?;
    Ok(Box::new(stream))
}

#[cfg(not(feature = "tls"))]
async fn handshake(
    _host: &str,
    _stream: AnyStream,
    _env: &crate::runtime::RuntimeEnv,
) -> Result<AnyStream> {
    Err(anyhow!(
        "https: not supported, the tls feature is not compiled in"
    ))
}

/// The response head, up to the blank line, and what came after it.
async fn read_head(stream: &mut AnyStream) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = buf.split_off(end + 4);
            return Ok((buf, rest));
        }
        if buf.len() > MAX_HEAD {
            return Err(anyhow!("response head longer than {} bytes", MAX_HEAD));
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(anyhow!("connection closed before a response"));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Reads to the end, which `Connection: close` puts at the body's.
async fn read_rest(stream: &mut AnyStream, buf: &mut Vec<u8>, max_body: usize) -> Result<()> {
    let mut chunk = [0u8; 16384];
    loop {
        if buf.len() > max_body {
            return Err(anyhow!("larger than {} bytes", max_body));
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// A chunked body (RFC 9112 §7.1), `buf` holding what was read already.
async fn read_chunked(
    stream: &mut AnyStream,
    mut buf: Vec<u8>,
    max_body: usize,
) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    let mut at = 0;
    loop {
        // The size line.
        let line_end = loop {
            if let Some(i) = buf[at..].windows(2).position(|w| w == b"\r\n") {
                break at + i;
            }
            more(stream, &mut buf).await?;
        };
        let line = std::str::from_utf8(&buf[at..line_end]).map_err(|_| anyhow!("bad chunk"))?;
        let size = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| anyhow!("bad chunk size {:?}", line))?;
        at = line_end + 2;
        if size == 0 {
            return Ok(body);
        }
        if body.len() + size > max_body {
            return Err(anyhow!("larger than {} bytes", max_body));
        }
        while buf.len() < at + size + 2 {
            more(stream, &mut buf).await?;
        }
        body.extend_from_slice(&buf[at..at + size]);
        at += size + 2;
        // Keeps the buffer from holding the whole body twice.
        buf.drain(..at);
        at = 0;
    }
}

async fn more(stream: &mut AnyStream, buf: &mut Vec<u8>) -> Result<()> {
    let mut chunk = [0u8; 16384];
    let n = stream.read(&mut chunk).await?;
    if n == 0 {
        return Err(anyhow!("connection closed in the body"));
    }
    buf.extend_from_slice(&chunk[..n]);
    Ok(())
}
