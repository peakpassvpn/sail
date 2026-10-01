//! The operations plane's downloads: what a host (sail-cli, an FFI host,
//! the runtime API) fetches for itself or for an instance, a profile's
//! includes or a data file, with sail's own HTTP and TLS, the rule-sets'
//! and outbound providers' GET. It dials directly, or through an outbound
//! of a running instance. The host says what is fetched and when, and
//! where it goes: core names no URL.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};

use crate::app::http::{self, Conn, Limits, Response, Via};
use crate::net::{DialDefaults, Dialer};
use crate::runtime::RuntimeEnv;
use crate::RuntimeManager;

/// How a download is made.
#[derive(Debug, Clone)]
pub struct Options {
    /// Request headers, besides `Host`, `User-Agent` and `Accept`, which
    /// these replace when they name them.
    pub headers: Vec<(String, String)>,
    /// How long it may take, redirects and all.
    pub timeout: Duration,
    /// The largest body taken.
    pub max_size: usize,
}

impl Default for Options {
    /// A minute, and 64 MiB: a rule-set's.
    fn default() -> Self {
        Options {
            headers: Vec::new(),
            timeout: http::TIMEOUT,
            max_size: http::MAX_BODY,
        }
    }
}

/// GETs `url` directly, following redirects, its names resolved by the
/// system and its certificate checked against the system's roots.
pub async fn fetch(url: &str, options: &Options) -> Result<Vec<u8>> {
    let env = RuntimeEnv::default();
    let dns = crate::app::dns::DnsClient::new(
        &Default::default(),
        Arc::new(DialDefaults::default()),
        &env,
    )?
    .into_shared();
    let conn = Conn {
        dispatcher: None,
        dns,
        env: &env,
    };
    get(&conn, &Via::Dialer(Dialer::system()), url, options).await
}

/// GETs `url` through the outbound `outbound` of the running instance
/// `manager`, following redirects.
pub async fn fetch_through(
    manager: &RuntimeManager,
    outbound: &str,
    url: &str,
    options: &Options,
) -> Result<Vec<u8>> {
    let dispatcher = manager
        .dispatcher
        .upgrade()
        .ok_or_else(|| anyhow!("the instance has stopped"))?;
    let conn = Conn {
        dispatcher: Some(&dispatcher),
        dns: dispatcher.dns_client(),
        env: dispatcher.env(),
    };
    get(&conn, &Via::Outbound(outbound.to_string()), url, options).await
}

async fn get(conn: &Conn<'_>, via: &Via, url: &str, options: &Options) -> Result<Vec<u8>> {
    let limits = Limits {
        timeout: options.timeout,
        max_body: options.max_size,
        max_body_is: "the size allowed",
    };
    match http::get_with(conn, via, &options.headers, url, None, limits).await? {
        Response::Body { data, .. } => Ok(data),
        Response::NotModified => Err(anyhow!("304 Not Modified, though asked for no ETag")),
    }
}

/// Writes `data` to `path` whole or not at all: to a file beside it, then
/// in its place. The directory is made if it is not there.
pub fn write_atomically(path: &Path, data: &[u8]) -> Result<()> {
    crate::app::http::write_atomically(path, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A server that answers one request with `response`.
    async fn serve(response: &'static [u8]) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let _ = stream.write_all(response).await;
        });
        format!("http://{}/a.conf", addr)
    }

    #[tokio::test]
    async fn fetches_directly_within_its_limits() {
        let url = serve(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello").await;
        assert_eq!(fetch(&url, &Options::default()).await.unwrap(), b"hello");

        let url = serve(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello").await;
        let small = Options {
            max_size: 4,
            ..Default::default()
        };
        let err = fetch(&url, &small).await.unwrap_err().to_string();
        assert!(
            err.contains("larger than the size allowed, 4 bytes"),
            "{}",
            err
        );

        let url = serve(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await;
        let err = fetch(&url, &Options::default())
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("404"), "{}", err);
    }

    #[tokio::test]
    async fn a_chunk_size_from_the_peer_is_checked() {
        let url =
            serve(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
                .await;
        assert_eq!(fetch(&url, &Options::default()).await.unwrap(), b"hello");

        let url = serve(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\nffffffffffffffff\r\n",
        )
        .await;
        let err = fetch(&url, &Options::default())
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("larger than"), "{}", err);

        let url = serve(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0000000000000000005\r\nhello\r\n",
        )
        .await;
        let err = fetch(&url, &Options::default())
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("bad chunk size"), "{}", err);
    }

    #[tokio::test]
    async fn a_bad_redirect_names_no_path() {
        let url = serve(
            b"HTTP/1.1 302 Found\r\nLocation: http://[bad/s3cret\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        let err = fetch(&url, &Options::default())
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("bad Location") && !err.contains("s3cret"),
            "{}",
            err
        );
    }

    #[tokio::test]
    async fn a_redirect_out_of_http_is_refused_and_names_no_path() {
        let url = serve(
            b"HTTP/1.1 302 Found\r\nLocation: ftp://files.example/s3cret\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        let err = fetch(&url, &Options::default())
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("redirect to a ftp: URL refused") && !err.contains("s3cret"),
            "{}",
            err
        );
    }

    #[test]
    fn writes_whole() {
        let dir = std::env::temp_dir().join(format!("sail-fetch-{}", std::process::id()));
        let path = dir.join("a").join("b.conf");
        write_atomically(&path, b"x").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"x");
        let _ = std::fs::remove_dir_all(dir);
    }
}
