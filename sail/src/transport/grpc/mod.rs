//! The gRPC transport, "gun", as Xray and sing-box speak it: a stream is one
//! HTTP/2 POST to `/<service_name>/Tun`, `content-type: application/grpc`,
//! its bytes gRPC messages each way. See `gun`.
//!
//! The inbound serves every call a connection carries, as many as the client
//! multiplexes onto it. The outbound opens a connection for each stream,
//! over the layers under it; see `outbound`.

pub mod gun;
#[cfg(feature = "inbound-grpc")]
pub mod inbound;
#[cfg(feature = "outbound-grpc")]
pub mod outbound;

use std::time::Duration;

use tracing::debug;

/// A stream's receive window. What one stream can have in flight towards
/// this side, and so what it can buffer here.
const STREAM_WINDOW: u32 = 1024 * 1024;

/// A connection's receive window: what all its streams together can.
const CONNECTION_WINDOW: u32 = 4 * 1024 * 1024;

/// The largest header block accepted. A gun call's headers are a few
/// hundred bytes.
const MAX_HEADER_LIST: u32 = 16 * 1024;

/// `/<service_name>/Tun`, the name escaped as a path segment, as sing-box
/// sends it.
pub fn service_path(service_name: &str) -> anyhow::Result<String> {
    let mut path = String::from("/");
    for byte in service_name.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                path.push(byte as char)
            }
            _ => path.push_str(&format!("%{:02X}", byte)),
        }
    }
    path.push_str("/Tun");
    path.parse::<http::uri::PathAndQuery>()
        .map_err(|_| anyhow::anyhow!("service_name: invalid"))?;
    Ok(path)
}

/// How long a ping may go unanswered when `ping_timeout` is not set, as in
/// sing-box.
pub const DEFAULT_PING_TIMEOUT: Duration = Duration::from_secs(15);

/// Keepalive: every `interval`, a ping, which must be answered within
/// `timeout` or the connection is given up with `abort`.
///
/// sing-box pings after `idle_timeout` without a frame received; h2 does not
/// say when one last was, so here the ping goes out every `idle_timeout`
/// whatever the traffic. Its cost is one frame each way.
fn keepalive(
    mut ping_pong: h2::PingPong,
    interval: Duration,
    timeout: Duration,
    abort: futures::future::AbortHandle,
) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            match tokio::time::timeout(timeout, ping_pong.ping(h2::Ping::opaque())).await {
                Ok(Ok(_)) => continue,
                // The connection is gone already.
                Ok(Err(_)) => break,
                Err(_) => {
                    debug!("gun: no pong within {:?}, closing the connection", timeout);
                    abort.abort();
                    break;
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_service_path() {
        assert_eq!(
            super::service_path("TunService").unwrap(),
            "/TunService/Tun"
        );
        assert_eq!(super::service_path("a b/c").unwrap(), "/a%20b%2Fc/Tun");
    }
}
