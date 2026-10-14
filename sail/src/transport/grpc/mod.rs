//! The gRPC transport, "gun", as Xray and sing-box speak it: a stream is one
//! HTTP/2 POST to `/<service_name>/Tun`, `content-type: application/grpc`,
//! its bytes gRPC messages each way. See `gun`.
//!
//! The inbound serves every call a connection carries, as many as the client
//! multiplexes onto it. The outbound multiplexes likewise: it keeps a pool
//! of connections to its server, dialled through the layers under it, and
//! makes each stream a call on one of them; see `outbound`.

pub mod gun;
#[cfg(feature = "inbound-grpc")]
pub mod inbound;
#[cfg(feature = "outbound-grpc")]
pub mod outbound;

#[cfg(feature = "inbound-grpc")]
use std::sync::atomic::Ordering;
#[cfg(feature = "inbound-grpc")]
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "inbound-grpc")]
use portable_atomic::AtomicU64;

use crate::transport::h2pool::Names;
#[cfg(feature = "inbound-grpc")]
use crate::transport::h2pool::Counted;

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

/// What gun's tasks are called, and what it logs under.
const NAMES: Names = Names {
    log: "gun",
    connection: "grpc connection",
    idle_check: "grpc idle check",
    keepalive: "grpc keepalive",
};

/// `h2pool::keepalive`, under gun's names.
#[cfg(feature = "inbound-grpc")]
fn keepalive(
    ping_pong: h2::PingPong,
    received: Arc<AtomicU64>,
    interval: Duration,
    timeout: Duration,
    wanted: impl Fn() -> bool + Send + 'static,
    abort: futures::future::AbortHandle,
) {
    crate::transport::h2pool::keepalive(
        NAMES, ping_pong, received, interval, timeout, wanted, abort,
    );
}

/// How a connection to the server is set up.
#[cfg(feature = "outbound-grpc")]
fn client_builder() -> h2::client::Builder {
    let mut builder = h2::client::Builder::new();
    builder
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONNECTION_WINDOW)
        .max_header_list_size(MAX_HEADER_LIST)
        .enable_push(false);
    builder
}

/// Whether nothing came from the peer since the last time this was asked:
/// a server's keepalive round. `received` counts what came.
#[cfg(feature = "inbound-grpc")]
fn quiet(received: Arc<AtomicU64>) -> impl Fn() -> bool + Send + 'static {
    let seen = AtomicU64::new(received.load(Ordering::Relaxed));
    move || {
        let now = received.load(Ordering::Relaxed);
        seen.swap(now, Ordering::Relaxed) == now
    }
}

#[cfg(all(test, feature = "inbound-grpc", feature = "outbound-grpc"))]
mod stall_tests;

#[cfg(test)]
mod tests {
    /// A round is quiet only when nothing came since the one before.
    #[cfg(feature = "inbound-grpc")]
    #[test]
    fn a_server_pings_only_after_a_round_with_nothing_received() {
        use std::sync::atomic::Ordering;
        let received = std::sync::Arc::new(super::AtomicU64::new(0));
        let quiet = super::quiet(received.clone());
        assert!(quiet());
        received.fetch_add(10, Ordering::Relaxed);
        assert!(!quiet());
        assert!(quiet());
        received.fetch_add(1, Ordering::Relaxed);
        assert!(!quiet());
    }

    #[test]
    fn test_service_path() {
        assert_eq!(
            super::service_path("TunService").unwrap(),
            "/TunService/Tun"
        );
        assert_eq!(super::service_path("a b/c").unwrap(), "/a%20b%2Fc/Tun");
    }
}
