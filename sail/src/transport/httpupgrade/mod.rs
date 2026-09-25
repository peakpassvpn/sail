//! HTTPUpgrade, as sing-box and Xray speak it: an HTTP/1.1 request to
//! upgrade to WebSocket, answered with `101 Switching Protocols`, after which
//! the connection is the stream itself, with no WebSocket framing. A CDN that
//! passes WebSocket passes it, at none of framing's cost.
//!
//! `http1` is the upgrade exchange, which the WebSocket transport opens with
//! too.

pub mod http1;
#[cfg(feature = "inbound-httpupgrade")]
pub mod inbound;
#[cfg(feature = "outbound-httpupgrade")]
pub mod outbound;
