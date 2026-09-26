//! What Hysteria2 adds to the QUIC glue in `transport::quic`: its transport
//! parameters and congestion control, Salamander under quinn, and the
//! HTTP/3 streams it keeps open.

use std::io;
use std::sync::Arc;

use quinn::AsyncUdpSocket;

use super::congestion::CongestionHandle;
use super::salamander::{Salamander, SalamanderSocket};
use crate::transport::quic::Side;

/// The ALPN Hysteria2 speaks unless configured otherwise: it is HTTP/3.
pub const DEFAULT_ALPN: &[&str] = &["h3"];

/// Flow control windows, the reference implementation's defaults.
const STREAM_RECEIVE_WINDOW: u32 = 8 * 1024 * 1024;
const CONNECTION_RECEIVE_WINDOW: u32 = 20 * 1024 * 1024;
/// Unidirectional streams a peer may open: HTTP/3 needs three at most.
const MAX_UNI_STREAMS: u32 = 16;

/// The transport parameters of one connection, its congestion controller
/// selected by `congestion`: Brutal or BBR, as the authentication decides.
pub fn transport_config(
    tuning: &crate::runtime::options::Quic,
    side: Side,
    congestion: &CongestionHandle,
) -> quinn::TransportConfig {
    let mut config = crate::transport::quic::transport_config(tuning, side, congestion.factory());
    config
        .max_concurrent_uni_streams(quinn::VarInt::from_u32(MAX_UNI_STREAMS))
        .stream_receive_window(quinn::VarInt::from_u32(STREAM_RECEIVE_WINDOW))
        .receive_window(quinn::VarInt::from_u32(CONNECTION_RECEIVE_WINDOW))
        .send_window(CONNECTION_RECEIVE_WINDOW as u64);
    config
}

/// `socket` under quinn, obfuscated if `obfs` is set.
pub fn wrap_socket(
    socket: std::net::UdpSocket,
    obfs: Option<&Salamander>,
) -> io::Result<Arc<dyn AsyncUdpSocket>> {
    let socket = crate::transport::quic::wrap_socket(socket)?;
    Ok(match obfs {
        Some(obfs) => Arc::new(SalamanderSocket::new(socket, obfs.clone())),
        None => socket,
    })
}

/// Opens our HTTP/3 control stream. It must stay open as long as the
/// connection: a peer closes the connection when it ends.
pub async fn open_control_stream(conn: &quinn::Connection) -> io::Result<quinn::SendStream> {
    let mut send = conn.open_uni().await.map_err(io::Error::other)?;
    send.write_all(&super::h3::control_stream_preface())
        .await
        .map_err(io::Error::other)?;
    Ok(send)
}

/// Accepts the peer's unidirectional streams, its HTTP/3 control stream
/// among them, and reads them to nothing, holding them open, until the
/// connection closes.
pub async fn drain_uni_streams(conn: quinn::Connection) {
    while let Ok(mut recv) = conn.accept_uni().await {
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            while let Ok(Some(_)) = recv.read(&mut buf).await {}
        });
    }
}
