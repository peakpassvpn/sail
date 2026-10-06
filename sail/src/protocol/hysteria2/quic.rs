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
    if side == Side::Server {
        // Until it authenticates; then as many as it likes.
        config.max_concurrent_bidi_streams(quinn::VarInt::from_u32(
            crate::transport::quic::STREAMS_BEFORE_AUTH,
        ));
    }
    config
        .max_concurrent_uni_streams(quinn::VarInt::from_u32(MAX_UNI_STREAMS))
        .stream_receive_window(
            quinn::VarInt::from_u64(tuning.hysteria2_stream_window as u64 * 1024)
                .unwrap_or(quinn::VarInt::MAX),
        )
        .receive_window(
            quinn::VarInt::from_u64(tuning.hysteria2_receive_window as u64 * 1024)
                .unwrap_or(quinn::VarInt::MAX),
        )
        .send_window(tuning.hysteria2_send_window as u64 * 1024);
    config
}

/// `socket` under quinn, obfuscated if `obfs` is set.
pub fn wrap_socket(
    socket: std::net::UdpSocket,
    obfs: Option<&Salamander>,
) -> io::Result<Arc<dyn AsyncUdpSocket>> {
    Ok(obfuscate(
        crate::transport::quic::wrap_socket(socket)?,
        obfs,
    ))
}

/// `socket`, obfuscated if `obfs` is set.
pub fn obfuscate(
    socket: Arc<dyn AsyncUdpSocket>,
    obfs: Option<&Salamander>,
) -> Arc<dyn AsyncUdpSocket> {
    match obfs {
        Some(obfs) => Arc::new(SalamanderSocket::new(socket, obfs.clone())),
        None => socket,
    }
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
/// connection closes. The streams are read within it, so that stopping it
/// lets them go: a stream kept keeps its connection open.
pub async fn drain_uni_streams(conn: quinn::Connection) {
    let mut streams = futures::stream::FuturesUnordered::new();
    loop {
        tokio::select! {
            accepted = conn.accept_uni() => match accepted {
                Ok(mut recv) => streams.push(async move {
                    let mut buf = [0u8; 1024];
                    while let Ok(Some(_)) = recv.read(&mut buf).await {}
                }),
                Err(_) => return,
            },
            Some(()) = futures::StreamExt::next(&mut streams), if !streams.is_empty() => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::options::{Profile, RuntimeOptions};

    /// The windows a connection is configured with, as quinn shows them.
    fn windows(profile: Profile) -> (String, String, String) {
        let config = transport_config(
            &RuntimeOptions::profile(profile).quic,
            Side::Client,
            &CongestionHandle::default(),
        );
        let shown = format!("{:?}", config);
        let field = |name: &str| {
            let start = shown.find(&format!(" {}: ", name)).expect(name) + name.len() + 3;
            shown[start..].split([',', ' ']).next().unwrap().to_string()
        };
        (
            field("stream_receive_window"),
            field("receive_window"),
            field("send_window"),
        )
    }

    /// A stream's window, the connection's, and what is kept in flight,
    /// as each profile sets them: a router's connection takes eight times
    /// a stream, so that streams nobody reads leave room for the rest.
    #[test]
    fn windows_follow_the_profile() {
        let mib = |n: u64| (n << 20).to_string();
        for profile in [Profile::Desktop, Profile::Server] {
            assert_eq!(windows(profile), (mib(8), mib(64), mib(16)));
        }
        assert_eq!(windows(Profile::Mobile), (mib(8), mib(32), mib(16)));
        assert_eq!(windows(Profile::Router), (mib(4), mib(32), mib(16)));
    }
}
