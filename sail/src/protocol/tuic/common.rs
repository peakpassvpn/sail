//! What the TUIC client and server share on top of quinn.
//!
//! Some of this repeats `transport::quic`, which stays as it is while the
//! QUIC protocols are written; they are to share one set of glue later.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{anyhow, Result};
use serde_derive::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::trace;

use super::frag::fragment;
use super::proto::{encode_heartbeat, encode_packet, PacketHeader, TOKEN_LEN};
use crate::session::SocksAddr;

/// The congestion controllers sing-box offers for TUIC, all in quinn.
#[derive(Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CongestionControl {
    /// sing-box's default.
    #[default]
    Cubic,
    NewReno,
    Bbr,
}

/// Which way UDP packets travel.
#[derive(Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UdpRelayMode {
    /// QUIC datagrams, fragmented to fit.
    #[default]
    Native,
    /// One unidirectional stream per packet.
    Quic,
}

/// How long an unfinished packet waits for the rest of its fragments.
pub const FRAGMENT_TIMEOUT: Duration = Duration::from_secs(10);
/// Unfinished packets one association keeps at once.
pub const MAX_PENDING_PACKETS: usize = 8;
/// Packets waiting in one association for the relay to take them.
pub const ASSOCIATION_QUEUE: usize = 64;
/// How long a command on a unidirectional stream may take to arrive.
pub const UNI_STREAM_TIMEOUT: Duration = Duration::from_secs(10);
/// The heartbeat interval when none is configured, as in sing-box.
pub const DEFAULT_HEARTBEAT: Duration = Duration::from_secs(10);
/// The ALPN offered and accepted when none is configured.
pub const DEFAULT_ALPN: &str = "h3";

/// The transport parameters of a TUIC connection.
pub fn transport_config(
    congestion: CongestionControl,
    tuning: &crate::runtime::options::Quic,
    idle_timeout: Duration,
) -> quinn::TransportConfig {
    let mut config = quinn::TransportConfig::default();
    let streams = quinn::VarInt::from_u32(tuning.max_concurrent_streams);
    config.max_concurrent_bidi_streams(streams);
    // In `quic` relay mode every UDP packet is a stream of its own.
    config.max_concurrent_uni_streams(streams);
    config.max_idle_timeout(quinn::IdleTimeout::try_from(idle_timeout).ok());
    // TUIC keeps a connection alive with heartbeats while it relays, and
    // lets it go idle otherwise.
    config.keep_alive_interval(None);
    match congestion {
        CongestionControl::Cubic => config
            .congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default())),
        CongestionControl::NewReno => config
            .congestion_controller_factory(Arc::new(quinn::congestion::NewRenoConfig::default())),
        CongestionControl::Bbr => {
            config.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()))
        }
    };
    config
}

/// The ALPN protocols as quinn-btls takes them.
pub fn alpn_protocols(alpn: Option<Vec<String>>) -> Vec<Vec<u8>> {
    alpn.filter(|a| !a.is_empty())
        .unwrap_or_else(|| vec![DEFAULT_ALPN.to_string()])
        .into_iter()
        .map(String::into_bytes)
        .collect()
}

pub fn parse_uuid(kind: &str, tag: &str, field: &str, uuid: &str) -> Result<[u8; 16]> {
    uuid::Uuid::parse_str(uuid)
        .map(|u| *u.as_bytes())
        .map_err(|e| anyhow!("[{}] {}: {}: invalid UUID: {}", tag, kind, field, e))
}

/// The `Authenticate` token: TLS keying material exported with the UUID
/// as label and the password as context.
pub fn token(
    conn: &quinn::Connection,
    uuid: &[u8; 16],
    password: &[u8],
) -> io::Result<[u8; TOKEN_LEN]> {
    let mut token = [0u8; TOKEN_LEN];
    conn.export_keying_material(&mut token, uuid, password)
        .map_err(|_| io::Error::other("tuic: export keying material failed"))?;
    Ok(token)
}

/// Compares tokens in time independent of where they differ.
#[cfg_attr(not(feature = "inbound-tuic"), allow(dead_code))]
pub fn tokens_equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Relays running on a connection. Heartbeats are sent only while there
/// are any.
#[derive(Clone, Default)]
pub struct Activity(Arc<AtomicUsize>);

impl Activity {
    pub fn start(&self) -> ActiveGuard {
        self.0.fetch_add(1, Ordering::Relaxed);
        ActiveGuard(self.0.clone())
    }

    pub fn is_active(&self) -> bool {
        self.0.load(Ordering::Relaxed) > 0
    }
}

/// One relay, counted while it lives.
pub struct ActiveGuard(Arc<AtomicUsize>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Sends `Heartbeat` every `interval` while `activity` says something is
/// relayed, until the connection closes.
pub async fn heartbeat(conn: quinn::Connection, activity: Activity, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = conn.closed() => return,
        }
        if activity.is_active() {
            if let Err(e) = conn.send_datagram(encode_heartbeat()) {
                trace!("tuic heartbeat failed: {}", e);
                return;
            }
        }
    }
}

/// Sends one UDP packet on `conn` the way `mode` says.
pub async fn send_packet(
    conn: &quinn::Connection,
    mode: UdpRelayMode,
    assoc_id: u16,
    pkt_id: u16,
    addr: &SocksAddr,
    payload: &[u8],
) -> io::Result<()> {
    match mode {
        UdpRelayMode::Native => {
            let max = conn
                .max_datagram_size()
                .ok_or_else(|| io::Error::other("tuic: the peer does not take QUIC datagrams"))?;
            for datagram in fragment(assoc_id, pkt_id, addr, payload, max)? {
                conn.send_datagram(datagram).map_err(io::Error::other)?;
            }
            Ok(())
        }
        UdpRelayMode::Quic => {
            let header = PacketHeader {
                assoc_id,
                pkt_id,
                frag_total: 1,
                frag_id: 0,
                addr: Some(addr.clone()),
            };
            let wire = encode_packet(&header, payload)?;
            let mut send = conn.open_uni().await.map_err(io::Error::other)?;
            send.write_all(&wire).await?;
            send.finish().map_err(io::Error::other)?;
            Ok(())
        }
    }
}

/// A bidirectional stream, relaying one TCP connection.
pub struct QuicStream {
    pub send: quinn::SendStream,
    pub recv: quinn::RecvStream,
    pub _active: ActiveGuard,
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map_err(io::Error::from)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Modes {
        congestion_control: CongestionControl,
        udp_relay_mode: UdpRelayMode,
    }

    #[test]
    fn modes_are_named_as_in_sing_box() {
        let parse = |cc: &str, mode: &str| {
            serde_json::from_str::<Modes>(&format!(
                r#"{{"congestion_control": "{}", "udp_relay_mode": "{}"}}"#,
                cc, mode
            ))
        };
        let m = parse("new_reno", "quic").unwrap();
        assert_eq!(m.congestion_control, CongestionControl::NewReno);
        assert_eq!(m.udp_relay_mode, UdpRelayMode::Quic);
        assert!(parse("bbr", "native").is_ok());
        assert!(parse("cubic", "native").is_ok());
        assert!(parse("reno", "native").is_err());
        assert!(parse("bbr", "tcp").is_err());
    }

    #[test]
    fn tokens_compare() {
        assert!(tokens_equal(b"abc", b"abc"));
        assert!(!tokens_equal(b"abc", b"abd"));
        assert!(!tokens_equal(b"abc", b"ab"));
    }

    #[test]
    fn activity_counts_guards() {
        let a = Activity::default();
        assert!(!a.is_active());
        let g = a.start();
        let h = a.start();
        drop(g);
        assert!(a.is_active());
        drop(h);
        assert!(!a.is_active());
    }
}
