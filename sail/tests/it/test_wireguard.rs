//! Two WireGuard shells over real UDP sockets on loopback: the handshake,
//! and IP packets both ways.

#![cfg(feature = "wireguard")]

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use sail::protocol::wireguard::crypto;
use sail::protocol::wireguard::{Device, DeviceConfig, PeerConfig, WireGuard};
use sail::runtime::scope::TaskClass;
use tokio::net::UdpSocket;
use tokio::time::timeout;

fn ipv4_udp(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let total = 28 + payload.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&dst);
    p[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    p[28..].copy_from_slice(payload);
    p
}

async fn node(
    private: [u8; 32],
    peer_public: [u8; 32],
    peer_ip: &str,
) -> (
    WireGuard,
    tokio::sync::mpsc::Receiver<sail::protocol::wireguard::shell::InboundPacket>,
    SocketAddr,
    sail::protocol::wireguard::PeerId,
) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let mut dev = Device::new(
        DeviceConfig::new(private),
        tokio::time::Instant::now().into_std(),
    );
    let mut pc = PeerConfig::new(peer_public);
    pc.allowed_ips = vec![(peer_ip.parse::<IpAddr>().unwrap(), 32)];
    let id = dev.add_peer(pc).unwrap();
    let (wg, rx) = crate::common::scoped(async {
        WireGuard::spawn(dev, Arc::new(sock), TaskClass::Essential)
    })
    .await;
    (wg, rx, addr, id)
}

#[tokio::test]
async fn loopback_handshake_and_data() {
    let ka = crypto::generate_private_key();
    let kb = crypto::generate_private_key();
    let (a, mut rx_a, _addr_a, pa) = node(ka, crypto::public_key(&kb), "10.0.0.2").await;
    let (b, mut rx_b, addr_b, pb) = node(kb, crypto::public_key(&ka), "10.0.0.1").await;
    // Only A knows where B is; B learns A's address from the handshake.
    a.with_device(|d, _| (d.set_endpoint(pa, addr_b).unwrap(), Vec::new()))
        .await;

    let p1 = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], b"ping");
    a.send(&p1).await.unwrap();
    let got = timeout(Duration::from_secs(5), rx_b.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.peer, pb);
    assert_eq!(got.packet, p1);

    for i in 0..100u32 {
        let p = ipv4_udp([10, 0, 0, 2], [10, 0, 0, 1], &i.to_be_bytes());
        b.send(&p).await.unwrap();
        let got = timeout(Duration::from_secs(5), rx_a.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.peer, pa);
        assert_eq!(got.packet, p);
    }

    let stats = b
        .with_device(|d, _| (d.peer_stats(pb).unwrap(), Vec::new()))
        .await;
    assert!(stats.has_session);
    assert!(stats.endpoint.is_some());
}
