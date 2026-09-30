//! `detour`: an outbound's TCP and UDP carried by another outbound in place
//! of sockets of its own, for protocols over streams and over QUIC alike,
//! and for DNS servers.
//!
//! The detour here is a socks outbound to a SOCKS5 server of the test's,
//! which counts what it carries and alone knows the name `far.test`: the
//! instances resolve nothing, so a connection to `far.test` that arrives
//! went through the detour, the name unresolved.

#![cfg(all(
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct",
))]

#[allow(unused_imports)] // Unused where features leave out every test.
use crate::common;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

/// The name only the SOCKS5 server here resolves.
const FAR: &str = "far.test";

/// What the SOCKS5 server carried.
#[derive(Default)]
struct Carried {
    connections: AtomicUsize,
    associations: AtomicUsize,
    datagrams: AtomicUsize,
}

/// A SOCKS5 server (CONNECT and UDP ASSOCIATE, no authentication) on a
/// thread of its own, and its port. It resolves `FAR` to 127.0.0.1 and
/// nothing else.
fn start_socks() -> (u16, Arc<Carried>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let carried = Arc::new(Carried::default());
    let c = carried.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let listener = TcpListener::from_std(listener).unwrap();
            while let Ok((stream, _)) = listener.accept().await {
                let c = c.clone();
                tokio::spawn(async move {
                    let _ = serve(stream, c).await;
                });
            }
        });
    });
    (port, carried)
}

/// Reads a SOCKS5 address, port last, resolving `FAR`.
fn address(buf: &[u8]) -> Option<(SocketAddr, usize)> {
    match buf.first()? {
        0x01 => {
            let b = buf.get(1..7)?;
            let ip = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
            let port = u16::from_be_bytes([b[4], b[5]]);
            Some((SocketAddr::new(ip.into(), port), 7))
        }
        0x03 => {
            let len = *buf.get(1)? as usize;
            let name = std::str::from_utf8(buf.get(2..2 + len)?).ok()?;
            let port = u16::from_be_bytes([*buf.get(2 + len)?, *buf.get(3 + len)?]);
            (name == FAR).then(|| (SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port), 4 + len))
        }
        _ => None,
    }
}

fn reply(bound: SocketAddr) -> Vec<u8> {
    let IpAddr::V4(ip) = bound.ip() else {
        unreachable!("bound on 127.0.0.1")
    };
    let mut reply = vec![0x05, 0x00, 0x00, 0x01];
    reply.extend_from_slice(&ip.octets());
    reply.extend_from_slice(&bound.port().to_be_bytes());
    reply
}

async fn serve(mut stream: TcpStream, carried: Arc<Carried>) -> anyhow::Result<()> {
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    let mut methods = vec![0u8; greeting[1] as usize];
    stream.read_exact(&mut methods).await?;
    stream.write_all(&[0x05, 0x00]).await?;
    let mut request = [0u8; 3];
    stream.read_exact(&mut request).await?;
    let mut addr = vec![0u8; 262];
    let mut n = 0;
    let target = loop {
        n += stream.read(&mut addr[n..n + 1]).await?;
        if let Some((target, len)) = address(&addr[..n]) {
            if len == n {
                break target;
            }
        }
        anyhow::ensure!(n < addr.len(), "no address");
    };
    match request[1] {
        0x01 => {
            let mut remote = TcpStream::connect(target).await?;
            carried.connections.fetch_add(1, Ordering::SeqCst);
            stream
                .write_all(&reply(remote.local_addr().unwrap()))
                .await?;
            tokio::io::copy_bidirectional(&mut stream, &mut remote).await?;
        }
        0x03 => {
            let relay = UdpSocket::bind("127.0.0.1:0").await?;
            let out = UdpSocket::bind("127.0.0.1:0").await?;
            carried.associations.fetch_add(1, Ordering::SeqCst);
            stream.write_all(&reply(relay.local_addr()?)).await?;
            let mut client = None;
            let (mut a, mut b) = (vec![0u8; 65536], vec![0u8; 65536]);
            let mut control = [0u8; 1];
            loop {
                tokio::select! {
                    r = relay.recv_from(&mut a) => {
                        let (n, from) = r?;
                        client = Some(from);
                        let Some((to, len)) = address(&a[3..n]) else { continue };
                        carried.datagrams.fetch_add(1, Ordering::SeqCst);
                        out.send_to(&a[3 + len..n], to).await?;
                    }
                    r = out.recv_from(&mut b) => {
                        let (n, from) = r?;
                        let Some(client) = client else { continue };
                        let mut packet = reply(from);
                        packet[..3].copy_from_slice(&[0, 0, 0]);
                        packet.extend_from_slice(&b[..n]);
                        relay.send_to(&packet, client).await?;
                    }
                    r = stream.read(&mut control) => {
                        if r? == 0 {
                            return Ok(());
                        }
                    }
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// DNS that resolves nothing: what is dialled by name is the detour's to
/// resolve.
fn no_dns() -> serde_json::Value {
    json!({ "servers": [
        { "type": "hosts", "tag": "none", "predefined": { "nothing.test": "127.0.0.1" } }
    ] })
}

/// The detour, a socks outbound to the SOCKS5 server here on `port`.
fn hop(port: u16) -> serde_json::Value {
    json!({ "type": "socks", "tag": "hop", "server": "127.0.0.1", "server_port": port })
}

/// sail: socks on `socks_port`, out through `proxy`, which detours through
/// `hop`.
fn client(socks_port: u16, proxy: serde_json::Value, hop_port: u16) -> String {
    json!({
        "dns": no_dns(),
        "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": socks_port }],
        "outbounds": [proxy, hop(hop_port)],
    })
    .to_string()
}

/// A proxy protocol over streams (socks), and its UDP, through the detour:
/// the SOCKS5 server here carries both, and the proxy's server, named
/// `far.test`, is reached only as it resolves there.
#[test]
fn tcp_and_udp_go_through_the_detour() -> anyhow::Result<()> {
    let (hop_port, carried) = start_socks();
    common::retry_port_clash(|| {
        let [socks_port, server_port] = common::free_ports();
        let proxy = json!({ "type": "socks", "tag": "proxy", "server": FAR,
            "server_port": server_port, "detour": "hop" });
        let server = json!({
            "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": server_port }],
            "outbounds": [{ "type": "direct" }],
        })
        .to_string();
        common::test_configs(
            vec![client(socks_port, proxy, hop_port), server],
            "127.0.0.1",
            socks_port,
        )
    })?;
    assert!(carried.connections.load(Ordering::SeqCst) > 0);
    assert!(carried.associations.load(Ordering::SeqCst) > 0);
    assert!(carried.datagrams.load(Ordering::SeqCst) > 0);
    Ok(())
}

/// A self-signed certificate for localhost, as PEM.
#[cfg(any(feature = "outbound-hysteria2", feature = "outbound-tuic"))]
fn cert() -> (String, String) {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    (cert.pem(), key_pair.serialize_pem())
}

/// Hysteria2's QUIC over the detour's UDP: the server named `far.test`,
/// its datagrams carried by the SOCKS5 server here.
#[cfg(all(feature = "inbound-hysteria2", feature = "outbound-hysteria2"))]
#[test]
fn hysteria2_goes_through_the_detour() -> anyhow::Result<()> {
    let (cert, key) = cert();
    let (hop_port, carried) = start_socks();
    common::retry_port_clash(|| {
        let [socks_port, server_port] = common::free_ports();
        let proxy = json!({
            "type": "hysteria2", "tag": "proxy", "server": FAR, "server_port": server_port,
            "password": "pw", "detour": "hop",
            "tls": { "enabled": true, "server_name": "localhost", "certificate": cert },
        });
        let server = json!({
            "inbounds": [{
                "type": "hysteria2", "listen": "127.0.0.1", "listen_port": server_port,
                "users": [{ "name": "alice", "password": "pw" }],
                "tls": { "enabled": true, "certificate": cert, "key": key },
            }],
            "outbounds": [{ "type": "direct" }],
        })
        .to_string();
        common::test_configs(
            vec![client(socks_port, proxy, hop_port), server],
            "127.0.0.1",
            socks_port,
        )
    })?;
    assert!(carried.associations.load(Ordering::SeqCst) > 0);
    assert!(carried.datagrams.load(Ordering::SeqCst) > 0);
    assert_eq!(carried.connections.load(Ordering::SeqCst), 0);
    Ok(())
}

/// TUIC's QUIC over the detour's UDP, as Hysteria2's.
#[cfg(all(feature = "inbound-tuic", feature = "outbound-tuic"))]
#[test]
fn tuic_goes_through_the_detour() -> anyhow::Result<()> {
    const UUID: &str = "2dd61d93-75d8-4da4-ac0e-6aece7eac365";
    let (cert, key) = cert();
    let (hop_port, carried) = start_socks();
    common::retry_port_clash(|| {
        let [socks_port, server_port] = common::free_ports();
        let proxy = json!({
            "type": "tuic", "tag": "proxy", "server": FAR, "server_port": server_port,
            "uuid": UUID, "password": "pw", "detour": "hop",
            "tls": { "enabled": true, "server_name": "localhost", "alpn": ["h3"],
                "certificate": cert },
        });
        let server = json!({
            "inbounds": [{
                "type": "tuic", "listen": "127.0.0.1", "listen_port": server_port,
                "users": [{ "name": "alice", "uuid": UUID, "password": "pw" }],
                "tls": { "enabled": true, "alpn": ["h3"], "certificate": cert, "key": key },
            }],
            "outbounds": [{ "type": "direct" }],
        })
        .to_string();
        common::test_configs(
            vec![client(socks_port, proxy, hop_port), server],
            "127.0.0.1",
            socks_port,
        )
    })?;
    assert!(carried.associations.load(Ordering::SeqCst) > 0);
    assert!(carried.datagrams.load(Ordering::SeqCst) > 0);
    Ok(())
}

/// A DNS server over QUIC through the detour: the query reaches the
/// server, and the SOCKS5 server here carried it.
#[cfg(all(feature = "tls", feature = "quic", feature = "dns-h3"))]
#[test]
fn a_doq_server_goes_through_the_detour() -> anyhow::Result<()> {
    use crate::test_dns_upstreams as doq;
    let (hop_port, carried) = start_socks();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let cert = doq::cert();
    let (doq_port, counters) = rt.block_on(async { doq::start_doq_server(&cert) });
    let socks_port = common::free_port();
    let config = json!({
        "dns": {
            "servers": [{
                "type": "quic", "tag": "doq", "server": "127.0.0.1", "server_port": doq_port,
                "detour": "hop",
                "tls": { "server_name": "localhost", "certificate": cert.cert_pem },
            }],
            "strategy": "ipv4_only",
        },
        "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": socks_port }],
        "outbounds": [{ "type": "direct", "tag": "direct" }, hop(hop_port)],
        "route": { "final": "direct" },
    })
    .to_string();
    let ids = common::run_sail_instances(&rt, vec![config])?;
    // The name resolves, with the DoQ server's answer, which is nowhere to
    // connect to: the connection may fail, the query is what counts.
    let sess = sail::session::Session {
        destination: sail::session::SocksAddr::Domain("anything.example".into(), 80),
        ..Default::default()
    };
    rt.block_on(async {
        let stream = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            common::new_socks_stream("127.0.0.1", socks_port, &sess, None, None),
        )
        .await;
        // The socks inbound answers before the outbound dials: what is
        // written waits on it.
        if let Ok(Ok(mut stream)) = stream {
            let _ = stream.write_all(b"GET / HTTP/1.0\r\n\r\n").await;
            let mut buf = [0u8; 16];
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf))
                .await;
        }
    });
    common::shutdown_instances(&rt, ids);
    assert!(counters.queries.load(Ordering::SeqCst) > 0);
    assert!(carried.datagrams.load(Ordering::SeqCst) > 0);
    Ok(())
}
