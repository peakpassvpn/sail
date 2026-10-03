//! A relayed connection's life, which the task routing it holds once the
//! inbound has handed it over: it is closed when asked, counted against
//! its user while it lives and no longer, and runs on when its inbound
//! stops listening, and ends when the inbound is removed.

#![cfg(all(
    feature = "inbound-socks",
    feature = "inbound-trojan",
    feature = "outbound-direct",
    feature = "outbound-trojan"
))]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use anyhow::{ensure, Result};

use crate::common;

fn echo_server() -> u16 {
    let echo = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = echo.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in echo.incoming() {
            let Ok(mut s) = s else { return };
            std::thread::spawn(move || {
                let mut buf = [0u8; 64];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 || s.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

/// A SOCKS5 connection through `proxy` to 127.0.0.1:`port`, past its
/// reply.
fn connect(proxy: u16, port: u16) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect(("127.0.0.1", proxy))?;
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    greet(&mut s)?;
    request(&mut s, port)?;
    Ok(s)
}

/// The SOCKS5 greeting on `s`, past its answer: the inbound has accepted
/// the connection, which is in its handshake.
fn greet(s: &mut TcpStream) -> std::io::Result<()> {
    s.write_all(&[5, 1, 0])?;
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply)
}

/// The SOCKS5 request for 127.0.0.1:`port` on `s`, greeted, past the
/// reply.
fn request(s: &mut TcpStream, port: u16) -> std::io::Result<()> {
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend(port.to_be_bytes());
    s.write_all(&request)?;
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply)?;
    if reply[1] != 0 {
        return Err(std::io::Error::other(format!("SOCKS REP {}", reply[1])));
    }
    Ok(())
}

/// Whether `s` relays a byte to the echo server and back; false when it
/// is closed, at once or within its read timeout.
fn echoes(s: &mut TcpStream) -> bool {
    let mut b = [0u8; 1];
    s.write_all(b"x").is_ok() && matches!(s.read(&mut b), Ok(1)) && b == *b"x"
}

/// Whether `s` is closed: a read ends, with nothing.
fn closed(s: &mut TcpStream) -> bool {
    let mut b = [0u8; 1];
    matches!(s.read(&mut b), Ok(0) | Err(_))
}

fn until(what: &str, mut f: impl FnMut() -> bool) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !f() {
        ensure!(Instant::now() < deadline, "{} within 10s", what);
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// A SOCKS inbound named `in` to direct.
fn socks_to_direct(rt: &tokio::runtime::Runtime) -> Result<(sail::RuntimeId, u16)> {
    common::retry_port_clash(|| {
        let [socks] = common::free_ports();
        let config = serde_json::json!({
            "inbounds": [{ "type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": socks }],
            "outbounds": [{ "type": "direct" }],
        });
        Ok((
            common::run_sail_instances(rt, vec![config.to_string()])?[0],
            socks,
        ))
    })
}

#[test]
fn a_relayed_connection_is_closed_when_asked() -> Result<()> {
    let echo = echo_server();
    let rt = runtime();
    let (id, socks) = socks_to_direct(&rt)?;
    let result = (|| {
        let mut a = connect(socks, echo)?;
        ensure!(echoes(&mut a), "relayed");
        let stats = sail::runtime_manager(id).unwrap().stat_manager();
        ensure!(stats.close_all() == 1, "one connection to close");
        ensure!(closed(&mut a), "closed when asked");
        until("no connection left", || stats.live() == 0)
    })();
    sail::shutdown(id);
    result
}

#[test]
fn a_relayed_connection_outlives_its_inbound() -> Result<()> {
    let echo = echo_server();
    let rt = runtime();
    let (id, socks) = socks_to_direct(&rt)?;
    let result = (|| {
        let mut a = connect(socks, echo)?;
        ensure!(echoes(&mut a), "relayed");
        let manager = sail::runtime_manager(id).unwrap();
        // Its listener's tasks end; the relay, a task of its own, does not
        // depend on them. (remove_inbound disconnects it besides: below.)
        rt.block_on(manager.stop_listening("in"))?;
        until("the inbound stops accepting", || {
            TcpStream::connect(("127.0.0.1", socks)).is_err()
        })?;
        ensure!(echoes(&mut a), "relayed after its inbound's tasks went");
        Ok(())
    })();
    sail::shutdown(id);
    result
}

/// Removing an inbound disconnects the connections it accepted, at once;
/// another inbound's go on.
#[test]
fn a_relayed_connection_ends_when_its_inbound_is_removed() -> Result<()> {
    let echo = echo_server();
    let rt = runtime();
    let (id, removed, kept) = common::retry_port_clash(|| {
        let [removed, kept] = common::free_ports();
        let config = serde_json::json!({
            "inbounds": [
                { "type": "socks", "tag": "removed", "listen": "127.0.0.1", "listen_port": removed },
                { "type": "socks", "tag": "kept", "listen": "127.0.0.1", "listen_port": kept },
            ],
            "outbounds": [{ "type": "direct" }],
        });
        Ok((
            common::run_sail_instances(&rt, vec![config.to_string()])?[0],
            removed,
            kept,
        ))
    })?;
    let result = (|| {
        let mut a = connect(removed, echo)?;
        let mut b = connect(kept, echo)?;
        ensure!(echoes(&mut a) && echoes(&mut b), "relayed");
        let manager = sail::runtime_manager(id).unwrap();
        rt.block_on(manager.remove_inbound("removed"))?;
        ensure!(closed(&mut a), "its inbound's connection ends");
        ensure!(echoes(&mut b), "another inbound's goes on");
        Ok(())
    })();
    sail::shutdown(id);
    result
}

/// A connection still in its handshake is not yet among those the runtime
/// lists. It ends with its inbound all the same when the inbound is
/// removed, and goes on to be relayed when only the listener stops.
#[test]
fn a_connection_in_its_handshake_ends_when_its_inbound_is_removed() -> Result<()> {
    let echo = echo_server();
    let rt = runtime();
    let (id, removed, stopped) = common::retry_port_clash(|| {
        let [removed, stopped] = common::free_ports();
        let config = serde_json::json!({
            "inbounds": [
                { "type": "socks", "tag": "removed", "listen": "127.0.0.1", "listen_port": removed },
                { "type": "socks", "tag": "stopped", "listen": "127.0.0.1", "listen_port": stopped },
            ],
            "outbounds": [{ "type": "direct" }],
        });
        Ok((
            common::run_sail_instances(&rt, vec![config.to_string()])?[0],
            removed,
            stopped,
        ))
    })?;
    let result = (|| {
        // Both greeted, so accepted, and neither has asked for anything:
        // in their handshake.
        let mut a = TcpStream::connect(("127.0.0.1", removed))?;
        let mut b = TcpStream::connect(("127.0.0.1", stopped))?;
        a.set_read_timeout(Some(Duration::from_secs(5)))?;
        b.set_read_timeout(Some(Duration::from_secs(5)))?;
        greet(&mut a)?;
        greet(&mut b)?;
        let manager = sail::runtime_manager(id).unwrap();
        rt.block_on(manager.stop_listening("stopped"))?;
        rt.block_on(manager.remove_inbound("removed"))?;
        ensure!(closed(&mut a), "in its handshake, it ends with its inbound");
        request(&mut b, echo)?;
        ensure!(echoes(&mut b), "its listener stopped, it is relayed still");
        Ok(())
    })();
    sail::shutdown(id);
    result
}

/// A connection that carries streams is not among those the runtime lists
/// either: its streams are. Removing its inbound ends it, so that no new
/// stream is opened on it.
#[cfg(feature = "mux")]
#[test]
fn a_connection_carrying_streams_ends_when_its_inbound_is_removed() -> Result<()> {
    let echo = echo_server();
    let rt = runtime();
    let (ids, socks) = common::retry_port_clash(|| {
        let [trojan, socks] = common::free_ports();
        let server = serde_json::json!({
            "inbounds": [{ "type": "trojan", "tag": "t", "listen": "127.0.0.1", "listen_port": trojan,
                           "users": [{ "name": "alice", "password": "a" }],
                           "multiplex": { "enabled": true } }],
            "outbounds": [{ "type": "direct" }],
        });
        let client = serde_json::json!({
            "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": socks }],
            "outbounds": [{ "type": "trojan", "server": "127.0.0.1", "server_port": trojan,
                            "password": "a", "multiplex": { "enabled": true } }],
        });
        Ok((
            common::run_sail_instances(&rt, vec![server.to_string(), client.to_string()])?,
            socks,
        ))
    })?;
    let result = (|| {
        let mut a = connect(socks, echo)?;
        ensure!(echoes(&mut a), "relayed over the carrier");
        let server = sail::runtime_manager(ids[0]).unwrap();
        rt.block_on(server.remove_inbound("t"))?;
        ensure!(closed(&mut a), "its stream ends");
        // The client opens its next stream on the carrier it has, while it
        // has one; once the carrier is gone it dials, and nothing listens.
        until("no stream is relayed any more", || {
            !connect(socks, echo).is_ok_and(|mut s| echoes(&mut s))
        })
    })();
    for id in ids {
        sail::shutdown(id);
    }
    result
}

/// A user's `max_connections` counts a connection for as long as it is
/// relayed, and no longer: were the count given back when the inbound's
/// part ended, a second connection would be let in.
#[test]
fn a_user_s_connection_counts_while_it_is_relayed() -> Result<()> {
    let echo = echo_server();
    let rt = runtime();
    let (ids, socks) = common::retry_port_clash(|| {
        let [trojan, socks] = common::free_ports();
        let server = serde_json::json!({
            "inbounds": [{ "type": "trojan", "tag": "t", "listen": "127.0.0.1", "listen_port": trojan,
                           "users": [{ "name": "alice", "password": "a" }] }],
            "outbounds": [{ "type": "direct" }],
            "user_limits": { "alice": { "max_connections": 1 } },
        });
        let client = serde_json::json!({
            "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": socks }],
            "outbounds": [{ "type": "trojan", "server": "127.0.0.1", "server_port": trojan,
                            "password": "a" }],
        });
        Ok((
            common::run_sail_instances(&rt, vec![server.to_string(), client.to_string()])?,
            socks,
        ))
    })?;
    let result = (|| {
        let server = sail::runtime_manager(ids[0]).unwrap().stat_manager();
        let mut a = connect(socks, echo)?;
        ensure!(echoes(&mut a), "alice's first connection is relayed");
        ensure!(server.live() == 1, "and counted");
        let mut b = connect(socks, echo)?;
        ensure!(
            !echoes(&mut b),
            "a second one is refused while the first lives"
        );
        drop(a);
        until("the first connection ends", || server.live() == 0)?;
        let mut c = connect(socks, echo)?;
        ensure!(echoes(&mut c), "then one is relayed again");
        Ok(())
    })();
    for id in ids {
        sail::shutdown(id);
    }
    result
}
