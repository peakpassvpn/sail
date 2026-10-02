//! `override_destination`: a connection to an address is dialled by the
//! name known for it, the sniffed one or the one sail's DNS answered with,
//! where its last hop is a proxy (or a direct dial too, with
//! `proxy_and_direct`), while the rules match the address.
#![cfg(all(
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct"
))]

use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;

#[cfg(feature = "inbound-direct")]
use sail::session::Network;
use sail::session::{Session, SocksAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common;
use crate::test_route_resolve_proxy::recording_socks_server;

/// A TLS ClientHello naming `name`, as much of one as sniffing reads.
fn client_hello(name: &str) -> Vec<u8> {
    let name = name.as_bytes();
    let mut list = ((3 + name.len()) as u16).to_be_bytes().to_vec();
    list.push(0);
    list.extend_from_slice(&(name.len() as u16).to_be_bytes());
    list.extend_from_slice(name);
    let mut extensions = vec![0, 0];
    extensions.extend_from_slice(&(list.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&list);
    let mut body = vec![3, 3];
    body.extend_from_slice(&[7; 32]);
    body.push(0);
    body.extend_from_slice(&[0, 2, 0x13, 0x01, 1, 0]);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    let mut handshake = vec![1];
    handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&body);
    let mut record = vec![0x16, 3, 1];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

fn to(ip: &str, port: u16) -> Session {
    Session {
        destination: SocksAddr::from(SocketAddr::new(ip.parse().unwrap(), port)),
        ..Default::default()
    }
}

/// Whether `data`, sent through sail's SOCKS `port` to `sess`, comes back
/// from an echo server.
async fn echoed(port: u16, sess: &Session, data: &[u8]) -> bool {
    let Ok(mut s) = common::new_socks_stream("127.0.0.1", port, sess, None, None).await else {
        return false;
    };
    let mut back = vec![0u8; data.len()];
    s.write_all(data).await.is_ok()
        && tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut back))
            .await
            .is_ok_and(|r| r.is_ok())
        && back == data
}

/// What the recording proxy at `asked` is asked for next when `data` goes
/// through sail's SOCKS `port` to `sess`.
async fn asked_for(
    port: u16,
    sess: &Session,
    data: &[u8],
    asked: &Mutex<Vec<String>>,
) -> anyhow::Result<String> {
    let before = asked.lock().unwrap().len();
    let mut s = common::new_socks_stream("127.0.0.1", port, sess, None, None).await?;
    s.write_all(data).await?;
    for _ in 0..50 {
        if let Some(host) = asked.lock().unwrap().get(before) {
            return Ok(host.clone());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    anyhow::bail!("the proxy was asked for nothing")
}

#[cfg(feature = "inbound-direct")]
/// Asks the DNS inbound at `dns` for `name`'s `kind` records, which sail
/// answers itself (hijack-dns), so that its reverse mapping keeps them.
async fn query(dns: u16, name: &str, kind: hickory_proto::rr::RecordType) -> anyhow::Result<()> {
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::Name;

    let mut m = Message::new(9, MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(Name::from_ascii(format!("{}.", name))?, kind));
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    udp.send_to(&m.to_vec()?, ("127.0.0.1", dns)).await?;
    let mut buf = vec![0u8; 1500];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), udp.recv_from(&mut buf)).await??;
    let reply = Message::from_vec(&buf[..n])?;
    anyhow::ensure!(!reply.answers.is_empty(), "{} has no answer", name);
    Ok(())
}

// app(socks, TLS to an address) -> sail(sniff; LAN -> direct; final proxy)
//
// The B2 bug: a sniffed name made the destination before the rules took a
// LAN address from its rule. The rules match the address, so the LAN
// connection goes direct, dialled by its address (the name resolves
// nowhere); one to a public address goes to the proxy, which is asked for
// the server name the client sent.
#[test]
fn a_sniffed_name_goes_to_a_proxy_and_a_lan_address_goes_direct() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let (proxy_port, asked) = rt.block_on(recording_socks_server());
    let (echo, serving) = rt.block_on(common::run_tcp_echo_server("127.0.0.1:0"))?;
    rt.spawn(serving);
    let (ids, port) = common::retry_port_clash(|| {
        let port = common::free_port();
        let config = serde_json::json!({
            "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": port }],
            "outbounds": [
                { "type": "direct", "tag": "direct" },
                { "type": "socks", "tag": "proxy", "server": "127.0.0.1",
                  "server_port": proxy_port }
            ],
            "route": {
                "rules": [
                    { "action": "sniff", "override_destination": true },
                    { "ip_cidr": ["127.0.0.1/32"], "outbound": "direct" }
                ],
                "final": "proxy"
            }
        });
        Ok((
            common::run_sail_instances(&rt, vec![config.to_string()])?,
            port,
        ))
    })?;
    let result = rt.block_on(async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let lan = to("127.0.0.1", echo.port());
        anyhow::ensure!(
            echoed(port, &lan, &client_hello("lan.invalid")).await,
            "the LAN address goes direct, by the address: {:?}",
            asked.lock().unwrap()
        );
        anyhow::ensure!(asked.lock().unwrap().is_empty(), "nothing to the proxy");
        let public = to("192.0.2.10", 443);
        let host = asked_for(port, &public, &client_hello("sni.test"), &asked).await?;
        anyhow::ensure!(host == "sni.test", "the proxy is asked for {}", host);
        anyhow::Ok(())
    });
    common::shutdown_instances(&rt, ids);
    result
}

// dns client -> (hijack-dns)sail; app(socks, to an address) ->
// sail(override_destination) -> proxy
//
// Without a sniffed name the proxy is asked for the name sail's DNS
// answered with for the address, also where the HTTP Host is an address,
// until the answer's TTL runs out; then for the address.
#[cfg(feature = "inbound-direct")]
#[test]
fn a_proxy_is_asked_for_the_name_sail_answered_until_its_ttl() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let (proxy_port, asked) = rt.block_on(recording_socks_server());
    let (ids, (port, dns)) = common::retry_port_clash(|| {
        let [port, dns] = common::free_ports();
        let config = serde_json::json!({
            "dns": {
                "servers": [{ "type": "hosts", "tag": "hosts",
                              "predefined": { "mapped.test": "192.0.2.20" } }],
                "rules": [{ "action": "route", "server": "hosts", "rewrite_ttl": 2 }],
                "final": "hosts",
                "reverse_mapping": true
            },
            "inbounds": [
                { "type": "socks", "tag": "socks", "listen": "127.0.0.1", "listen_port": port },
                { "type": "direct", "tag": "dns-in", "listen": "127.0.0.1", "listen_port": dns }
            ],
            "outbounds": [
                { "type": "socks", "tag": "proxy", "server": "127.0.0.1",
                  "server_port": proxy_port }
            ],
            "route": {
                "rules": [
                    { "inbound": "dns-in", "action": "hijack-dns" },
                    { "action": "sniff", "timeout": "100ms" },
                    { "inbound": "socks", "action": "route-options",
                      "override_destination": "proxy" }
                ],
                "final": "proxy"
            }
        });
        Ok((
            common::run_sail_instances(&rt, vec![config.to_string()])?,
            (port, dns),
        ))
    })?;
    let result = rt.block_on(async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let sess = to("192.0.2.20", 80);
        let plain = b"\x00\x01plain";
        let host = asked_for(port, &sess, plain, &asked).await?;
        anyhow::ensure!(host == "192.0.2.20", "nothing named the address: {}", host);

        query(dns, "mapped.test", hickory_proto::rr::RecordType::A).await?;
        let host = asked_for(port, &sess, plain, &asked).await?;
        anyhow::ensure!(host == "mapped.test", "named by the DNS: {}", host);
        let by_address = b"GET / HTTP/1.1\r\nHost: 192.0.2.20\r\n\r\n";
        let host = asked_for(port, &sess, by_address, &asked).await?;
        anyhow::ensure!(host == "mapped.test", "a Host that is an address: {}", host);
        let named = b"GET / HTTP/1.1\r\nHost: host.test\r\n\r\n";
        let host = asked_for(port, &sess, named, &asked).await?;
        anyhow::ensure!(host == "host.test", "a Host that is a name wins: {}", host);

        tokio::time::sleep(Duration::from_millis(2500)).await;
        let host = asked_for(port, &sess, plain, &asked).await?;
        anyhow::ensure!(host == "192.0.2.20", "the TTL ran out: {}", host);
        anyhow::Ok(())
    });
    common::shutdown_instances(&rt, ids);
    result
}

// app(socks) -> sail(resolve, override_destination) -> proxy
//
// With both, the proxy is asked for the name, not the address the resolve
// action resolved it to.
#[test]
fn the_override_beats_a_resolve_for_a_proxy() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let (proxy_port, asked) = rt.block_on(recording_socks_server());
    let (ids, port) = common::retry_port_clash(|| {
        let port = common::free_port();
        let config = serde_json::json!({
            "dns": { "servers": [
                { "type": "hosts", "predefined": { "resolve.test": "127.0.0.7" } }
            ] },
            "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": port }],
            "outbounds": [{ "type": "socks", "tag": "proxy",
                            "server": "127.0.0.1", "server_port": proxy_port }],
            "route": {
                "rules": [
                    { "action": "resolve" },
                    { "action": "route-options", "override_destination": true }
                ],
                "final": "proxy",
            },
        });
        Ok((
            common::run_sail_instances(&rt, vec![config.to_string()])?,
            port,
        ))
    })?;
    let result = rt.block_on(async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let sess = Session {
            destination: SocksAddr::Domain("resolve.test".into(), 80),
            ..Default::default()
        };
        asked_for(port, &sess, b"x", &asked).await
    });
    common::shutdown_instances(&rt, ids);
    let host = result?;
    anyhow::ensure!(host == "resolve.test", "the proxy is asked for {}", host);
    Ok(())
}

// dns client -> (hijack-dns)sail; app(socks, UDP to an address) ->
// sail(override_destination) -> (socks)sail -> udp echo
//
// Datagrams go to the name, and the answers come back from the address the
// client sent to; or, with `udp_disable_domain_unmapping`, from the name.
#[cfg(feature = "inbound-direct")]
#[test]
fn answers_to_the_name_come_back_as_the_option_says() -> anyhow::Result<()> {
    for disabled in [false, true] {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let (echo, serving) = rt.block_on(common::run_udp_echo_server("127.0.0.1:0"))?;
        rt.spawn(serving);
        let (ids, (port, dns)) = common::retry_port_clash(|| {
            let [port, dns, proxy_port] = common::free_ports();
            let proxy = serde_json::json!({
                "dns": { "servers": [
                    { "type": "hosts", "predefined": { "udp.test": "127.0.0.1" } }
                ] },
                "inbounds": [{ "type": "socks", "listen": "127.0.0.1",
                               "listen_port": proxy_port }],
                "outbounds": [{ "type": "direct" }],
            });
            let config = serde_json::json!({
                "dns": {
                    "servers": [{ "type": "hosts", "tag": "hosts",
                                  "predefined": { "udp.test": "192.0.2.30" } }],
                    "final": "hosts",
                    "reverse_mapping": true
                },
                "inbounds": [
                    { "type": "socks", "listen": "127.0.0.1", "listen_port": port },
                    { "type": "direct", "tag": "dns-in", "listen": "127.0.0.1",
                      "listen_port": dns }
                ],
                "outbounds": [{ "type": "socks", "tag": "proxy",
                                "server": "127.0.0.1", "server_port": proxy_port }],
                "route": {
                    "rules": [
                        { "inbound": "dns-in", "action": "hijack-dns" },
                        { "action": "route-options", "override_destination": true,
                          "udp_timeout": "30s", "udp_disable_domain_unmapping": disabled }
                    ],
                    "final": "proxy",
                },
            });
            Ok((
                common::run_sail_instances(&rt, vec![proxy.to_string(), config.to_string()])?,
                (port, dns),
            ))
        })?;
        let result = rt.block_on(async {
            tokio::time::sleep(Duration::from_millis(200)).await;
            query(dns, "udp.test", hickory_proto::rr::RecordType::A).await?;
            let sess = Session {
                network: Network::Udp,
                ..to("192.0.2.30", echo.port())
            };
            let (mut recv, mut send) =
                common::new_socks_datagram("127.0.0.1", port, &sess, None, None)
                    .await?
                    .split();
            send.send_to(b"x", &sess.destination).await?;
            let mut buf = [0u8; 16];
            let (_, from) =
                tokio::time::timeout(Duration::from_secs(10), recv.recv_from(&mut buf)).await??;
            anyhow::Ok((from, sess.destination))
        });
        common::shutdown_instances(&rt, ids);
        let (from, asked) = result?;
        let expected = if disabled {
            SocksAddr::Domain("udp.test".into(), echo.port())
        } else {
            asked
        };
        anyhow::ensure!(from == expected, "disabled {}: from {}", disabled, from);
    }
    Ok(())
}

// dns client -> (hijack-dns)sail; app(socks, to [2001:db8::50]) ->
// sail(override_destination: proxy_and_direct for global IPv6) -> direct,
// which resolves the name IPv4 only -> echo on 127.0.0.1
//
// A host with IPv6 on but no IPv6 egress: a direct dial goes to the name,
// which the direct outbound's own domain_resolver resolves to its IPv4
// address, over TCP with the name an HTTP Host or a TLS server name gives,
// or the one sail's DNS answered with (an HTTP/1.0 request without a Host),
// and over UDP; and the name is still known after an in-place reload, with
// no DNS query since. "proxy" leaves a direct dial the address.
#[cfg(feature = "inbound-direct")]
#[test]
fn proxy_and_direct_dials_a_direct_ipv6_destination_by_its_ipv4_name() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let (tcp_echo, serving) = rt.block_on(common::run_tcp_echo_server("127.0.0.1:0"))?;
    rt.spawn(serving);
    let (udp_echo, serving) = rt.block_on(common::run_udp_echo_server("127.0.0.1:0"))?;
    rt.spawn(serving);
    let config = |port: u16, dns: u16, how: &str| {
        serde_json::json!({
            "dns": {
                "servers": [{ "type": "hosts", "tag": "local",
                              "predefined": { "dual.lab.test": ["127.0.0.1", "2001:db8::50"] } }],
                "final": "local",
                "reverse_mapping": true
            },
            "inbounds": [
                { "type": "socks", "tag": "tun", "listen": "127.0.0.1", "listen_port": port },
                { "type": "direct", "tag": "dns-in", "listen": "127.0.0.1", "listen_port": dns }
            ],
            "outbounds": [{ "type": "direct", "tag": "direct",
                            "domain_resolver": { "server": "local", "strategy": "ipv4_only" } }],
            "route": {
                "rules": [
                    { "inbound": "dns-in", "action": "hijack-dns" },
                    { "action": "sniff", "timeout": "100ms" },
                    { "protocol": "dns", "action": "hijack-dns" },
                    { "inbound": ["tun"], "ip_cidr": ["2000::/3"], "action": "route-options",
                      "override_destination": how, "udp_timeout": "30s" }
                ],
                "final": "direct"
            }
        })
        .to_string()
    };
    let (ids, (port, dns)) = common::retry_port_clash(|| {
        let [port, dns] = common::free_ports();
        Ok((
            common::run_sail_instances(&rt, vec![config(port, dns, "proxy_and_direct")])?,
            (port, dns),
        ))
    })?;
    let id = ids[0];
    let udp_round = |port: u16| async move {
        let sess = Session {
            network: Network::Udp,
            ..to("2001:db8::50", udp_echo.port())
        };
        let (mut recv, mut send) = common::new_socks_datagram("127.0.0.1", port, &sess, None, None)
            .await?
            .split();
        send.send_to(b"x", &sess.destination).await?;
        let mut buf = [0u8; 16];
        let (_, from) =
            tokio::time::timeout(Duration::from_secs(5), recv.recv_from(&mut buf)).await??;
        anyhow::ensure!(from == sess.destination, "the answer comes from {}", from);
        anyhow::Ok(())
    };
    let result = rt.block_on(async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let v6 = to("2001:db8::50", tcp_echo.port());
        // 1. An HTTP Host.
        anyhow::ensure!(
            echoed(port, &v6, b"GET / HTTP/1.1\r\nHost: dual.lab.test\r\n\r\n").await,
            "an HTTP Host"
        );
        // 2. A TLS server name.
        anyhow::ensure!(
            echoed(port, &v6, &client_hello("dual.lab.test")).await,
            "a TLS server name"
        );
        // 3. No Host: the name sail's DNS answered with.
        anyhow::ensure!(
            !echoed(port, &v6, b"GET / HTTP/1.0\r\n\r\n").await,
            "nothing names the address yet"
        );
        query(dns, "dual.lab.test", hickory_proto::rr::RecordType::AAAA).await?;
        anyhow::ensure!(
            echoed(port, &v6, b"GET / HTTP/1.0\r\n\r\n").await,
            "an HTTP/1.0 request without a Host"
        );
        // 4. UDP, by the name sail's DNS answered with.
        udp_round(port).await?;
        // 5. Again after an in-place reload, with no query since.
        let reloaded = sail::config::from_string(&config(port, dns, "proxy_and_direct"))
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        sail::runtime_manager(id)
            .ok_or_else(|| anyhow::anyhow!("no instance"))?
            .reload_with(reloaded)
            .await
            .map_err(|e| anyhow::anyhow!("reload: {}", e))?;
        udp_round(port).await?;
        // "proxy" leaves a direct dial the address, which is unreachable.
        let proxy_only = sail::config::from_string(&config(port, dns, "proxy"))
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        sail::runtime_manager(id)
            .ok_or_else(|| anyhow::anyhow!("no instance"))?
            .reload_with(proxy_only)
            .await
            .map_err(|e| anyhow::anyhow!("reload: {}", e))?;
        anyhow::ensure!(
            !echoed(port, &v6, b"GET / HTTP/1.1\r\nHost: dual.lab.test\r\n\r\n").await,
            "with proxy, a direct dial keeps the address"
        );
        anyhow::Ok(())
    });
    common::shutdown_instances(&rt, ids);
    result
}

// app(socks, TLS to an address) -> sail, read from a Clash configuration
// whose sniffer overrides the destination -> direct
//
// As Mihomo's: the sniffed name is the destination for the rules after,
// and a rule on addresses resolves it; the direct dial goes to the name.
#[cfg(all(feature = "config-clash", feature = "inbound-mixed"))]
#[test]
fn the_clash_sniffer_overrides_the_destination_as_mihomo_does() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let (echo, serving) = rt.block_on(common::run_tcp_echo_server("127.0.0.1:0"))?;
    rt.spawn(serving);
    let (ids, port) = common::retry_port_clash(|| {
        let port = common::free_port();
        let yaml = format!(
            "mixed-port: {port}\n\
             log-level: silent\n\
             hosts:\n  sni.test: 127.0.0.1\n\
             sniffer:\n  enable: true\n  sniff:\n    TLS: {{ ports: [{echo}] }}\n\
             rules:\n  - IP-CIDR,127.0.0.1/32,DIRECT\n  - MATCH,REJECT\n",
            port = port,
            echo = echo.port()
        );
        Ok((common::run_sail_instances(&rt, vec![yaml])?, port))
    })?;
    let result = rt.block_on(async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let sess = to("192.0.2.40", echo.port());
        anyhow::ensure!(
            echoed(port, &sess, &client_hello("sni.test")).await,
            "the name, resolved by the rule on addresses, goes direct"
        );
        anyhow::Ok(())
    });
    common::shutdown_instances(&rt, ids);
    result
}
