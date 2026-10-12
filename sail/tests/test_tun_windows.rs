//! Real traffic through a Wintun adapter: what tun-macos's script and the
//! Android emulator show of the other systems. auto_route sends
//! 198.18.0.0/15 and 2001:db8::/32 into the TUN; a route rule overrides
//! 198.18.0.10 to 127.0.0.1 and 2001:db8::10 to ::1, where echo servers
//! listen, so a reply proves the round trip through the adapter, sail's
//! netstack and the direct outbound:
//! - DNS queries to the TUN's servers of both families, hijacked and
//!   answered by a hosts server;
//! - a 256 KiB TCP echo and 20 UDP echoes, over IPv4 and IPv6;
//! - a stop and a start again, with the traffic once more.
//!
//! Throughout, nothing is told of the system changing (the integrity
//! events are for what others change, tests/test_tun_integrity_windows.rs),
//! and each stop leaves no adapter, route or DNS server behind.
//!
//! As administrator, with wintun.dll beside the test: CI's tun-windows
//! job. Only test prefixes are routed: the runner's own traffic stays out.
#![cfg(all(
    target_os = "windows",
    feature = "inbound-tun",
    feature = "outbound-direct"
))]
// The test's own echo servers, no instance's tasks.
#![allow(clippy::disallowed_methods)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::Command;
use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Context, Result};
use futures::{Stream, StreamExt};
use sail::embed::{Config, Event, Instance, Kinds, LeftKind, Options, RunDir};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

/// Where the echo servers listen, on both loopbacks.
const PORT: u16 = 18877;

/// The addresses the route rules send to the loopbacks.
const TARGET_V4: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 10);
const TARGET_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10);

/// The TUN's peers: the next hops of its routes, and its DNS servers.
const PEER_V4: &str = "172.19.0.2";
const PEER_V6: &str = "fdfe:dcba:9876::2";

const ROUTED: [&str; 2] = ["198.18.0.0/15", "2001:db8::/32"];

/// How long nothing told is taken as nothing to tell: the check runs at
/// most a second after a notice (lib.rs SETTLE_MAX).
const QUIET: Duration = Duration::from_secs(3);

const CONFIG: &str = r#"{
    "log": { "level": "debug" },
    "inbounds": [{
        "type": "tun", "tag": "tun-in",
        "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
        "auto_route": true,
        "route_address": ["198.18.0.0/15", "2001:db8::/32"]
    }],
    "outbounds": [{ "type": "direct", "tag": "direct" }],
    "dns": { "servers": [{ "type": "hosts", "tag": "hosts", "predefined": {
        "probe.sail": ["198.18.0.10", "2001:db8::10"] } }] },
    "route": { "rules": [
        { "port": 53, "action": "hijack-dns" },
        { "ip_cidr": ["198.18.0.10/32"], "action": "route-options", "override_address": "127.0.0.1" },
        { "ip_cidr": ["2001:db8::10/128"], "action": "route-options", "override_address": "::1" }
    ], "final": "direct" }
}"#;

fn powershell(command: &str) -> Result<String> {
    let out = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", command])
        .output()
        .with_context(|| command.to_owned())?;
    ensure!(
        out.status.success(),
        "{}: {}",
        command,
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// Echoes TCP until the client's FIN, and each UDP datagram, on `host`.
async fn echo(host: IpAddr) -> Result<()> {
    let tcp = TcpListener::bind((host, PORT)).await?;
    let udp = UdpSocket::bind((host, PORT)).await?;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = tcp.accept().await {
            tokio::spawn(async move {
                let (mut read, mut write) = stream.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
                let _ = write.shutdown().await;
            });
        }
    });
    tokio::spawn(async move {
        let mut buf = vec![0; 65536];
        while let Ok((n, from)) = udp.recv_from(&mut buf).await {
            let _ = udp.send_to(&buf[..n], from).await;
        }
    });
    Ok(())
}

/// A query for `probe.sail`, of `qtype`.
fn query(qtype: u16) -> Vec<u8> {
    let mut q = vec![0x05, 0xa1, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["probe", "sail"] {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&[0, 1]);
    q
}

/// The addresses in a reply's answers.
fn answers(reply: &[u8]) -> Option<Vec<IpAddr>> {
    let count = u16::from_be_bytes([*reply.get(6)?, *reply.get(7)?]);
    let mut i = 12;
    while *reply.get(i)? != 0 {
        i += usize::from(reply[i]) + 1;
    }
    i += 5;
    let mut found = Vec::new();
    for _ in 0..count {
        if reply.get(i)? & 0xc0 == 0xc0 {
            i += 2;
        } else {
            while *reply.get(i)? != 0 {
                i += usize::from(reply[i]) + 1;
            }
            i += 1;
        }
        let head = reply.get(i..i + 10)?;
        let rtype = u16::from_be_bytes([head[0], head[1]]);
        let len = usize::from(u16::from_be_bytes([head[8], head[9]]));
        i += 10;
        let data = reply.get(i..i + len)?;
        i += len;
        match (rtype, len) {
            (1, 4) => found.push(IpAddr::from(<[u8; 4]>::try_from(data).ok()?)),
            (28, 16) => found.push(IpAddr::from(<[u8; 16]>::try_from(data).ok()?)),
            _ => {}
        }
    }
    Some(found)
}

/// Asks `server`, a TUN's DNS server, for `probe.sail`'s `qtype`: `want`
/// is among the answers.
async fn dns(server: &str, qtype: u16, want: IpAddr) -> Result<()> {
    let server: SocketAddr = SocketAddr::new(server.parse()?, 53);
    let local: SocketAddr = if server.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = UdpSocket::bind(local).await?;
    let mut buf = [0; 4096];
    let mut got = Vec::new();
    for _ in 0..3 {
        socket.send_to(&query(qtype), server).await?;
        if let Ok(Ok((n, _))) = timeout(Duration::from_secs(3), socket.recv_from(&mut buf)).await {
            got = answers(&buf[..n]).ok_or_else(|| anyhow!("a reply that does not parse"))?;
            break;
        }
    }
    ensure!(
        got.contains(&want),
        "DNS type {} of probe.sail from {}: {:?}, without {}",
        qtype,
        server,
        got,
        want
    );
    Ok(())
}

/// 256 KiB to `host` come back as sent.
async fn tcp(host: IpAddr) -> Result<()> {
    let data: Vec<u8> = (0..256 * 1024u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
        .collect();
    let stream = timeout(Duration::from_secs(10), TcpStream::connect((host, PORT)))
        .await
        .map_err(|_| anyhow!("TCP {}: connecting timed out", host))?
        .with_context(|| format!("TCP {}", host))?;
    let (mut read, mut write) = stream.into_split();
    let sent = data.clone();
    let writing = tokio::spawn(async move {
        write.write_all(&sent).await?;
        write.shutdown().await
    });
    let mut back = Vec::new();
    timeout(Duration::from_secs(30), read.read_to_end(&mut back))
        .await
        .map_err(|_| anyhow!("TCP {}: {} bytes back, then nothing", host, back.len()))??;
    writing.await??;
    ensure!(
        back == data,
        "TCP {}: {} bytes back, not the 256 KiB sent",
        host,
        back.len()
    );
    Ok(())
}

/// 20 datagrams to `host`, of four sizes, come back as sent.
async fn udp(host: IpAddr) -> Result<()> {
    let local: SocketAddr = if host.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = UdpSocket::bind(local).await?;
    let mut buf = vec![0; 65536];
    let mut good = 0;
    for (n, size) in [1usize, 100, 512, 1200].repeat(5).into_iter().enumerate() {
        let payload: Vec<u8> = (0..=size).map(|i| (n * 31 + i * 7) as u8).collect();
        for _ in 0..3 {
            socket.send_to(&payload, (host, PORT)).await?;
            match timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await {
                Ok(Ok((len, _))) if buf[..len] == payload[..] => {
                    good += 1;
                    break;
                }
                _ => continue,
            }
        }
    }
    ensure!(good == 20, "UDP {}: {} of 20 datagrams echoed", host, good);
    Ok(())
}

/// DNS, TCP and UDP through the TUN, over both families.
async fn traffic() -> Result<()> {
    let (v4, v6) = (IpAddr::V4(TARGET_V4), IpAddr::V6(TARGET_V6));
    dns(PEER_V4, 1, v4).await?;
    dns(PEER_V4, 28, v6).await?;
    dns(PEER_V6, 28, v6).await?;
    tcp(v4).await?;
    tcp(v6).await?;
    udp(v4).await?;
    udp(v6).await?;
    Ok(())
}

/// The routes to the test prefixes, whatever interface they are on.
fn routes() -> Result<String> {
    powershell(&format!(
        "(Get-NetRoute -ErrorAction SilentlyContinue | Where-Object {{ \
         $_.DestinationPrefix -in @('{}','{}') }} | ForEach-Object {{ \
         $_.DestinationPrefix + ' on ' + $_.InterfaceAlias }}) -join '; '",
        ROUTED[0], ROUTED[1]
    ))
}

/// What the system has of the TUN named `tun`, after a stop: nothing.
fn nothing_left(tun: &str, adapters_before: &str) -> Result<()> {
    let adapter = powershell(&format!(
        "@(Get-NetAdapter -Name '{}' -IncludeHidden -ErrorAction SilentlyContinue).Count",
        tun
    ))?;
    ensure!(adapter == "0", "the adapter {} is still there", tun);
    let adapters = wintun_adapters()?;
    ensure!(
        adapters == adapters_before,
        "Wintun adapters left: {:?}, before the start {:?}",
        adapters,
        adapters_before
    );
    let routes = routes()?;
    ensure!(routes.is_empty(), "routes left: {}", routes);
    let dns = powershell(&format!(
        "(Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Where-Object {{ \
         $_.ServerAddresses -contains '{}' -or $_.ServerAddresses -contains '{}' }} | \
         ForEach-Object {{ $_.InterfaceAlias }}) -join '; '",
        PEER_V4, PEER_V6
    ))?;
    ensure!(dns.is_empty(), "the TUN's DNS servers are left on: {}", dns);
    Ok(())
}

/// The Wintun adapters there are, by name.
fn wintun_adapters() -> Result<String> {
    powershell(
        "(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object { \
         $_.InterfaceDescription -like '*Wintun*' } | Sort-Object Name | \
         ForEach-Object { $_.Name }) -join '; '",
    )
}

/// The system changes told within `QUIET`.
async fn told(events: &mut (impl Stream<Item = Event> + Unpin)) -> Vec<(LeftKind, String)> {
    let mut seen = Vec::new();
    while let Ok(Some(event)) = timeout(QUIET, events.next()).await {
        match event {
            Event::SystemChanged { kind, resource } => seen.push((kind, resource)),
            other => panic!("not asked for: {:?}", other),
        }
    }
    seen
}

/// A start, the routes into the TUN, the traffic, and a stop that leaves
/// nothing; the system's changes told meanwhile are added to `seen`.
fn round(
    sail: &Instance,
    runtime: &tokio::runtime::Runtime,
    events: &mut (impl Stream<Item = Event> + Unpin),
    adapters_before: &str,
    seen: &mut Vec<(LeftKind, String)>,
) -> Result<()> {
    sail.blocking_start(Config::Json(CONFIG.into()))?;
    let tun = match sail.tun_names()?.get("tun-in") {
        Some(name) => name.name.clone(),
        None => bail!("no TUN named"),
    };
    let result = (|| -> Result<()> {
        let routes = routes()?;
        for prefix in ROUTED {
            ensure!(
                routes.contains(&format!("{} on {}", prefix, tun)),
                "{} is not routed into {}: {}",
                prefix,
                tun,
                routes
            );
        }
        runtime.block_on(traffic())
    })();
    seen.extend(runtime.block_on(told(events)));
    sail.blocking_stop(Duration::from_secs(10))?;
    seen.extend(runtime.block_on(told(events)));
    result?;
    nothing_left(&tun, adapters_before)
}

#[test]
#[ignore = "needs administrator and wintun.dll: CI's tun-windows"]
fn traffic_goes_through_the_tun_and_a_stop_leaves_nothing() -> Result<()> {
    let dir = std::env::temp_dir().join(format!("sail-tun-windows-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    runtime.block_on(async {
        echo(IpAddr::V4(Ipv4Addr::LOCALHOST)).await?;
        echo(IpAddr::V6(Ipv6Addr::LOCALHOST)).await
    })?;
    let adapters_before = wintun_adapters()?;
    let before = routes()?;
    ensure!(
        before.is_empty(),
        "routes there before the start: {}",
        before
    );

    let sail = Instance::new(Options::new().run_dir(RunDir::Dir(dir.join("run"))))?;
    let mut events = Box::pin(sail.events(Kinds::SYSTEM));
    let mut seen = Vec::new();
    let result = (|| -> Result<()> {
        round(&sail, &runtime, &mut events, &adapters_before, &mut seen)
            .context("the first run")?;
        // Stopped, and started again: the same, on an adapter made anew.
        round(&sail, &runtime, &mut events, &adapters_before, &mut seen).context("the second run")
    })();
    let _ = sail.blocking_stop(Duration::from_secs(10));
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    ensure!(
        seen.is_empty(),
        "told of the system changing, with no one else changing it: {:?}",
        seen
    );
    Ok(())
}
