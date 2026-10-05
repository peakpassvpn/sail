//! What someone else changes of a TUN's routes and DNS servers is told,
//! once, and left as it is: sail restores nothing (design-notes'
//! tun-integrity). What sail changes itself, starting and stopping, is
//! told never.
//!
//! As administrator, with wintun.dll beside the test: CI's windows-msvc
//! job. The TUN routes 1.0.0.0/8 alone, so that the runner's own traffic
//! stays out of it; a 0/0 that wins over sail's is therefore not tried
//! here (the comparison's unit tests are platform/integrity.rs).
#![cfg(all(
    target_os = "windows",
    feature = "inbound-tun",
    feature = "outbound-direct"
))]

use std::process::Command;
use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use futures::{Stream, StreamExt};
use sail::embed::{Config, Event, Instance, Kinds, LeftKind, Options, RunDir};

const CONFIG: &str = r#"{
    "log": { "level": "debug" },
    "inbounds": [{
        "type": "tun", "tag": "tun-in",
        "address": ["172.31.235.1/30"],
        "auto_route": true,
        "route_address": ["1.0.0.0/8"]
    }],
    "outbounds": [{ "type": "direct", "tag": "direct" }]
}"#;

/// The TUN's peer: the next hop of its routes, and its DNS server.
const PEER: &str = "172.31.235.2";

/// How long nothing told is taken as nothing to tell: the check runs at
/// most a second after a notice (lib.rs SETTLE_MAX).
const QUIET: Duration = Duration::from_secs(3);

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

/// Whether the TUN has a route to 1.0.0.0/8.
fn routed(tun: &str) -> Result<bool> {
    let found = powershell(&format!(
        "@(Get-NetRoute -InterfaceAlias '{}' -DestinationPrefix 1.0.0.0/8 \
         -ErrorAction SilentlyContinue).Count",
        tun
    ))?;
    Ok(found != "0")
}

/// The system changes told within `QUIET`.
async fn told(events: &mut (impl Stream<Item = Event> + Unpin)) -> Vec<(LeftKind, String)> {
    let mut seen = Vec::new();
    while let Ok(Some(event)) = tokio::time::timeout(QUIET, events.next()).await {
        match event {
            Event::SystemChanged { kind, resource } => seen.push((kind, resource)),
            other => panic!("not asked for: {:?}", other),
        }
    }
    seen
}

#[test]
#[ignore = "needs administrator and wintun.dll: CI's windows-msvc"]
fn a_foreign_route_or_dns_change_is_told_once_and_sail_s_own_never() -> Result<()> {
    let dir = std::env::temp_dir().join(format!("sail-integrity-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let sail = Instance::new(Options::new().run_dir(RunDir::Dir(dir.join("run"))))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let mut events = Box::pin(sail.events(Kinds::SYSTEM));

    sail.blocking_start(Config::Json(CONFIG.into()))?;
    let tun = match sail.tun_names()?.get("tun-in") {
        Some(name) => name.name.clone(),
        None => bail!("no TUN named"),
    };
    let result = (|| -> Result<()> {
        ensure!(routed(&tun)?, "no route to 1.0.0.0/8 into {}", tun);
        // Its own start: nothing.
        let seen = runtime.block_on(told(&mut events));
        ensure!(seen.is_empty(), "told of sail's own start: {:?}", seen);

        // Someone removes the route: told once, and not put back.
        powershell(&format!(
            "Remove-NetRoute -InterfaceAlias '{}' -DestinationPrefix 1.0.0.0/8 -Confirm:$false",
            tun
        ))?;
        let seen = runtime.block_on(told(&mut events));
        ensure!(
            seen == [(
                LeftKind::Route,
                format!("route 1.0.0.0/8 into {}: gone", tun)
            )],
            "{:?}",
            seen
        );
        ensure!(!routed(&tun)?, "sail put the route back");

        // Put back by someone else: right again, nothing told.
        powershell(&format!(
            "New-NetRoute -InterfaceAlias '{}' -DestinationPrefix 1.0.0.0/8 -NextHop {} \
             -RouteMetric 0 -PolicyStore ActiveStore | Out-Null",
            tun, PEER
        ))?;
        let seen = runtime.block_on(told(&mut events));
        ensure!(seen.is_empty(), "told of a route put right: {:?}", seen);

        // Someone sets the adapter's DNS servers: told once, not put back.
        powershell(&format!(
            "Set-DnsClientServerAddress -InterfaceAlias '{}' -ServerAddresses 1.1.1.1",
            tun
        ))?;
        let seen = runtime.block_on(told(&mut events));
        ensure!(
            seen == [(
                LeftKind::Dns,
                format!(
                    "the IPv4 DNS servers of {}: 1.1.1.1 instead of {}",
                    tun, PEER
                )
            )],
            "{:?}",
            seen
        );
        let servers = powershell(&format!(
            "(Get-DnsClientServerAddress -InterfaceAlias '{}' -AddressFamily IPv4).ServerAddresses",
            tun
        ))?;
        ensure!(servers == "1.1.1.1", "sail set its DNS back: {}", servers);

        // Set back by someone else: right again, nothing told.
        powershell(&format!(
            "Set-DnsClientServerAddress -InterfaceAlias '{}' -ServerAddresses {}",
            tun, PEER
        ))?;
        let seen = runtime.block_on(told(&mut events));
        ensure!(seen.is_empty(), "told of DNS put right: {:?}", seen);
        Ok(())
    })();
    // Its own stop: nothing, whatever the steps above came to.
    sail.blocking_stop(Duration::from_secs(10))?;
    let seen = runtime.block_on(told(&mut events));
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    ensure!(seen.is_empty(), "told of sail's own stop: {:?}", seen);
    Ok(())
}
