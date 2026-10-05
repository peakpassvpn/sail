//! What someone else changes of a TUN's routes is told, once, and left as
//! it is: sail restores nothing (design-notes' tun-integrity). What sail
//! changes itself, starting and stopping, is told never.
//!
//! As root, on a machine of its own: CI's tun-macos job. The TUN routes
//! 1.0.0.0/8 alone, one of the halves auto_route takes from the default
//! route, so that the runner's own traffic stays out of it.
#![cfg(all(
    target_os = "macos",
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

/// How long nothing told is taken as nothing to tell: the check runs at
/// most a second after a notice (lib.rs SETTLE_MAX).
const QUIET: Duration = Duration::from_secs(3);

fn route(args: &str) -> Result<String> {
    let out = Command::new("route")
        .args(["-n"])
        .args(args.split_whitespace())
        .output()
        .with_context(|| format!("route {}", args))?;
    ensure!(
        out.status.success(),
        "route {}: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The interface 1.0.0.1 goes out of now.
fn interface_of_probe() -> Result<String> {
    let out = route("get 1.0.0.1").unwrap_or_default();
    Ok(out
        .lines()
        .find_map(|l| l.trim().strip_prefix("interface: "))
        .unwrap_or("none")
        .to_owned())
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
#[ignore = "needs root and a utun: CI's tun-macos"]
fn a_foreign_route_change_is_told_once_and_sail_s_own_never() -> Result<()> {
    let dir = std::env::temp_dir().join(format!("sail-integrity-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let sail = Instance::new(Options::new().run_dir(RunDir::Dir(dir.join("run"))))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let mut events = Box::pin(sail.events(Kinds::SYSTEM));

    sail.blocking_start(Config::Json(CONFIG.into()))?;
    let utun = match sail.tun_names()?.get("tun-in") {
        Some(name) => name.name.clone(),
        None => bail!("no TUN named"),
    };
    let result = (|| -> Result<()> {
        ensure!(interface_of_probe()? == utun, "1.0.0.1 goes into {}", utun);
        // Its own start: nothing.
        let seen = runtime.block_on(told(&mut events));
        ensure!(seen.is_empty(), "told of sail's own start: {:?}", seen);

        // Someone deletes the route: told once, and not put back.
        route("delete -net 1.0.0.0/8")?;
        let seen = runtime.block_on(told(&mut events));
        ensure!(
            seen == [(
                LeftKind::Route,
                format!("route 1.0.0.0/8 into {}: gone", utun)
            )],
            "{:?}",
            seen
        );
        ensure!(interface_of_probe()? != utun, "sail put the route back");

        // Put back by someone else: right again, nothing told.
        route(&format!("add -net 1.0.0.0/8 -interface {}", utun))?;
        let seen = runtime.block_on(told(&mut events));
        ensure!(seen.is_empty(), "told of a route put right: {:?}", seen);

        // A longer route of its span, through loopback, wins: told once.
        route("add -net 1.0.0.0/9 -interface lo0")?;
        let seen = runtime.block_on(told(&mut events));
        route("delete -net 1.0.0.0/9")?;
        ensure!(
            seen == [(
                LeftKind::Route,
                format!("route 1.0.0.0/8 into {}: 1.0.0.0/9 on lo0 wins", utun)
            )],
            "{:?}",
            seen
        );
        let _ = runtime.block_on(told(&mut events));
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
