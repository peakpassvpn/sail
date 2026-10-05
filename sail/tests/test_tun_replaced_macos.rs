//! A route of someone else's that auto_route replaces with its own goes
//! back when sail stops; is left alone when its owner took it back in the
//! meantime; and goes back by a sweep after a kill -9
//! (design-notes' macos-replaced-routes).
//!
//! As root, on a machine of its own: CI's tun-macos job, which gives the
//! sail CLI in SAIL. "Someone else's" route is one to lo0, of a range
//! nothing else uses, so that the runner's own traffic stays out of it.
#![cfg(all(
    target_os = "macos",
    feature = "inbound-tun",
    feature = "outbound-direct"
))]

use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Context, Result};
use futures::{Stream, StreamExt};
use sail::embed::{Config, Event, Instance, Kinds, LeftKind, Options, RunDir};

const RANGE: &str = "198.18.0.0/15";
const PROBE: &str = "198.18.0.1";

fn config() -> String {
    format!(
        r#"{{
            "log": {{ "level": "debug" }},
            "inbounds": [{{
                "type": "tun", "tag": "tun-in",
                "address": ["172.31.236.1/30"],
                "auto_route": true,
                "route_address": ["{RANGE}"]
            }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#
    )
}

/// Whether `line` names the lo0 route to the range: with a next hop or
/// without, whichever the kernel keeps for a route to an interface.
fn is_theirs(line: &str) -> bool {
    line.starts_with(&format!("route {} ", RANGE)) && line.contains(" on lo0")
}

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

/// The interface the probe goes out of now.
fn interface_of_probe() -> String {
    route(&format!("get {}", PROBE))
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.trim().strip_prefix("interface: "))
        .unwrap_or("none")
        .to_owned()
}

/// The table's routes to the range (`netstat`'s lines): `route delete`
/// answers 0 for one not in the table, so it cannot count them.
fn routes_to_range() -> Vec<String> {
    let out = Command::new("netstat")
        .args(["-rn", "-f", "inet"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    out.lines()
        .filter(|l| l.starts_with("198.18.0/15 ") || l.starts_with("198.18/15 "))
        .map(str::to_owned)
        .collect()
}

/// Someone else's route: the range to lo0.
fn add_theirs() -> Result<()> {
    route(&format!("add -net {} -interface lo0", RANGE)).map(drop)
}

/// Whatever routes the range, gone; none is as well.
fn clear() {
    for _ in 0..3 {
        if route(&format!("delete -net {}", RANGE)).is_err() {
            break;
        }
    }
}

/// The system changes told within 3 s.
async fn told(events: &mut (impl Stream<Item = Event> + Unpin)) -> Vec<(LeftKind, String)> {
    let mut seen = Vec::new();
    while let Ok(Some(event)) = tokio::time::timeout(Duration::from_secs(3), events.next()).await {
        if let Event::SystemChanged { kind, resource } = event {
            seen.push((kind, resource));
        }
    }
    seen
}

fn instance(dir: &std::path::Path) -> Result<Instance> {
    Ok(Instance::new(
        Options::new().run_dir(RunDir::Dir(dir.join("run"))),
    )?)
}

fn tempdir(name: &str) -> Result<std::path::PathBuf> {
    let dir = std::env::temp_dir().join(format!("sail-{}-{}", name, std::process::id()));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// One at a time: they share the range.
static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
#[ignore = "needs root and a utun: CI's tun-macos"]
fn a_replaced_route_goes_back_when_sail_stops() -> Result<()> {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    clear();
    add_theirs()?;
    let dir = tempdir("replaced")?;
    let sail = instance(&dir)?;
    sail.blocking_start(Config::Json(config()))?;
    let utun = sail.tun_names()?["tun-in"].name.clone();
    let result = (|| -> Result<()> {
        ensure!(interface_of_probe() == utun, "the range goes into {}", utun);
        let replaced = sail.replaced_routes()?;
        ensure!(
            replaced.len() == 1 && is_theirs(&replaced[0]),
            "{:?}",
            replaced
        );
        Ok(())
    })();
    sail.blocking_stop(Duration::from_secs(10))?;
    let back = interface_of_probe();
    clear();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    ensure!(back == "lo0", "put back to lo0, not {}", back);
    Ok(())
}

#[test]
#[ignore = "needs root and a utun: CI's tun-macos"]
fn a_replaced_route_its_owner_took_back_is_left_alone() -> Result<()> {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    clear();
    add_theirs()?;
    let dir = tempdir("taken")?;
    let sail = instance(&dir)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let mut events = Box::pin(sail.events(Kinds::SYSTEM));
    sail.blocking_start(Config::Json(config()))?;
    let utun = sail.tun_names()?["tun-in"].name.clone();
    let result = (|| -> Result<()> {
        ensure!(
            runtime.block_on(told(&mut events)).is_empty(),
            "told of its start"
        );
        // The other VPN puts its route back over sail's.
        route(&format!("delete -net {}", RANGE))?;
        add_theirs()?;
        let seen = runtime.block_on(told(&mut events));
        let prefix = format!("route {} into {}: gone; it had replaced the ", RANGE, utun);
        ensure!(
            seen.len() == 1
                && seen[0].0 == LeftKind::Route
                && seen[0].1.strip_prefix(&prefix).is_some_and(is_theirs),
            "{:?}",
            seen
        );
        Ok(())
    })();
    sail.blocking_stop(Duration::from_secs(10))?;
    // Theirs, left as it was: one route, to lo0.
    let back = interface_of_probe();
    let routes = routes_to_range();
    clear();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    ensure!(back == "lo0", "theirs left, to lo0, not {}", back);
    ensure!(routes.len() == 1, "one route to the range: {:?}", routes);
    Ok(())
}

#[test]
#[ignore = "needs root, a utun and the sail CLI in SAIL: CI's tun-macos"]
fn a_replaced_route_goes_back_by_a_sweep_after_a_kill() -> Result<()> {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let Ok(cli) = std::env::var("SAIL") else {
        bail!("SAIL names no sail CLI");
    };
    clear();
    add_theirs()?;
    let dir = tempdir("killed")?;
    let file = dir.join("config.json");
    std::fs::write(&file, config())?;
    // Its run dir is the system's: /var/run/sail, as root.
    let mut child = Command::new(&cli)
        .arg("-c")
        .arg(&file)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("the sail CLI")?;
    let deadline = Instant::now() + Duration::from_secs(15);
    while !interface_of_probe().starts_with("utun") {
        if Instant::now() >= deadline {
            let _ = child.kill();
            clear();
            bail!("the CLI did not route the range");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    child.kill()?;
    child.wait()?;
    let after_kill = interface_of_probe();
    let undone = sail::embed::sweep(&RunDir::Default);
    let back = interface_of_probe();
    clear();
    let _ = std::fs::remove_dir_all(&dir);
    ensure!(
        !after_kill.starts_with("utun") && after_kill != "lo0",
        "after the kill the range is neither sail's nor theirs: {}",
        after_kill
    );
    ensure!(back == "lo0", "put back to lo0 by the sweep, not {}", back);
    ensure!(
        undone.len() == 1
            && undone[0]
                .strip_suffix(", which sail had replaced")
                .is_some_and(is_theirs),
        "{:?}",
        undone
    );
    Ok(())
}
