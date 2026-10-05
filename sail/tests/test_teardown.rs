//! What a failing instance leaves in the system while its host lives on:
//! nothing. sail runs in this process, as an embedding host runs it; a
//! fault the test arms (feature fault-injection) fails it, and what it
//! could have left is then as it was before it started -- on Linux the ip
//! rules, the routes of every table, the nftables tables and the links; on
//! macOS the routes through a utun and the utuns; on Windows the adapters,
//! the routes and DNS of the TUN's and strict_route's WFP filters -- and
//! it starts again.
//!
//! As root: on Linux in the namespace tests/scripts/auto_redirect_netns.sh
//! builds; on macOS on a machine of its own (CI's tun-macos job); on
//! Windows as administrator, with wintun.dll beside the test (CI's
//! windows-msvc job).
//!
//! Locks, with auto_route and, on Linux, with auto_redirect:
//! - an essential task's panic, and the TUN runner's, leave nothing; on
//!   the host's tokio runtime too, which goes on;
//! - the TUN's netstack failing fails the instance, and leaves nothing;
//! - a start that fails once the TUN is routed leaves nothing;
//! - a teardown step that panics leaves its own resource alone, and the
//!   others still go (Linux).
#![cfg(all(
    any(target_os = "linux", target_os = "macos", target_os = "windows"),
    feature = "inbound-tun",
    feature = "outbound-direct",
    feature = "fault-injection"
))]

use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Context, Result};
use sail::embed::{Config, Instance, Options, RunDir, Runtime, State};
use sail::fault::{self, Point};
#[cfg(target_os = "linux")]
use sail::runtime::teardown::LeftKind;

#[cfg(target_os = "linux")]
const TABLE: &str = "sail_sadtd0";

/// auto_redirect too, where there is one.
#[cfg(target_os = "linux")]
const REDIRECT: &[bool] = &[false, true];
#[cfg(any(target_os = "macos", target_os = "windows"))]
const REDIRECT: &[bool] = &[false];

/// The TUN's name on Windows, which sail does not choose there.
#[cfg(target_os = "windows")]
const WINDOWS_TUN: &str = "sadtd0";

/// One at a time: they share the namespace, and the faults are the
/// process's.
static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn run(program: &str, args: &str) -> Result<String> {
    let out = Command::new(program)
        .args(args.split_whitespace())
        .output()
        .with_context(|| format!("{} {}", program, args))?;
    ensure!(
        out.status.success(),
        "{} {}: {}",
        program,
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// What an instance could leave: rules, routes of every table, nftables
/// tables, links.
#[cfg(target_os = "linux")]
fn system() -> Result<String> {
    let mut out = String::new();
    for (program, args) in [
        ("ip", "-4 rule"),
        ("ip", "-6 rule"),
        ("ip", "-4 route show table all"),
        ("ip", "-6 route show table all"),
        ("nft", "list tables"),
        ("ip", "-o link"),
    ] {
        out.push_str(&format!("$ {} {}\n{}", program, args, run(program, args)?));
    }
    Ok(out)
}

/// What an instance could leave: the routes through a utun, and the utuns.
/// (Other routes' columns change by themselves: an ARP entry's expiry.)
#[cfg(target_os = "macos")]
fn system() -> Result<String> {
    let mut out = String::new();
    for family in ["inet", "inet6"] {
        out.push_str(&format!("$ netstat -rn -f {}\n", family));
        for line in run("netstat", &format!("-rn -f {}", family))?.lines() {
            if line
                .split_whitespace()
                .any(|field| field.starts_with("utun"))
            {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    out.push_str(&format!("$ ifconfig -l\n{}", run("ifconfig", "-l")?));
    // The resolvers' servers, which sail's DNS joins while the TUN runs.
    out.push_str("$ scutil --dns (servers)\n");
    for line in run("scutil", "--dns")?.lines() {
        if line.starts_with("resolver #") || line.contains("nameserver[") {
            out.push_str(line);
            out.push('\n');
        }
    }
    Ok(out)
}

/// What an instance could leave: the adapters, the routes and DNS servers
/// of the TUN's and the routes into it, and the WFP filters strict_route
/// names "sail". Only into 198.18.0.0/16, the runner's own traffic stays
/// out of it.
#[cfg(target_os = "windows")]
fn system() -> Result<String> {
    let script = format!(
        r#"$ErrorActionPreference = "SilentlyContinue"
"adapters: " + ((Get-NetAdapter -IncludeHidden | ForEach-Object Name | Sort-Object) -join ", ")
"routes into 198.18.0.0/16: " + ((Get-NetRoute -DestinationPrefix 198.18.0.0/16 | ForEach-Object {{ "$($_.InterfaceAlias) $($_.NextHop)" }}) -join ", ")
"routes of {tun}: " + ((Get-NetRoute -InterfaceAlias {tun} | ForEach-Object DestinationPrefix | Sort-Object) -join ", ")
"dns of {tun}: " + ((Get-DnsClientServerAddress -InterfaceAlias {tun} | ForEach-Object {{ $_.ServerAddresses }}) -join ", ")
$xml = Join-Path $env:TEMP "sail-teardown-wfp.xml"
netsh wfp show filters file=$xml | Out-Null
"wfp filters named sail: " + (Select-String -Path $xml -Pattern "<name>sail" -SimpleMatch).Count"#,
        tun = WINDOWS_TUN
    );
    run_ps(&script)
}

#[cfg(target_os = "windows")]
fn run_ps(script: &str) -> Result<String> {
    let out = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .context("powershell")?;
    ensure!(
        out.status.success(),
        "powershell: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The system once it is still: what a step before this one undid (CI
/// runs other TUN tests first) may still be going.
fn settled() -> Result<String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut last = system()?;
    loop {
        std::thread::sleep(Duration::from_millis(300));
        let now = system()?;
        if now == last || Instant::now() >= deadline {
            return Ok(now);
        }
        last = now;
    }
}

fn config(redirect: bool) -> String {
    // macOS names the utun itself. On Windows strict_route too, routing
    // only a range nothing else uses, so that the runner's own traffic
    // stays out of it.
    let name = if cfg!(target_os = "linux") {
        r#" "interface_name": "sadtd0","#
    } else if cfg!(target_os = "windows") {
        r#" "interface_name": "sadtd0", "strict_route": true, "route_address": ["198.18.0.0/16"],"#
    } else {
        ""
    };
    let redirect = if redirect {
        r#", "auto_redirect": true"#
    } else {
        ""
    };
    format!(
        r#"{{
            "log": {{ "level": "debug" }},
            "inbounds": [{{
                "type": "tun", "tag": "tun-in",{name}
                "address": ["172.31.234.1/30", "fdfe:234::1/126"],
                "auto_route": true{redirect}
            }}],
            "outbounds": [{{ "type": "direct", "tag": "direct" }}]
        }}"#
    )
}

fn instance(dir: &std::path::Path) -> Result<Instance> {
    instance_on(dir, Runtime::Own)
}

fn instance_on(dir: &std::path::Path, runtime: Runtime) -> Result<Instance> {
    Ok(Instance::new(
        Options::new()
            .run_dir(RunDir::Dir(dir.join("run")))
            .log_lines(4096)
            .runtime(runtime),
    )?)
}

/// Waits until `instance` has failed, and says why.
fn failed(instance: &Instance) -> Result<String> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match instance.state() {
            State::Failed(e) => return Ok(e.to_string()),
            state if Instant::now() >= deadline => bail!("still {} after 15 s", state.name()),
            _ => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

/// Starts with `redirect`, makes it fail by `point`, and checks what is
/// left: nothing; then that it starts and stops again.
fn fails_and_leaves_nothing(redirect: bool, point: Point) -> Result<()> {
    fails_and_leaves_nothing_on(redirect, point, Runtime::Own)
}

/// `fails_and_leaves_nothing`, the instance on `runtime`.
fn fails_and_leaves_nothing_on(redirect: bool, point: Point, runtime: Runtime) -> Result<()> {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    fault::disarm();
    let dir = tempdir()?;
    let before = settled()?;
    let sail = instance_on(&dir, runtime.clone())?;
    sail.blocking_start(Config::Json(config(redirect)))?;
    ensure!(system()? != before, "routed once started");
    fault::arm(point.clone());
    let why = failed(&sail)?;
    ensure!(
        why.contains("fault injected"),
        "failed for its fault: {}",
        why
    );
    let _ = sail.blocking_stop(Duration::from_secs(10));
    let after = system()?;
    ensure!(
        before == after,
        "{:?} left the system changed:\n--- before\n{}\n--- after\n{}",
        point,
        before,
        after
    );
    // The host lives on, and starts it again.
    let again = instance_on(&dir, runtime)?;
    again.blocking_start(Config::Json(config(redirect)))?;
    ensure!(system()? != before, "routed when started again");
    again.blocking_stop(Duration::from_secs(10))?;
    ensure!(
        system()? == before,
        "a stop after a failure left the system changed"
    );
    Ok(())
}

fn tempdir() -> Result<std::path::PathBuf> {
    let dir = std::env::temp_dir().join(format!(
        "sail-teardown-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

#[test]
#[ignore = "needs root: tests/scripts/auto_redirect_netns.sh, or CI's tun-macos"]
fn an_essential_task_s_panic_leaves_nothing() -> Result<()> {
    for &redirect in REDIRECT {
        fails_and_leaves_nothing(redirect, Point::EssentialTask)?;
    }
    Ok(())
}

/// On the host's runtime: the instance fails and leaves nothing, as on its
/// own, and the host's runtime goes on, its task through the failure too.
#[test]
#[ignore = "needs root: tests/scripts/auto_redirect_netns.sh, or CI's tun-macos"]
fn an_essential_task_s_panic_on_the_hosts_runtime_leaves_nothing() -> Result<()> {
    let host = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let ticks = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let ticking = ticks.clone();
    // The host's task, on the host's runtime: not an instance's.
    #[allow(clippy::disallowed_methods)]
    let host_task = host.spawn(async move {
        loop {
            ticking.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });
    for &redirect in REDIRECT {
        fails_and_leaves_nothing_on(
            redirect,
            Point::EssentialTask,
            Runtime::Host(host.handle().clone()),
        )?;
        let after = ticks.load(std::sync::atomic::Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(100));
        ensure!(
            ticks.load(std::sync::atomic::Ordering::Relaxed) > after && !host_task.is_finished(),
            "the host's task goes on"
        );
    }
    host_task.abort();
    Ok(())
}

#[test]
#[ignore = "needs root: tests/scripts/auto_redirect_netns.sh, or CI's tun-macos"]
fn the_tun_runner_s_panic_leaves_nothing() -> Result<()> {
    for &redirect in REDIRECT {
        fails_and_leaves_nothing(redirect, Point::TunRunner)?;
    }
    Ok(())
}

#[test]
#[ignore = "needs root: tests/scripts/auto_redirect_netns.sh, or CI's tun-macos"]
fn the_netstack_s_failure_fails_it_and_leaves_nothing() -> Result<()> {
    for &redirect in REDIRECT {
        fails_and_leaves_nothing(redirect, Point::NetstackFails)?;
    }
    Ok(())
}

#[test]
#[ignore = "needs root: tests/scripts/auto_redirect_netns.sh, or CI's tun-macos"]
fn a_start_that_fails_once_routed_leaves_nothing() -> Result<()> {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    for &redirect in REDIRECT {
        fault::disarm();
        let dir = tempdir()?;
        let before = settled()?;
        fault::arm(Point::StartFails);
        let sail = instance(&dir)?;
        let started = sail.blocking_start(Config::Json(config(redirect)));
        let e = match started {
            Ok(()) => bail!("started despite its fault"),
            Err(e) => e.to_string(),
        };
        ensure!(e.contains("fault injected"), "failed for its fault: {}", e);
        let after = system()?;
        if after != before {
            // Whether it settles, and when: the start returned first.
            let returned = Instant::now();
            let settled = loop {
                if system()? == before {
                    break Some(returned.elapsed());
                }
                if returned.elapsed() > Duration::from_secs(5) {
                    break None;
                }
                std::thread::sleep(Duration::from_millis(20));
            };
            bail!(
                "a failed start (auto_redirect {}) left the system changed (settled after it \
                 returned: {:?}):\n--- before\n{}\n--- after\n{}",
                redirect,
                settled,
                before,
                after
            );
        }
    }
    Ok(())
}

/// On macOS the routes, the one step, go with the utun all the same.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "needs root: tests/scripts/auto_redirect_netns.sh, or CI's tun-macos"]
fn a_panicking_step_leaves_its_own_and_the_rest_go() -> Result<()> {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    fault::disarm();
    let dir = tempdir()?;
    let before = settled()?;
    let sail = instance(&dir)?;
    sail.blocking_start(Config::Json(config(true)))?;
    // The table goes at the end, whatever fails: the tests after this one
    // compare with a system without it.
    struct DropTable;
    impl Drop for DropTable {
        fn drop(&mut self) {
            let _ = run("nft", &format!("delete table inet {}", TABLE));
        }
    }
    let _table = DropTable;
    fault::arm(Point::TeardownStep(format!("nft table inet {}", TABLE)));
    // The stop says what it left: the table, and how to clear it.
    let stopped = sail.blocking_stop(Duration::from_secs(10));
    let said = match stopped {
        Ok(()) => bail!("the stop said nothing was left"),
        Err(e) => e.to_string(),
    };
    ensure!(
        said.contains(&format!("nft delete table inet {}", TABLE)),
        "the stop names the table and its command: {}",
        said
    );
    let left = sail.stop_report().map(|r| r.left).unwrap_or_default();
    ensure!(
        left.len() == 1 && left[0].kind == LeftKind::Nft,
        "the report has the table alone: {:?}",
        left
    );
    // The table is left, and only it.
    ensure!(
        run("nft", "list tables")?.contains(TABLE),
        "the table is left"
    );
    run("nft", &format!("delete table inet {}", TABLE))?;
    ensure!(
        system()? == before,
        "more than the table was left:\n--- before\n{}\n--- after\n{}",
        before,
        system()?
    );
    Ok(())
}

/// A stop undoes strict_route's firewall rules first, then the TUN's DNS,
/// the routes, and last the wintun session: there is no moment where the
/// rules keep DNS off every interface but a TUN already gone. Read from
/// the order of the teardown's lines in the instance's log.
#[cfg(target_os = "windows")]
#[test]
#[ignore = "needs administrator and wintun.dll: CI's windows-msvc"]
fn a_stop_closes_the_firewall_rules_before_the_adapter() -> Result<()> {
    use futures::StreamExt;
    use sail::embed::LogFilter;

    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    fault::disarm();
    let dir = tempdir()?;
    let before = settled()?;
    let sail = instance(&dir)?;
    sail.blocking_start(Config::Json(config(false)))?;
    // What the adapter's hand-clearing command finds it by.
    eprintln!(
        "{}",
        run_ps(&format!(
            "Get-NetAdapter -IncludeHidden -Name '{}' | Format-List Name,InterfaceDescription,PnPDeviceID",
            WINDOWS_TUN
        ))?
    );
    ensure!(
        system()?.contains("wfp filters named sail: 6"),
        "strict_route's six filters while it runs:\n{}",
        system()?
    );
    sail.blocking_stop(Duration::from_secs(10))?;
    ensure!(
        system()? == before,
        "a stop left the system changed:\n--- before\n{}\n--- after\n{}",
        before,
        system()?
    );
    let backlog = futures::executor::block_on(Box::pin(sail.logs(LogFilter::default())).next())
        .context("the log's backlog")?;
    let undone: Vec<String> = backlog
        .lines
        .iter()
        .filter(|l| l.message.starts_with("teardown: ") && l.message.ends_with(" undone"))
        .map(|l| l.message.clone())
        .collect();
    let at = |what: &str| {
        undone
            .iter()
            .position(|l| l.contains(what))
            .with_context(|| format!("no \"{}\" undone in {:#?}", what, undone))
    };
    let order = [
        at("strict_route's firewall rules")?,
        at("the DNS servers of")?,
        at("auto_route's routes")?,
        at("the wintun session of")?,
        // The check, once the runner is dropped.
        at("the wintun adapter")?,
    ];
    ensure!(
        order.windows(2).all(|w| w[0] < w[1]),
        "undone out of order: {:#?}",
        undone
    );
    Ok(())
}
