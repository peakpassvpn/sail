//! What a failing instance leaves in the system while its host lives on:
//! nothing. sail runs in this process, as an embedding host runs it; a
//! fault the test arms (feature fault-injection) fails it, and what it
//! could have left is then as it was before it started -- on Linux the ip
//! rules, the routes of every table, the nftables tables and the links; on
//! macOS the routes through a utun and the utuns -- and it starts again.
//!
//! As root: on Linux in the namespace tests/scripts/auto_redirect_netns.sh
//! builds; on macOS on a machine of its own (CI's tun-macos job).
//!
//! Locks, with auto_route and, on Linux, with auto_redirect:
//! - an essential task's panic, and the TUN runner's, leave nothing;
//! - the TUN's netstack failing fails the instance, and leaves nothing;
//! - a start that fails once the TUN is routed leaves nothing;
//! - a teardown step that panics leaves its own resource alone, and the
//!   others still go (Linux).
#![cfg(all(
    any(target_os = "linux", target_os = "macos"),
    feature = "inbound-tun",
    feature = "outbound-direct",
    feature = "fault-injection"
))]

use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Context, Result};
use sail::embed::{Config, Instance, Options, RunDir, State};
use sail::fault::{self, Point};
#[cfg(target_os = "linux")]
use sail::runtime::teardown::LeftKind;

#[cfg(target_os = "linux")]
const TABLE: &str = "sail_sadtd0";

/// auto_redirect too, where there is one.
#[cfg(target_os = "linux")]
const REDIRECT: &[bool] = &[false, true];
#[cfg(target_os = "macos")]
const REDIRECT: &[bool] = &[false];

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
    Ok(out)
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
    // macOS names the utun itself.
    let name = if cfg!(target_os = "linux") {
        r#" "interface_name": "sadtd0","#
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
    Ok(Instance::new(
        Options::new().run_dir(RunDir::Dir(dir.join("run"))),
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
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    fault::disarm();
    let dir = tempdir()?;
    let before = settled()?;
    let sail = instance(&dir)?;
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
    let again = instance(&dir)?;
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
