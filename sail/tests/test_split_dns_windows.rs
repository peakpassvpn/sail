//! The system's split DNS, followed by a `local` server that asks the
//! system's servers itself (auto_detect_interface): a name under an NRPT
//! rule's namespace is asked of its servers; a rule whose server is
//! reached through sail's own TUN is passed over for the system's own
//! servers.
//!
//! As administrator, with wintun.dll beside the test: CI's windows-msvc
//! job. It adds two NRPT rules, a DNS server of its own on 127.0.0.2, and
//! removes the rules after.
#![cfg(all(
    target_os = "windows",
    feature = "inbound-tun",
    feature = "inbound-direct",
    feature = "outbound-direct"
))]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Command;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{ensure, Context, Result};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{rdata::A, Name, RData, Record, RecordType};
use sail::embed::{Config, Instance, Options, RunDir};

/// The TUN's peer: on sail's own TUN's network.
const PEER: &str = "172.31.236.2";
const ANSWER: Ipv4Addr = Ipv4Addr::new(10, 9, 9, 9);

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

/// The rules this test adds, removed however it ends.
struct Cleanup;

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = powershell(
            "Get-DnsClientNrptRule | Where-Object { $_.Namespace -in '.split.test','.own.test' } \
             | Remove-DnsClientNrptRule -Force",
        );
    }
}

/// A DNS server on 127.0.0.2:53, on a thread of its own, that answers
/// every A query with ANSWER and keeps the names it was asked.
fn server(asked: Arc<Mutex<Vec<String>>>) -> Result<()> {
    let socket = std::net::UdpSocket::bind("127.0.0.2:53")?;
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 1500];
        while let Ok((n, from)) = socket.recv_from(&mut buf) {
            let Ok(query) = Message::from_vec(&buf[..n]) else {
                continue;
            };
            let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
            reply.metadata.recursion_desired = query.metadata.recursion_desired;
            reply.metadata.response_code = ResponseCode::NoError;
            for q in &query.queries {
                asked.lock().unwrap().push(q.name().to_ascii());
                reply.add_query(q.clone());
                if q.query_type() == RecordType::A {
                    reply.add_answer(Record::from_rdata(
                        q.name().clone(),
                        60,
                        RData::A(A(ANSWER)),
                    ));
                }
            }
            if let Ok(bytes) = reply.to_vec() {
                let _ = socket.send_to(&bytes, from);
            }
        }
    });
    Ok(())
}

async fn ask(server: SocketAddr, name: &str) -> Result<(ResponseCode, Vec<IpAddr>, Duration)> {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let mut m = Message::new(7, MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(Name::from_str(name)?, RecordType::A));
    let started = Instant::now();
    socket.send_to(&m.to_vec()?, server).await?;
    let mut buf = vec![0u8; 1500];
    let (n, _) = tokio::time::timeout(Duration::from_secs(15), socket.recv_from(&mut buf))
        .await
        .context("no answer")??;
    let reply = Message::from_vec(&buf[..n])?;
    let ips = reply
        .answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            _ => None,
        })
        .collect();
    Ok((reply.metadata.response_code, ips, started.elapsed()))
}

#[test]
#[ignore = "needs administrator and wintun.dll: CI's windows-msvc"]
fn split_dns_is_followed_and_a_rule_through_sail_s_tun_passed_over() -> Result<()> {
    let _cleanup = Cleanup;
    powershell("Add-DnsClientNrptRule -Namespace '.split.test' -NameServers 127.0.0.2")?;
    powershell(&format!(
        "Add-DnsClientNrptRule -Namespace '.own.test' -NameServers {PEER}"
    ))?;

    let port = std::net::UdpSocket::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let config = format!(
        r#"{{
        "log": {{ "level": "debug" }},
        "dns": {{ "servers": [{{ "type": "local", "tag": "sys" }}] }},
        "inbounds": [
            {{ "type": "tun", "tag": "tun-in", "address": ["172.31.236.1/30"],
               "auto_route": true, "route_address": ["1.0.0.0/8"] }},
            {{ "type": "direct", "tag": "dns-in", "listen": "127.0.0.1", "listen_port": {port} }}
        ],
        "outbounds": [{{ "type": "direct", "tag": "direct" }}],
        "route": {{ "auto_detect_interface": true,
                    "rules": [{{ "inbound": "dns-in", "action": "hijack-dns" }}] }}
    }}"#
    );
    let dir = std::env::temp_dir().join(format!("sail-split-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let sail = Instance::new(Options::new().run_dir(RunDir::Dir(dir.join("run"))))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let asked = Arc::new(Mutex::new(Vec::new()));
    server(asked.clone())?;
    sail.blocking_start(Config::Json(config))?;
    let listener = SocketAddr::from(([127, 0, 0, 1], port));
    let result = runtime.block_on(async {
        // A name under .split.test: its rule's server answers.
        let (code, ips, _) = ask(listener, "a.split.test.").await?;
        ensure!(
            code == ResponseCode::NoError && ips == [IpAddr::V4(ANSWER)],
            "a.split.test: {:?} {:?}",
            code,
            ips
        );
        ensure!(
            asked.lock().unwrap().iter().any(|n| n == "a.split.test."),
            "the rule's server was not asked"
        );
        // A name under .own.test: its server is on sail's TUN, so the
        // system's own servers are asked instead, and answer at once
        // rather than the query going into the TUN until it times out.
        let (code, _, took) = ask(listener, "a.own.test.").await?;
        ensure!(
            code != ResponseCode::ServFail && took < Duration::from_secs(4),
            "a.own.test: {:?} after {:?}",
            code,
            took
        );
        // Another name: the system's servers. The system's own resolver
        // may ask the rule's server too: only sail's other names must not
        // reach it.
        let _ = ask(listener, "example.com.").await?;
        let seen = asked.lock().unwrap().clone();
        ensure!(
            !seen
                .iter()
                .any(|n| n == "a.own.test." || n == "example.com."),
            "the rule's server was asked for other names: {:?}",
            seen
        );
        Ok(())
    });
    sail.blocking_stop(Duration::from_secs(10))?;
    let _ = std::fs::remove_dir_all(&dir);
    result
}
