//! sail embedded in a host that installed its own `tracing` subscriber
//! first: with `sail::embed::tracing_layer()` in it, each instance's log
//! gets its own lines, at its own level. A binary of its own: the global
//! subscriber is the process's.
#![cfg(all(feature = "outbound-direct", feature = "inbound-socks"))]

use std::time::Duration;

use futures::StreamExt;
use sail::embed::{Config, Instance, LogFilter, Options, Threads};
use tracing_subscriber::layer::SubscriberExt;

fn config(port: u16, level: &str, tag: &str) -> String {
    serde_json::json!({
        "log": { "level": level },
        "inbounds": [{ "type": "socks", "tag": tag, "listen": "127.0.0.1", "listen_port": port }],
        "outbounds": [{ "type": "direct", "tag": "direct" }],
    })
    .to_string()
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The lines of `instance`'s log so far: those kept.
async fn lines(instance: &Instance) -> Vec<String> {
    let mut logs = Box::pin(instance.logs(LogFilter::default()));
    let first = tokio::time::timeout(Duration::from_secs(5), logs.next())
        .await
        .expect("the backlog at once")
        .expect("a first batch");
    first.lines.iter().map(|l| l.message.clone()).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_instance_gets_its_own_lines_under_the_hosts_subscriber() {
    // The host's subscriber, with sail's layer added.
    let subscriber = tracing_subscriber::registry().with(sail::embed::tracing_layer());
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let (a_port, b_port) = (free_port(), free_port());
    let a = Instance::new(Options::new().threads(Threads::One)).unwrap();
    let b = Instance::new(Options::new().threads(Threads::One)).unwrap();
    a.start(Config::Json(config(a_port, "info", "in-a")))
        .await
        .unwrap();
    // b keeps warnings and errors only: its start's info lines are not
    // its.
    b.start(Config::Json(config(b_port, "warn", "in-b")))
        .await
        .unwrap();

    let a_lines = lines(&a).await;
    let b_lines = lines(&b).await;
    let (a_listens, b_listens) = (
        format!("listening tcp 127.0.0.1:{}", a_port),
        format!("listening tcp 127.0.0.1:{}", b_port),
    );
    assert!(
        a_lines.iter().any(|l| l.contains(&a_listens)),
        "a logs its start: {:?}",
        a_lines
    );
    assert!(
        a_lines.iter().all(|l| !l.contains(&b_listens)),
        "none of b's lines in a's log: {:?}",
        a_lines
    );
    assert!(
        b_lines
            .iter()
            .all(|l| !l.contains(&a_listens) && !l.contains(&b_listens)),
        "b keeps no info line, and none of a's: {:?}",
        b_lines
    );

    a.stop().await.unwrap();
    b.stop().await.unwrap();
}
