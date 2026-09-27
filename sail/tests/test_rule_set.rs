mod common;

// app(socks) -> (socks)sail(route by rule-set) -> echo
//
// A rule-set holding the echo server's address makes the rule reject the
// connection; one that does not lets it through.
#[cfg(all(
    feature = "inbound-socks",
    feature = "outbound-direct",
    feature = "rule-set"
))]
#[test]
fn a_rule_set_decides_the_route() -> anyhow::Result<()> {
    let dir = common::TempDir::new("rule-set")?;
    let file = |name: &str, cidr: &str| {
        let path = dir.join(name);
        std::fs::write(
            &path,
            serde_json::json!({ "version": 3, "rules": [{ "ip_cidr": cidr }] }).to_string(),
        )
        .unwrap();
        path
    };
    let loopback = file("loopback.json", "127.0.0.0/8");
    let elsewhere = file("elsewhere.json", "192.0.2.0/24");
    for (rule_set, rejected) in [
        (
            serde_json::json!({ "type": "local", "tag": "s", "path": loopback }),
            true,
        ),
        (
            serde_json::json!({ "type": "local", "tag": "s", "path": elsewhere }),
            false,
        ),
        (
            serde_json::json!({ "tag": "s", "rules": [{ "ip_cidr": "127.0.0.1/32" }] }),
            true,
        ),
    ] {
        let result = common::retry_port_clash(|| {
            let [port] = common::free_ports();
            let config = serde_json::json!({
                "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": port }],
                "outbounds": [{ "type": "direct" }],
                "route": {
                    "rule_set": [rule_set],
                    "rules": [{ "rule_set": "s", "action": "reject" }]
                }
            });
            common::test_configs(vec![config.to_string()], "127.0.0.1", port)
        });
        assert_eq!(result.is_err(), rejected, "{}: {:?}", rule_set, result);
    }
    Ok(())
}

/// Serves `/s.json` as a redirect to `/rules.json`, which answers chunked,
/// and anything else as 404; counts the requests for the rules.
#[cfg(all(
    feature = "inbound-socks",
    feature = "outbound-direct",
    feature = "rule-set"
))]
fn rule_set_server(body: &'static str) -> (u16, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use std::io::{BufRead, BufReader, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let fetched = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = fetched.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() {
                continue;
            }
            // The rest of the head.
            loop {
                let mut header = String::new();
                if reader.read_line(&mut header).is_err() || header == "\r\n" {
                    break;
                }
            }
            let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
            let response = match path.as_str() {
                "/s.json" => {
                    "HTTP/1.1 302 Found\r\nLocation: /rules.json\r\nContent-Length: 0\r\n\r\n"
                        .to_string()
                }
                "/rules.json" => {
                    counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let (a, b) = body.split_at(body.len() / 2);
                    format!(
                        "HTTP/1.1 200 OK\r\nETag: \"v1\"\r\nTransfer-Encoding: chunked\r\n\r\n\
                         {:x}\r\n{}\r\n{:x}\r\n{}\r\n0\r\n\r\n",
                        a.len(),
                        a,
                        b.len(),
                        b
                    )
                }
                _ => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string(),
            };
            let _ = stream.write_all(response.as_bytes());
        }
    });
    (port, fetched)
}

// A remote rule-set is downloaded, through the redirect and in chunks,
// before the first connection: holding the echo server's address, it
// rejects that connection. One that cannot be downloaded fails the start.
#[cfg(all(
    feature = "inbound-socks",
    feature = "outbound-direct",
    feature = "rule-set"
))]
#[test]
fn a_remote_rule_set_is_downloaded_before_the_first_connection() -> anyhow::Result<()> {
    let (http_port, fetched) =
        rule_set_server(r#"{ "version": 3, "rules": [{ "ip_cidr": "127.0.0.0/8" }] }"#);
    let (other_port, _) =
        rule_set_server(r#"{ "version": 3, "rules": [{ "ip_cidr": "192.0.2.0/24" }] }"#);
    let config = |http_port: u16, path: &str, port: u16| {
        serde_json::json!({
            "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": port }],
            "outbounds": [{ "type": "direct" }],
            "route": {
                "rule_set": [{
                    "type": "remote", "tag": "s", "format": "source",
                    "url": format!("http://127.0.0.1:{}{}", http_port, path)
                }],
                "rules": [{ "rule_set": "s", "action": "reject" }]
            }
        })
        .to_string()
    };
    let result = common::retry_port_clash(|| {
        let [port] = common::free_ports();
        common::test_configs(vec![config(http_port, "/s.json", port)], "127.0.0.1", port)
    });
    assert!(
        result.is_err(),
        "not rejected: the rule-set was not in place"
    );
    assert!(fetched.load(std::sync::atomic::Ordering::SeqCst) >= 1);
    // The same, with a rule-set that does not hold the address, runs.
    common::retry_port_clash(|| {
        let [port] = common::free_ports();
        common::test_configs(vec![config(other_port, "/s.json", port)], "127.0.0.1", port)
    })?;

    let rt = tokio::runtime::Runtime::new()?;
    let [port] = common::free_ports();
    let err = common::run_sail_instances(&rt, vec![config(http_port, "/missing.json", port)])
        .expect_err("started without its rule-set");
    assert!(
        format!("{:#}", err).contains("rule-set [s]: download: http status 404"),
        "{:#}",
        err
    );
    Ok(())
}
