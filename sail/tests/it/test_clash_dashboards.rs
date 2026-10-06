#[allow(unused_imports)] // Unused where features leave out every test.
use crate::common;

// yacd, Yacd-meta, metacubexd -> (clash api)sail: the requests the three
// dashboards make, as their sources make them (recorded 2026-10-06 from
// MetaCubeX/metacubexd packages/ui, MetaCubeX/Yacd-meta src/api and
// haishanh/yacd src/api), and in each answer the fields they read, of the
// type they read them as. What sail does not fill is in docs/compat
// (clash.md's Clash API section), and is not asked for here.

/// What a dashboard reads at a place in an answer.
#[cfg(all(
    feature = "clash-api",
    feature = "outbound-select",
    feature = "outbound-direct",
    feature = "inbound-socks",
    feature = "tokio-tungstenite"
))]
#[derive(Clone, Copy, Debug)]
enum Read {
    Str,
    Num,
    Bool,
    Arr,
    Obj,
}

/// Whether `value` at `path` is read as `read`: a path of keys and
/// indexes separated by `/`, `*` for every key of an object or item of an
/// array (none at all is a failure: the dashboards iterate them).
#[cfg(all(
    feature = "clash-api",
    feature = "outbound-select",
    feature = "outbound-direct",
    feature = "inbound-socks",
    feature = "tokio-tungstenite"
))]
fn check(value: &serde_json::Value, path: &str, read: Read) -> Result<(), String> {
    fn walk<'a>(
        value: &'a serde_json::Value,
        parts: &[&str],
        at: String,
        out: &mut Vec<(String, &'a serde_json::Value)>,
    ) -> Result<(), String> {
        let Some((part, rest)) = parts.split_first() else {
            out.push((at, value));
            return Ok(());
        };
        if *part == "*" {
            let items: Vec<(String, &serde_json::Value)> = match value {
                serde_json::Value::Object(map) => map.iter().map(|(k, v)| (k.clone(), v)).collect(),
                serde_json::Value::Array(items) => items
                    .iter()
                    .enumerate()
                    .map(|(i, v)| (i.to_string(), v))
                    .collect(),
                _ => return Err(format!("{}: not an object or array", at)),
            };
            if items.is_empty() {
                return Err(format!("{}: empty", at));
            }
            for (key, item) in items {
                walk(item, rest, format!("{}/{}", at, key), out)?;
            }
            return Ok(());
        }
        let next = match value {
            serde_json::Value::Array(items) => {
                part.parse::<usize>().ok().and_then(|i| items.get(i))
            }
            other => other.get(*part),
        };
        match next {
            Some(next) => walk(next, rest, format!("{}/{}", at, part), out),
            None => Err(format!("{}/{}: missing", at, part)),
        }
    }
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    let mut found = Vec::new();
    walk(value, &parts, String::new(), &mut found)?;
    for (at, v) in found {
        let ok = match read {
            Read::Str => v.is_string(),
            Read::Num => v.is_number(),
            Read::Bool => v.is_boolean(),
            Read::Arr => v.is_array(),
            Read::Obj => v.is_object(),
        };
        if !ok {
            return Err(format!("{}: {} is not {:?}", at, v, read));
        }
    }
    Ok(())
}

/// A request a dashboard makes: who, the method, the path, the body, the
/// status it must get, and what it reads of the answer.
#[cfg(all(
    feature = "clash-api",
    feature = "outbound-select",
    feature = "outbound-direct",
    feature = "inbound-socks",
    feature = "tokio-tungstenite"
))]
type Recorded = (
    &'static str,
    &'static str,
    String,
    &'static str,
    u16,
    Vec<(&'static str, Read)>,
);

#[cfg(all(
    feature = "clash-api",
    feature = "outbound-select",
    feature = "outbound-direct",
    feature = "inbound-socks",
    feature = "tokio-tungstenite"
))]
#[test]
fn the_dashboards_requests_get_what_they_read() -> anyhow::Result<()> {
    use futures::StreamExt;
    use Read::*;

    use super::test_clash_api::{call, json, socks_connect};

    let secret = sail::generate::secret();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    // An HTTP server to measure delays against, and one that holds the
    // connections it takes, for them to be listed.
    let (web, hold) = rt.block_on(async {
        let web = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let hold = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let ports = (web.local_addr()?.port(), hold.local_addr()?.port());
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((mut s, _)) = web.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = s.read(&mut buf).await;
                    let _ = s
                        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                        .await;
                });
            }
        });
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = hold.accept().await {
                held.push(s);
            }
        });
        anyhow::Ok(ports)
    })?;
    let (ids, (port, socks)) = common::retry_port_clash(|| {
        let [port, socks] = common::free_ports();
        let config = serde_json::json!({
            "log": { "level": "info" },
            "clash_api": {
                "external_controller": format!("127.0.0.1:{}", port),
                "secret": secret,
            },
            "inbounds": [
                { "type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": socks }
            ],
            "dns": { "servers": [
                { "type": "hosts", "predefined": { "a.example": "10.0.0.1" } }
            ] },
            "outbounds": [
                { "type": "selector", "tag": "g", "outbounds": ["a", "b"], "providers": "p" },
                { "type": "direct", "tag": "a" },
                { "type": "direct", "tag": "b" },
            ],
            "outbound_providers": [{
                "type": "inline", "tag": "p",
                "outbounds": [{ "type": "direct", "tag": "m1" }]
            }],
            "route": {
                "rule_set": [{
                    "type": "inline", "tag": "r",
                    "rules": [{ "domain_suffix": ["a.example", "b.example"] }]
                }],
                "rules": [
                    { "rule_set": "r", "outbound": "a" },
                    { "domain_suffix": "c.example", "network": "tcp", "outbound": "b" },
                    { "port": 1, "action": "reject" },
                ],
                "final": "g",
            },
        });
        Ok((
            common::run_sail_instances(&rt, vec![config.to_string()])?,
            (port, socks),
        ))
    })?;
    let s = Some(secret.as_str());
    let delay = format!("url=http://127.0.0.1:{}/&timeout=5000", web);
    // Each request, by who makes it: the status it must get, and what it
    // reads of the answer.
    let requests: Vec<Recorded> = vec![
        (
            "all",
            "GET",
            "/version".into(),
            "",
            200,
            vec![("version", Str), ("meta", Bool)],
        ),
        (
            "all",
            "GET",
            "/configs".into(),
            "",
            200,
            vec![
                ("mode", Str),
                ("log-level", Str),
                ("port", Num),
                ("socks-port", Num),
                ("redir-port", Num),
                ("tproxy-port", Num),
                ("mixed-port", Num),
                ("allow-lan", Bool),
                ("tun/enable", Bool),
                ("interface-name", Str),
                ("sniffing", Bool),
            ],
        ),
        (
            "metacubexd",
            "GET",
            "/configs".into(),
            "",
            200,
            vec![
                ("mode-list", Arr),
                ("unified-delay", Bool),
                ("tun/stack", Str),
                ("tun/device", Str),
            ],
        ),
        (
            "all",
            "PATCH",
            "/configs".into(),
            r#"{"mode":"rule"}"#,
            204,
            vec![],
        ),
        (
            "Yacd",
            "PATCH",
            "/configs".into(),
            r#"{"log-level":"info"}"#,
            204,
            vec![],
        ),
        (
            "all",
            "GET",
            "/proxies".into(),
            "",
            200,
            vec![
                ("proxies/*/name", Str),
                ("proxies/*/type", Str),
                ("proxies/*/history", Arr),
                ("proxies/*/udp", Bool),
                ("proxies/GLOBAL/all", Arr),
                ("proxies/GLOBAL/now", Str),
                ("proxies/g/all", Arr),
                ("proxies/g/now", Str),
                ("proxies/g/hidden", Bool),
                ("proxies/g/testUrl", Str),
            ],
        ),
        (
            "metacubexd",
            "GET",
            "/proxies".into(),
            "",
            200,
            vec![("proxies/g/icon", Str), ("proxies/a/extra", Obj)],
        ),
        (
            "all",
            "PUT",
            "/proxies/g".into(),
            r#"{"name":"b"}"#,
            204,
            vec![],
        ),
        (
            "all",
            "GET",
            format!("/proxies/a/delay?{}", delay),
            "",
            200,
            vec![("delay", Num)],
        ),
        (
            "Yacd-meta",
            "GET",
            format!("/proxies/a/delay?{}&expected=204", delay),
            "",
            200,
            vec![("delay", Num)],
        ),
        (
            "meta",
            "GET",
            format!("/group/g/delay?{}", delay),
            "",
            200,
            vec![("*", Num)],
        ),
        (
            "all",
            "GET",
            "/providers/proxies".into(),
            "",
            200,
            vec![
                ("providers/p/name", Str),
                ("providers/p/type", Str),
                ("providers/p/vehicleType", Str),
                ("providers/p/proxies/*/name", Str),
                ("providers/p/proxies/*/history", Arr),
            ],
        ),
        (
            "all",
            "GET",
            "/providers/proxies/p/healthcheck".into(),
            "",
            204,
            vec![],
        ),
        (
            "meta",
            "GET",
            format!("/providers/proxies/p/m1/healthcheck?{}", delay),
            "",
            200,
            vec![("delay", Num)],
        ),
        ("all", "PUT", "/providers/proxies/p".into(), "", 204, vec![]),
        (
            "meta",
            "GET",
            "/providers/rules".into(),
            "",
            200,
            vec![
                ("providers/r/name", Str),
                ("providers/r/behavior", Str),
                ("providers/r/ruleCount", Num),
                ("providers/r/vehicleType", Str),
                ("providers/r/type", Str),
            ],
        ),
        ("meta", "PUT", "/providers/rules/r".into(), "", 204, vec![]),
        (
            "all",
            "GET",
            "/rules".into(),
            "",
            200,
            vec![
                ("rules/*/type", Str),
                ("rules/*/payload", Str),
                ("rules/*/proxy", Str),
                ("rules/*/size", Num),
                ("rules/*/index", Num),
                ("rules/*/extra/disabled", Bool),
                ("rules/*/extra/hitCount", Num),
                ("rules/*/extra/hitAt", Str),
            ],
        ),
        (
            "meta",
            "PATCH",
            "/rules/disable".into(),
            r#"{"2": true}"#,
            204,
            vec![],
        ),
        (
            "metacubexd",
            "GET",
            "/dns/query?name=a.example&type=A".into(),
            "",
            200,
            vec![("Answer/*/data", Str)],
        ),
        (
            "meta",
            "POST",
            "/cache/fakeip/flush".into(),
            "{}",
            204,
            vec![],
        ),
        (
            "metacubexd",
            "POST",
            "/cache/dns/flush".into(),
            "",
            204,
            vec![],
        ),
    ];
    let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rt.block_on(async {
            let mut failed = Vec::new();
            for (who, method, path, body, status, reads) in &requests {
                let (got, _, answer) = call(port, method, path, s, &[], body).await?;
                if got != *status {
                    failed.push(format!(
                        "{} {} {} ({}): {} {}",
                        who, method, path, status, got, answer
                    ));
                    continue;
                }
                if reads.is_empty() {
                    continue;
                }
                let answer = json(&answer);
                for (at, read) in reads {
                    if let Err(e) = check(&answer, at, *read) {
                        failed.push(format!("{} {} {}: {}", who, method, path, e));
                    }
                }
            }

            // A connection open, as the connections page reads it.
            let _held = socks_connect(socks, hold).await?;
            let mut listed = serde_json::Value::Null;
            for _ in 0..50 {
                let (_, _, body) = call(port, "GET", "/connections", s, &[], "").await?;
                listed = json(&body);
                if !listed["connections"].as_array().unwrap().is_empty() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            let connection_reads = [
                ("downloadTotal", Num),
                ("uploadTotal", Num),
                ("connections/*/id", Str),
                ("connections/*/upload", Num),
                ("connections/*/download", Num),
                ("connections/*/start", Str),
                ("connections/*/chains", Arr),
                ("connections/*/rule", Str),
                ("connections/*/rulePayload", Str),
                ("connections/*/metadata/network", Str),
                ("connections/*/metadata/type", Str),
                ("connections/*/metadata/sourceIP", Str),
                ("connections/*/metadata/sourcePort", Str),
                ("connections/*/metadata/destinationIP", Str),
                ("connections/*/metadata/destinationPort", Str),
                ("connections/*/metadata/host", Str),
                ("connections/*/metadata/sniffHost", Str),
                ("connections/*/metadata/processPath", Str),
                ("connections/*/metadata/inboundName", Str),
                ("connections/*/metadata/dnsMode", Str),
                ("connections/*/metadata/process", Str),
                ("connections/*/metadata/inboundIP", Str),
                ("connections/*/metadata/inboundPort", Str),
                ("connections/*/metadata/inboundUser", Str),
                ("connections/*/metadata/dscp", Num),
                ("connections/*/metadata/specialProxy", Str),
                ("connections/*/metadata/specialRules", Str),
                ("connections/*/metadata/remoteDestination", Str),
            ];
            // The inbound the connection came in by, as Mihomo tells it.
            let first = &listed["connections"][0]["metadata"];
            if first["inboundIP"] != "127.0.0.1"
                || first["inboundPort"]
                    .as_str()
                    .and_then(|p| p.parse::<u16>().ok())
                    != Some(socks)
            {
                failed.push(format!("all GET /connections: inbound {}", first));
            }

            // The switch the rules page shows: the rule turned off by the
            // PATCH above is off, and a connection it would have matched
            // goes on to the next; on again, it matches.
            let (_, _, body) = call(port, "GET", "/rules", s, &[], "").await?;
            let rules = json(&body);
            if rules["rules"][2]["extra"]["disabled"] != true {
                failed.push(format!("meta PATCH /rules/disable: not off: {}", rules));
            }
            let (status, ..) =
                call(port, "PATCH", "/rules/disable", s, &[], r#"{"2": false}"#).await?;
            let (_, _, body) = call(port, "GET", "/rules", s, &[], "").await?;
            if status != 204 || json(&body)["rules"][2]["extra"]["disabled"] != false {
                failed.push(format!("meta PATCH /rules/disable: not on again: {}", body));
            }
            let (status, ..) = call(port, "PATCH", "/rules/disable", s, &[], "not json").await?;
            if status != 400 {
                failed.push(format!(
                    "meta PATCH /rules/disable with a bad body: {}",
                    status
                ));
            }
            for (at, read) in connection_reads {
                if let Err(e) = check(&listed, at, read) {
                    failed.push(format!("all GET /connections: {}", e));
                }
            }

            // The streams, over WebSockets with the secret as ?token=, as
            // all three open them: one frame each.
            let streams: [(&str, Vec<(&str, Read)>); 4] = [
                ("/traffic", vec![("up", Num), ("down", Num)]),
                ("/memory", vec![("inuse", Num), ("oslimit", Num)]),
                (
                    "/connections",
                    vec![("connections", Arr), ("downloadTotal", Num)],
                ),
                ("/logs?level=info", vec![("type", Str), ("payload", Str)]),
            ];
            for (path, reads) in streams {
                let join = if path.contains('?') { '&' } else { '?' };
                let url = format!("ws://127.0.0.1:{}{}{}token={}", port, path, join, secret);
                let (mut ws, _) = tokio_tungstenite::connect_async(url).await?;
                // A log line comes of something logged: connections made
                // through the instance, until one is sent.
                let logs = path.starts_with("/logs");
                let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
                let frame = loop {
                    tokio::select! {
                        frame = ws.next() => break frame,
                        _ = tokio::time::sleep(std::time::Duration::from_millis(300)) => {
                            anyhow::ensure!(
                                tokio::time::Instant::now() < deadline,
                                "ws {}: no frame in 10 s",
                                path
                            );
                            if logs {
                                let _ = socks_connect(socks, hold).await;
                            }
                        }
                    }
                };
                let frame = frame.ok_or_else(|| anyhow::anyhow!("ws {}: closed", path))??;
                let frame = json(frame.to_text()?);
                for (at, read) in reads {
                    if let Err(e) = check(&frame, at, read) {
                        failed.push(format!("all ws {}: {} in {}", path, e, frame));
                    }
                }
            }

            // Closing them, as the connections page does.
            let (status, ..) = call(port, "DELETE", "/connections", s, &[], "").await?;
            if status != 204 {
                failed.push(format!("all DELETE /connections: {}", status));
            }
            assert!(failed.is_empty(), "{}", failed.join("\n"));
            anyhow::Ok(())
        })
    }));
    common::shutdown_instances(&rt, ids);
    match checked {
        Ok(checked) => checked,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}
