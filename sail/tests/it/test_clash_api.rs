#[allow(unused_imports)] // Unused where features leave out every test.
use crate::common;

/// A request to the API at `port`, with `secret` as a bearer token when
/// given: the status, the headers (lowercase names), and the body.
#[cfg(all(
    feature = "clash-api",
    feature = "outbound-select",
    feature = "outbound-direct",
    feature = "inbound-socks",
    feature = "tokio-tungstenite"
))]
pub(crate) async fn call(
    port: u16,
    method: &str,
    path: &str,
    secret: Option<&str>,
    extra: &[(&str, &str)],
    body: &str,
) -> anyhow::Result<(u16, Vec<(String, String)>, String)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    let mut request = format!(
        "{} {} HTTP/1.1\r\nHost: sail\r\nConnection: close\r\nContent-Length: {}\r\n",
        method,
        path,
        body.len()
    );
    if let Some(secret) = secret {
        request.push_str(&format!("Authorization: Bearer {}\r\n", secret));
    }
    for (name, value) in extra {
        request.push_str(&format!("{}: {}\r\n", name, value));
    }
    request.push_str("\r\n");
    request.push_str(body);
    s.write_all(request.as_bytes()).await?;
    let mut reply = String::new();
    s.read_to_string(&mut reply).await?;
    let (head, body) = reply.split_once("\r\n\r\n").unwrap_or((&reply, ""));
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let headers = lines
        .filter_map(|l| l.split_once(": "))
        .map(|(n, v)| (n.to_ascii_lowercase(), v.to_string()))
        .collect();
    Ok((status, headers, body.to_string()))
}

/// A body that may be chunked, as JSON.
#[cfg(all(
    feature = "clash-api",
    feature = "outbound-select",
    feature = "outbound-direct",
    feature = "inbound-socks",
    feature = "tokio-tungstenite"
))]
pub(crate) fn json(body: &str) -> serde_json::Value {
    let start = body.find(['{', '[']).unwrap_or(0);
    let end = body.rfind(['}', ']']).map_or(body.len(), |e| e + 1);
    serde_json::from_str(&body[start..end]).unwrap_or_else(|e| panic!("{}: {}", e, body))
}

/// A connection to 127.0.0.1:`to` through the SOCKS5 inbound at `socks`.
#[cfg(all(
    feature = "clash-api",
    feature = "outbound-select",
    feature = "outbound-direct",
    feature = "inbound-socks",
    feature = "tokio-tungstenite"
))]
pub(crate) async fn socks_connect(socks: u16, to: u16) -> anyhow::Result<tokio::net::TcpStream> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", socks)).await?;
    s.write_all(&[5, 1, 0]).await?;
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply).await?;
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&to.to_be_bytes());
    s.write_all(&request).await?;
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await?;
    anyhow::ensure!(reply[1] == 0, "socks reply {}", reply[1]);
    Ok(s)
}

/// The connection to port `to` the API lists, once it does.
#[cfg(all(
    feature = "clash-api",
    feature = "outbound-select",
    feature = "outbound-direct",
    feature = "inbound-socks",
    feature = "tokio-tungstenite"
))]
async fn connection_to(
    port: u16,
    secret: Option<&str>,
    to: u16,
) -> anyhow::Result<serde_json::Value> {
    let to = to.to_string();
    for _ in 0..50 {
        let (_, _, body) = call(port, "GET", "/connections", secret, &[], "").await?;
        let listed = json(&body)["connections"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["metadata"]["destinationPort"] == to.as_str())
            .cloned();
        if let Some(listed) = listed {
            return Ok(listed);
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    anyhow::bail!("no connection to {} listed", to)
}

/// That the connection is closed: a read ends or fails, soon.
#[cfg(all(
    feature = "clash-api",
    feature = "outbound-select",
    feature = "outbound-direct",
    feature = "inbound-socks",
    feature = "tokio-tungstenite"
))]
async fn assert_closed(s: &mut tokio::net::TcpStream) {
    use tokio::io::AsyncReadExt;
    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(std::time::Duration::from_secs(5), s.read(&mut buf))
        .await
        .expect("still open");
    assert!(matches!(read, Ok(0) | Err(_)), "{:?}", read);
}

// dashboard -> (clash api)sail: the outbounds and groups, selecting,
// modes, delays, DNS, and the streams, with the secret asked for.
#[cfg(all(
    feature = "clash-api",
    feature = "outbound-select",
    feature = "outbound-direct",
    feature = "inbound-socks",
    feature = "tokio-tungstenite"
))]
#[test]
fn a_dashboard_controls_the_instance_through_the_clash_api() -> anyhow::Result<()> {
    use futures::StreamExt;

    let secret = sail::generate::secret();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    // An HTTP server to measure delays against.
    let web = rt.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((mut s, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = s.read(&mut buf).await;
                    let _ = s
                        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                        .await;
                });
            }
        });
        anyhow::Ok(port)
    })?;
    // A server that holds the connections it takes, for them to be listed.
    let hold = rt.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = listener.accept().await {
                held.push(s);
            }
        });
        anyhow::Ok(port)
    })?;
    let (ids, (port, socks)) = common::retry_port_clash(|| {
        let [port, socks] = common::free_ports();
        let config = serde_json::json!({
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
                { "type": "selector", "tag": "g", "outbounds": ["a", "b"] },
                { "type": "direct", "tag": "a" },
                { "type": "direct", "tag": "b" },
            ],
            "route": { "rules": [{ "clash_mode": "Global", "outbound": "a" }] },
        });
        Ok((
            common::run_sail_instances(&rt, vec![config.to_string()])?,
            (port, socks),
        ))
    })?;
    let s = Some(secret.as_str());
    // A failure still shuts the instance down: the runtime waits for it
    // when dropped.
    let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rt.block_on(async {
            // No secret, or a wrong one: refused.
            let (status, _, body) = call(port, "GET", "/version", None, &[], "").await?;
            assert_eq!(status, 401, "{}", body);
            assert_eq!(json(&body)["message"], "Unauthorized");
            let (status, ..) = call(port, "GET", "/version", Some("wrong"), &[], "").await?;
            assert_eq!(status, 401);
            let (status, _, body) = call(port, "GET", "/version", s, &[], "").await?;
            assert_eq!(status, 200);
            assert_eq!(json(&body)["meta"], true);

            // A preflight is answered without the secret.
            let (status, headers, _) = call(
                port,
                "OPTIONS",
                "/proxies",
                None,
                &[
                    ("Origin", "http://yacd.example"),
                    ("Access-Control-Request-Method", "GET"),
                ],
                "",
            )
            .await?;
            assert_eq!(status, 204);
            assert!(headers.iter().any(|(n, v)| {
                n == "access-control-allow-origin" && v == "http://yacd.example"
            }));

            // The outbounds and groups.
            let (_, _, body) = call(port, "GET", "/proxies", s, &[], "").await?;
            let proxies = json(&body)["proxies"].clone();
            assert_eq!(proxies["g"]["type"], "Selector");
            assert_eq!(proxies["g"]["now"], "a");
            assert_eq!(proxies["g"]["all"], serde_json::json!(["a", "b"]));
            assert_eq!(proxies["a"]["type"], "Direct");
            assert_eq!(proxies["GLOBAL"]["now"], "g");

            // Selecting.
            let (status, ..) = call(port, "PUT", "/proxies/g", s, &[], r#"{"name":"b"}"#).await?;
            assert_eq!(status, 204);
            let (_, _, body) = call(port, "GET", "/proxies/g", s, &[], "").await?;
            assert_eq!(json(&body)["now"], "b");
            let (status, _, body) =
                call(port, "PUT", "/proxies/a", s, &[], r#"{"name":"b"}"#).await?;
            assert_eq!(status, 400, "{}", body);
            let (status, _, _) = call(port, "PUT", "/proxies/g", s, &[], r#"{"name":"c"}"#).await?;
            assert_eq!(status, 400);

            // The mode, in any case.
            let (_, _, body) = call(port, "GET", "/configs", s, &[], "").await?;
            let configs = json(&body);
            assert_eq!(configs["mode"], "Rule");
            assert_eq!(configs["mode-list"], serde_json::json!(["Rule", "Global"]));
            let (status, ..) =
                call(port, "PATCH", "/configs", s, &[], r#"{"mode":"global"}"#).await?;
            assert_eq!(status, 204);
            let (_, _, body) = call(port, "GET", "/configs", s, &[], "").await?;
            assert_eq!(json(&body)["mode"], "Global");

            // The connections, with the group's member first and the rule
            // that decided; back in Rule mode, `final`, the group.
            let (status, ..) =
                call(port, "PATCH", "/configs", s, &[], r#"{"mode":"Rule"}"#).await?;
            assert_eq!(status, 204);
            let (_, _, body) = call(port, "GET", "/proxies/g", s, &[], "").await?;
            assert_eq!(json(&body)["now"], "b");
            let mut conn = socks_connect(socks, hold).await?;
            let listed = connection_to(port, s, hold).await?;
            assert_eq!(
                listed["chains"],
                serde_json::json!(["b", "g"]),
                "{}",
                listed
            );
            // No rule matched: Mihomo's Match.
            assert_eq!(listed["rule"], "Match");
            assert_eq!(listed["rulePayload"], "");
            assert_eq!(listed["metadata"]["network"], "tcp");
            assert_eq!(listed["metadata"]["type"], "socks/in");
            assert_eq!(listed["metadata"]["destinationIP"], "127.0.0.1");
            let (status, ..) =
                call(port, "PATCH", "/configs", s, &[], r#"{"mode":"Global"}"#).await?;
            assert_eq!(status, 204);
            let mut ruled = socks_connect(socks, hold).await?;
            let mut all = serde_json::Value::Null;
            for _ in 0..50 {
                let (_, _, body) = call(port, "GET", "/connections", s, &[], "").await?;
                all = json(&body);
                if all["connections"].as_array().unwrap().len() == 2 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            let ruled_listed = all["connections"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["id"] != listed["id"])
                .cloned()
                .unwrap_or_else(|| panic!("{}", all));
            assert_eq!(ruled_listed["chains"], serde_json::json!(["a"]));
            // Mihomo has no type for clash_mode: sing-box's field name.
            assert_eq!(ruled_listed["rule"], "clash_mode");
            assert_eq!(ruled_listed["rulePayload"], "Global");
            assert!(all["uploadTotal"].as_u64().is_some());

            // The rules, as Mihomo lists its own.
            let (_, _, body) = call(port, "GET", "/rules", s, &[], "").await?;
            let mut rules = json(&body)["rules"].clone();
            // The connection in Global mode matched it once.
            let extra = rules[0]["extra"].take();
            assert_eq!(extra["disabled"], false);
            assert_eq!(extra["hitCount"], 1, "{}", extra);
            assert_ne!(extra["hitAt"], "0001-01-01T00:00:00Z");
            rules[0].as_object_mut().unwrap().remove("extra");
            assert_eq!(
                rules,
                serde_json::json!([
                    { "index": 0, "type": "clash_mode", "payload": "Global", "proxy": "a", "size": -1 }
                ])
            );

            // Closing one, then the rest.
            let path = format!("/connections/{}", listed["id"].as_str().unwrap());
            let (status, ..) = call(port, "DELETE", &path, s, &[], "").await?;
            assert_eq!(status, 204);
            assert_closed(&mut conn).await;
            let (status, ..) = call(port, "DELETE", "/connections", s, &[], "").await?;
            assert_eq!(status, 204);
            assert_closed(&mut ruled).await;

            // Delays, of an outbound and of a group's members.
            let url = format!("http://127.0.0.1:{}/", web);
            let path = format!("/proxies/a/delay?timeout=3000&url={}", url);
            let (status, _, body) = call(port, "GET", &path, s, &[], "").await?;
            assert_eq!(status, 200, "{}", body);
            assert!(json(&body)["delay"].as_u64().unwrap() > 0);
            let (_, _, body) = call(port, "GET", "/proxies/a", s, &[], "").await?;
            assert_eq!(json(&body)["history"].as_array().unwrap().len(), 1);
            let path = format!("/group/g/delay?timeout=3000&url={}", url);
            let (_, _, body) = call(port, "GET", &path, s, &[], "").await?;
            let delays = json(&body);
            assert!(
                delays["a"].as_u64().is_some() && delays["b"].as_u64().is_some(),
                "{}",
                delays
            );
            let (status, ..) = call(port, "GET", "/proxies/a/delay", s, &[], "").await?;
            assert_eq!(status, 400);

            // DNS, as the rules pick its server.
            let (_, _, body) =
                call(port, "GET", "/dns/query?name=a.example&type=A", s, &[], "").await?;
            let answer = json(&body);
            assert_eq!(answer["Status"], 0);
            assert_eq!(answer["Answer"][0]["data"], "10.0.0.1");
            let (status, ..) = call(port, "POST", "/cache/dns/flush", s, &[], "").await?;
            assert_eq!(status, 204);
            let (status, ..) = call(port, "POST", "/cache/fakeip/flush", s, &[], "").await?;
            assert_eq!(status, 204);

            // The traffic, over a WebSocket, with the secret as ?token=.
            let url = format!("ws://127.0.0.1:{}/traffic?token={}", port, secret);
            let (mut ws, _) = tokio_tungstenite::connect_async(url).await?;
            let frame = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
                .await?
                .unwrap()?;
            let frame = json(frame.to_text()?);
            assert!(frame["upTotal"].as_u64().is_some(), "{}", frame);
            // Without it, refused.
            let url = format!("ws://127.0.0.1:{}/traffic", port);
            assert!(tokio_tungstenite::connect_async(url).await.is_err());
            anyhow::Ok(())
        })
    }));
    common::shutdown_instances(&rt, ids);
    match checked {
        Ok(checked) => checked,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

// dashboard -> (clash api)sail: a fallback is pinned to a member and
// unpinned, as Mihomo's, and shows what it tests with.
#[cfg(all(
    feature = "clash-api",
    feature = "outbound-select",
    feature = "outbound-direct",
    feature = "outbound-fallback",
    feature = "inbound-socks",
    feature = "tokio-tungstenite"
))]
#[test]
fn a_dashboard_pins_a_fallback() -> anyhow::Result<()> {
    let secret = sail::generate::secret();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    // What the members are tested with: both pass.
    let (_server, served) = rt.block_on(crate::test_group_common::serve(
        "probe",
        std::time::Duration::ZERO,
    ));
    let url = format!("http://127.0.0.1:{}/generate_204", served);
    let dir = common::TempDir::new("clash-api-pin")?;
    let cache = dir.join("cache.db");
    let start = || {
        common::retry_port_clash(|| {
            let [port] = common::free_ports();
            let config = serde_json::json!({
                "clash_api": {
                    "external_controller": format!("127.0.0.1:{}", port),
                    "secret": secret,
                },
                "experimental": { "cache_file": {
                    "enabled": true,
                    "path": cache.to_str().unwrap(),
                } },
                "outbounds": [
                    { "type": "fallback", "tag": "fb", "outbounds": ["a", "b"], "url": url,
                      "expected_status": "204" },
                    { "type": "selector", "tag": "s", "outbounds": ["a"] },
                    { "type": "direct", "tag": "a" },
                    { "type": "direct", "tag": "b" },
                ],
            });
            Ok((
                common::run_sail_instances(&rt, vec![config.to_string()])?,
                port,
            ))
        })
    };
    let s = Some(secret.as_str());
    let get = |port: u16, name: &'static str| async move {
        let (_, _, body) = call(port, "GET", &format!("/proxies/{}", name), s, &[], "").await?;
        anyhow::Ok(json(&body))
    };
    let (ids, port) = start()?;
    let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rt.block_on(async {
            let fb = get(port, "fb").await?;
            assert_eq!(fb["now"], "a", "{}", fb);
            assert_eq!(fb["fixed"], "");
            assert_eq!(fb["testUrl"], url);
            assert_eq!(fb["expectedStatus"], "204");
            // A group that does not test has the key too, empty.
            assert_eq!(get(port, "s").await?["expectedStatus"], "");

            let (status, _, body) =
                call(port, "PUT", "/proxies/fb", s, &[], r#"{"name":"b"}"#).await?;
            assert_eq!(status, 204, "{}", body);
            let fb = get(port, "fb").await?;
            assert_eq!((&fb["now"], &fb["fixed"]), (&"b".into(), &"b".into()));
            let (status, ..) = call(port, "PUT", "/proxies/fb", s, &[], r#"{"name":"c"}"#).await?;
            assert_eq!(status, 400);
            anyhow::Ok(())
        })
    }));
    common::shutdown_instances(&rt, ids);
    checked.unwrap_or_else(|panic| std::panic::resume_unwind(panic))?;

    // The pin outlives a restart; unpinned, it does not.
    let (ids, port) = start()?;
    let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rt.block_on(async {
            let fb = get(port, "fb").await?;
            assert_eq!((&fb["now"], &fb["fixed"]), (&"b".into(), &"b".into()));
            let (status, ..) = call(port, "DELETE", "/proxies/fb", s, &[], "").await?;
            assert_eq!(status, 204);
            let fb = get(port, "fb").await?;
            assert_eq!((&fb["now"], &fb["fixed"]), (&"a".into(), &"".into()));
            anyhow::Ok(())
        })
    }));
    common::shutdown_instances(&rt, ids);
    checked.unwrap_or_else(|panic| std::panic::resume_unwind(panic))?;

    let (ids, port) = start()?;
    let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rt.block_on(async {
            let fb = get(port, "fb").await?;
            assert_eq!((&fb["now"], &fb["fixed"]), (&"a".into(), &"".into()));
            anyhow::Ok(())
        })
    }));
    common::shutdown_instances(&rt, ids);
    checked.unwrap_or_else(|panic| std::panic::resume_unwind(panic))
}

// dashboard -> (clash api)sail: a PASS outbound is listed, a selector
// picks it, and GLOBAL leaves it out as it does DIRECT.
#[cfg(all(
    feature = "clash-api",
    feature = "outbound-select",
    feature = "outbound-direct",
    feature = "outbound-pass",
    feature = "inbound-socks",
    feature = "tokio-tungstenite"
))]
#[test]
fn a_dashboard_picks_pass_in_a_selector() -> anyhow::Result<()> {
    let secret = sail::generate::secret();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let (ids, port) = common::retry_port_clash(|| {
        let [port] = common::free_ports();
        let config = serde_json::json!({
            "clash_api": {
                "external_controller": format!("127.0.0.1:{}", port),
                "secret": secret,
            },
            "outbounds": [
                { "type": "selector", "tag": "g", "outbounds": ["a", "PASS"] },
                { "type": "direct", "tag": "a" },
                { "type": "pass", "tag": "PASS" },
            ],
        });
        Ok((
            common::run_sail_instances(&rt, vec![config.to_string()])?,
            port,
        ))
    })?;
    let s = Some(secret.as_str());
    let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rt.block_on(async {
            let (_, _, body) = call(port, "GET", "/proxies", s, &[], "").await?;
            let proxies = json(&body)["proxies"].clone();
            assert_eq!(proxies["PASS"]["type"], "Pass", "{}", body);
            assert_eq!(proxies["g"]["all"], serde_json::json!(["a", "PASS"]));
            assert_eq!(proxies["GLOBAL"]["all"], serde_json::json!(["g"]));

            let (status, _, body) =
                call(port, "PUT", "/proxies/g", s, &[], r#"{"name":"PASS"}"#).await?;
            assert_eq!(status, 204, "{}", body);
            let (_, _, body) = call(port, "GET", "/proxies/g", s, &[], "").await?;
            assert_eq!(json(&body)["now"], "PASS");
            anyhow::Ok(())
        })
    }));
    common::shutdown_instances(&rt, ids);
    match checked {
        Ok(checked) => checked,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

// dashboard -> (clash api)sail: the outbound providers, their members
// among the proxies, and the rule-sets, as Mihomo's providers.
#[cfg(all(
    feature = "clash-api",
    feature = "outbound-select",
    feature = "outbound-direct",
    feature = "outbound-provider",
    feature = "rule-set",
    feature = "inbound-socks",
    feature = "tokio-tungstenite"
))]
#[test]
fn a_dashboard_sees_the_providers_through_the_clash_api() -> anyhow::Result<()> {
    let secret = sail::generate::secret();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let web = rt.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((mut s, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    let request = String::from_utf8_lossy(&buf[..n]);
                    // A subscription, which says what it used; one that
                    // fails; and anything else, for the delay tests.
                    let response = if request.starts_with("GET /sub ") {
                        let body = "proxies:\n  - { name: s1, type: socks5, server: 127.0.0.1, port: 1 }\n";
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\
                             subscription-userinfo: upload=1; download=2; total=3; expire=1767225600\r\n\
                             Connection: close\r\n\r\n{}",
                            body.len(),
                            body
                        )
                    } else if request.starts_with("GET /broken") {
                        "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_string()
                    } else {
                        "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string()
                    };
                    let _ = s.write_all(response.as_bytes()).await;
                });
            }
        });
        anyhow::Ok(port)
    })?;
    let (ids, port) = common::retry_port_clash(|| {
        let [port] = common::free_ports();
        let config = serde_json::json!({
            "clash_api": {
                "external_controller": format!("127.0.0.1:{}", port),
                "secret": secret,
            },
            "outbounds": [
                { "type": "selector", "tag": "g", "providers": "p" },
                { "type": "direct", "tag": "direct" },
            ],
            "outbound_providers": [{
                "type": "inline", "tag": "p",
                "outbounds": [{ "type": "direct", "tag": "m1" }, { "type": "direct", "tag": "m2" }]
            }, {
                "type": "remote", "tag": "sub",
                "url": format!("http://127.0.0.1:{}/sub", web), "download_detour": "direct"
            }, {
                "type": "remote", "tag": "broken",
                "url": format!("http://127.0.0.1:{}/broken?token=s3cret", web),
                "download_detour": "direct"
            }, {
                "type": "remote", "tag": "small", "size_limit": 10,
                "url": format!("http://127.0.0.1:{}/sub", web), "download_detour": "direct"
            }],
            "route": {
                "rule_set": [{
                    "type": "inline", "tag": "r",
                    "rules": [{ "domain_suffix": ["a.example", "b.example"] }]
                }],
                "rules": [{ "rule_set": "r", "outbound": "direct" }],
            },
        });
        Ok((
            common::run_sail_instances(&rt, vec![config.to_string()])?,
            port,
        ))
    })?;
    let s = Some(secret.as_str());
    let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rt.block_on(async {
            // The members among the proxies, for the group that takes them.
            let (_, _, body) = call(port, "GET", "/proxies", s, &[], "").await?;
            let proxies = json(&body)["proxies"].clone();
            assert_eq!(proxies["g"]["all"], serde_json::json!(["m1", "m2"]));
            assert_eq!(proxies["m1"]["type"], "Direct", "{}", proxies);

            // The provider, and one of its members.
            let (_, _, body) = call(port, "GET", "/providers/proxies", s, &[], "").await?;
            let p = json(&body)["providers"]["p"].clone();
            assert_eq!(p["type"], "Proxy");
            assert_eq!(p["vehicleType"], "Inline");
            let names: Vec<&str> = p["proxies"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|m| m["name"].as_str())
                .collect();
            assert_eq!(names, ["m1", "m2"]);
            let (_, _, body) = call(port, "GET", "/providers/proxies/p/m2", s, &[], "").await?;
            assert_eq!(json(&body)["name"], "m2");
            let (status, ..) = call(port, "GET", "/providers/proxies/nope", s, &[], "").await?;
            assert_eq!(status, 404);

            // Measuring a member, and updating (an inline one is as it is).
            let path = format!(
                "/providers/proxies/p/m1/healthcheck?timeout=3000&url=http://127.0.0.1:{}/",
                web
            );
            let (status, _, body) = call(port, "GET", &path, s, &[], "").await?;
            assert_eq!(status, 200, "{}", body);
            assert!(json(&body)["delay"].as_u64().unwrap() > 0);
            let (_, _, body) = call(port, "GET", "/proxies/m1", s, &[], "").await?;
            assert_eq!(json(&body)["history"].as_array().unwrap().len(), 1);
            let (status, ..) = call(port, "PUT", "/providers/proxies/p", s, &[], "").await?;
            assert_eq!(status, 204);

            // A subscription says what it used, as Mihomo shows it; an
            // update that fails says so, and an unknown provider is none.
            let (status, ..) = call(port, "PUT", "/providers/proxies/sub", s, &[], "").await?;
            assert_eq!(status, 204);
            let (_, _, body) = call(port, "GET", "/providers/proxies/sub", s, &[], "").await?;
            let sub = json(&body);
            assert_eq!(sub["vehicleType"], "HTTP");
            assert_eq!(
                sub["subscriptionInfo"],
                serde_json::json!({ "Upload": 1, "Download": 2, "Total": 3, "Expire": 1767225600 })
            );
            assert_eq!(sub["proxies"][0]["name"], "s1", "{}", sub);
            let (status, _, body) =
                call(port, "PUT", "/providers/proxies/broken", s, &[], "").await?;
            assert_eq!(status, 503, "{}", body);
            assert!(body.contains("503") && !body.contains("s3cret"), "{}", body);
            // Past its size_limit, which the error tells, with no URL.
            let (status, _, body) =
                call(port, "PUT", "/providers/proxies/small", s, &[], "").await?;
            assert_eq!(status, 503, "{}", body);
            assert!(
                body.contains("larger than its size_limit, 10 bytes") && !body.contains("/sub"),
                "{}",
                body
            );
            let (status, ..) = call(port, "PUT", "/providers/proxies/nope", s, &[], "").await?;
            assert_eq!(status, 404);

            // The rule-sets.
            let (_, _, body) = call(port, "GET", "/providers/rules", s, &[], "").await?;
            let r = json(&body)["providers"]["r"].clone();
            assert_eq!(r["type"], "Rule");
            assert_eq!(r["vehicleType"], "Inline");
            assert_eq!(r["behavior"], "Classical");
            assert_eq!(r["ruleCount"], 2, "{}", r);
            let (status, ..) = call(port, "PUT", "/providers/rules/r", s, &[], "").await?;
            assert_eq!(status, 204);
            let (status, ..) = call(port, "PUT", "/providers/rules/nope", s, &[], "").await?;
            assert_eq!(status, 404);
            anyhow::Ok(())
        })
    }));
    common::shutdown_instances(&rt, ids);
    match checked {
        Ok(checked) => checked,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

/// A ZIP of `entries`, stored.
#[cfg(all(
    feature = "clash-api",
    feature = "outbound-select",
    feature = "outbound-direct",
    feature = "http-client",
    feature = "inbound-socks",
    feature = "tokio-tungstenite"
))]
fn stored_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let (mut out, mut directory) = (Vec::new(), Vec::new());
    for (name, body) in entries {
        let offset = out.len() as u32;
        let sizes = [(body.len() as u32).to_le_bytes(); 2].concat();
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&[20, 0, 0, 0, 0, 0]);
        out.extend_from_slice(&[0; 8]);
        out.extend_from_slice(&sizes);
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(body);
        directory.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        directory.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0]);
        directory.extend_from_slice(&[0; 8]);
        directory.extend_from_slice(&sizes);
        directory.extend_from_slice(&(name.len() as u16).to_le_bytes());
        directory.extend_from_slice(&[0; 12]);
        directory.extend_from_slice(&offset.to_le_bytes());
        directory.extend_from_slice(name.as_bytes());
    }
    let offset = out.len() as u32;
    out.extend_from_slice(&directory);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&[(entries.len() as u16).to_le_bytes(); 2].concat());
    out.extend_from_slice(&(directory.len() as u32).to_le_bytes());
    out.extend_from_slice(&offset.to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out
}

// dashboard -> (clash api)sail: the dashboard downloaded into an empty
// external_ui from the host's URL, downloaded again, and the
// configuration reloaded from its file.
#[cfg(all(
    feature = "clash-api",
    feature = "outbound-select",
    feature = "outbound-direct",
    feature = "http-client",
    feature = "inbound-socks",
    feature = "tokio-tungstenite"
))]
#[test]
fn a_dashboard_is_downloaded_and_the_configuration_reloaded() -> anyhow::Result<()> {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    let secret = sail::generate::secret();
    let dir = common::TempDir::new("clash-ui")?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    // Serves the dashboard's ZIP, which the test changes.
    let archive = Arc::new(Mutex::new(stored_zip(&[
        ("d-gh-pages/index.html", b"first"),
        ("d-gh-pages/assets/app.js", b"let a;"),
    ])));
    let web = rt.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let archive = archive.clone();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((mut s, _)) = listener.accept().await {
                let body = archive.lock().unwrap().clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = s.read(&mut buf).await;
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = s.write_all(head.as_bytes()).await;
                    let _ = s.write_all(&body).await;
                });
            }
        });
        anyhow::Ok(port)
    })?;
    let port = common::free_port();
    let config = |rules: serde_json::Value| {
        serde_json::json!({
            "clash_api": {
                "external_controller": format!("127.0.0.1:{}", port),
                "secret": secret,
                "external_ui": "ui",
                "external_ui_download_detour": "direct",
            },
            "outbounds": [{ "type": "direct", "tag": "direct" }],
            "route": { "rules": rules },
        })
        .to_string()
    };
    let path = dir.join("config.json");
    std::fs::write(&path, config(serde_json::json!([])))?;
    let id = common::next_rt_id();
    let opts = sail::StartOptions {
        signals: false,
        config: sail::Config::File(path.to_string_lossy().to_string()),
        #[cfg(feature = "auto-reload")]
        auto_reload: false,
        runtime_opt: sail::RuntimeOption::SingleThread,
        runtime: common::runtime_options(),
        host: sail::runtime::Host {
            data_dir: Some(dir.path().to_path_buf()),
            ui_download_url: Some(format!("http://127.0.0.1:{}/ui.zip", web)),
            ..Default::default()
        },
    };
    common::start_instance(id, opts)?;
    let s = Some(secret.as_str());
    let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rt.block_on(async {
            // Downloaded at start, without its top directory, and served
            // without the secret.
            let mut body = String::new();
            for _ in 0..100 {
                let (status, _, got) = call(port, "GET", "/ui/", None, &[], "").await?;
                if status == 200 {
                    body = got;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            assert!(body.contains("first"), "{:?}", body);
            let (_, _, js) = call(port, "GET", "/ui/assets/app.js", None, &[], "").await?;
            assert!(js.contains("let a;"));

            // Downloaded again, in place of what was there.
            *archive.lock().unwrap() = stored_zip(&[("index.html", b"second")]);
            let (status, ..) = call(port, "POST", "/upgrade/ui", None, &[], "").await?;
            assert_eq!(status, 401);
            let (status, _, err) = call(port, "POST", "/upgrade/ui", s, &[], "").await?;
            assert_eq!(status, 204, "{}", err);
            let (_, _, body) = call(port, "GET", "/ui/", None, &[], "").await?;
            assert!(body.contains("second"), "{:?}", body);
            let (status, ..) = call(port, "GET", "/ui/assets/app.js", None, &[], "").await?;
            assert_eq!(status, 404);

            // Reloaded from the file: a mode its rules name now.
            std::fs::write(
                &path,
                config(serde_json::json!([{ "clash_mode": "Custom", "outbound": "direct" }])),
            )?;
            let (status, _, err) = call(port, "PUT", "/configs", s, &[], "{}").await?;
            assert_eq!(status, 204, "{}", err);
            let (_, _, body) = call(port, "GET", "/configs", s, &[], "").await?;
            let modes = json(&body)["mode-list"].clone();
            assert!(
                modes.as_array().unwrap().iter().any(|m| m == "Custom"),
                "{}",
                modes
            );
            // Another's payload or path is refused.
            let (status, ..) = call(port, "PUT", "/configs", s, &[], r#"{"payload":"{}"}"#).await?;
            assert_eq!(status, 400);
            anyhow::Ok(())
        })
    }));
    common::shutdown_instances(&rt, vec![id]);
    match checked {
        Ok(checked) => checked,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

// dashboard -> (clash api)sail, embedded: a dashboard's streams end when
// the instance stops -- the /traffic WebSocket with a close, a /traffic
// stream of JSON lines at its end -- rather than outlive it on the host's
// runtime, and the stop leaves no task of the API behind.
#[cfg(all(
    feature = "clash-api",
    feature = "outbound-direct",
    feature = "tokio-tungstenite"
))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dashboard_s_streams_end_with_the_instance() -> anyhow::Result<()> {
    use futures::StreamExt;
    use sail::embed::{Config, Instance, Options};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let secret = sail::generate::secret();
    let [port] = common::free_ports();
    let config = serde_json::json!({
        "clash_api": {
            "external_controller": format!("127.0.0.1:{}", port),
            "secret": secret,
        },
        "outbounds": [{ "type": "direct", "tag": "direct" }],
    })
    .to_string();
    let instance = Instance::new(Options::new())?;
    instance.start(Config::Json(config)).await?;

    let url = format!("ws://127.0.0.1:{}/traffic?token={}", port, secret);
    let (mut ws, _) = tokio_tungstenite::connect_async(url).await?;
    tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await?
        .expect("a frame")?;

    let mut lines = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    lines
        .write_all(
            format!(
                "GET /traffic HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {}\r\n\r\n",
                secret
            )
            .as_bytes(),
        )
        .await?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(5), lines.read(&mut buf)).await??;
    assert!(
        String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&buf[..n])
    );

    instance.stop().await?;
    // The WebSocket is closed, not left open.
    let ended = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match ws.next().await {
                None | Some(Err(_)) => return,
                Some(Ok(m)) if m.is_close() => return,
                Some(Ok(_)) => {}
            }
        }
    })
    .await;
    assert!(ended.is_ok(), "the WebSocket outlived the instance");
    // The stream of JSON lines ends.
    let ended = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match lines.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    })
    .await;
    assert!(
        ended.is_ok(),
        "the stream of JSON lines outlived the instance"
    );
    let report = instance.stop_report().expect("a stop report");
    assert!(report.clean(), "{:?}", report);
    Ok(())
}
