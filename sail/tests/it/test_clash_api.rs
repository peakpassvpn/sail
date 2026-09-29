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
async fn call(
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
fn json(body: &str) -> serde_json::Value {
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
async fn socks_connect(socks: u16, to: u16) -> anyhow::Result<tokio::net::TcpStream> {
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
            assert_eq!(listed["rule"], "final");
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
            assert_eq!(ruled_listed["rule"], "clash_mode=Global => route(a)");
            assert!(all["uploadTotal"].as_u64().is_some());

            // The rules, as sing-box tells them.
            let (_, _, body) = call(port, "GET", "/rules", s, &[], "").await?;
            assert_eq!(
                json(&body)["rules"],
                serde_json::json!([
                    { "type": "default", "payload": "clash_mode=Global", "proxy": "route(a)" }
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
