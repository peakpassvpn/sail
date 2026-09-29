#[allow(unused_imports)] // Unused where features leave out every test.
use crate::common;

/// A request to the API at `port`, with `secret` as a bearer token when
/// given: the status, the headers (lowercase names), and the body.
#[cfg(all(
    feature = "clash-api",
    feature = "outbound-select",
    feature = "outbound-direct",
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
    feature = "tokio-tungstenite"
))]
fn json(body: &str) -> serde_json::Value {
    let start = body.find(['{', '[']).unwrap_or(0);
    let end = body.rfind(['}', ']']).map_or(body.len(), |e| e + 1);
    serde_json::from_str(&body[start..end]).unwrap_or_else(|e| panic!("{}: {}", e, body))
}

// dashboard -> (clash api)sail: the outbounds and groups, selecting,
// modes, delays, DNS, and the streams, with the secret asked for.
#[cfg(all(
    feature = "clash-api",
    feature = "outbound-select",
    feature = "outbound-direct",
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
    let (ids, port) = common::retry_port_clash(|| {
        let [port] = common::free_ports();
        let config = serde_json::json!({
            "clash_api": {
                "external_controller": format!("127.0.0.1:{}", port),
                "secret": secret,
            },
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
            port,
        ))
    })?;
    let s = Some(secret.as_str());
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
        assert!(headers
            .iter()
            .any(|(n, v)| { n == "access-control-allow-origin" && v == "http://yacd.example" }));

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
        let (status, _, body) = call(port, "PUT", "/proxies/a", s, &[], r#"{"name":"b"}"#).await?;
        assert_eq!(status, 400, "{}", body);
        let (status, _, _) = call(port, "PUT", "/proxies/g", s, &[], r#"{"name":"c"}"#).await?;
        assert_eq!(status, 400);

        // The mode, in any case.
        let (_, _, body) = call(port, "GET", "/configs", s, &[], "").await?;
        let configs = json(&body);
        assert_eq!(configs["mode"], "Rule");
        assert_eq!(configs["mode-list"], serde_json::json!(["Rule", "Global"]));
        let (status, ..) = call(port, "PATCH", "/configs", s, &[], r#"{"mode":"global"}"#).await?;
        assert_eq!(status, 204);
        let (_, _, body) = call(port, "GET", "/configs", s, &[], "").await?;
        assert_eq!(json(&body)["mode"], "Global");

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
    })?;
    common::shutdown_instances(&rt, ids);
    Ok(())
}
