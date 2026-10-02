// The control API: served on a unix socket, or on loopback behind a
// secret; what it refuses, and why, in its JSON errors.

#![cfg(all(feature = "api", feature = "outbound-direct"))]

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::common;

const SECRET: &str = "Zq3Lp8Rk1Vn6Xc2Bm7Ws4Ty9Hd5Gf0Ja";

/// Where the API is reached.
enum At {
    Port(u16),
    #[cfg(unix)]
    Socket(std::path::PathBuf),
}

/// One call: its status, `Www-Authenticate`'s presence, and its body.
fn call(
    rt: &tokio::runtime::Runtime,
    at: &At,
    secret: Option<&str>,
    method: &str,
    path: &str,
    body: &str,
) -> anyhow::Result<(u16, bool, serde_json::Value)> {
    let auth = secret.map_or(String::new(), |s| {
        format!("Authorization: Bearer {}\r\n", s)
    });
    let request = format!(
        "{} {} HTTP/1.1\r\nHost: sail\r\nContent-Type: application/json\r\n{}\
         Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        method,
        path,
        auth,
        body.len(),
        body
    );
    async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
        mut s: S,
        request: &str,
    ) -> anyhow::Result<String> {
        s.write_all(request.as_bytes()).await?;
        let mut reply = String::new();
        s.read_to_string(&mut reply).await?;
        Ok(reply)
    }
    let reply = rt.block_on(async {
        match at {
            At::Port(port) => {
                exchange(
                    tokio::net::TcpStream::connect(("127.0.0.1", *port)).await?,
                    &request,
                )
                .await
            }
            #[cfg(unix)]
            At::Socket(path) => {
                exchange(tokio::net::UnixStream::connect(path).await?, &request).await
            }
        }
    })?;
    let status = reply
        .split(' ')
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let (head, body) = reply.split_once("\r\n\r\n").unwrap_or((&reply, ""));
    let challenged = head
        .to_ascii_lowercase()
        .contains("www-authenticate: bearer");
    let body = serde_json::from_str(body).unwrap_or(serde_json::Value::String(body.to_owned()));
    Ok((status, challenged, body))
}

/// The error a body carries: its code and message.
fn error(body: &serde_json::Value) -> (&str, &str) {
    (
        body["error"]["code"].as_str().unwrap_or_default(),
        body["error"]["message"].as_str().unwrap_or_default(),
    )
}

#[cfg(feature = "inbound-mixed")]
#[test]
fn the_api_on_loopback_needs_its_secret_and_refuses_an_inbound_on_no_port() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (ids, api_port, mixed_port) = common::retry_port_clash(|| {
        let [api_port, mixed_port] = common::free_ports();
        let config = serde_json::json!({
            "api": { "listen": format!("127.0.0.1:{}", api_port), "secret": SECRET },
            "outbounds": [{ "type": "direct" }],
        });
        Ok((
            common::run_sail_instances(&rt, vec![config.to_string()])?,
            api_port,
            mixed_port,
        ))
    })?;
    let at = At::Port(api_port);
    let result = (|| {
        let assets = "/api/v1/runtime/assets";
        for secret in [None, Some("not-the-secret"), Some(&SECRET[1..])] {
            let (status, challenged, body) = call(&rt, &at, secret, "GET", assets, "")?;
            anyhow::ensure!(
                status == 401 && challenged,
                "{:?}: {} {}",
                secret,
                status,
                body
            );
            anyhow::ensure!(error(&body).0 == "unauthenticated", "{}", body);
        }
        // Refused before it is read: nothing changes without the secret.
        let (status, _, body) = call(&rt, &at, None, "POST", "/api/v1/runtime/shutdown", "")?;
        anyhow::ensure!(status == 401, "{} {}", status, body);
        let (status, _, body) = call(&rt, &at, Some(SECRET), "GET", assets, "")?;
        anyhow::ensure!(status == 200, "{} {}", status, body);

        // An inbound with no port listens on nothing: refused, and why.
        let inbounds = "/api/v1/runtime/inbounds";
        let (status, _, body) = call(
            &rt,
            &at,
            Some(SECRET),
            "POST",
            inbounds,
            r#"{ "type": "mixed", "tag": "system-proxy" }"#,
        )?;
        anyhow::ensure!(status == 400, "{} {}", status, body);
        let (code, message) = error(&body);
        anyhow::ensure!(
            code == "invalid"
                && message.starts_with("[system-proxy] inbound: listen_port: missing"),
            "{}",
            body
        );
        let inbound = serde_json::json!({
            "type": "mixed", "tag": "system-proxy",
            "listen": "127.0.0.1", "listen_port": mixed_port,
        });
        let (status, _, body) = call(
            &rt,
            &at,
            Some(SECRET),
            "POST",
            inbounds,
            &inbound.to_string(),
        )?;
        anyhow::ensure!(status == 200, "{} {}", status, body);
        rt.block_on(tokio::net::TcpStream::connect(("127.0.0.1", mixed_port)))?;
        Ok(())
    })();
    for id in ids {
        sail::shutdown(id);
    }
    result
}

#[cfg(unix)]
#[test]
fn the_api_is_on_a_socket_of_the_users_own_in_the_data_directory() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    // Short: a socket's path is at most 103 bytes on macOS.
    let dir = std::path::PathBuf::from(format!("/tmp/sail-api-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let config = serde_json::json!({ "api": {}, "outbounds": [{ "type": "direct" }] });
    let ids = common::run_sail_instances_in(&rt, vec![config.to_string()], Some(&dir))?;
    let socket = dir.join("api.sock");
    let result = (|| {
        let mode = std::fs::metadata(&socket)?.permissions().mode() & 0o777;
        anyhow::ensure!(mode == 0o600, "{:o}", mode);
        let (status, _, body) = call(
            &rt,
            &At::Socket(socket.clone()),
            None,
            "GET",
            "/api/v1/runtime/assets",
            "",
        )?;
        anyhow::ensure!(status == 200, "{} {}", status, body);
        Ok(())
    })();
    for id in ids {
        sail::shutdown(id);
    }
    let _ = std::fs::remove_dir_all(&dir);
    result
}

#[test]
fn a_reload_that_fails_says_why_and_keeps_what_runs() -> anyhow::Result<()> {
    let dir = common::TempDir::new("api-reload")?;
    let path = dir.join("config.json");
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let id = 960;
    let config = |api_port: u16, outbounds: serde_json::Value| {
        serde_json::json!({
            "api": { "listen": format!("127.0.0.1:{}", api_port), "secret": SECRET },
            "outbounds": outbounds,
        })
        .to_string()
    };
    let api_port = common::retry_port_clash(|| {
        let [api_port] = common::free_ports();
        std::fs::write(
            &path,
            config(api_port, serde_json::json!([{ "type": "direct" }])),
        )?;
        let opts = sail::StartOptions {
            config: sail::Config::File(path.to_string_lossy().to_string()),
            #[cfg(feature = "auto-reload")]
            auto_reload: false,
            runtime_opt: sail::RuntimeOption::SingleThread,
            runtime: common::runtime_options(),
            host: sail::runtime::Host {
                data_dir: Some(dir.path().to_path_buf()),
                cache_dir: Some(dir.path().to_path_buf()),
                ..Default::default()
            },
        };
        let start = std::thread::spawn(move || sail::start(id, opts));
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !sail::is_running(id) {
            if start.is_finished() {
                match start.join() {
                    Ok(Err(e)) => anyhow::bail!("start sail failed: {}", e),
                    _ => anyhow::bail!("sail stopped as soon as it started"),
                }
            }
            anyhow::ensure!(std::time::Instant::now() < deadline, "sail did not start");
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(api_port)
    })?;
    let at = At::Port(api_port);
    let reload = "/api/v1/runtime/reload";
    let result = (|| {
        std::fs::write(
            &path,
            config(api_port, serde_json::json!([{ "type": "nope" }])),
        )?;
        let (status, _, body) = call(&rt, &at, Some(SECRET), "POST", reload, "")?;
        anyhow::ensure!(status == 400, "{} {}", status, body);
        let (code, message) = error(&body);
        anyhow::ensure!(
            code == "invalid" && message.starts_with("[nope] outbound: unknown protocol"),
            "{}",
            body
        );
        // What ran runs on.
        anyhow::ensure!(sail::is_running(id));
        let (status, _, body) = call(&rt, &at, Some(SECRET), "GET", "/api/v1/runtime/assets", "")?;
        anyhow::ensure!(status == 200, "{} {}", status, body);

        std::fs::write(
            &path,
            config(
                api_port,
                serde_json::json!([{ "type": "direct", "tag": "d" }]),
            ),
        )?;
        let (status, _, body) = call(&rt, &at, Some(SECRET), "POST", reload, "")?;
        anyhow::ensure!(status == 200, "{} {}", status, body);
        Ok(())
    })();
    sail::shutdown(id);
    result
}

#[cfg(feature = "inbound-trojan")]
#[test]
fn the_api_reads_and_changes_users_and_connections() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (ids, api_port) = common::retry_port_clash(|| {
        let [api_port, trojan_port] = common::free_ports();
        let config = serde_json::json!({
            "api": { "listen": format!("127.0.0.1:{}", api_port), "secret": SECRET },
            "inbounds": [{ "type": "trojan", "tag": "t", "listen": "127.0.0.1",
                           "listen_port": trojan_port,
                           "users": [{ "name": "alice", "password": "a" }] }],
            "outbounds": [{ "type": "direct" }],
            "user_limits": { "alice": { "max_connections": 2 } },
        });
        Ok((
            common::run_sail_instances(&rt, vec![config.to_string()])?,
            api_port,
        ))
    })?;
    let at = At::Port(api_port);
    let get = |path: &str| call(&rt, &at, Some(SECRET), "GET", path, "");
    let result = (|| {
        let (status, _, body) = get("/api/v1")?;
        anyhow::ensure!(
            status == 200 && body["api_version"] == 1 && body["json_version"] == 4,
            "{} {}",
            status,
            body
        );

        let (status, _, body) = get("/api/v1/runtime/users")?;
        anyhow::ensure!(status == 200, "{} {}", status, body);
        let alice = &body["users"][0];
        anyhow::ensure!(
            alice["name"] == "alice"
                && alice["inbounds"] == serde_json::json!(["t"])
                && alice["active"] == true
                && alice["limits"]["max_connections"] == 2,
            "{}",
            body
        );
        let (status, _, body) = get("/api/v1/runtime/users/bob")?;
        anyhow::ensure!(
            status == 404 && error(&body).0 == "not_found",
            "{} {}",
            status,
            body
        );

        let limits = "/api/v1/runtime/users/alice/limits";
        let (status, _, body) = call(
            &rt,
            &at,
            Some(SECRET),
            "PUT",
            limits,
            r#"{ "max_connections": 0 }"#,
        )?;
        anyhow::ensure!(
            status == 400 && error(&body).0 == "invalid",
            "{} {}",
            status,
            body
        );
        let (status, _, body) = call(
            &rt,
            &at,
            Some(SECRET),
            "PUT",
            limits,
            r#"{ "max_connections": 5, "up_mbps": 10 }"#,
        )?;
        anyhow::ensure!(status == 204, "{} {}", status, body);
        let (_, _, body) = get("/api/v1/runtime/users/alice")?;
        anyhow::ensure!(
            body["limits"]["max_connections"] == 5 && body["limits"]["up_mbps"] == 10,
            "{}",
            body
        );
        // Back to what the configuration sets.
        let (status, _, body) = call(&rt, &at, Some(SECRET), "DELETE", limits, "")?;
        anyhow::ensure!(status == 204, "{} {}", status, body);
        let (_, _, body) = get("/api/v1/runtime/users/alice")?;
        anyhow::ensure!(
            body["limits"]["max_connections"] == 2 && body["limits"]["up_mbps"].is_null(),
            "{}",
            body
        );
        // A time in milliseconds goes back as it came; one in RFC 3339 is
        // taken as user_limits has it; both at once is a mistake.
        let expire_at_ms = 4_102_444_800_123u64;
        let put = |body: &str| call(&rt, &at, Some(SECRET), "PUT", limits, body);
        let (status, _, body) = put(&format!(r#"{{ "expire_at_ms": {} }}"#, expire_at_ms))?;
        anyhow::ensure!(status == 204, "{} {}", status, body);
        let (_, _, got) = get("/api/v1/runtime/users/alice")?;
        anyhow::ensure!(got["limits"]["expire_at_ms"] == expire_at_ms, "{}", got);
        let (status, _, body) = put(&got["limits"].to_string())?;
        anyhow::ensure!(status == 204, "{} {}", status, body);
        let (_, _, again) = get("/api/v1/runtime/users/alice")?;
        anyhow::ensure!(again["limits"] == got["limits"], "{} {}", got, again);
        let (status, _, body) = put(r#"{ "expire_at": "2100-01-01T00:00:00Z" }"#)?;
        anyhow::ensure!(status == 204, "{} {}", status, body);
        let (_, _, got) = get("/api/v1/runtime/users/alice")?;
        anyhow::ensure!(
            got["limits"]["expire_at_ms"] == 4_102_444_800_000u64,
            "{}",
            got
        );
        let (status, _, body) = put(&format!(
            r#"{{ "expire_at": "2100-01-01T00:00:00Z", "expire_at_ms": {} }}"#,
            expire_at_ms
        ))?;
        anyhow::ensure!(
            status == 400 && error(&body).0 == "invalid",
            "{} {}",
            status,
            body
        );
        let (status, _, _) = call(&rt, &at, Some(SECRET), "DELETE", limits, "")?;
        anyhow::ensure!(status == 204);

        let (status, _, body) = call(
            &rt,
            &at,
            Some(SECRET),
            "PUT",
            "/api/v1/runtime/users/bob/limits",
            r#"{ "max_connections": 5 }"#,
        )?;
        anyhow::ensure!(status == 404, "{} {}", status, body);

        let (status, _, body) = call(
            &rt,
            &at,
            Some(SECRET),
            "POST",
            "/api/v1/runtime/users/alice/quota/reset",
            "",
        )?;
        anyhow::ensure!(status == 204, "{} {}", status, body);
        let (status, _, body) = call(
            &rt,
            &at,
            Some(SECRET),
            "POST",
            "/api/v1/runtime/users/alice/disconnect",
            "",
        )?;
        anyhow::ensure!(status == 200 && body["closed"] == 0, "{} {}", status, body);

        for path in ["/api/v1/runtime/stats", "/api/v1/runtime/stats?clear=true"] {
            let (status, _, body) = get(path)?;
            anyhow::ensure!(
                status == 200 && body["users"].is_object() && body["inbounds"].is_object(),
                "{}: {} {}",
                path,
                status,
                body
            );
        }
        let (status, _, body) = get("/api/v1/runtime/status")?;
        anyhow::ensure!(
            status == 200 && body["connections"].is_number() && body["memory"].is_number(),
            "{} {}",
            status,
            body
        );
        let (status, _, body) = get("/api/v1/runtime/connections")?;
        anyhow::ensure!(
            status == 200 && body["connections"].is_array(),
            "{} {}",
            status,
            body
        );
        let (status, _, body) = call(
            &rt,
            &at,
            Some(SECRET),
            "DELETE",
            "/api/v1/runtime/connections/999999",
            "",
        )?;
        anyhow::ensure!(status == 404, "{} {}", status, body);
        let (status, _, body) = call(
            &rt,
            &at,
            Some(SECRET),
            "DELETE",
            "/api/v1/runtime/connections",
            "",
        )?;
        anyhow::ensure!(
            status == 200 && body["closed"].is_number(),
            "{} {}",
            status,
            body
        );

        // The pages /connections replaced are gone.
        let (status, _, _) = get("/api/v1/runtime/stat/json")?;
        anyhow::ensure!(status == 404, "{}", status);
        Ok(())
    })();
    for id in ids {
        sail::shutdown(id);
    }
    result
}
