#[allow(unused_imports)] // Unused where features leave out every test.
use crate::common;

/// A site list of one group, `CN`, of `domain`.
#[allow(dead_code)]
fn site_list(domain: &str) -> Vec<u8> {
    use protobuf::Message;
    use sail::config::geosite;
    let mut group = geosite::SiteGroup::new();
    group.tag = "CN".into();
    let mut d = geosite::Domain::new();
    d.type_ = geosite::domain::Type::Domain.into();
    d.value = domain.into();
    group.domain.push(d);
    let mut list = geosite::SiteGroupList::new();
    list.site_group.push(group);
    list.write_to_bytes().unwrap()
}

/// A server that answers one request with `body`.
#[allow(dead_code)]
async fn serve(body: Vec<u8>) -> anyhow::Result<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf).await?;
        let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
        stream.write_all(head.as_bytes()).await?;
        stream.write_all(&body).await?;
        anyhow::Ok(())
    });
    Ok(format!("http://{}/site.dat", addr))
}

// The runtime API lists the assets the configuration reads, and updates
// one: downloaded through an outbound, checked, put in place, reloaded.
#[cfg(all(feature = "api", feature = "http-client", feature = "outbound-direct"))]
#[test]
fn the_api_lists_and_updates_assets() -> anyhow::Result<()> {
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let dir = common::TempDir::new("assets")?;
    let site = dir.join("site.dat");
    std::fs::write(&site, site_list("old.example"))?;
    let path = dir.join("config.json");
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let id = common::next_rt_id();
    let api_port = common::retry_port_clash(|| {
        let [api_port] = common::free_ports();
        let config = serde_json::json!({
            "api": {
                "listen": format!("127.0.0.1:{}", api_port),
                "secret": "Zq3Lp8Rk1Vn6Xc2Bm7Ws4Ty9Hd5Gf0Ja",
            },
            "outbounds": [{ "type": "direct" }],
            "route": { "rules": [{ "geosite": "cn", "outbound": "direct" }] },
        });
        std::fs::write(&path, config.to_string())?;
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
        let start = rt.spawn_blocking(move || sail::start(id, opts));
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !sail::is_running(id) {
            if start.is_finished() {
                match rt.block_on(start)? {
                    Err(e) => anyhow::bail!("start sail failed: {}", e),
                    Ok(()) => anyhow::bail!("sail stopped as soon as it started"),
                }
            }
            anyhow::ensure!(
                std::time::Instant::now() < deadline,
                "sail did not start within 10s"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(api_port)
    })?;
    let api = |method: &str, path: &str, body: &str| -> anyhow::Result<(u16, String)> {
        rt.block_on(async {
            let mut s = tokio::net::TcpStream::connect(("127.0.0.1", api_port)).await?;
            let request = format!(
                "{} {} HTTP/1.1\r\nHost: sail\r\nContent-Type: application/json\r\n\
                 Authorization: Bearer Zq3Lp8Rk1Vn6Xc2Bm7Ws4Ty9Hd5Gf0Ja\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                method,
                path,
                body.len(),
                body
            );
            s.write_all(request.as_bytes()).await?;
            let mut reply = String::new();
            s.read_to_string(&mut reply).await?;
            let status = reply
                .split(' ')
                .nth(1)
                .and_then(|c| c.parse().ok())
                .unwrap_or(0);
            let body = reply.split("\r\n\r\n").nth(1).unwrap_or("").to_owned();
            Ok((status, body))
        })
    };
    let update = "/api/v1/runtime/assets/site.dat/update";

    // Fails with an error rather than a panic, so that the instance is shut
    // down either way.
    let result = (|| {
        let (status, body) = api("GET", "/api/v1/runtime/assets", "")?;
        anyhow::ensure!(status == 200, "{} {}", status, body);
        let assets: serde_json::Value = serde_json::from_str(&body)?;
        anyhow::ensure!(assets[0]["name"] == "site.dat", "{}", assets);
        anyhow::ensure!(assets[0]["kind"] == "site", "{}", assets);
        anyhow::ensure!(assets[0]["present"] == true, "{}", assets);
        anyhow::ensure!(
            assets[0]["used_by"] == serde_json::json!(["route.rules[0].geosite"]),
            "{}",
            assets
        );

        let (status, body) = api("POST", "/api/v1/runtime/assets/asn.mmdb/update", "")?;
        anyhow::ensure!(status == 404, "{} {}", status, body);
        let (status, body) = api("POST", update, "")?;
        anyhow::ensure!(
            status == 400 && body.contains("asset_sources"),
            "{} {}",
            status,
            body
        );
        let (status, body) = api("POST", update, r#"{ "URL": "x" }"#)?;
        anyhow::ensure!(status == 400, "{} {}", status, body);

        // Not a site list: the old one stays.
        let url = rt.block_on(serve(b"<html>".to_vec()))?;
        let (status, body) = api("POST", update, &format!(r#"{{ "url": "{}" }}"#, url))?;
        anyhow::ensure!(
            status == 502 && body.contains("not a site list"),
            "{} {}",
            status,
            body
        );
        anyhow::ensure!(std::fs::read(&site)? == site_list("old.example"));

        let url = rt.block_on(serve(site_list("new.example")))?;
        let (status, body) = api(
            "POST",
            update,
            &format!(r#"{{ "url": "{}", "detour": "direct" }}"#, url),
        )?;
        anyhow::ensure!(status == 200, "{} {}", status, body);
        let updated: serde_json::Value = serde_json::from_str(&body)?;
        anyhow::ensure!(updated["reloaded"] == true, "{}", updated);
        anyhow::ensure!(std::fs::read(&site)? == site_list("new.example"));
        anyhow::Ok(())
    })();
    assert!(sail::shutdown(id));
    rt.shutdown_timeout(Duration::from_secs(1));
    result
}
