//! No secret of a configuration reaches what an instance tells: its log at
//! trace, the configuration's Debug, the Clash API, the hosts' JSON, and
//! the errors a mistaken secret is refused with.

#![cfg(all(
    feature = "inbound-mixed",
    feature = "inbound-trojan",
    feature = "inbound-vless",
    feature = "inbound-shadowsocks",
    feature = "inbound-reality",
    feature = "outbound-trojan",
    feature = "outbound-vless",
    feature = "outbound-shadowsocks",
    feature = "outbound-hysteria2",
    feature = "outbound-tuic",
    feature = "outbound-socks",
    feature = "outbound-http",
    feature = "outbound-provider",
    feature = "all-endpoints",
    feature = "clash-api",
    feature = "dns-doh"
))]

use std::time::Duration;

use crate::common;

const PASSWORD: &str = "pw-7e57-s3cr3t";
const UUID: &str = "5ec7e7a1-1111-4111-8111-111111111111";
/// 32 bytes of 0x44, a Shadowsocks 2022 key.
const PSK: &str = "REREREREREREREREREREREREREREREREREREREREREQ=";
/// 32 bytes of 0xab, a REALITY private key.
const REALITY_KEY: &str = "abababababababababababababababababababababababababababababababab";
const SHORT_ID: &str = "7e57c0de";
/// 32 bytes of 0x33 and of 0x55, WireGuard keys.
const WG_PRIVATE: &str = "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=";
const WG_PRESHARED: &str = "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU=";
/// A password a client tries, which the server refuses.
const WRONG: &str = "wrong-7e57-s3cr3t";
const API_SECRET: &str = "api-7e57-s3cr3t-0123456789abcdef0123456789";
const SUB_TOKEN: &str = "sub-7e57-t0ken";
const HEADER_TOKEN: &str = "hdr-7e57-t0ken";
const DOH_PATH: &str = "doh-7e57-path";

/// What `text` gives away of `secrets`.
fn leaks<'a>(text: &str, secrets: &[&'a str]) -> Vec<&'a str> {
    secrets
        .iter()
        .copied()
        .filter(|s| text.contains(s))
        .collect()
}

/// A GET of the Clash API, its body.
async fn get(port: u16, path: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // The API may listen a moment after the instance runs.
    let mut s = None;
    for _ in 0..50 {
        match tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
            Ok(c) => {
                s = Some(c);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    let Some(mut s) = s else {
        return format!("(no answer on {})", path);
    };
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
        path, API_SECRET
    );
    s.write_all(request.as_bytes()).await.unwrap();
    let mut body = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut body)).await;
    String::from_utf8_lossy(&body).to_string()
}

#[test]
fn no_secret_reaches_what_an_instance_tells() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key_pem = cert.key_pair.serialize_pem();
    // A line of the private key's body, as it would show.
    let key_line = key_pem.lines().nth(1).unwrap().to_string();
    let [api, mixed, trojan, vless, vless_tls, ss] = common::free_ports();
    let config = serde_json::json!({
        "log": { "level": "trace" },
        "clash_api": { "external_controller": format!("127.0.0.1:{}", api), "secret": API_SECRET },
        "dns": { "servers": [
            { "type": "https", "tag": "doh", "server": "127.0.0.1", "server_port": 9,
              "path": format!("/{}", DOH_PATH) },
            { "type": "local", "tag": "local" }
        ] },
        "http_clients": [{ "tag": "hc", "headers": { "Authorization": format!("Bearer {}", HEADER_TOKEN) } }],
        "inbounds": [
            { "type": "mixed", "tag": "mixed", "listen": "127.0.0.1", "listen_port": mixed,
              "users": [{ "username": "u", "password": PASSWORD }] },
            { "type": "trojan", "tag": "trojan-in", "listen": "127.0.0.1", "listen_port": trojan,
              "users": [{ "name": "a", "password": PASSWORD }],
              "tls": { "enabled": true, "certificate": cert.cert.pem(), "key": key_pem } },
            { "type": "vless", "tag": "vless-in", "listen": "127.0.0.1", "listen_port": vless,
              "users": [{ "name": "a", "uuid": UUID }],
              "tls": { "enabled": true, "server_name": "www.example.com", "reality": {
                  "enabled": true, "handshake": { "server": "127.0.0.1", "server_port": 9 },
                  "private_key": REALITY_KEY, "short_id": [SHORT_ID] } } },
            { "type": "vless", "tag": "vless-tls-in", "listen": "127.0.0.1", "listen_port": vless_tls,
              "users": [{ "name": "a", "uuid": UUID }],
              "tls": { "enabled": true, "certificate": cert.cert.pem(), "key": key_pem } },
            { "type": "shadowsocks", "tag": "ss-in", "listen": "127.0.0.1", "listen_port": ss,
              "method": "2022-blake3-aes-256-gcm", "password": PSK }
        ],
        "outbounds": [
            // Each through the instance's own inbound, and two with a
            // password the server refuses.
            { "type": "trojan", "tag": "trojan", "server": "127.0.0.1", "server_port": trojan,
              "password": PASSWORD, "tls": { "enabled": true, "server_name": "localhost", "insecure": true } },
            { "type": "trojan", "tag": "trojan-bad", "server": "127.0.0.1", "server_port": trojan,
              "password": WRONG, "tls": { "enabled": true, "server_name": "localhost", "insecure": true } },
            { "type": "vless", "tag": "vless", "server": "127.0.0.1", "server_port": vless_tls, "uuid": UUID,
              "tls": { "enabled": true, "server_name": "localhost", "insecure": true } },
            { "type": "shadowsocks", "tag": "ss", "server": "127.0.0.1", "server_port": ss,
              "method": "2022-blake3-aes-256-gcm", "password": PSK },
            { "type": "hysteria2", "tag": "hy2", "server": "127.0.0.1", "server_port": 9,
              "password": PASSWORD, "obfs": { "type": "salamander", "password": PASSWORD },
              "tls": { "enabled": true, "server_name": "localhost" } },
            { "type": "tuic", "tag": "tuic", "server": "127.0.0.1", "server_port": 9,
              "uuid": UUID, "password": PASSWORD, "tls": { "enabled": true, "server_name": "localhost" } },
            { "type": "socks", "tag": "socks", "server": "127.0.0.1", "server_port": mixed,
              "username": "u", "password": PASSWORD },
            { "type": "socks", "tag": "socks-bad", "server": "127.0.0.1", "server_port": mixed,
              "username": "u", "password": WRONG },
            { "type": "http", "tag": "http", "server": "127.0.0.1", "server_port": mixed,
              "username": "u", "password": PASSWORD },
            { "type": "selector", "tag": "sel", "outbounds": ["direct", "trojan", "trojan-bad", "vless", "ss", "socks-bad",
              "hy2", "tuic", "socks", "http"], "providers": "sub" },
            { "type": "direct", "tag": "direct" }
        ],
        "endpoints": [{ "type": "wireguard", "tag": "wg", "address": ["10.0.0.2/32"],
            "private_key": WG_PRIVATE,
            "peers": [{ "address": "127.0.0.1", "port": 9, "public_key": WG_PRIVATE,
                        "pre_shared_key": WG_PRESHARED, "allowed_ips": ["0.0.0.0/0"] }] }],
        "outbound_providers": [{ "type": "remote", "tag": "sub",
            "url": format!("http://127.0.0.1:9/sub?token={}", SUB_TOKEN), "http_client": "hc" }],
        "route": { "final": "sel", "default_domain_resolver": "local" }
    });
    let secrets = [
        PASSWORD,
        WRONG,
        UUID,
        PSK,
        REALITY_KEY,
        SHORT_ID,
        WG_PRIVATE,
        WG_PRESHARED,
        API_SECRET,
        SUB_TOKEN,
        HEADER_TOKEN,
        DOH_PATH,
        &key_line,
    ];
    let text = config.to_string();
    let parsed = sail::config::from_string(&text).unwrap();
    assert!(parsed.warnings.is_empty(), "{:?}", parsed.warnings);
    let debug = format!("{:?}", parsed);
    assert_eq!(
        leaks(&debug, &secrets),
        Vec::<&str>::new(),
        "Debug: {}",
        debug
    );

    let log = sail::app::logger::InstanceLog::new(100_000);
    let rt_id = common::next_rt_id();
    let opts = sail::StartOptions {
        config: sail::Config::Internal(Box::new(parsed)),
        #[cfg(feature = "auto-reload")]
        auto_reload: false,
        runtime_opt: sail::RuntimeOption::SingleThread,
        runtime: common::runtime_options(),
        host: sail::runtime::Host {
            log: Some(sail::app::logger::InstanceLogRef(log.clone())),
            cache_dir: Some(std::env::temp_dir().join(format!("sail-redaction-{}", rt_id))),
            ..Default::default()
        },
    };
    let start = std::thread::spawn(move || sail::start(rt_id, opts));
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !sail::is_running(rt_id) {
        assert!(!start.is_finished(), "sail stopped: {:?}", start.join());
        assert!(std::time::Instant::now() < deadline, "sail did not start");
        std::thread::sleep(Duration::from_millis(20));
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let told = rt.block_on(async {
        // A connection through each outbound, for what they log of it.
        let manager = sail::runtime_manager(rt_id).unwrap();
        // To the API, which answers: every handshake and authentication
        // runs to its end, or to its refusal.
        let target = format!("http://127.0.0.1:{}/version", api);
        let mut measured = Vec::new();
        for tag in [
            "trojan",
            "trojan-bad",
            "vless",
            "ss",
            "socks",
            "socks-bad",
            "http",
            "hy2",
            "tuic",
            "wg",
        ] {
            let r = manager
                .url_test(tag, Some(&target), Duration::from_secs(3))
                .await;
            measured.push((tag, r.is_ok()));
        }
        // The ones through the instance's own inbounds got through.
        for (tag, ok) in &measured {
            let through = matches!(*tag, "trojan" | "vless" | "ss" | "socks" | "http");
            assert_eq!(*ok, through, "{}: {:?}", tag, measured);
        }
        let _ = manager.update_provider("sub").await;
        let mut told = String::new();
        for path in [
            "/configs",
            "/proxies",
            "/group",
            "/providers/proxies",
            "/providers/rules",
            "/rules",
            "/connections",
            "/version",
        ] {
            told.push_str(&get(api, path).await);
        }
        let outbounds: Vec<_> = manager
            .outbounds()
            .await
            .iter()
            .map(sail::control::json::Outbound::of)
            .collect();
        told.push_str(
            &serde_json::to_string(&sail::control::json::Outbounds { outbounds }).unwrap(),
        );
        let providers: Vec<_> = manager
            .providers()
            .await
            .iter()
            .map(sail::control::json::Provider::of)
            .collect();
        told.push_str(
            &serde_json::to_string(&sail::control::json::Providers { providers }).unwrap(),
        );
        told
    });
    sail::shutdown(rt_id);
    let _ = start.join();
    let (lines, _) = log.follow();
    let logged: String = lines.iter().map(|l| format!("{}\n", l.message)).collect();
    assert!(
        logged.lines().count() > 10,
        "too little logged at trace: {}",
        logged
    );
    assert!(
        !told.contains("(no answer on"),
        "the API did not answer: {}\n{}",
        told,
        logged
    );
    assert_eq!(
        leaks(&told, &secrets),
        Vec::<&str>::new(),
        "the APIs told: {}",
        told
    );
    assert_eq!(
        leaks(&logged, &secrets),
        Vec::<&str>::new(),
        "the log: {}",
        logged
    );
}

/// A secret sail refuses is not repeated in the error.
#[test]
fn a_refused_secret_is_not_repeated() {
    let bad = "not-a-key-7e57-s3cr3t";
    for config in [
        serde_json::json!({ "outbounds": [{ "type": "vless", "tag": "v", "server": "a", "server_port": 1, "uuid": bad }] }),
        serde_json::json!({ "outbounds": [{ "type": "shadowsocks", "tag": "s", "server": "a", "server_port": 1,
                            "method": "2022-blake3-aes-256-gcm", "password": bad }] }),
        serde_json::json!({ "endpoints": [{ "type": "wireguard", "tag": "w", "address": ["10.0.0.2/32"],
                            "private_key": bad, "peers": [{ "address": "a", "port": 1, "public_key": WG_PRIVATE,
                            "allowed_ips": ["0.0.0.0/0"] }] }] }),
        serde_json::json!({ "inbounds": [{ "type": "vless", "tag": "v", "listen_port": 1, "users": [{ "uuid": UUID }],
                            "tls": { "enabled": true, "server_name": "a", "reality": { "enabled": true,
                            "handshake": { "server": "a", "server_port": 1 }, "private_key": bad,
                            "short_id": ["00"] } } }] }),
    ] {
        let err = match sail::config::from_string(&config.to_string()) {
            Err(e) => format!("{:#}", e),
            Ok(c) => match sail::check_config(&c, &Default::default()) {
                Err(e) => format!("{:#}", e),
                Ok(()) => panic!("taken: {}", config),
            },
        };
        assert!(!err.contains(bad), "{}", err);
    }
}
