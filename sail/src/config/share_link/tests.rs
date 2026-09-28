use serde_json::json;

use super::*;

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const PASSWORD: &str = "fake-Pa55word";
/// A REALITY public key, base64url as Xray writes it.
const PBK: &str = "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0";
/// A 2022-blake3-aes-128-gcm key.
const PSK_128: &str = "Dx4tPEtaaXiHlqW0w9Lh8A==";

fn b64(data: &[u8], url_safe: bool, pad: bool) -> String {
    let alphabet: &[u8] = if url_safe {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    } else {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    };
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk.iter().fold(0u32, |n, b| n << 8 | *b as u32) << (8 * (3 - chunk.len()));
        for i in 0..=chunk.len() {
            out.push(alphabet[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
        if pad {
            out.push_str(&"=".repeat(3 - chunk.len()));
        }
    }
    out
}

fn ok(uri: &str) -> Value {
    parse(uri).unwrap_or_else(|e| panic!("{}: {}", uri, e))
}

/// The error `uri` gives, checked for secrets.
fn err(uri: &str) -> String {
    let e = parse(uri).expect_err(uri).to_string();
    for secret in [UUID, PASSWORD, PBK, PSK_128, uri] {
        assert!(!e.contains(secret), "{} leaks a secret: {}", uri, e);
    }
    e
}

#[test]
fn base64_is_read_in_every_dialect() {
    let data = b"\xfb\xff\xfe any bytes, of every length";
    for n in 0..data.len() {
        let data = &data[..n];
        for (url_safe, pad) in [(false, true), (false, false), (true, true), (true, false)] {
            let encoded = b64(data, url_safe, pad);
            assert_eq!(url::base64_decode(&encoded).as_deref(), Some(data));
        }
    }
    assert_eq!(url::base64_decode("YW\r\nJj").unwrap(), b"abc");
    assert!(url::base64_decode("YWJ").is_some());
    assert!(url::base64_decode("Y").is_none());
    assert!(url::base64_decode("YQ==YQ").is_none());
    assert!(url::base64_decode("YQ===").is_none());
    assert!(url::base64_decode("a:b").is_none());
}

#[test]
fn shadowsocks_sip002_with_base64_userinfo() {
    let userinfo = b64(format!("aes-256-gcm:{}", PASSWORD).as_bytes(), true, false);
    let ss = ok(&format!(
        "ss://{}@198.51.100.1:8388/?uot=1#%F0%9F%87%AF%F0%9F%87%B5%20%E4%B8%9C%E4%BA%AC%2001",
        userinfo
    ));
    assert_eq!(
        ss,
        json!({
            "type": "shadowsocks", "tag": "🇯🇵 东京 01",
            "server": "198.51.100.1", "server_port": 8388,
            "method": "aes-256-gcm", "password": PASSWORD,
            "udp_over_tcp": true,
        })
    );
    // Standard base64, padded, a `/` in it, as some tools write it.
    let userinfo = b64(b"chacha20-ietf-poly1305:?>?>?>", false, true);
    assert!(userinfo.contains('/'));
    let ss = ok(&format!("ss://{}@example.com:443#a", userinfo));
    assert_eq!(ss["password"], "?>?>?>");
    assert_eq!(ss["method"], "chacha20-ietf-poly1305");
}

#[test]
fn shadowsocks_2022_with_a_plain_userinfo_and_ipv6() {
    let ss = ok(&format!(
        "ss://2022-blake3-aes-128-gcm:{}@[2001:db8::1]:8388#v6",
        PSK_128.replace('=', "%3D")
    ));
    assert_eq!(ss["server"], "2001:db8::1");
    assert_eq!(ss["password"], PSK_128);
    assert_eq!(ss["method"], "2022-blake3-aes-128-gcm");
}

#[test]
fn shadowsocks_before_sip002_is_all_base64() {
    let body = b64(
        format!("aes-128-gcm:{}@ss.example.com:8388", PASSWORD).as_bytes(),
        false,
        false,
    );
    let ss = ok(&format!("ss://{}#old", body));
    assert_eq!(ss["tag"], "old");
    assert_eq!(ss["server"], "ss.example.com");
    assert_eq!(ss["server_port"], 8388);
    assert_eq!(ss["password"], PASSWORD);
    // No name: the host.
    assert_eq!(ok(&format!("ss://{}", body))["tag"], "ss.example.com");
}

#[test]
fn shadowsocks_plugins() {
    let userinfo = b64(format!("aes-128-gcm:{}", PASSWORD).as_bytes(), true, false);
    let ss = ok(&format!(
        "ss://{}@example.com:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dcdn.example.com#o",
        userinfo
    ));
    assert_eq!(ss["plugin"], "obfs-local");
    assert_eq!(ss["plugin_opts"], "obfs=http;obfs-host=cdn.example.com");
    let e = err(&format!(
        "ss://{}@example.com:8388/?plugin=v2ray-plugin%3Bmode%3Dwebsocket#v",
        userinfo
    ));
    assert!(e.contains("v2ray-plugin"), "{}", e);
    err(&format!(
        "ss://{}@example.com:8388/?plugin=obfs-local%3Bobfs%3Dwebsocket",
        userinfo
    ));
}

#[test]
fn shadowsocks_ciphers_sail_lacks_are_errors() {
    let userinfo = b64(format!("aes-256-cfb:{}", PASSWORD).as_bytes(), true, false);
    let e = err(&format!("ss://{}@example.com:8388#x", userinfo));
    assert!(e.contains("\"aes-256-cfb\""), "{}", e);
    // A password where the method goes is not shown.
    let e = err(&format!(
        "ss://{}:x@example.com:8388",
        PASSWORD.replace('-', "+")
    ));
    assert!(e.contains("not shown"), "{}", e);
}

#[test]
fn trojan_over_tls_ws_grpc_and_reality() {
    let t = ok(&format!(
        "trojan://{}@trojan.example.com:443?sni=sni.example.com&allowInsecure=1&alpn=h2,http/1.1#T",
        PASSWORD
    ));
    assert_eq!(
        t,
        json!({
            "type": "trojan", "tag": "T",
            "server": "trojan.example.com", "server_port": 443,
            "password": PASSWORD,
            "tls": {
                "enabled": true, "server_name": "sni.example.com", "insecure": true,
                "alpn": ["h2", "http/1.1"],
            },
        })
    );
    // An `@` and a `#` percent-encoded in the password; `peer` for SNI.
    let t = ok("trojan://p%40ss%23word@1.2.3.4:443?peer=x.example.com&type=ws&path=%2Fws&host=cdn.example.com&fp=firefox");
    assert_eq!(t["password"], "p@ss#word");
    assert_eq!(t["tag"], "1.2.3.4");
    assert_eq!(t["tls"]["server_name"], "x.example.com");
    assert_eq!(
        t["tls"]["utls"],
        json!({"enabled": true, "fingerprint": "firefox"})
    );
    assert_eq!(
        t["transport"],
        json!({"type": "ws", "path": "/ws", "headers": {"Host": "cdn.example.com"}})
    );
    let t = ok(&format!(
        "trojan://{}@example.com:443?security=tls&type=grpc&serviceName=svc#g",
        PASSWORD
    ));
    assert_eq!(
        t["transport"],
        json!({"type": "grpc", "service_name": "svc"})
    );
    let t = ok(&format!(
        "trojan://{}@example.com:443?security=reality&pbk={}&sid=6ba85179e30d4fc2&sni=www.microsoft.com",
        PASSWORD, PBK
    ));
    assert_eq!(
        t["tls"]["reality"],
        json!({"enabled": true, "public_key": PBK, "short_id": "6ba85179e30d4fc2"})
    );
    let t = ok(&format!(
        "trojan://{}@example.com:80?security=none",
        PASSWORD
    ));
    assert!(t.get("tls").is_none());
}

#[test]
fn vless_reality_vision() {
    let v = ok(&format!(
        "vless://{}@203.0.113.9:443?encryption=none&flow=xtls-rprx-vision&security=reality\
         &sni=www.apple.com&fp=safari&pbk={}&sid=1a2b&spx=%2F&type=tcp&headerType=none#R%20%E9%A6%99%E6%B8%AF",
        UUID, PBK
    ));
    assert_eq!(
        v,
        json!({
            "type": "vless", "tag": "R 香港",
            "server": "203.0.113.9", "server_port": 443,
            "uuid": UUID, "flow": "xtls-rprx-vision",
            "tls": {
                "enabled": true, "server_name": "www.apple.com",
                "utls": {"enabled": true, "fingerprint": "safari"},
                "reality": {"enabled": true, "public_key": PBK, "short_id": "1a2b"},
            },
        })
    );
}

#[test]
fn vless_transports() {
    // Early data in the path, as Xray writes it.
    let v = ok(&format!(
        "vless://{}@[2001:db8::2]:443?security=tls&type=ws&host=h.example.com&path=%2Fray%3Fed%3D2048",
        UUID
    ));
    assert_eq!(v["server"], "2001:db8::2");
    assert_eq!(v["tag"], "2001:db8::2");
    assert_eq!(v["tls"]["server_name"], "h.example.com");
    assert_eq!(
        v["transport"],
        json!({
            "type": "ws", "path": "/ray", "headers": {"Host": "h.example.com"},
            "max_early_data": 2048, "early_data_header_name": "Sec-WebSocket-Protocol",
        })
    );
    let v = ok(&format!(
        "vless://{}@example.com:80?type=httpupgrade&host=h.example.com&path=%2Fup",
        UUID
    ));
    assert_eq!(
        v["transport"],
        json!({"type": "httpupgrade", "host": "h.example.com", "path": "/up"})
    );
    assert!(v.get("tls").is_none());
    let v = ok(&format!(
        "vless://{}@example.com:443?security=tls&type=grpc&serviceName=grpc-svc&mode=gun&packetEncoding=none",
        UUID
    ));
    assert_eq!(
        v["transport"],
        json!({"type": "grpc", "service_name": "grpc-svc"})
    );
    assert_eq!(v["packet_encoding"], "");

    for (params, what) in [
        ("type=xhttp&path=%2Fx", "XHTTP"),
        ("type=http&path=%2F", "HTTP/2"),
        ("type=h2", "HTTP/2"),
        ("type=tcp&headerType=http", "HTTP header"),
        ("type=kcp", "mKCP"),
        ("type=quic", "QUIC"),
        ("type=grpc&mode=multi", "multi"),
        (
            "encryption=mlkem768x25519plus.native.0rtt.abc",
            "encryption",
        ),
        ("security=tls&fp=randomized", "\"randomized\""),
        ("security=reality&sni=a.com", "pbk"),
        ("security=tls&pcs=abcd", "pcs"),
        ("flow=xtls-rprx-vision", "flow"),
        ("security=tls&type=ws&alpn=h2", "alpn"),
    ] {
        let e = err(&format!("vless://{}@example.com:443?{}", UUID, params));
        assert!(e.contains(what), "{}: {}", params, e);
    }
    let e = err("vless://not-a-uuid@example.com:443");
    assert!(e.contains("uuid"), "{}", e);
}

fn v2rayn(fields: serde_json::Value, url_safe: bool, pad: bool) -> String {
    format!(
        "vmess://{}",
        b64(fields.to_string().as_bytes(), url_safe, pad)
    )
}

#[test]
fn vmess_v2rayn_json() {
    let link = v2rayn(
        json!({
            "v": "2", "ps": "美国 🇺🇸 ws", "add": "vm.example.com", "port": "443",
            "id": UUID, "aid": "0", "scy": "auto", "net": "ws", "type": "none",
            "host": "cdn.example.com", "path": "/vm", "tls": "tls", "sni": "",
            "alpn": "h2,http/1.1", "fp": "chrome",
        }),
        false,
        true,
    );
    assert_eq!(
        ok(&link),
        json!({
            "type": "vmess", "tag": "美国 🇺🇸 ws",
            "server": "vm.example.com", "server_port": 443,
            "uuid": UUID, "security": "auto", "packet_encoding": "xudp",
            "tls": {
                "enabled": true, "server_name": "cdn.example.com",
                "alpn": ["h2", "http/1.1"],
                "utls": {"enabled": true, "fingerprint": "chrome"},
            },
            "transport": {"type": "ws", "path": "/vm", "headers": {"Host": "cdn.example.com"}},
        })
    );
    // Numbers as numbers, URL-safe base64 without padding, no name.
    let link = v2rayn(
        json!({"add": "2001:db8::3", "port": 8080, "id": UUID, "aid": 0, "net": "tcp", "scy": "none"}),
        true,
        false,
    );
    let v = ok(&link);
    assert_eq!(v["tag"], "2001:db8::3");
    assert_eq!(v["server_port"], 8080);
    assert_eq!(v["security"], "none");
    assert!(v.get("tls").is_none() && v.get("transport").is_none());
    // gRPC: the service name in `path`, the mode in `type`.
    let v = ok(&v2rayn(
        json!({"add": "g.example.com", "port": 443, "id": UUID, "net": "grpc", "type": "gun", "path": "svc", "tls": "tls"}),
        false,
        true,
    ));
    assert_eq!(
        v["transport"],
        json!({"type": "grpc", "service_name": "svc"})
    );
}

#[test]
fn vmess_errors() {
    for (fields, what) in [
        (json!({"aid": "64"}), "alterId"),
        (json!({"aid": 1}), "alterId"),
        (json!({"net": "h2"}), "HTTP/2"),
        (json!({"net": "tcp", "type": "http"}), "HTTP header"),
        (json!({"net": "kcp"}), "mKCP"),
        (json!({"net": "grpc", "type": "multi"}), "multi"),
        (json!({"scy": "aes-128-cfb"}), "cipher"),
        (json!({"id": "nope"}), "id"),
    ] {
        let mut base = json!({"ps": "x", "add": "e.example.com", "port": 443, "id": UUID});
        for (k, v) in fields.as_object().unwrap() {
            base[k] = v.clone();
        }
        let e = err(&v2rayn(base, false, true));
        assert!(e.contains(what), "{}: {}", fields, e);
    }
    let e = err(&format!("vmess://{}", b64(b"not json", false, true)));
    assert!(e.contains("JSON"), "{}", e);
}

#[test]
fn vmess_xray_url() {
    let v = ok(&format!(
        "vmess://{}@example.com:443?encryption=chacha20-poly1305&security=tls&type=ws&path=%2F#X",
        UUID
    ));
    assert_eq!(v["security"], "chacha20-poly1305");
    assert_eq!(v["transport"]["type"], "ws");
    assert_eq!(v["tag"], "X");
}

#[test]
fn hysteria2() {
    let h = ok(&format!(
        "hysteria2://{}@hy.example.com:443/?sni=real.example.com&insecure=1&obfs=salamander&obfs-password=ob-pass&up=50&down=200%20Mbps#Hy2",
        PASSWORD
    ));
    assert_eq!(
        h,
        json!({
            "type": "hysteria2", "tag": "Hy2",
            "server": "hy.example.com", "server_port": 443,
            "password": PASSWORD, "up_mbps": 50, "down_mbps": 200,
            "obfs": {"type": "salamander", "password": "ob-pass"},
            "tls": {"enabled": true, "server_name": "real.example.com", "insecure": true},
        })
    );
    // Port hopping in the port, `user:pass` auth.
    let h = ok("hy2://user:pa%3Ass@[2001:db8::4]:443,20000-30000/?alpn=h3");
    assert_eq!(h["server"], "2001:db8::4");
    assert_eq!(h["server_port"], 443);
    assert_eq!(h["server_ports"], json!(["443:443", "20000:30000"]));
    assert_eq!(h["password"], "user:pa:ss");
    assert_eq!(h["tls"]["alpn"], json!(["h3"]));
    // No port: 443.
    let h = ok(&format!(
        "hy2://{}@hy.example.com?mport=5000-6000",
        PASSWORD
    ));
    assert_eq!(h["server_port"], 5000);
    assert_eq!(h["server_ports"], json!(["5000:6000"]));
    assert_eq!(
        ok(&format!("hy2://{}@hy.example.com", PASSWORD))["server_port"],
        443
    );

    let e = err(&format!(
        "hy2://{}@h.example.com:443?pinSHA256=ab:cd",
        PASSWORD
    ));
    assert!(e.contains("pinSHA256"), "{}", e);
    let e = err(&format!("hy2://{}@h.example.com:443?obfs=gecko", PASSWORD));
    assert!(e.contains("salamander"), "{}", e);
    err(&format!(
        "hy2://{}@h.example.com:443?obfs=salamander",
        PASSWORD
    ));
    err(&format!("hy2://{}@h.example.com:443?up=fast", PASSWORD));
    err(&format!("hy2://{}@h.example.com:3000-2000", PASSWORD));
}

#[test]
fn tuic() {
    let t = ok(&format!(
        "tuic://{}:{}@tuic.example.com:443?congestion_control=bbr&udp_relay_mode=quic&alpn=h3&sni=s.example.com&allow_insecure=1#TUIC",
        UUID, PASSWORD
    ));
    assert_eq!(
        t,
        json!({
            "type": "tuic", "tag": "TUIC",
            "server": "tuic.example.com", "server_port": 443,
            "uuid": UUID, "password": PASSWORD,
            "congestion_control": "bbr", "udp_relay_mode": "quic",
            "tls": {"enabled": true, "server_name": "s.example.com", "insecure": true, "alpn": ["h3"]},
        })
    );
    let e = err(&format!("tuic://{}@tuic.example.com:443", PASSWORD));
    assert!(e.contains("v4"), "{}", e);
    err(&format!(
        "tuic://{}:{}@t.example.com:443?disable_sni=1",
        UUID, PASSWORD
    ));
    err(&format!(
        "tuic://{}:{}@t.example.com:443?congestion_control=brutal",
        UUID, PASSWORD
    ));
}

#[test]
fn anytls() {
    let a = ok(&format!(
        "anytls://{}@any.example.com:8443/?sni=s.example.com&insecure=1#A",
        PASSWORD
    ));
    assert_eq!(
        a,
        json!({
            "type": "anytls", "tag": "A",
            "server": "any.example.com", "server_port": 8443,
            "password": PASSWORD,
            "tls": {"enabled": true, "server_name": "s.example.com", "insecure": true},
        })
    );
    err(&format!(
        "anytls://{}@any.example.com:8443/?hpkp=abc",
        PASSWORD
    ));
}

#[test]
fn schemes_sail_does_not_import() {
    for (uri, what) in [
        (
            "wireguard://key@wg.example.com:51820?publickey=k",
            "endpoint",
        ),
        ("ssr://abc", "ShadowsocksR"),
        ("hysteria://h.example.com:443?auth=x", "v1"),
        ("naive+https://u:p@n.example.com", "unknown scheme"),
        ("just text", "not a share link"),
    ] {
        let e = err(uri);
        assert!(e.contains(what), "{}: {}", uri, e);
    }
}

#[test]
fn links_that_are_malformed() {
    for uri in [
        "trojan://p@:443",
        "trojan://p@example.com",
        "trojan://p@example.com:0",
        "trojan://p@example.com:70000",
        "trojan://p@2001:db8::1:443",
        "trojan://p@[2001:db8::1:443",
        "trojan://p@[not-v6]:443",
        "trojan://@example.com:443",
        "trojan://p@example.com:443?allowInsecure=maybe",
        "trojan://%FF@example.com:443",
    ] {
        err(uri);
    }
}

#[test]
fn subscriptions() {
    let ss_userinfo = b64(format!("aes-128-gcm:{}", PASSWORD).as_bytes(), true, false);
    let plain = format!(
        "# a comment\r\n\
         STATUS=traffic left: 1 GB\r\n\
         \r\n\
         ss://{ss}@a.example.com:8388#Node\r\n\
         trojan://{pw}@b.example.com:443#Node\r\n\
         vless://{uuid}@c.example.com:443?type=xhttp#Broken\r\n\
         trojan://{pw}@d.example.com:443\r\n\
         trojan://{pw}@d.example.com:8443\r\n\
         trojan://{pw}@d.example.com:8443\r\n\
         ssr://whatever\r\n\
         trojan://{pw}@e.example.com:443#Node%202\r\n\
         // another comment\n\
         tuic://{pw}@f.example.com:443\n",
        ss = ss_userinfo,
        pw = PASSWORD,
        uuid = UUID,
    );
    let expected_tags = [
        "Node",
        "Node 2",
        "d.example.com",
        "d.example.com:8443",
        "d.example.com:8443 2",
        "Node 2 2",
    ];
    let expected_warnings = [(6, "XHTTP"), (10, "ShadowsocksR"), (13, "v4")];

    for body in [
        plain.clone(),
        b64(plain.as_bytes(), false, true),
        b64(plain.as_bytes(), true, false),
        // Wrapped at 76 columns, as MIME writes it.
        b64(plain.as_bytes(), false, true)
            .as_bytes()
            .chunks(76)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join("\r\n"),
    ] {
        let (outbounds, warnings) = parse_subscription(&body);
        let tags: Vec<_> = outbounds
            .iter()
            .map(|o| o["tag"].as_str().unwrap())
            .collect();
        assert_eq!(tags, expected_tags);
        assert_eq!(warnings.len(), expected_warnings.len(), "{:?}", warnings);
        for (warning, (line, what)) in warnings.iter().zip(expected_warnings) {
            assert!(
                warning.starts_with(&format!("line {}: ", line)) && warning.contains(what),
                "{}",
                warning
            );
            for secret in [PASSWORD, UUID, &ss_userinfo] {
                assert!(!warning.contains(secret), "{}", warning);
            }
        }
    }

    // A single link, and nothing at all.
    let (outbounds, warnings) =
        parse_subscription(&format!("trojan://{}@x.example.com:1", PASSWORD));
    assert_eq!((outbounds.len(), warnings.len()), (1, 0));
    assert_eq!(parse_subscription(""), (vec![], vec![]));
    let (outbounds, warnings) = parse_subscription("not base64, and no links");
    assert_eq!((outbounds.len(), warnings.len()), (0, 1));
}

/// A link of every kind of outbound the links make.
fn corpus() -> Vec<String> {
    let ss = |method: &str, password: &str| {
        b64(format!("{}:{}", method, password).as_bytes(), true, false)
    };
    vec![
        format!("ss://{}@a.example.com:8388#ss", ss("aes-256-gcm", PASSWORD)),
        format!(
            "ss://{}@a.example.com:8388/?uot=1#ss-uot",
            ss("chacha20-ietf-poly1305", PASSWORD)
        ),
        format!(
            "ss://2022-blake3-aes-128-gcm:{}@[2001:db8::1]:8388#ss2022",
            PSK_128.replace('=', "%3D")
        ),
        format!(
            "ss://{}@a.example.com:8388/?plugin=obfs-local%3Bobfs%3Dtls%3Bobfs-host%3Dx.example.com#ss-obfs",
            ss("aes-128-gcm", PASSWORD)
        ),
        format!(
            "trojan://{}@b.example.com:443?sni=s.example.com#trojan",
            PASSWORD
        ),
        format!(
            "trojan://{}@b.example.com:443?type=ws&path=%2Fws%3Fed%3D2048&host=h.example.com&fp=firefox#trojan-ws",
            PASSWORD
        ),
        format!(
            "trojan://{}@b.example.com:443?type=grpc&serviceName=s#trojan-grpc",
            PASSWORD
        ),
        format!(
            "vless://{}@c.example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.apple.com&fp=chrome&pbk={}&sid=1a2b#vless-reality",
            UUID, PBK
        ),
        format!(
            "vless://{}@c.example.com:443?security=tls&type=httpupgrade&host=h.example.com&path=%2Fu&alpn=http%2F1.1#vless-hu",
            UUID
        ),
        format!(
            "vless://{}@c.example.com:80?type=ws&path=%2F&packetEncoding=none#vless-ws",
            UUID
        ),
        v2rayn(
            json!({"ps": "vmess", "add": "d.example.com", "port": "443", "id": UUID, "aid": "0",
                   "net": "ws", "host": "h.example.com", "path": "/v", "tls": "tls"}),
            false,
            true,
        ),
        v2rayn(
            json!({"ps": "vmess-grpc", "add": "d.example.com", "port": 443, "id": UUID,
                   "net": "grpc", "path": "svc", "tls": "tls", "scy": "zero"}),
            true,
            false,
        ),
        format!(
            "vmess://{}@d.example.com:443?encryption=auto&security=tls#vmess-xray",
            UUID
        ),
        format!(
            "hy2://{}@e.example.com:443,20000-30000/?sni=s.example.com&obfs=salamander&obfs-password=o&up=10&down=100#hy2",
            PASSWORD
        ),
        format!("hysteria2://{}@e.example.com#hy2-default-port", PASSWORD),
        format!(
            "tuic://{}:{}@f.example.com:443?congestion_control=cubic&udp_relay_mode=native&alpn=h3#tuic",
            UUID, PASSWORD
        ),
        format!(
            "anytls://{}@g.example.com:443/?sni=s.example.com&insecure=1#anytls",
            PASSWORD
        ),
    ]
}

#[test]
fn the_corpus_loads_as_a_configuration() {
    let (outbounds, warnings) = parse_subscription(&corpus().join("\n"));
    assert!(warnings.is_empty(), "{:?}", warnings);
    assert_eq!(outbounds.len(), corpus().len());
    let config = json!({ "outbounds": outbounds }).to_string();
    let config = crate::config::Config::from_json(&config).unwrap();
    assert_eq!(config.outbounds.len(), corpus().len());
    assert!(config.warnings.is_empty(), "{:?}", config.warnings);
}

/// Each built as the runtime builds it: every field is one its outbound
/// takes, and every value one it accepts.
#[cfg(all(
    feature = "outbound-shadowsocks",
    feature = "outbound-obfs",
    feature = "outbound-trojan",
    feature = "outbound-vless",
    feature = "outbound-vmess",
    feature = "outbound-tls",
    feature = "outbound-reality",
    feature = "outbound-ws",
    feature = "outbound-httpupgrade",
    feature = "outbound-grpc",
    feature = "outbound-hysteria2",
    feature = "outbound-tuic",
    feature = "outbound-anytls",
))]
#[tokio::test]
async fn the_corpus_builds() {
    use std::sync::Arc;

    use crate::app::outbound::manager::OutboundManager;
    use crate::net::DialOptions;
    use crate::runtime::RuntimeEnv;

    let build = |outbound: &Value| {
        let config = json!({ "outbounds": [outbound] }).to_string();
        let config = crate::config::Config::from_json(&config).unwrap();
        let dial = DialOptions::default();
        let dns = crate::app::dns::DnsClient::new(
            &config.dns,
            Arc::new(dial.clone()),
            &Default::default(),
        )
        .unwrap()
        .into_shared();
        OutboundManager::new(&config.outbounds, &dial, &RuntimeEnv::default(), dns).map(|_| ())
    };
    for link in corpus() {
        let outbound = parse(&link).unwrap();
        if let Err(e) = build(&outbound) {
            panic!("{}: {:#}", outbound["tag"], e);
        }
    }
    // A field the outbound does not take fails here, as it would at start.
    let mut outbound = parse(&corpus()[4]).unwrap();
    outbound["tls"]["no_such_field"] = json!(true);
    assert!(build(&outbound).is_err());
}
