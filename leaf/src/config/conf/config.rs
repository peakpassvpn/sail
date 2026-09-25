use std::borrow::Cow;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

use anyhow::{anyhow, Result};
use regex::Regex;
use serde_json::json;

use crate::config::model;

#[derive(Debug, Default)]
pub struct Tun {
    pub name: Option<String>,
    pub address: Option<String>,
    pub netmask: Option<String>,
    pub gateway: Option<String>,
    pub mtu: Option<i32>,
}

#[derive(Debug, Default)]
pub struct Nf {
    pub driver_name: String,
    pub nfapi: Option<String>,
}

#[derive(Debug, Default)]
pub struct General {
    pub tun: Option<Tun>,
    pub tun_fd: Option<i32>,
    pub tun_auto: Option<bool>,
    pub tun2socks_backend: Option<String>,
    pub nf: Option<Nf>,
    pub loglevel: Option<String>,
    pub logoutput: Option<String>,
    pub logformat: Option<String>,
    pub dns_server: Option<Vec<String>>,
    pub dns_interface: Option<String>,
    pub always_real_ip: Option<Vec<String>>,
    pub always_fake_ip: Option<Vec<String>>,
    pub http_interface: Option<String>,
    pub http_port: Option<u16>,
    pub socks_interface: Option<String>,
    pub socks_port: Option<u16>,
    pub api_interface: Option<String>,
    pub api_port: Option<u16>,
    pub routing_domain_resolve: Option<bool>,
    pub wintun: Option<String>,
    pub tun_dns_server: Option<Vec<String>>,
    /// Surge's `ipv6`: whether IPv6 is used at all.
    pub ipv6: Option<bool>,
    /// With `tun = auto`, forwards the traffic of other hosts.
    pub gateway_mode: Option<bool>,
}

#[derive(Debug)]
pub struct Proxy {
    pub tag: String,
    pub protocol: String,
    /// Surge's `interface=`: the interface, or local address, to send through.
    pub interface: Option<String>,

    // common
    pub address: Option<String>,
    pub port: Option<u16>,

    // shadowsocks
    pub encrypt_method: Option<String>,
    pub prefix: Option<String>,

    // shadowsocks, trojan
    pub password: Option<String>,

    // simple-obfs
    pub obfs_type: Option<String>,
    pub obfs_host: Option<String>,
    pub obfs_path: Option<String>,

    pub ws: Option<bool>,
    pub tls: Option<bool>,
    pub tls_cert: Option<String>,
    pub tls_insecure: Option<bool>,
    pub tls_ech: Option<bool>,
    pub tls_ech_disable_dns_lookup: Option<bool>,
    pub tls_ech_config_list: Option<String>,
    pub ws_path: Option<String>,
    pub ws_host: Option<String>,

    // trojan
    pub sni: Option<String>,

    // vmess
    pub username: Option<String>,
    pub uuid: Option<String>,

    pub amux: Option<bool>,
    pub amux_max: Option<i32>,
    pub amux_con: Option<i32>,
    pub amux_max_recv: Option<u64>,
    pub amux_max_lifetime: Option<u64>,

    pub quic: Option<bool>,

    // reality
    pub reality: Option<bool>,
    pub reality_public_key: Option<String>,
    pub reality_short_id: Option<String>,
}

impl Default for Proxy {
    fn default() -> Self {
        Proxy {
            tag: "".to_string(),
            protocol: "".to_string(),
            interface: None,
            address: None,
            port: None,
            encrypt_method: Some("chacha20-ietf-poly1305".to_string()),
            prefix: None,
            password: None,
            obfs_type: None,
            obfs_host: None,
            obfs_path: None,
            ws: Some(false),
            tls: Some(false),
            tls_cert: None,
            tls_insecure: Some(false),
            tls_ech: Some(false),
            tls_ech_disable_dns_lookup: Some(false),
            tls_ech_config_list: None,
            ws_path: None,
            ws_host: None,
            sni: None,
            username: None,
            uuid: None,
            amux: Some(false),
            amux_max: Some(8),
            amux_con: Some(2),
            amux_max_recv: Some(0),
            amux_max_lifetime: Some(0),
            quic: Some(false),
            reality: Some(false),
            reality_public_key: None,
            reality_short_id: None,
        }
    }
}
#[derive(Debug)]
pub struct ProxyGroup {
    pub tag: String,
    pub protocol: String,
    pub actors: Option<Vec<String>>,

    // common
    pub address: Option<String>,
    pub port: Option<u16>,

    // failover
    pub health_check: Option<bool>,
    pub check_interval: Option<u32>,
    pub fail_timeout: Option<u32>,
    pub failover: Option<bool>,
    pub fallback_cache: Option<bool>,
    pub cache_size: Option<u32>,
    pub cache_timeout: Option<u32>,
    pub last_resort: Option<String>,
    pub health_check_timeout: Option<u32>,
    pub health_check_delay: Option<u32>,
    pub health_check_active: Option<u32>,
    pub health_check_prefers: Option<Vec<String>>,
    pub health_check_on_start: Option<bool>,
    pub health_check_wait: Option<bool>,
    pub health_check_attempts: Option<u32>,
    pub health_check_success_percentage: Option<u32>,

    // tryall
    pub delay_base: Option<u32>,

    // static
    pub method: Option<String>,
}

impl Default for ProxyGroup {
    fn default() -> Self {
        ProxyGroup {
            tag: "".to_string(),
            protocol: "".to_string(),
            actors: None,
            address: None,
            port: None,
            health_check: None,
            check_interval: None,
            fail_timeout: None,
            failover: None,
            fallback_cache: None,
            cache_size: None,
            cache_timeout: None,
            last_resort: None,
            health_check_timeout: None,
            health_check_delay: None,
            health_check_active: None,
            health_check_prefers: None,
            health_check_on_start: None,
            health_check_wait: None,
            health_check_attempts: None,
            health_check_success_percentage: None,
            delay_base: None,
            method: None,
        }
    }
}

#[derive(Debug, Default)]
pub struct Rule {
    pub type_field: String,
    pub filter: Option<String>,
    pub target: String,
}

#[derive(Debug, Default)]
pub struct Config {
    pub general: Option<General>,
    pub proxy: Option<Vec<Proxy>>,
    pub proxy_group: Option<Vec<ProxyGroup>>,
    pub rule: Option<Vec<Rule>>,
    pub host: Option<HashMap<String, Vec<String>>>,
    pub certificates: Option<HashMap<String, String>>,
    pub ech_configs: Option<HashMap<String, String>>,
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

fn remove_comments(text: &str) -> Cow<'_, str> {
    let re = Regex::new(r"(#[^*]*)").unwrap();
    re.replace(text, "")
}

fn get_section(text: &str) -> Option<&str> {
    let re = Regex::new(r"^\s*\[\s*([^\]]*)\s*\]\s*$").unwrap();
    let caps = re.captures(text);
    caps.as_ref()?;
    Some(caps.unwrap().get(1).unwrap().as_str())
}

fn normalize_section(s: &str) -> String {
    s.to_lowercase().replace(' ', "").replace('_', "")
}

fn get_certificate_sections<'a, I>(lines: I) -> HashMap<String, String>
where
    I: Iterator<Item = &'a io::Result<String>>,
{
    let mut certificates = HashMap::new();
    let mut current_name: Option<String> = None;
    let mut current_lines: Vec<String> = Vec::new();

    for line in lines {
        let line = match line {
            Ok(line) => line,
            Err(_) => continue,
        };
        let trimmed = line.trim();
        if let Some(section) = get_section(trimmed) {
            if let Some(name) = current_name.take() {
                if !current_lines.is_empty() {
                    let mut content = current_lines.join("\n");
                    content.push('\n');
                    certificates.insert(name, content);
                }
                current_lines.clear();
            }
            let lower = section.to_lowercase();
            if let Some(name) = section.strip_prefix("Certificate.") {
                let name = name.trim();
                if !name.is_empty() {
                    current_name = Some(name.to_string());
                }
            } else if lower.starts_with("certificate.") {
                let name = &section["certificate.".len()..];
                let name = name.trim();
                if !name.is_empty() {
                    current_name = Some(name.to_string());
                }
            } else if lower.starts_with("certificate_") {
                let name = &section["certificate_".len()..];
                let name = name.trim();
                if !name.is_empty() {
                    current_name = Some(name.to_string());
                }
            } else if lower.starts_with("certificate ") {
                let name = &section["certificate ".len()..];
                let name = name.trim();
                if !name.is_empty() {
                    current_name = Some(name.to_string());
                }
            } else if lower.starts_with("certificate") {
                let name = &section["certificate".len()..];
                let name = name.trim();
                if !name.is_empty() {
                    current_name = Some(name.to_string());
                }
            }
            continue;
        }
        if current_name.is_some() {
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            current_lines.push(trimmed.to_string());
        }
    }

    if let Some(name) = current_name.take() {
        if !current_lines.is_empty() {
            let mut content = current_lines.join("\n");
            content.push('\n');
            certificates.insert(name, content);
        }
    }

    certificates
}

fn get_ech_sections<'a, I>(lines: I) -> HashMap<String, String>
where
    I: Iterator<Item = &'a io::Result<String>>,
{
    let mut ech_configs = HashMap::new();
    let mut current_name: Option<String> = None;
    let mut current_lines: Vec<String> = Vec::new();

    for line in lines {
        let line = match line {
            Ok(line) => line,
            Err(_) => continue,
        };
        let trimmed = line.trim();
        if let Some(section) = get_section(trimmed) {
            if let Some(name) = current_name.take() {
                if !current_lines.is_empty() {
                    let mut content = current_lines.join("\n");
                    content.push('\n');
                    ech_configs.insert(name, content);
                }
                current_lines.clear();
            }
            let lower = section.to_lowercase();
            if let Some(name) = section.strip_prefix("Ech.") {
                let name = name.trim();
                if !name.is_empty() {
                    current_name = Some(name.to_string());
                }
            } else if lower.starts_with("ech.") {
                let name = &section["ech.".len()..];
                let name = name.trim();
                if !name.is_empty() {
                    current_name = Some(name.to_string());
                }
            } else if lower.starts_with("ech_") {
                let name = &section["ech_".len()..];
                let name = name.trim();
                if !name.is_empty() {
                    current_name = Some(name.to_string());
                }
            } else if lower.starts_with("ech ") {
                let name = &section["ech ".len()..];
                let name = name.trim();
                if !name.is_empty() {
                    current_name = Some(name.to_string());
                }
            } else if lower.starts_with("ech") {
                let name = &section["ech".len()..];
                let name = name.trim();
                if !name.is_empty() {
                    current_name = Some(name.to_string());
                }
            }
            continue;
        }
        if current_name.is_some() {
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            current_lines.push(trimmed.to_string());
        }
    }

    if let Some(name) = current_name.take() {
        if !current_lines.is_empty() {
            let mut content = current_lines.join("\n");
            content.push('\n');
            ech_configs.insert(name, content);
        }
    }

    ech_configs
}

fn get_lines_by_section<'a, I>(section: &str, lines: I) -> Vec<String>
where
    I: Iterator<Item = &'a io::Result<String>>,
{
    let mut new_lines = Vec::new();
    let mut curr_sect: String = "".to_string();
    let normalized_target = normalize_section(section);
    for line in lines.flatten().map(|x| x.trim()) {
        let line = remove_comments(line);
        if let Some(s) = get_section(line.as_ref()) {
            curr_sect = s.to_string();
            continue;
        }
        if normalize_section(&curr_sect) == normalized_target && !line.is_empty() {
            new_lines.push(line.to_string());
        }
    }
    new_lines
}

fn get_char_sep_slice(text: &str, pat: char) -> Option<Vec<String>>
where
{
    let mut items = Vec::new();
    for item in text.split(pat).map(str::trim) {
        if !item.is_empty() {
            items.push(item.to_string());
        }
    }
    if !items.is_empty() {
        Some(items)
    } else {
        None
    }
}

fn get_string(text: &str) -> Option<String> {
    if !text.is_empty() {
        Some(text.to_string())
    } else {
        None
    }
}

fn get_value<T>(text: &str) -> Option<T>
where
    T: std::str::FromStr,
{
    if !text.is_empty() {
        if let Ok(v) = text.parse::<T>() {
            return Some(v);
        }
    }
    None
}

fn parse_bool(key: &str, value: &str) -> Result<bool> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(anyhow!(
            "{}: expected true or false, got \"{}\"",
            key,
            value
        )),
    }
}

pub fn from_lines(lines: Vec<io::Result<String>>) -> Result<Config> {
    let certificates = get_certificate_sections(lines.iter());
    let ech_configs = get_ech_sections(lines.iter());
    if !get_lines_by_section("Env", lines.iter()).is_empty() {
        return Err(anyhow!(
            "[Env] is not supported: tuning is given at start (--profile, --set), \
             and everything else has a configuration field"
        ));
    }

    let mut general = General::default();
    let general_lines = get_lines_by_section("General", lines.iter());
    for line in general_lines {
        let parts: Vec<&str> = line.split('=').map(str::trim).collect();
        if parts.len() != 2 {
            continue;
        }
        match parts[0] {
            "tun-fd" => {
                general.tun_fd = get_value::<i32>(parts[1]);
            }
            "tun" => {
                if let Some(items) = get_char_sep_slice(parts[1], ',') {
                    if items.len() >= 1 && items[0] == "auto" {
                        general.tun_auto = Some(true);
                        continue;
                    }
                    if items.len() < 5 {
                        continue;
                    }
                    let tun = Tun {
                        name: Some(items[0].clone()),
                        address: Some(items[1].clone()),
                        netmask: Some(items[2].clone()),
                        gateway: Some(items[3].clone()),
                        mtu: get_value::<i32>(&items[4]),
                    };
                    general.tun = Some(tun);
                }
            }
            "tun2socks-backend" => {
                general.tun2socks_backend = Some(parts[1].to_string());
            }
            "nf" => {
                // nf = driver_name, path/to/nfapi.dll
                if let Some(items) = get_char_sep_slice(parts[1], ',') {
                    let nfapi = if items.len() >= 2 {
                        Some(items[1].trim().to_owned())
                    } else {
                        None
                    };
                    let nf = Nf {
                        driver_name: items[0].trim().to_owned(),
                        nfapi,
                    };
                    general.nf = Some(nf);
                }
            }
            "loglevel" => {
                general.loglevel = Some(parts[1].to_string());
            }
            "logoutput" => {
                general.logoutput = Some(parts[1].to_string());
            }
            "logformat" => {
                general.logformat = Some(parts[1].to_string());
            }
            "dns-server" => {
                general.dns_server = get_char_sep_slice(parts[1], ',');
            }
            "dns-interface" => {
                general.dns_interface = get_string(parts[1]);
            }
            "always-real-ip" => {
                general.always_real_ip = get_char_sep_slice(parts[1], ',');
            }
            "always-fake-ip" => {
                general.always_fake_ip = get_char_sep_slice(parts[1], ',');
            }
            "routing-domain-resolve" => {
                general.routing_domain_resolve = if parts[1] == "true" {
                    Some(true)
                } else {
                    Some(false)
                };
            }
            "http-interface" | "interface" => {
                general.http_interface = get_string(parts[1]);
            }
            "http-port" | "port" => {
                general.http_port = get_value::<u16>(parts[1]);
            }
            "socks-interface" => {
                general.socks_interface = get_string(parts[1]);
            }
            "socks-port" => {
                general.socks_port = get_value::<u16>(parts[1]);
            }
            "api-interface" => {
                general.api_interface = get_string(parts[1]);
            }
            "api-port" => {
                general.api_port = get_value::<u16>(parts[1]);
            }
            "wintun" => {
                general.wintun = get_string(parts[1]);
            }
            "tun-dns-server" => {
                general.tun_dns_server = get_char_sep_slice(parts[1], ',');
            }
            "ipv6" => {
                general.ipv6 = Some(parse_bool("ipv6", parts[1])?);
            }
            "gateway-mode" => {
                general.gateway_mode = Some(parse_bool("gateway-mode", parts[1])?);
            }
            _ => {}
        }
    }

    let mut proxies = Vec::new();
    let proxy_lines = get_lines_by_section("Proxy", lines.iter());
    for line in proxy_lines {
        let parts: Vec<&str> = line.splitn(2, '=').map(str::trim).collect();
        if parts.len() != 2 {
            continue;
        }
        let mut proxy = Proxy::default();
        let tag = parts[0];
        if tag.is_empty() {
            // empty tag is not allowed
            continue;
        }
        proxy.tag = tag.to_string();
        let params = if let Some(p) = get_char_sep_slice(parts[1], ',') {
            p
        } else {
            continue;
        };
        if params.is_empty() {
            // there must be at least one param, i.e. the protocol field
            continue;
        }
        proxy.protocol = params[0].clone();

        // extract key-value params
        // let params = &params[2..];
        for param in &params {
            let parts: Vec<&str> = param.split('=').map(str::trim).collect();
            if parts.len() != 2 {
                continue;
            }
            let k = parts[0];
            let v = parts[1];
            if k.is_empty() || v.is_empty() {
                continue;
            }
            match k {
                "encrypt-method" => {
                    proxy.encrypt_method = Some(v.to_string());
                }
                "prefix" => {
                    proxy.prefix = Some(v.to_string());
                }
                "password" => {
                    proxy.password = Some(v.to_string());
                }
                "obfs" => {
                    proxy.obfs_type = Some(v.to_string());
                }
                "obfs-host" => {
                    proxy.obfs_host = Some(v.to_string());
                }
                "obfs-path" => {
                    proxy.obfs_path = Some(v.to_string());
                }
                "ws" => proxy.ws = if v == "true" { Some(true) } else { Some(false) },
                "tls" => proxy.tls = if v == "true" { Some(true) } else { Some(false) },
                "tls-cert" => {
                    proxy.tls_cert = Some(v.to_string());
                }
                "tls-insecure" => {
                    proxy.tls_insecure = if v == "true" { Some(true) } else { Some(false) }
                }
                "tls-ech" => proxy.tls_ech = if v == "true" { Some(true) } else { Some(false) },
                "tls-ech-disable-dns-lookup" => {
                    proxy.tls_ech_disable_dns_lookup =
                        if v == "true" { Some(true) } else { Some(false) }
                }
                "tls-ech-config-list" | "ech-config-list" => {
                    proxy.tls_ech_config_list = Some(v.to_string());
                }
                "ws-path" => {
                    proxy.ws_path = Some(v.to_string());
                }
                "ws-host" => {
                    proxy.ws_host = Some(v.to_string());
                }
                "sni" => {
                    proxy.sni = Some(v.to_string());
                }
                "username" => {
                    proxy.username = Some(v.to_string());
                }
                "uuid" => {
                    proxy.uuid = Some(v.to_string());
                }
                "amux" => proxy.amux = if v == "true" { Some(true) } else { Some(false) },
                "amux-max" => {
                    let i = v.parse::<i32>().ok();
                    proxy.amux_max = i;
                }
                "amux-con" => {
                    let i = v.parse::<i32>().ok();
                    proxy.amux_con = i;
                }
                "amux-max-recv" => {
                    let i = v.parse::<u64>().ok();
                    proxy.amux_max_recv = i;
                }
                "amux-max-lifetime" => {
                    let i = v.parse::<u64>().ok();
                    proxy.amux_max_lifetime = i;
                }
                "quic" => proxy.quic = if v == "true" { Some(true) } else { Some(false) },
                "reality" => proxy.reality = if v == "true" { Some(true) } else { Some(false) },
                "reality-public-key" => {
                    proxy.reality_public_key = Some(v.to_string());
                }
                "reality-short-id" => {
                    proxy.reality_short_id = Some(v.to_string());
                }
                "interface" => {
                    proxy.interface = Some(v.to_string());
                }
                _ => {}
            }
        }

        // built-in protocols have no address port, password
        match proxy.protocol.as_str() {
            "direct" => {
                proxies.push(proxy);
                continue;
            }
            "drop" => {
                proxies.push(proxy);
                continue;
            }
            // compat
            "reject" => {
                proxy.protocol = "drop".to_string();
                proxies.push(proxy);
                continue;
            }
            _ => {}
        }

        // parse address and port
        let params = &params[1..];
        if params.len() < 2 {
            // address and port are required
            continue;
        }
        proxy.address = Some(params[0].clone());
        let port = if let Ok(p) = params[1].parse::<u16>() {
            p
        } else {
            continue; // not valid port
        };
        proxy.port = Some(port);

        // parse positional params
        let pos_params = &params[2..];
        for (i, param) in pos_params.iter().enumerate() {
            if param.contains('=') {
                continue;
            }
            match (proxy.protocol.as_str(), i) {
                ("ss" | "shadowsocks", 0) => proxy.encrypt_method = Some(param.clone()),
                ("ss" | "shadowsocks", 1) => proxy.password = Some(param.clone()),
                ("trojan", 0) => proxy.password = Some(param.clone()),
                ("vmess", 0) => proxy.username = Some(param.clone()),
                ("vless", 0) => proxy.password = Some(param.clone()),
                _ => (),
            }
        }

        // compat
        if let "ss" = proxy.protocol.as_str() {
            proxy.protocol = "shadowsocks".to_string();
        }

        proxies.push(proxy);
    }

    let mut proxy_groups = Vec::new();
    let proxy_group_lines = get_lines_by_section("Proxy Group", lines.iter());
    for line in proxy_group_lines {
        let parts: Vec<&str> = line.splitn(2, '=').map(str::trim).collect();
        if parts.len() != 2 {
            continue;
        }
        let mut group = ProxyGroup::default();
        let tag = parts[0];
        if tag.is_empty() {
            // empty tag is not allowed
            continue;
        }
        group.tag = tag.to_string();
        let params = if let Some(p) = get_char_sep_slice(parts[1], ',') {
            p
        } else {
            continue;
        };
        if params.is_empty() {
            // there must be at least one param, i.e. the protocol field
            continue;
        }
        group.protocol = params[0].clone();

        let params = &params[1..];
        if params.is_empty() {
            // require at least one proxy
            continue;
        }

        let mut actors = Vec::new();
        for param in params {
            if !param.contains('=') && !param.is_empty() {
                actors.push(param.to_string());
            }
        }
        if actors.is_empty() {
            // require at least one actor
            continue;
        }
        group.actors = Some(actors);

        for param in params {
            if param.contains('=') {
                let parts: Vec<&str> = param.split('=').map(str::trim).collect();
                if parts.len() != 2 {
                    continue;
                }
                let k = parts[0];
                let v = parts[1];
                if k.is_empty() || v.is_empty() {
                    continue;
                }
                match k {
                    "address" => {
                        group.address = Some(v.to_string());
                    }
                    "port" => {
                        group.port = v.parse().ok();
                    }
                    "health-check" => {
                        group.health_check = if v == "true" { Some(true) } else { Some(false) };
                    }
                    "check-interval" => {
                        let i = v.parse().ok();
                        group.check_interval = i;
                    }
                    "fail-timeout" => {
                        let i = v.parse().ok();
                        group.fail_timeout = i;
                    }
                    "failover" => {
                        group.failover = if v == "true" { Some(true) } else { Some(false) };
                    }
                    "fallback-cache" => {
                        group.fallback_cache = if v == "true" { Some(true) } else { Some(false) };
                    }
                    "cache-size" => {
                        let i = v.parse().ok();
                        group.cache_size = i;
                    }
                    "cache-timeout" => {
                        let i = v.parse().ok();
                        group.cache_timeout = i;
                    }
                    "last-resort" => {
                        group.last_resort = if !v.is_empty() {
                            Some(v.to_owned())
                        } else {
                            None
                        };
                    }
                    "health-check-timeout" => {
                        let i = v.parse().ok();
                        group.health_check_timeout = i;
                    }
                    "health-check-delay" => {
                        let i = v.parse().ok();
                        group.health_check_delay = i;
                    }
                    "health-check-active" => {
                        let i = v.parse().ok();
                        group.health_check_active = i;
                    }
                    "health-check-prefers" => {
                        let i = v
                            .split(":")
                            .map(str::trim)
                            .map(|x| x.to_owned())
                            .collect::<Vec<_>>();
                        let i = if !i.is_empty() { Some(i) } else { None };
                        group.health_check_prefers = i;
                    }
                    "health-check-on-start" => {
                        group.health_check_on_start =
                            if v == "true" { Some(true) } else { Some(false) };
                    }
                    "health-check-wait" => {
                        group.health_check_wait =
                            if v == "true" { Some(true) } else { Some(false) };
                    }
                    "health-check-attempts" => {
                        let i = v.parse().ok();
                        group.health_check_attempts = i;
                    }
                    "health-check-success-percentage" => {
                        let i = v.parse().ok();
                        group.health_check_success_percentage = i;
                    }
                    "delay-base" => {
                        let i = v.parse().ok();
                        group.delay_base = i;
                    }
                    "method" => {
                        group.method = if !v.is_empty() {
                            Some(v.to_owned())
                        } else {
                            None
                        };
                    }
                    _ => {}
                }
            }
        }

        // compat
        match group.protocol.as_str() {
            // url-test group is just failover without failover
            "url-test" => {
                group.protocol = "failover".to_string();
                group.failover = Some(false);
            }
            // fallback group is just failover
            "fallback" => {
                group.protocol = "failover".to_string();
            }
            _ => {}
        }

        proxy_groups.push(group);
    }

    let mut rules = Vec::new();
    let rule_lines = get_lines_by_section("Rule", lines.iter());
    for line in rule_lines {
        let params = if let Some(p) = get_char_sep_slice(&line, ',') {
            p
        } else {
            continue;
        };
        if params.len() < 2 {
            continue; // at lease 2 params
        }
        let mut rule = Rule {
            type_field: params[0].to_string(),
            ..Default::default()
        };

        // handle the FINAL rule first
        if rule.type_field == "FINAL" {
            rule.target = params[1].to_string();
            rules.push(rule);
            break; // FINAL is final.
        }

        if params.len() < 3 {
            continue; // at lease 3 params except the FINAL rule
        }

        // the 3th must be the target
        rule.target = params[2].to_string();

        match rule.type_field.as_str() {
            "IP-CIDR" | "DOMAIN" | "DOMAIN-SUFFIX" | "DOMAIN-KEYWORD" | "GEOIP" | "EXTERNAL"
            | "PORT-RANGE" | "NETWORK" | "INBOUND-TAG" | "PROCESS-NAME" => {
                rule.filter = Some(params[1].to_string());
            }
            _ => {}
        }

        rules.push(rule);
    }

    let mut hosts = HashMap::new();
    let host_lines = get_lines_by_section("Host", lines.iter());
    for line in host_lines {
        let parts: Vec<&str> = line.split('=').map(str::trim).collect();
        if parts.len() != 2 {
            continue;
        }
        let name = parts[0];
        let ips: Vec<String> = parts[1]
            .split(',')
            .map(str::trim)
            .map(|x| x.to_owned())
            .collect();
        hosts.insert(name.to_owned(), ips);
    }

    Ok(Config {
        general: Some(general),
        proxy: Some(proxies),
        proxy_group: Some(proxy_groups),
        rule: Some(rules),
        host: Some(hosts),
        certificates: if certificates.is_empty() {
            None
        } else {
            Some(certificates)
        },
        ech_configs: if ech_configs.is_empty() {
            None
        } else {
            Some(ech_configs)
        },
    })
}

/// Turns a parsed `.conf` into the configuration model.
pub fn to_config(conf: &Config) -> Result<model::Config> {
    let mut config = model::Config::default();

    if let Some(ext_general) = &conf.general {
        config.log = to_log(ext_general)?;

        if let (Some(interface), Some(port)) = (
            ext_general.http_interface.as_ref(),
            ext_general.http_port.as_ref(),
        ) {
            config
                .inbounds
                .push(inbound("http", "http", Some((interface, *port)), json!({})));
        }

        if let (Some(interface), Some(port)) = (
            ext_general.socks_interface.as_ref(),
            ext_general.socks_port.as_ref(),
        ) {
            config.inbounds.push(inbound(
                "socks",
                "socks",
                Some((interface, *port)),
                json!({}),
            ));
        }

        if let Some(nf) = &ext_general.nf {
            config.inbounds.push(inbound(
                "nf",
                "nf",
                None,
                json!({
                    "driver_name": nf.driver_name,
                    "nfapi": nf.nfapi,
                    "fake_dns_exclude": ext_general.always_real_ip,
                    "fake_dns_include": ext_general.always_fake_ip,
                }),
            ));
        }

        if ext_general.gateway_mode.is_some() && ext_general.tun_auto != Some(true) {
            return Err(anyhow!("gateway-mode needs tun = auto"));
        }
        if ext_general.tun_fd.is_some()
            || ext_general.tun_auto.is_some()
            || ext_general.tun.is_some()
        {
            let mut tun = json!({
                "fake_dns_exclude": ext_general.always_real_ip,
                "fake_dns_include": ext_general.always_fake_ip,
                "tun2socks": ext_general.tun2socks_backend,
                "wintun": ext_general.wintun,
                "dns_servers": ext_general.tun_dns_server,
            });
            if let Some(fd) = ext_general.tun_fd {
                tun["fd"] = json!(fd);
            } else if ext_general.tun_auto == Some(true) {
                tun["auto"] = json!(true);
                config.route.auto_detect_interface = true;
                if let Some(gateway_mode) = ext_general.gateway_mode {
                    tun["gateway_mode"] = json!(gateway_mode);
                }
            } else if let Some(ext_tun) = &ext_general.tun {
                tun["name"] = json!(ext_tun.name);
                tun["address"] = json!(ext_tun.address);
                tun["gateway"] = json!(ext_tun.gateway);
                tun["netmask"] = json!(ext_tun.netmask);
                tun["mtu"] = json!(ext_tun.mtu);
            }
            config.inbounds.push(inbound("tun", "tun", None, tun));
        }
    }

    let certificates = conf.certificates.as_ref();
    let ech_configs = conf.ech_configs.as_ref();
    let resolve_cert = |value: &Option<String>| -> Option<String> {
        let value = value.as_ref()?;
        if let Some(certificates) = certificates {
            if let Some(content) = certificates.get(value) {
                return Some(content.clone());
            }
        }
        Some(value.clone())
    };
    let resolve_ech = |value: &Option<String>| -> Option<String> {
        let value = value.as_ref()?;
        if let Some(ech_configs) = ech_configs {
            if let Some(content) = ech_configs.get(value) {
                return Some(content.clone());
            }
        }
        Some(value.clone())
    };

    let outbounds = &mut config.outbounds;
    for ext_proxy in conf.proxy.iter().flatten() {
        let tag = ext_proxy.tag.as_str();
        let first_new = outbounds.len();
        match ext_proxy.protocol.as_str() {
            "direct" => outbounds.push(outbound(tag, "direct", json!({}))),
            "drop" => outbounds.push(outbound(tag, "block", json!({}))),
            "redirect" => outbounds.push(outbound(
                tag,
                "redirect",
                json!({ "server": ext_proxy.address, "server_port": ext_proxy.port }),
            )),
            "socks" => outbounds.push(outbound(
                tag,
                "socks",
                json!({
                    "server": ext_proxy.address,
                    "server_port": ext_proxy.port,
                    "username": ext_proxy.username,
                    "password": ext_proxy.password,
                }),
            )),
            "ss" | "shadowsocks" => {
                let mut ss = json!({
                    "server": ext_proxy.address,
                    "server_port": ext_proxy.port,
                    "method": ext_proxy.encrypt_method,
                    "password": ext_proxy.password,
                    "prefix": ext_proxy.prefix,
                });
                if let Some(obfs) = &ext_proxy.obfs_type {
                    let mut opts = format!("obfs={}", obfs);
                    if let Some(host) = &ext_proxy.obfs_host {
                        opts.push_str(&format!(";obfs-host={}", host));
                    }
                    if let Some(path) = &ext_proxy.obfs_path {
                        opts.push_str(&format!(";obfs-uri={}", path));
                    }
                    ss["plugin"] = json!("obfs-local");
                    ss["plugin_opts"] = json!(opts);
                }
                outbounds.push(outbound(tag, "shadowsocks", ss));
            }
            "vless" => {
                let mut vless = json!({
                    "server": ext_proxy.address,
                    "server_port": ext_proxy.port,
                    // prioritize uuid, then password
                    "uuid": ext_proxy.uuid.as_ref().or(ext_proxy.password.as_ref()),
                });
                if ext_proxy.reality.unwrap_or(false) {
                    vless["tls"] = json!({
                        "enabled": true,
                        "server_name": ext_proxy.sni,
                        "reality": {
                            "enabled": true,
                            "public_key": ext_proxy.reality_public_key,
                            "short_id": ext_proxy.reality_short_id,
                        },
                    });
                }
                outbounds.push(outbound(tag, "vless", vless));
            }
            protocol @ ("trojan" | "vmess") => {
                let mut proxy = if protocol == "trojan" {
                    json!({
                        "server": ext_proxy.address,
                        "server_port": ext_proxy.port,
                        "password": ext_proxy.password,
                    })
                } else {
                    json!({
                        "server": ext_proxy.address,
                        "server_port": ext_proxy.port,
                        "uuid": ext_proxy.uuid.as_ref().or(ext_proxy.username.as_ref()),
                        "security": ext_proxy
                            .encrypt_method
                            .as_deref()
                            .unwrap_or("chacha20-ietf-poly1305"),
                    })
                };
                let quic = ext_proxy.quic.unwrap_or(false);
                let certificate = resolve_cert(&ext_proxy.tls_cert);
                // A certificate from a [Certificate] section is inline.
                let (certificate, certificate_path) = match certificate {
                    Some(c) if c.contains("-----BEGIN") => (Some(c), None),
                    other => (None, other),
                };
                let ech = ext_proxy.tls_ech.unwrap_or(false).then(|| {
                    json!({
                        "enabled": true,
                        "config": resolve_ech(&ext_proxy.tls_ech_config_list),
                        "disable_dns_lookup": ext_proxy.tls_ech_disable_dns_lookup,
                    })
                });
                proxy["tls"] = json!({
                    "enabled": true,
                    "server_name": ext_proxy.sni,
                    "insecure": ext_proxy.tls_insecure,
                    "alpn": if protocol == "trojan" && !quic { None } else { Some(["http/1.1"]) },
                    "certificate": certificate,
                    "certificate_path": certificate_path,
                    "ech": ech,
                });
                if quic {
                    proxy["transport"] = json!({ "type": "quic" });
                } else if ext_proxy.ws.unwrap_or(false) {
                    let headers = ext_proxy
                        .ws_host
                        .as_ref()
                        .map(|host| json!({ "Host": host }));
                    proxy["transport"] = json!({
                        "type": "ws",
                        "path": ext_proxy.ws_path.as_deref().unwrap_or("/"),
                        "headers": headers,
                    });
                }
                if ext_proxy.amux.unwrap_or(false) && !quic {
                    proxy["multiplex"] = json!({
                        "enabled": true,
                        "protocol": "amux",
                        "max_accepts": ext_proxy.amux_max,
                        "concurrency": ext_proxy.amux_con,
                        "max_recv_bytes": ext_proxy.amux_max_recv,
                        "max_lifetime": ext_proxy.amux_max_lifetime,
                    });
                }
                outbounds.push(outbound(tag, protocol, proxy));
            }
            other => {
                return Err(anyhow!(
                    "[Proxy] {}: unsupported proxy type \"{}\"",
                    tag,
                    other
                ))
            }
        }
        if let Some(interface) = &ext_proxy.interface {
            if ext_proxy.protocol == "drop" {
                return Err(anyhow!(
                    "[Proxy] {}: interface: a drop proxy sends nothing",
                    tag
                ));
            }
            let (field, value) = match interface.parse::<std::net::IpAddr>() {
                Ok(std::net::IpAddr::V4(_)) => ("inet4_bind_address", interface),
                Ok(std::net::IpAddr::V6(_)) => ("inet6_bind_address", interface),
                Err(_) => ("bind_interface", interface),
            };
            for outbound in &mut outbounds[first_new..] {
                outbound.options.insert(field.into(), json!(value));
            }
        }
    }

    for ext_proxy_group in conf.proxy_group.iter().flatten() {
        let tag = ext_proxy_group.tag.as_str();
        let members = &ext_proxy_group.actors;
        let group = match ext_proxy_group.protocol.as_str() {
            "chain" => {
                // Each hop after the first is a copy of its proxy that dials
                // through the hop before; the last copy is the group.
                let hops = members.as_deref().unwrap_or_default();
                if hops.len() < 2 {
                    return Err(anyhow!(
                        "[Proxy Group] {}: a chain needs at least two proxies",
                        tag
                    ));
                }
                let mut previous = hops[0].clone();
                for (i, hop) in hops.iter().enumerate().skip(1) {
                    let proxy = config
                        .outbounds
                        .iter()
                        .find(|o| &o.tag == hop)
                        .filter(|o| o.options.contains_key("server"))
                        .ok_or_else(|| {
                            anyhow!(
                                "[Proxy Group] {}: [{}] is not a proxy defined in [Proxy]",
                                tag,
                                hop
                            )
                        })?;
                    let mut copy = proxy.clone();
                    if copy.options.contains_key("detour") {
                        return Err(anyhow!(
                            "[Proxy Group] {}: [{}] already dials through another proxy",
                            tag,
                            hop
                        ));
                    }
                    copy.tag = if i + 1 == hops.len() {
                        tag.to_string()
                    } else {
                        format!("{}/{}", tag, hop)
                    };
                    copy.options.insert("detour".into(), json!(previous));
                    previous = copy.tag.clone();
                    config.outbounds.push(copy);
                }
                continue;
            }
            "tryall" => outbound(
                tag,
                "tryall",
                json!({ "outbounds": members, "delay_base": ext_proxy_group.delay_base }),
            ),
            "static" => outbound(
                tag,
                "static",
                json!({ "outbounds": members, "method": ext_proxy_group.method }),
            ),
            "failover" => outbound(
                tag,
                "failover",
                json!({
                    "outbounds": members,
                    "fail_timeout": ext_proxy_group.fail_timeout,
                    "health_check": ext_proxy_group.health_check,
                    "health_check_timeout": ext_proxy_group.health_check_timeout,
                    "health_check_delay": ext_proxy_group.health_check_delay,
                    "health_check_active": ext_proxy_group.health_check_active,
                    "health_check_prefers": ext_proxy_group.health_check_prefers,
                    "check_interval": ext_proxy_group.check_interval,
                    "health_check_on_start": ext_proxy_group.health_check_on_start,
                    "health_check_wait": ext_proxy_group.health_check_wait,
                    "health_check_attempts": ext_proxy_group.health_check_attempts,
                    "health_check_success_percentage": ext_proxy_group.health_check_success_percentage,
                    "failover": ext_proxy_group.failover,
                    "fallback_cache": ext_proxy_group.fallback_cache,
                    "cache_size": ext_proxy_group.cache_size,
                    "cache_timeout": ext_proxy_group.cache_timeout,
                }),
            ),
            "select" => outbound(tag, "selector", json!({ "outbounds": members })),
            "mptp" => outbound(
                tag,
                "mptp",
                json!({
                    "outbounds": members,
                    "server": ext_proxy_group.address,
                    "server_port": ext_proxy_group.port,
                }),
            ),
            other => {
                return Err(anyhow!(
                    "[Proxy Group] {}: unsupported group type \"{}\"",
                    tag,
                    other
                ))
            }
        };
        config.outbounds.push(group);
    }

    for ext_rule in conf.rule.iter().flatten() {
        if ext_rule.type_field == "FINAL" {
            config.route.final_outbound = Some(ext_rule.target.clone());
            continue;
        }
        let mut rule = model::Rule {
            outbound: ext_rule.target.clone(),
            ..Default::default()
        };
        let filter = ext_rule.filter.clone().ok_or_else(|| {
            anyhow!(
                "[Rule] {},{}: missing the value to match",
                ext_rule.type_field,
                ext_rule.target
            )
        })?;
        let condition = match ext_rule.type_field.as_str() {
            "IP-CIDR" => &mut rule.ip_cidr,
            "DOMAIN" => &mut rule.domain,
            "DOMAIN-KEYWORD" => &mut rule.domain_keyword,
            "DOMAIN-SUFFIX" => &mut rule.domain_suffix,
            "GEOIP" => &mut rule.geoip,
            "EXTERNAL" => &mut rule.external,
            "PORT-RANGE" => &mut rule.port_range,
            "NETWORK" => &mut rule.network,
            "INBOUND-TAG" => &mut rule.inbound,
            "PROCESS-NAME" => &mut rule.process_name,
            other => return Err(anyhow!("[Rule] unsupported rule type \"{}\"", other)),
        };
        condition.push(filter);
        config.route.rules.push(rule);
    }
    config.route.domain_resolve = conf
        .general
        .as_ref()
        .and_then(|g| g.routing_domain_resolve)
        .unwrap_or(false);

    if let Some(servers) = conf.general.as_ref().and_then(|g| g.dns_server.clone()) {
        config.dns.servers = servers;
    }
    if let Some(ipv6) = conf.general.as_ref().and_then(|g| g.ipv6) {
        config.dns.strategy = if ipv6 {
            model::DnsStrategy::PreferIpv4
        } else {
            model::DnsStrategy::Ipv4Only
        };
    }
    if let Some(general) = &conf.general {
        match (&general.api_interface, general.api_port) {
            (Some(interface), Some(port)) => {
                let ip = interface.parse::<std::net::IpAddr>().map_err(|_| {
                    anyhow!("api-interface: \"{}\" is not an IP address", interface)
                })?;
                config.api.listen = Some((ip, port).into());
            }
            (None, None) => {}
            _ => return Err(anyhow!("api-interface and api-port go together")),
        }
    }
    if let Some(hosts) = &conf.host {
        config.dns.hosts = hosts.clone();
    }

    config.validate()?;
    Ok(config)
}

fn to_log(general: &General) -> Result<model::Log> {
    let level = match general.loglevel.as_deref() {
        None => model::LogLevel::default(),
        Some(level) => serde_json::from_value(json!(level.to_lowercase()))
            .map_err(|_| anyhow!("[General] loglevel: unknown level \"{}\"", level))?,
    };
    let format = match general.logformat.as_deref() {
        None => model::LogFormat::default(),
        Some(format) => serde_json::from_value(json!(format.to_lowercase()))
            .map_err(|_| anyhow!("[General] logformat: unknown format \"{}\"", format))?,
    };
    let output = general
        .logoutput
        .clone()
        .filter(|output| output != "console");
    Ok(model::Log {
        level,
        output,
        format,
    })
}

/// The options in `value`, less the ones the `.conf` left out, at any depth.
fn options(value: serde_json::Value) -> model::Options {
    match options_value(value) {
        serde_json::Value::Object(map) => map,
        _ => unreachable!("options are always an object"),
    }
}

fn options_value(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.into_iter()
                .filter(|(_, v)| !v.is_null())
                .map(|(k, v)| (k, options_value(v)))
                .collect(),
        ),
        other => other,
    }
}

fn inbound(
    tag: &str,
    protocol: &str,
    listen: Option<(&String, u16)>,
    value: serde_json::Value,
) -> model::Inbound {
    model::Inbound {
        protocol: protocol.to_string(),
        tag: tag.to_string(),
        listen: listen.map(|(address, _)| address.clone()),
        listen_port: listen.map(|(_, port)| port),
        udp_timeout: None,
        options: options(value),
    }
}

fn outbound(tag: &str, protocol: &str, value: serde_json::Value) -> model::Outbound {
    model::Outbound {
        protocol: protocol.to_string(),
        tag: tag.to_string(),
        options: options(value),
    }
}

pub fn from_string(s: &str) -> Result<model::Config> {
    let lines = s.lines().map(|s| Ok(s.to_string())).collect();
    let config = from_lines(lines)?;
    to_config(&config)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(conf: &str) -> model::Config {
        let lines: Vec<io::Result<String>> = conf.lines().map(|s| Ok(s.to_string())).collect();
        to_config(&from_lines(lines).unwrap()).unwrap()
    }

    fn load_err(conf: &str) -> String {
        let lines: Vec<io::Result<String>> = conf.lines().map(|s| Ok(s.to_string())).collect();
        from_lines(lines)
            .and_then(|c| to_config(&c))
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn general_ipv6_api_and_gateway_mode() {
        let config = load(
            r#"
[General]
ipv6 = true
api-interface = 127.0.0.1
api-port = 9090
tun = auto
gateway-mode = true
"#,
        );
        assert_eq!(config.dns.strategy, model::DnsStrategy::PreferIpv4);
        assert_eq!(config.api.listen, Some("127.0.0.1:9090".parse().unwrap()));
        let tun = config
            .inbounds
            .iter()
            .find(|i| i.protocol == "tun")
            .unwrap();
        assert_eq!(tun.options["gateway_mode"], json!(true));
    }

    #[test]
    fn general_mistakes_are_errors() {
        assert!(load_err("[Env]\nFOO = 1\n").contains("[Env]"));
        assert!(load_err("[General]\nipv6 = yes\n").contains("ipv6"));
        assert!(load_err("[General]\napi-port = 9090\n").contains("api-interface"));
        assert!(load_err("[General]\ngateway-mode = true\n").contains("tun = auto"));
    }

    fn outbound<'a>(config: &'a model::Config, tag: &str) -> &'a model::Outbound {
        config.outbounds.iter().find(|o| o.tag == tag).unwrap()
    }

    #[test]
    fn test_trojan_tls_outbound_order() {
        let config = load(
            r#"
[Proxy]
Direct = direct
Trojan = trojan, 1.2.3.4, 443, password, sni=www.google.com
"#,
        );
        assert_eq!(config.outbounds.len(), 2);
        assert_eq!(config.outbounds[0].tag, "Direct");
        let trojan = &config.outbounds[1];
        assert_eq!(trojan.tag, "Trojan");
        assert_eq!(trojan.protocol, "trojan");
        assert_eq!(
            trojan.options["tls"],
            json!({ "enabled": true, "server_name": "www.google.com", "insecure": false })
        );
    }

    #[test]
    fn test_vmess_amux_outbound_order() {
        let config = load(
            r#"
[Proxy]
Vmess = vmess, 1.2.3.4, 443, username, amux=true, sni=www.google.com
"#,
        );
        assert_eq!(config.outbounds.len(), 1);
        let vmess = outbound(&config, "Vmess");
        assert_eq!(vmess.protocol, "vmess");
        assert_eq!(vmess.options["uuid"], "username");
        assert_eq!(vmess.options["server"], "1.2.3.4");
        assert_eq!(vmess.options["multiplex"]["protocol"], "amux");
        assert_eq!(vmess.options["tls"]["alpn"], json!(["http/1.1"]));
    }

    #[test]
    fn test_trojan_tls_ech_mapping() {
        let config = load(
            r#"
[Proxy]
Trojan = trojan, 1.2.3.4, 443, password, sni=www.google.com, tls-ech=true, tls-ech-config-list=AQID
"#,
        );
        let ech = &outbound(&config, "Trojan").options["tls"]["ech"];
        assert_eq!(ech["enabled"], true);
        assert_eq!(ech["config"], "AQID");
    }

    #[test]
    fn test_trojan_tls_ech_mapping_from_section() {
        let config = load(
            r#"
[Proxy]
Trojan = trojan, 1.2.3.4, 443, password, sni=www.google.com, tls-ech=true, tls-ech-config-list=myech

[Ech.myech]
AQI=
"#,
        );
        let ech = &outbound(&config, "Trojan").options["tls"]["ech"];
        assert_eq!(ech["config"].as_str().map(str::trim), Some("AQI="));
    }

    #[test]
    fn test_wintun_conf() {
        let config = load(
            r#"
[General]
tun = auto
wintun = /path/to/wintun.dll
tun-dns-server = 8.8.8.8, 8.8.4.4
"#,
        );
        let tun = config.inbounds.iter().find(|i| i.tag == "tun").unwrap();
        assert_eq!(tun.options["wintun"], "/path/to/wintun.dll");
        assert_eq!(tun.options["dns_servers"], json!(["8.8.8.8", "8.8.4.4"]));
    }

    #[test]
    fn test_tls_ech_fallback_mapping() {
        let config = load(
            r#"
[General]
dns-server = 1.1.1.1

[Proxy]
Trojan = trojan, 1.2.3.4, 443, password, sni=www.google.com, tls-ech=true, tls-ech-disable-dns-lookup=true, tls-ech-config-list=AQID
"#,
        );
        let ech = &outbound(&config, "Trojan").options["tls"]["ech"];
        assert_eq!(ech["enabled"], true);
        assert_eq!(ech["disable_dns_lookup"], true);
        assert_eq!(ech["config"], "AQID");
    }

    #[test]
    fn test_vmess_vless_uuid() {
        let config = load(
            r#"
[Proxy]
Vmess1 = vmess, 1.2.3.4, 443, username, uuid=uuid1
Vmess2 = vmess, 1.2.3.4, 443, username
Vless1 = vless, 1.2.3.4, 443, password, uuid=uuid2
Vless2 = vless, 1.2.3.4, 443, password
"#,
        );
        // An explicit uuid wins; otherwise vmess falls back to the username
        // and vless to the password.
        assert_eq!(outbound(&config, "Vmess1").options["uuid"], "uuid1");
        assert_eq!(outbound(&config, "Vmess2").options["uuid"], "username");
        assert_eq!(outbound(&config, "Vless1").options["uuid"], "uuid2");
        assert_eq!(outbound(&config, "Vless2").options["uuid"], "password");
    }

    #[test]
    fn test_mptp_proxy_group() {
        let config = load(
            r#"
[Proxy Group]
MptpOutTag = mptp, actor1, actor2, actor3, address=1.2.3.4, port=10000
"#,
        );
        assert_eq!(config.outbounds.len(), 1);
        let mptp = &config.outbounds[0];
        assert_eq!(mptp.tag, "MptpOutTag");
        assert_eq!(mptp.protocol, "mptp");
        assert_eq!(
            mptp.options["outbounds"],
            json!(["actor1", "actor2", "actor3"])
        );
        assert_eq!(mptp.options["server"], "1.2.3.4");
        assert_eq!(mptp.options["server_port"], 10000);
    }

    #[test]
    fn a_final_rule_becomes_the_final_outbound() {
        let config = load(
            r#"
[Proxy]
Direct = direct
Proxy = ss, 1.2.3.4, 8388, encrypt-method=aes-128-gcm, password=pw

[Rule]
DOMAIN-SUFFIX, example.com, Direct
FINAL, Proxy
"#,
        );
        assert_eq!(config.route.final_outbound.as_deref(), Some("Proxy"));
        assert_eq!(config.route.rules.len(), 1);
        assert_eq!(config.route.rules[0].domain_suffix, ["example.com"]);
        assert_eq!(config.route.rules[0].outbound, "Direct");
    }

    #[test]
    fn shadowsocks_obfs_becomes_a_plugin() {
        let config = load(
            r#"
[Proxy]
SS = ss, 1.2.3.4, 8388, encrypt-method=aes-128-gcm, password=pw, obfs=http, obfs-host=example.com
"#,
        );
        let ss = outbound(&config, "SS");
        assert_eq!(ss.options["plugin"], "obfs-local");
        assert_eq!(ss.options["plugin_opts"], "obfs=http;obfs-host=example.com");
    }

    #[test]
    fn vless_reality_becomes_a_tls_block() {
        let config = load(
            r#"
[Proxy]
V = vless, 1.2.3.4, 443, uuid=id, sni=example.com, reality=true, reality-public-key=pk, reality-short-id=ab
"#,
        );
        let tls = &outbound(&config, "V").options["tls"];
        assert_eq!(tls["server_name"], "example.com");
        assert_eq!(
            tls["reality"],
            json!({ "enabled": true, "public_key": "pk", "short_id": "ab" })
        );
    }

    #[test]
    fn a_chain_group_becomes_detours() {
        let config = load(
            r#"
[Proxy]
A = ss, 1.1.1.1, 1, encrypt-method=aes-128-gcm, password=a
B = ss, 2.2.2.2, 2, encrypt-method=aes-128-gcm, password=b
C = ss, 3.3.3.3, 3, encrypt-method=aes-128-gcm, password=c

[Proxy Group]
ABC = chain, A, B, C
"#,
        );
        let b = outbound(&config, "ABC/B");
        assert_eq!(b.options["server"], "2.2.2.2");
        assert_eq!(b.options["detour"], "A");
        let c = outbound(&config, "ABC");
        assert_eq!(c.options["server"], "3.3.3.3");
        assert_eq!(c.options["detour"], "ABC/B");
    }

    #[test]
    fn a_proxy_interface_becomes_its_dial_fields() {
        let config = load(
            r#"
[Proxy]
ByName = direct, interface=en1
ByAddress = trojan, 1.2.3.4, 443, password=p, interface=192.168.1.20
"#,
        );
        assert_eq!(outbound(&config, "ByName").options["bind_interface"], "en1");
        assert_eq!(
            outbound(&config, "ByAddress").options["inet4_bind_address"],
            "192.168.1.20"
        );
        assert!(!outbound(&config, "ByName")
            .options
            .contains_key("inet4_bind_address"));
    }

    #[test]
    fn an_unsupported_proxy_type_is_an_error() {
        let lines: Vec<io::Result<String>> = "[Proxy]\nP = hysteria2, 1.2.3.4, 443\n"
            .lines()
            .map(|s| Ok(s.to_string()))
            .collect();
        let err = to_config(&from_lines(lines).unwrap()).unwrap_err();
        assert!(
            err.to_string().contains("unsupported proxy type"),
            "{}",
            err
        );
    }

    #[test]
    fn test_section_name_compatibility() {
        let conf = r#"
[general]
loglevel = trace

[PROXY_GROUP]
ProxyGroup1 = select, Direct, Trojan

[proxygroup]
ProxyGroup2 = select, Direct, Trojan

[proxy_group]
ProxyGroup3 = select, Direct, Trojan

[rule]
DOMAIN,google.com,Direct

[host]
google.com = 1.2.3.4

[certificate_MyCert]
CERT1

[certificate.AnotherCert]
CERT2

[certificate MyThirdCert]
CERT3

[certificateNoSpaceCert]
CERT4
"#;
        let lines: Vec<io::Result<String>> = conf.lines().map(|s| Ok(s.to_string())).collect();
        let config = from_lines(lines).unwrap();

        assert!(config.general.is_some());
        assert_eq!(config.general.unwrap().loglevel, Some("trace".to_string()));

        assert!(config.proxy_group.is_some());
        assert_eq!(config.proxy_group.as_ref().unwrap().len(), 3);
        assert_eq!(config.proxy_group.as_ref().unwrap()[0].tag, "ProxyGroup1");
        assert_eq!(config.proxy_group.as_ref().unwrap()[1].tag, "ProxyGroup2");
        assert_eq!(config.proxy_group.as_ref().unwrap()[2].tag, "ProxyGroup3");

        assert!(config.rule.is_some());
        assert_eq!(config.rule.unwrap().len(), 1);

        assert!(config.host.is_some());
        assert_eq!(config.host.unwrap().len(), 1);

        assert!(config.certificates.is_some());
        let certs = config.certificates.unwrap();
        assert!(certs.contains_key("MyCert"));
        assert!(certs.contains_key("AnotherCert"));
        assert!(certs.contains_key("MyThirdCert"));
        assert!(certs.contains_key("NoSpaceCert"));
        assert_eq!(certs.get("MyCert").unwrap(), "CERT1\n");
        assert_eq!(certs.get("AnotherCert").unwrap(), "CERT2\n");
        assert_eq!(certs.get("MyThirdCert").unwrap(), "CERT3\n");
        assert_eq!(certs.get("NoSpaceCert").unwrap(), "CERT4\n");
    }
}

pub fn from_file<P>(path: P) -> Result<model::Config>
where
    P: AsRef<Path>,
{
    let lines = read_lines(path)?.collect();
    let config = from_lines(lines)?;
    to_config(&config)
}
