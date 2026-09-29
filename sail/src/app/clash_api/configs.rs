//! `/version` and `/configs`: what the instance runs with, as Mihomo tells
//! it, and the two things a dashboard changes of it at run time, the mode
//! rules match and the log level. The rest, the listeners and the TUN,
//! are the configuration's, and a change to them is left alone, as in
//! sing-box.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Map, Value};

use super::{ApiError, Clash};
use crate::config::model::{Config, DnsStrategy, LogLevel, Rule};

/// What `/configs` tells of a configuration, worked out as it is loaded.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct ConfigView {
    /// The listen ports of the first inbound of each kind, 0 without.
    pub port: u16,
    pub socks_port: u16,
    pub mixed_port: u16,
    pub redir_port: u16,
    pub tproxy_port: u16,
    /// Whether an inbound listens on other than a loopback address.
    pub allow_lan: bool,
    /// Whether there is a TUN inbound.
    pub tun: bool,
    /// Whether names resolve to IPv6 addresses.
    pub ipv6: bool,
    pub log_level: &'static str,
    /// The modes rules match on, as sing-box lists them.
    pub modes: Vec<String>,
}

impl ConfigView {
    pub(crate) fn of(config: &Config) -> Self {
        let mut view = ConfigView {
            ipv6: config.dns.strategy != DnsStrategy::Ipv4Only,
            log_level: if config.log.disabled {
                "silent"
            } else {
                match config.log.level {
                    LogLevel::Trace | LogLevel::Debug => "debug",
                    LogLevel::Info => "info",
                    LogLevel::Warn => "warning",
                    LogLevel::Error | LogLevel::Fatal | LogLevel::Panic => "error",
                }
            },
            modes: modes(config),
            ..Default::default()
        };
        for inbound in &config.inbounds {
            let port = inbound.listen_port.unwrap_or(0);
            let slot = match inbound.protocol.as_str() {
                "http" => &mut view.port,
                "socks" => &mut view.socks_port,
                "mixed" => &mut view.mixed_port,
                "redirect" => &mut view.redir_port,
                "tproxy" => &mut view.tproxy_port,
                "tun" => {
                    view.tun = true;
                    continue;
                }
                _ => continue,
            };
            if *slot == 0 {
                *slot = port;
            }
            if inbound.listen_port.is_some() {
                let listen = inbound.listen.as_deref().unwrap_or("127.0.0.1");
                let loopback = listen == "localhost"
                    || listen
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback());
                view.allow_lan |= !loopback;
            }
        }
        view
    }
}

/// The modes, as sing-box lists them: those the routing and DNS rules
/// name that are not Clash's own, sorted, then Clash's own they name, in
/// Clash's order; the default mode first if none of them.
fn modes(config: &Config) -> Vec<String> {
    fn collect(rule: &Rule, into: &mut Vec<String>) {
        if let Some(mode) = &rule.clash_mode {
            into.push(mode.clone());
        }
        for rule in &rule.rules {
            collect(rule, into);
        }
    }
    let mut named = Vec::new();
    for rule in &config.route.rules {
        collect(rule, &mut named);
    }
    for rule in &config.dns.rules {
        collect(&rule.conditions(), &mut named);
    }
    const CLASH: [&str; 3] = ["Rule", "Global", "Direct"];
    let is_clash = |m: &str| CLASH.iter().any(|c| c.eq_ignore_ascii_case(m));
    let mut modes: Vec<String> = named.iter().filter(|m| !is_clash(m)).cloned().collect();
    modes.sort();
    modes.dedup();
    for clash in CLASH {
        if named.iter().any(|m| m.eq_ignore_ascii_case(clash)) {
            modes.push(clash.to_string());
        }
    }
    let default = config
        .clash_api
        .as_ref()
        .and_then(|api| api.default_mode.clone())
        .unwrap_or_else(|| "Rule".to_string());
    if !modes.iter().any(|m| m.eq_ignore_ascii_case(&default)) {
        modes.insert(0, default);
    }
    modes
}

pub(super) async fn version() -> Json<Value> {
    Json(json!({
        "version": format!("sail {}", env!("CARGO_PKG_VERSION")),
        "premium": true,
        "meta": true,
    }))
}

pub(super) async fn get_configs(State(clash): State<Arc<Clash>>) -> Json<Value> {
    let view = clash.rm.clash_view();
    let mode = clash
        .rm
        .env()
        .clash_mode
        .get()
        .unwrap_or_else(|| "Rule".to_string());
    Json(json!({
        "port": view.port,
        "socks-port": view.socks_port,
        "redir-port": view.redir_port,
        "tproxy-port": view.tproxy_port,
        "mixed-port": view.mixed_port,
        "allow-lan": view.allow_lan,
        "bind-address": "*",
        "mode": mode,
        "mode-list": view.modes,
        "log-level": view.log_level,
        "ipv6": view.ipv6,
        "tun": { "enable": view.tun },
    }))
}

/// Switches the mode (matched as it is, then in any case, among the modes;
/// another is left alone, as in sing-box) and the log level; the rest is
/// the configuration's.
pub(super) async fn patch_configs(
    State(clash): State<Arc<Clash>>,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let fields: Map<String, Value> =
        serde_json::from_slice(&body).map_err(|_| ApiError::bad_request("Body invalid"))?;
    if let Some(mode) = fields.get("mode").and_then(Value::as_str) {
        let modes = clash.rm.clash_view().modes;
        let found = modes
            .iter()
            .find(|m| *m == mode)
            .or_else(|| modes.iter().find(|m| m.eq_ignore_ascii_case(mode)));
        if let Some(mode) = found {
            clash.rm.switch_clash_mode(mode);
        }
    }
    if let Some(level) = fields.get("log-level").and_then(Value::as_str) {
        let level = match level {
            "debug" => LogLevel::Debug,
            "info" => LogLevel::Info,
            "warning" | "warn" => LogLevel::Warn,
            "error" => LogLevel::Error,
            "silent" => {
                crate::app::logger::set_level(None);
                return Ok(StatusCode::NO_CONTENT);
            }
            _ => return Err(ApiError::bad_request("Body invalid")),
        };
        crate::app::logger::set_level(Some(level));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Reloading from a path or a payload is not taken: the host's
/// configuration is what the instance runs.
pub(super) async fn put_configs() -> StatusCode {
    StatusCode::NO_CONTENT
}
