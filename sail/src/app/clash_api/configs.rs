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
use crate::config::model::{Config, DnsStrategy, LogLevel};

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

pub(super) async fn version() -> Json<Value> {
    Json(json!({
        "version": format!("sail {}", env!("CARGO_PKG_VERSION")),
        "premium": true,
        "meta": true,
    }))
}

pub(super) async fn get_configs(State(clash): State<Arc<Clash>>) -> Json<Value> {
    let view = clash.rm.clash_view();
    let (mode, modes) = match clash.rm.mode() {
        Some(mode) => (mode.current, mode.modes),
        None => ("Rule".to_string(), Vec::new()),
    };
    Json(json!({
        "port": view.port,
        "socks-port": view.socks_port,
        "redir-port": view.redir_port,
        "tproxy-port": view.tproxy_port,
        "mixed-port": view.mixed_port,
        "allow-lan": view.allow_lan,
        "bind-address": "*",
        "mode": mode,
        "mode-list": modes,
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
        // A mode not among them is left alone, as in sing-box.
        let _ = clash.rm.set_mode(mode);
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

/// Reloads the configuration from its file, as a dashboard's reload
/// asks. A path or a payload of another is refused: the host says what
/// the instance runs. What `clash_api` itself says is taken at the next
/// start.
pub(super) async fn put_configs(
    State(clash): State<Arc<Clash>>,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let fields: Map<String, Value> = if body.iter().all(u8::is_ascii_whitespace) {
        Map::new()
    } else {
        serde_json::from_slice(&body).map_err(|_| ApiError::bad_request("Body invalid"))?
    };
    for field in ["path", "payload"] {
        if fields
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(|v| !v.is_empty())
        {
            return Err(ApiError::bad_request(format!(
                "{}: sail reloads its own configuration file only",
                field
            )));
        }
    }
    clash
        .rm
        .reload()
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}
