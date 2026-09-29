//! `/proxies` and `/group`: the outbounds and groups, as Mihomo shows them
//! (type, `now`, `all`, the delays measured), selecting a group's member,
//! and measuring delays.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Map, Value};

use super::{ApiError, Clash};
use crate::app::healthcheck::{HttpProbe, DEFAULT_URL};

/// The delays measured of an outbound kept, the latest last; Mihomo's.
const HISTORY: usize = 10;

/// A delay measured, as Mihomo gives it.
#[derive(Debug, Clone)]
pub(crate) struct Delay {
    time: String,
    /// In milliseconds; 0 for a failure.
    delay: u64,
}

/// The name Mihomo gives outbounds of `protocol`.
fn clash_type(protocol: &str) -> &'static str {
    match protocol {
        "direct" => "Direct",
        "drop" | "block" | "reject" => "Reject",
        "dns" => "Dns",
        "selector" => "Selector",
        "urltest" => "URLTest",
        "fallback" => "Fallback",
        "load-balance" => "LoadBalance",
        "smart" => "Smart",
        "chain" => "Relay",
        "shadowsocks" => "Shadowsocks",
        "vmess" => "Vmess",
        "vless" => "Vless",
        "trojan" => "Trojan",
        "socks" => "Socks5",
        "http" => "Http",
        "hysteria2" => "Hysteria2",
        "tuic" => "Tuic",
        "anytls" => "AnyTLS",
        "wireguard" => "WireGuard",
        "redirect" => "Redirect",
        _ => "Unknown",
    }
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

impl Clash {
    fn record(&self, tag: &str, delay: Option<Duration>) {
        let mut history = self.history.lock().unwrap_or_else(|e| e.into_inner());
        let entries = history.entry(tag.to_string()).or_default();
        entries.push_back(Delay {
            time: now_rfc3339(),
            delay: delay.map_or(0, |d| d.as_millis().max(1) as u64),
        });
        while entries.len() > HISTORY {
            entries.pop_front();
        }
    }

    fn history_of(&self, tag: &str) -> Vec<Delay> {
        self.history
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(tag)
            .map(|h| h.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// `tag` as Mihomo shows an outbound or a group; none if there is none.
    async fn proxy(&self, tag: &str, latencies: &HashMap<String, Duration>) -> Option<Value> {
        let om = self.rm.outbound_manager();
        let handler = om.get(tag)?;
        let protocol = om.protocol(tag).unwrap_or_default().to_string();
        let mut history = self.history_of(tag);
        // A group's own checks, where nothing was measured here.
        if history.is_empty() {
            if let Some(latency) = latencies.get(tag) {
                history.push(Delay {
                    time: now_rfc3339(),
                    delay: latency.as_millis().max(1) as u64,
                });
            }
        }
        let alive = history.last().is_none_or(|d| d.delay > 0);
        let mut proxy = Map::new();
        proxy.insert("name".into(), json!(tag));
        proxy.insert("type".into(), json!(clash_type(&protocol)));
        proxy.insert("udp".into(), json!(handler.datagram().is_ok()));
        proxy.insert("xudp".into(), json!(false));
        proxy.insert("tfo".into(), json!(false));
        proxy.insert("alive".into(), json!(alive));
        proxy.insert(
            "history".into(),
            Value::Array(
                history
                    .iter()
                    .map(|d| json!({ "time": d.time, "delay": d.delay }))
                    .collect(),
            ),
        );
        proxy.insert("extra".into(), json!({}));
        #[cfg(feature = "outbound-select")]
        if let Some(selector) = om.get_selector(tag) {
            let selector = selector.read().await;
            proxy.insert("now".into(), json!(selector.get_selected_tag()));
            proxy.insert("all".into(), json!(selector.get_available_tags()));
            proxy.insert("hidden".into(), json!(false));
            proxy.insert("icon".into(), json!(""));
            proxy.insert("testUrl".into(), json!(""));
            if !selector.is_selectable() {
                proxy.insert("fixed".into(), json!(""));
            }
        }
        Some(Value::Object(proxy))
    }

    /// The latest latencies the groups measured of their members.
    async fn latencies(&self) -> HashMap<String, Duration> {
        #[cfg_attr(not(feature = "outbound-select"), allow(unused_mut))]
        let mut out = HashMap::new();
        #[cfg(feature = "outbound-select")]
        {
            let om = self.rm.outbound_manager();
            for handler in om.handlers() {
                if let Some(selector) = om.get_selector(handler.tag()) {
                    for (tag, latency) in selector.read().await.get_latencies().unwrap_or_default()
                    {
                        if let Some(latency) = latency {
                            out.insert(tag, latency);
                        }
                    }
                }
            }
        }
        out
    }

    /// Measures the delay of `tag` with an HTTP request to `url`.
    async fn measure(&self, tag: &str, url: &str, timeout: Duration) -> Result<Duration, ApiError> {
        let handler = self
            .rm
            .outbound_manager()
            .get(tag)
            .ok_or_else(ApiError::not_found)?;
        let dns = self.rm.dns_client();
        let probe = HttpProbe::new(url, dns.clone(), &self.rm.env())
            .map_err(|e| ApiError::bad_request(e.to_string()))?;
        let measured = match tokio::time::timeout(timeout, probe.run(dns, &handler)).await {
            Ok(Ok(delay)) => Ok(delay),
            Ok(Err(_)) => Err(ApiError(
                StatusCode::SERVICE_UNAVAILABLE,
                "An error occurred in the delay test".into(),
            )),
            Err(_) => Err(ApiError(StatusCode::GATEWAY_TIMEOUT, "Timeout".into())),
        };
        self.record(tag, measured.as_ref().ok().copied());
        measured
    }
}

/// The URL and timeout of a delay test, as dashboards give them.
fn test_params(params: &HashMap<String, String>) -> Result<(String, Duration), ApiError> {
    let timeout: u64 = params
        .get("timeout")
        .and_then(|t| t.parse().ok())
        .filter(|t| *t > 0)
        .ok_or_else(|| ApiError::bad_request("Body invalid"))?;
    let url = params
        .get("url")
        .filter(|u| !u.is_empty())
        .cloned()
        .unwrap_or_else(|| DEFAULT_URL.to_string());
    Ok((url, Duration::from_millis(timeout)))
}

pub(super) async fn list(State(clash): State<Arc<Clash>>) -> Json<Value> {
    let latencies = clash.latencies().await;
    let om = clash.rm.outbound_manager();
    let mut proxies = Map::new();
    let tags: Vec<String> = om.handlers().map(|h| h.tag().clone()).collect();
    for tag in &tags {
        if let Some(proxy) = clash.proxy(tag, &latencies).await {
            proxies.insert(tag.clone(), proxy);
        }
    }
    // Mihomo's GLOBAL group, as sing-box shows it, unless an outbound is so
    // tagged (a Clash configuration's is).
    if !proxies.contains_key("GLOBAL") {
        let default = om.default_handler().unwrap_or_default();
        let mut all: Vec<&String> = tags
            .iter()
            .filter(|t| {
                !matches!(
                    om.protocol(t).unwrap_or_default(),
                    "direct" | "drop" | "block" | "dns"
                )
            })
            .collect();
        all.sort();
        if let Some(i) = all.iter().position(|t| **t == default) {
            let d = all.remove(i);
            all.insert(0, d);
        }
        proxies.insert(
            "GLOBAL".into(),
            json!({
                "name": "GLOBAL", "type": "Fallback", "udp": true, "history": [],
                "all": all, "now": default, "hidden": true, "icon": "",
            }),
        );
    }
    Json(json!({ "proxies": proxies }))
}

pub(super) async fn one(
    State(clash): State<Arc<Clash>>,
    Path(name): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let latencies = clash.latencies().await;
    clash
        .proxy(&name, &latencies)
        .await
        .map(Json)
        .ok_or_else(ApiError::not_found)
}

/// Selects `{"name": member}` of the group `name`, which must be a
/// selector: the choice is kept in the cache file, as sing-box keeps it.
pub(super) async fn select(
    State(clash): State<Arc<Clash>>,
    Path(name): Path<String>,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let body: Map<String, Value> =
        serde_json::from_slice(&body).map_err(|_| ApiError::bad_request("Body invalid"))?;
    let member = body
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::bad_request("Body invalid"))?;
    #[cfg(feature = "outbound-select")]
    {
        let selector = clash
            .rm
            .outbound_manager()
            .get_selector(&name)
            .ok_or_else(|| ApiError::bad_request("Must be a Selector"))?;
        let mut selector = selector.write().await;
        if !selector.is_selectable() {
            return Err(ApiError::bad_request("Must be a Selector"));
        }
        selector
            .set_selected(member)
            .map_err(|e| ApiError::bad_request(format!("Selector update error: {}", e)))?;
        Ok(StatusCode::NO_CONTENT)
    }
    #[cfg(not(feature = "outbound-select"))]
    {
        let _ = (clash, name, member);
        Err(ApiError::bad_request("Must be a Selector"))
    }
}

/// Mihomo unpins a group that selects by itself; sail's groups do not pin,
/// so there is nothing to undo, but for a selector, which is not such.
pub(super) async fn unfix(
    State(clash): State<Arc<Clash>>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    let om = clash.rm.outbound_manager();
    om.get(&name).ok_or_else(ApiError::not_found)?;
    if om.protocol(&name) == Some("selector") {
        return Err(ApiError::bad_request("Must not be a Selector"));
    }
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn delay(
    State(clash): State<Arc<Clash>>,
    Path(name): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let (url, timeout) = test_params(&params)?;
    let delay = clash.measure(&name, &url, timeout).await?;
    Ok(Json(json!({ "delay": delay.as_millis().max(1) as u64 })))
}

/// The groups, as an array, as Mihomo gives them.
pub(super) async fn groups(State(clash): State<Arc<Clash>>) -> Json<Value> {
    let latencies = clash.latencies().await;
    let om = clash.rm.outbound_manager();
    #[cfg_attr(not(feature = "outbound-select"), allow(unused_mut))]
    let mut groups: Vec<Value> = Vec::new();
    #[cfg(feature = "outbound-select")]
    for handler in om.handlers() {
        if om.get_selector(handler.tag()).is_some() {
            if let Some(group) = clash.proxy(handler.tag(), &latencies).await {
                groups.push(group);
            }
        }
    }
    #[cfg(not(feature = "outbound-select"))]
    let _ = (&om, &latencies);
    Json(json!({ "proxies": groups }))
}

pub(super) async fn group(
    State(clash): State<Arc<Clash>>,
    Path(name): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let latencies = clash.latencies().await;
    let group = clash
        .proxy(&name, &latencies)
        .await
        .filter(|p| p.get("all").is_some())
        .ok_or_else(ApiError::not_found)?;
    Ok(Json(group))
}

/// Measures each member of the group `name`, ten at a time: their delays
/// by name, those that failed left out, as Mihomo answers.
pub(super) async fn group_delay(
    State(clash): State<Arc<Clash>>,
    Path(name): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let (url, timeout) = test_params(&params)?;
    let group = {
        let latencies = HashMap::new();
        clash
            .proxy(&name, &latencies)
            .await
            .ok_or_else(ApiError::not_found)?
    };
    let members: Vec<String> = group
        .get("all")
        .and_then(Value::as_array)
        .ok_or_else(ApiError::not_found)?
        .iter()
        .filter_map(|m| m.as_str().map(str::to_owned))
        .collect();
    use futures::StreamExt;
    let delays: Vec<(String, Option<Duration>)> = futures::stream::iter(members)
        .map(|member| {
            let clash = clash.clone();
            let url = url.clone();
            async move {
                let delay = clash.measure(&member, &url, timeout).await.ok();
                (member, delay)
            }
        })
        .buffer_unordered(10)
        .collect()
        .await;
    let map: Map<String, Value> = delays
        .into_iter()
        .filter_map(|(m, d)| d.map(|d| (m, json!(d.as_millis().max(1) as u64))))
        .collect();
    Ok(Json(Value::Object(map)))
}

/// The outbound providers; filled in by the providers stage.
pub(super) async fn providers() -> Json<Value> {
    Json(json!({ "providers": {} }))
}

/// The rule providers; filled in by the providers stage.
pub(super) async fn rule_providers() -> Json<Value> {
    Json(json!({ "providers": {} }))
}
