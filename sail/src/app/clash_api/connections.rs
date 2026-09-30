//! `/connections` and `/rules`: the connections open now, as Mihomo lists
//! them, closing them, and the routing rules, as sing-box tells them.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures::StreamExt;
use serde_json::{json, Value};

use super::streams::send;
use super::Clash;
use crate::control::ConnectionInfo;
use crate::RuntimeManager;

/// How often a WebSocket is sent the connections, unless `?interval=`
/// (milliseconds) says otherwise, as in Mihomo.
const INTERVAL: Duration = Duration::from_millis(1000);

/// The shortest interval taken: a dashboard cannot ask for a busy loop.
const INTERVAL_MIN: Duration = Duration::from_millis(100);

/// The connections now, once, or, over a WebSocket, every interval.
pub(super) async fn list(
    State(clash): State<Arc<Clash>>,
    Query(query): Query<HashMap<String, String>>,
    ws: Option<WebSocketUpgrade>,
) -> Response {
    let Some(ws) = ws else {
        return Json(snapshot(&clash.rm).await).into_response();
    };
    let interval = query
        .get("interval")
        .and_then(|ms| ms.parse().ok())
        .map(Duration::from_millis)
        .unwrap_or(INTERVAL)
        .max(INTERVAL_MIN);
    let frames =
        futures::stream::unfold(tokio::time::interval(interval), |mut interval| async move {
            interval.tick().await;
            Some(((), interval))
        })
        .then(move |()| {
            let clash = clash.clone();
            async move { snapshot(&clash.rm).await }
        });
    send(Some(ws), frames)
}

async fn snapshot(rm: &RuntimeManager) -> Value {
    let traffic = rm.traffic().await;
    let connections = rm.connections().await;
    json!({
        "downloadTotal": traffic.down_total,
        "uploadTotal": traffic.up_total,
        "connections": connections.iter().map(connection).collect::<Vec<_>>(),
        "memory": crate::control::resident_memory(),
    })
}

fn connection(c: &ConnectionInfo) -> Value {
    let start = chrono::DateTime::from_timestamp(i64::from(c.start), 0)
        .unwrap_or_default()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    json!({
        "id": c.id.to_string(),
        "metadata": {
            "network": c.network.to_string(),
            "type": format!("{}/{}", c.inbound_type, c.inbound_tag),
            "sourceIP": c.source.ip().to_string(),
            "sourcePort": c.source.port().to_string(),
            "destinationIP": c.destination.ip().map(|ip| ip.to_string()).unwrap_or_default(),
            "destinationPort": c.destination.port().to_string(),
            "host": c.host.clone().unwrap_or_default(),
            "dnsMode": "normal",
            "processPath": c.process.clone().unwrap_or_default(),
            "inboundName": c.inbound_tag,
        },
        "upload": c.upload,
        "download": c.download,
        "start": start,
        "chains": c.chains,
        "rule": c.rule.as_deref().unwrap_or("final"),
        "rulePayload": "",
    })
}

/// Closes every connection.
pub(super) async fn close_all(State(clash): State<Arc<Clash>>) -> StatusCode {
    clash.rm.close_all_connections().await;
    StatusCode::NO_CONTENT
}

/// Closes one; one there is not is no error, as in Mihomo.
pub(super) async fn close(State(clash): State<Arc<Clash>>, Path(id): Path<String>) -> StatusCode {
    if let Ok(id) = id.parse() {
        clash.rm.close_connection(id).await;
    }
    StatusCode::NO_CONTENT
}

/// The routing rules, in order.
pub(super) async fn rules(State(clash): State<Arc<Clash>>) -> Json<Value> {
    let router = clash.rm.router();
    let rules: Vec<Value> = router
        .rules()
        .map(|about| {
            json!({
                "type": about.kind,
                "payload": about.payload,
                "proxy": about.action,
            })
        })
        .collect();
    Json(json!({ "rules": rules }))
}
