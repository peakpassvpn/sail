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

use super::streams::{resident_memory, send};
use super::Clash;
use crate::app::stat_manager::{Counter, StatManager};

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
    let stats = clash.rm.stat_manager();
    let Some(ws) = ws else {
        return Json(snapshot(&*stats.read().await)).into_response();
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
            let stats = stats.clone();
            async move { snapshot(&*stats.read().await) }
        });
    send(Some(ws), frames)
}

fn snapshot(stats: &StatManager) -> Value {
    let (up, down) = stats.totals();
    let mut counters: Vec<&Counter> = stats.counters.values().collect();
    counters.sort_by_key(|c| c.id);
    json!({
        "downloadTotal": down,
        "uploadTotal": up,
        "connections": counters.into_iter().map(connection).collect::<Vec<_>>(),
        "memory": resident_memory(),
    })
}

fn connection(counter: &Counter) -> Value {
    let sess = &counter.sess;
    let host = sess
        .destination
        .domain()
        .cloned()
        .or_else(|| sess.sniffed.as_ref().map(|(_, domain)| domain.clone()))
        .unwrap_or_default();
    // The group took members to get here, last first; the outbound the
    // rules picked comes last, as Mihomo lists them.
    let mut chains = sess.chain.get();
    chains.push(sess.outbound_tag.clone());
    let start = chrono::DateTime::from_timestamp(i64::from(counter.start_time()), 0)
        .unwrap_or_default()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    json!({
        "id": counter.id.to_string(),
        "metadata": {
            "network": sess.network.to_string(),
            "type": format!("{}/{}", sess.inbound_type, sess.inbound_tag),
            "sourceIP": sess.source.ip().to_string(),
            "sourcePort": sess.source.port().to_string(),
            "destinationIP": sess.destination.ip().map(|ip| ip.to_string()).unwrap_or_default(),
            "destinationPort": sess.destination.port().to_string(),
            "host": host,
            "dnsMode": "normal",
            "processPath": sess.process_name.clone().unwrap_or_default(),
            "inboundName": sess.inbound_tag,
        },
        "upload": counter.bytes_sent(),
        "download": counter.bytes_recvd(),
        "start": start,
        "chains": chains,
        "rule": sess.matched_rule.as_deref().unwrap_or("final"),
        "rulePayload": "",
    })
}

/// Closes every connection.
pub(super) async fn close_all(State(clash): State<Arc<Clash>>) -> StatusCode {
    clash.rm.stat_manager().read().await.close_all();
    StatusCode::NO_CONTENT
}

/// Closes one; one there is not is no error, as in Mihomo.
pub(super) async fn close(State(clash): State<Arc<Clash>>, Path(id): Path<String>) -> StatusCode {
    if let Ok(id) = id.parse() {
        clash.rm.stat_manager().read().await.close(id);
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
