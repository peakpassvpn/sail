//! `/dns/query`, and flushing the DNS cache and the fake IPs.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use hickory_proto::op::Message;
use hickory_proto::rr::{Name, Record, RecordType};
use serde_json::{json, Value};

use super::{ApiError, Clash};
use crate::app::dns::{DnsClient, LookupContext};
use crate::util::DnsMessageExt;

/// Asks the DNS client for `?name=` of `?type=` (A when unset), as the
/// rules pick its server: the answer in the JSON of DNS over HTTPS (RFC
/// 8427-like), as Mihomo and sing-box give it.
pub(super) async fn query(
    State(clash): State<Arc<Clash>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let name = params
        .get("name")
        .filter(|n| !n.is_empty())
        .ok_or_else(|| ApiError::bad_request("invalid query name"))?;
    let ty = RecordType::from_str(params.get("type").map_or("A", String::as_str))
        .map_err(|_| ApiError::bad_request("invalid query type"))?;
    let name = Name::from_str(&format!("{}.", name.trim_end_matches('.')))
        .map_err(|_| ApiError::bad_request("invalid query name"))?;
    let query = DnsClient::query_message(name, ty)
        .to_vec()
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let reply = clash
        .rm
        .dns_client()
        .load()
        .exchange(&query, &LookupContext::default())
        .await
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let m = Message::from_vec(&reply)
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let records = |records: &[Record]| -> Vec<Value> {
        records
            .iter()
            .map(|r| {
                json!({
                    "name": r.name.to_utf8(),
                    "type": u16::from(r.record_type()),
                    "TTL": r.ttl,
                    "data": r.data.to_string(),
                })
            })
            .collect()
    };
    let mut answer = json!({
        "Status": u16::from(m.response_code()),
        "Question": m.queries().iter().map(|q| json!({
            "Name": q.name().to_utf8(),
            "Qtype": u16::from(q.query_type()),
            "Qclass": u16::from(q.query_class()),
        })).collect::<Vec<_>>(),
        "Server": "internal",
        "TC": m.metadata.truncation,
        "RD": m.metadata.recursion_desired,
        "RA": m.metadata.recursion_available,
        "AD": m.metadata.authentic_data,
        "CD": m.metadata.checking_disabled,
    });
    for (key, section) in [
        ("Answer", &m.answers),
        ("Authority", &m.authorities),
        ("Additional", &m.additionals),
    ] {
        if !section.is_empty() {
            answer[key] = Value::Array(records(section));
        }
    }
    Ok(Json(answer))
}

pub(super) async fn flush_fake_ips(State(clash): State<Arc<Clash>>) -> StatusCode {
    clash.rm.dns_client().load().clear_fake_ips();
    StatusCode::NO_CONTENT
}

pub(super) async fn flush_dns(State(clash): State<Arc<Clash>>) -> StatusCode {
    clash.rm.clear_dns_cache();
    StatusCode::NO_CONTENT
}
