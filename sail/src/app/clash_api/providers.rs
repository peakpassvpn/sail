//! `/providers/proxies` and `/providers/rules`: the outbound providers and
//! the rule-sets, as Mihomo shows its proxy and rule providers, updating
//! them, and measuring a provider's members.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Map, Value};

use super::proxies::test_params;
use super::{ApiError, Clash};

/// How long a provider's health check waits on each member.
#[cfg(feature = "outbound-provider")]
const HEALTH_CHECK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// A time as Mihomo gives it; Go's zero time for none.
#[cfg(any(feature = "outbound-provider", feature = "rule-set"))]
fn time(at: Option<std::time::SystemTime>) -> String {
    match at {
        Some(at) => chrono::DateTime::<chrono::Utc>::from(at)
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        None => "0001-01-01T00:00:00Z".to_string(),
    }
}

#[cfg(any(feature = "outbound-provider", feature = "rule-set"))]
fn update_failed(e: impl std::fmt::Display) -> ApiError {
    ApiError(StatusCode::SERVICE_UNAVAILABLE, format!("{:#}", e))
}

#[cfg(feature = "outbound-provider")]
impl Clash {
    fn provider(&self, name: &str) -> Result<Arc<crate::app::provider::Provider>, ApiError> {
        self.rm
            .outbound_manager()
            .providers()
            .all()
            .iter()
            .find(|p| &*p.tag == name)
            .cloned()
            .ok_or_else(ApiError::not_found)
    }

    /// Measures the member `name` of the provider `provider`.
    async fn probe_member(
        &self,
        provider: &str,
        name: &str,
        url: &str,
        timeout: std::time::Duration,
    ) -> Result<std::time::Duration, ApiError> {
        let handler = self
            .provider(provider)?
            .members()
            .load()
            .find(name)
            .map(|m| m.handler.clone())
            .ok_or_else(ApiError::not_found)?;
        self.probe(name, &handler, url, timeout).await
    }

    async fn show_provider(&self, provider: &crate::app::provider::Provider) -> Value {
        let latencies = HashMap::new();
        let mut proxies = Vec::new();
        for member in provider.members().load().members.iter() {
            if let Some(proxy) = self
                .describe(
                    &member.key.name,
                    &member.handler,
                    member.kind,
                    false,
                    &latencies,
                )
                .await
            {
                proxies.push(proxy);
            }
        }
        json!({
            "name": &*provider.tag,
            "type": "Proxy",
            "vehicleType": provider.vehicle(),
            "proxies": proxies,
            "testUrl": "",
            "expectedStatus": "*",
            "updatedAt": time(provider.updated()),
        })
    }
}

/// The outbound providers, by tag.
pub(super) async fn proxy_providers(State(clash): State<Arc<Clash>>) -> Json<Value> {
    #[cfg_attr(not(feature = "outbound-provider"), allow(unused_mut))]
    let mut providers = Map::new();
    #[cfg(feature = "outbound-provider")]
    for provider in clash.rm.outbound_manager().providers().all() {
        providers.insert(
            provider.tag.to_string(),
            clash.show_provider(provider).await,
        );
    }
    #[cfg(not(feature = "outbound-provider"))]
    let _ = clash;
    Json(json!({ "providers": providers }))
}

pub(super) async fn proxy_provider(
    State(clash): State<Arc<Clash>>,
    Path(name): Path<String>,
) -> Result<Json<Value>, ApiError> {
    #[cfg(feature = "outbound-provider")]
    {
        let provider = clash.provider(&name)?;
        Ok(Json(clash.show_provider(&provider).await))
    }
    #[cfg(not(feature = "outbound-provider"))]
    {
        let _ = (clash, name);
        Err(ApiError::not_found())
    }
}

/// Downloads the provider, or reads its file, again.
pub(super) async fn update_proxy_provider(
    State(clash): State<Arc<Clash>>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    #[cfg(feature = "outbound-provider")]
    {
        let provider = clash.provider(&name)?;
        let dispatcher = clash
            .rm
            .dispatcher()
            .ok_or_else(|| update_failed("the instance is stopping"))?;
        provider.update(&dispatcher).await.map_err(update_failed)?;
        Ok(StatusCode::NO_CONTENT)
    }
    #[cfg(not(feature = "outbound-provider"))]
    {
        let _ = (clash, name);
        Err(ApiError::not_found())
    }
}

/// Measures every member of the provider, ten at a time, keeping their
/// delays, as Mihomo's health check does.
pub(super) async fn health_check(
    State(clash): State<Arc<Clash>>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    #[cfg(feature = "outbound-provider")]
    {
        use futures::StreamExt;
        let provider = clash.provider(&name)?;
        let names: Vec<String> = provider
            .members()
            .load()
            .members
            .iter()
            .map(|m| m.key.name.to_string())
            .collect();
        futures::stream::iter(names)
            .map(|member| {
                let clash = clash.clone();
                let name = name.clone();
                async move {
                    clash
                        .probe_member(
                            &name,
                            &member,
                            crate::app::healthcheck::DEFAULT_URL,
                            HEALTH_CHECK_TIMEOUT,
                        )
                        .await
                }
            })
            .buffer_unordered(10)
            .collect::<Vec<_>>()
            .await;
        Ok(StatusCode::NO_CONTENT)
    }
    #[cfg(not(feature = "outbound-provider"))]
    {
        let _ = (clash, name);
        Err(ApiError::not_found())
    }
}

/// One member of the provider.
pub(super) async fn member(
    State(clash): State<Arc<Clash>>,
    Path((name, proxy)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    #[cfg(feature = "outbound-provider")]
    {
        let provider = clash.provider(&name)?;
        let members = provider.members().load();
        let member = members.find(&proxy).ok_or_else(ApiError::not_found)?;
        clash
            .describe(&proxy, &member.handler, member.kind, false, &HashMap::new())
            .await
            .map(Json)
            .ok_or_else(ApiError::not_found)
    }
    #[cfg(not(feature = "outbound-provider"))]
    {
        let _ = (clash, name, proxy);
        Err(ApiError::not_found())
    }
}

/// Measures one member of the provider, as `/proxies/:name/delay` does.
pub(super) async fn member_delay(
    State(clash): State<Arc<Clash>>,
    Path((name, proxy)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let (url, timeout) = test_params(&params)?;
    #[cfg(feature = "outbound-provider")]
    {
        let delay = clash.probe_member(&name, &proxy, &url, timeout).await?;
        Ok(Json(json!({ "delay": delay.as_millis().max(1) as u64 })))
    }
    #[cfg(not(feature = "outbound-provider"))]
    {
        let _ = (clash, name, proxy, url, timeout);
        Err(ApiError::not_found())
    }
}

/// The rule-sets, by tag, as Mihomo's rule providers.
pub(super) async fn rule_providers(State(clash): State<Arc<Clash>>) -> Json<Value> {
    #[cfg_attr(not(feature = "rule-set"), allow(unused_mut))]
    let mut providers = Map::new();
    #[cfg(feature = "rule-set")]
    for set in clash.rm.router().rule_sets().list() {
        providers.insert(set.tag.clone(), rule_provider(&set));
    }
    #[cfg(not(feature = "rule-set"))]
    let _ = clash;
    Json(json!({ "providers": providers }))
}

#[cfg(feature = "rule-set")]
fn rule_provider(set: &crate::app::router::rule_set::Listed) -> Value {
    use crate::config::rule_set::{ClashBehavior, RuleSetFormat, RuleSetKind};
    json!({
        "name": set.tag,
        "type": "Rule",
        "vehicleType": match set.kind {
            RuleSetKind::Remote => "HTTP",
            RuleSetKind::Local => "File",
            RuleSetKind::Inline => "Inline",
        },
        // sing-box's rule-sets hold rules of every kind.
        "behavior": match set.behavior {
            Some(ClashBehavior::Domain) => "Domain",
            Some(ClashBehavior::Ipcidr) => "IPCIDR",
            Some(ClashBehavior::Classical) | None => "Classical",
        },
        "format": match set.format {
            Some(RuleSetFormat::ClashYaml) => "YamlRule",
            Some(RuleSetFormat::ClashText) => "TextRule",
            Some(RuleSetFormat::Mrs) => "MrsRule",
            Some(RuleSetFormat::Binary) => "Binary",
            Some(RuleSetFormat::Source) | None => "Source",
            #[allow(unreachable_patterns)]
            Some(_) => "Unknown",
        },
        "ruleCount": set.size,
        "updatedAt": time(set.updated),
    })
}

/// Downloads the rule-set again; one not downloaded is left as it is.
pub(super) async fn update_rule_provider(
    State(clash): State<Arc<Clash>>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    #[cfg(feature = "rule-set")]
    {
        let dispatcher = clash
            .rm
            .dispatcher()
            .ok_or_else(|| update_failed("the instance is stopping"))?;
        let router = clash.rm.router();
        match router.rule_sets().update(&name, &dispatcher).await {
            Ok(true) => Ok(StatusCode::NO_CONTENT),
            Ok(false) => Err(ApiError::not_found()),
            Err(e) => Err(update_failed(e)),
        }
    }
    #[cfg(not(feature = "rule-set"))]
    {
        let _ = (clash, name);
        Err(ApiError::not_found())
    }
}
