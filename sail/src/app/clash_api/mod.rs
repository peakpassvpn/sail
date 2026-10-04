//! The Clash API, as Mihomo serves it, which dashboards (yacd, metacubexd)
//! and clients control an instance through: its outbounds and groups, the
//! mode rules match, traffic, logs, DNS. Its shapes are Mihomo's, of
//! which sing-box's are a part; its configuration is sing-box's
//! `clash_api`.
//!
//! It is served only with a strong secret (see
//! [`crate::generate::weak_secret`]), which every call carries, as
//! `Authorization: Bearer`, or a WebSocket's `?token=`; without one, or
//! with a weak one, the instance runs without it, and says why.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde_json::json;
use tracing::{info, warn};

use crate::config::model::ClashApi;
use crate::RuntimeManager;

mod configs;
mod connections;
mod dns;
mod providers;
mod proxies;
mod streams;
mod ui;
#[cfg(feature = "http-client")]
mod zip;

pub(crate) use configs::ConfigView;

/// The listener for `api`, bound now so that an address in use fails the
/// start; none when it is not to be served: no `external_controller`, or
/// no strong secret, which is warned of.
pub(crate) fn bind(api: Option<&ClashApi>) -> Result<Option<(std::net::TcpListener, ClashApi)>> {
    let Some(api) = api else { return Ok(None) };
    let Some(controller) = api.external_controller.as_deref().filter(|c| !c.is_empty()) else {
        return Ok(None);
    };
    let secret = api.secret.as_deref().unwrap_or_default();
    if let Some(why) = crate::generate::weak_secret(secret) {
        warn!(
            "clash_api: not served at {}: the secret is {}; set clash_api.secret to what \
             `sail generate secret` makes",
            controller,
            if secret.is_empty() {
                "not set".to_string()
            } else {
                format!("too weak ({})", why)
            }
        );
        return Ok(None);
    }
    let addr = listen_address(controller)?;
    let listener = crate::net::listen_tcp(&addr)
        .map_err(|e| anyhow!("clash_api.external_controller: {}: {}", controller, e))?;
    Ok(Some((listener, api.clone())))
}

/// `host:port`, an empty host every address, as Mihomo takes it.
fn listen_address(controller: &str) -> Result<SocketAddr> {
    let bad = || {
        anyhow!(
            "clash_api.external_controller: \"{}\" is not host:port",
            controller
        )
    };
    if let Ok(addr) = controller.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let (host, port) = controller.rsplit_once(':').ok_or_else(bad)?;
    let port: u16 = port.parse().map_err(|_| bad())?;
    match host {
        "" | "*" => Ok(SocketAddr::from(([0, 0, 0, 0], port))),
        "localhost" => Ok(SocketAddr::from(([127, 0, 0, 1], port))),
        _ => Err(bad()),
    }
}

/// What the handlers share.
pub(crate) struct Clash {
    rm: Arc<RuntimeManager>,
    secret: String,
    /// The origins browsers may call from; any when empty.
    origins: Vec<String>,
    private_network: bool,
    ui: Option<PathBuf>,
    /// Where the dashboard is downloaded from: the configuration's URL, or
    /// the host's.
    #[cfg_attr(not(feature = "http-client"), allow(dead_code))]
    ui_url: Option<String>,
    /// The outbound it is downloaded through; the default one when unset.
    #[cfg_attr(not(feature = "http-client"), allow(dead_code))]
    ui_detour: Option<String>,
    /// One download at a time.
    #[cfg_attr(not(feature = "http-client"), allow(dead_code))]
    ui_downloading: tokio::sync::Mutex<()>,
}

/// Serves the API on `listener` until the instance stops.
pub(crate) fn serve(
    listener: std::net::TcpListener,
    api: &ClashApi,
    rm: Arc<RuntimeManager>,
) -> std::io::Result<crate::Runner> {
    let ui = api
        .external_ui
        .as_deref()
        .filter(|p| !p.is_empty())
        .map(|p| PathBuf::from(rm.env().data_path(p)));
    let scope = rm.env().scope.clone();
    let clash = Arc::new(Clash {
        secret: api.secret.clone().unwrap_or_default(),
        origins: api.access_control_allow_origin.clone(),
        private_network: api.access_control_allow_private_network,
        ui_url: api
            .external_ui_download_url
            .clone()
            .or_else(|| rm.env().host.ui_download_url.clone())
            .filter(|u| !u.is_empty()),
        ui_detour: api.external_ui_download_detour.clone(),
        ui_downloading: Default::default(),
        ui,
        rm,
    });
    let addr = listener.local_addr()?;
    listener.set_nonblocking(true)?;
    let listener = tokio::net::TcpListener::from_std(listener)?;
    // axum spawns each connection on a task of its own, which carries no
    // scope: each request runs in the instance's, so that what a handler
    // spawns is the instance's (E2). The connections themselves end with
    // the runtime.
    let app =
        router(clash.clone()).layer(middleware::from_fn(move |request: Request, next: Next| {
            scope.enter(next.run(request))
        }));
    info!("clash_api: serving on {}", addr);
    Ok(Box::pin(async move {
        #[cfg(feature = "http-client")]
        crate::runtime::scope::spawn("clash ui download", async move {
            ui::download_if_empty(&clash).await
        });
        #[cfg(not(feature = "http-client"))]
        drop(clash);
        if let Err(e) = axum::serve(listener, app).await {
            warn!("clash_api: {}", e);
        }
    }))
}

fn router(clash: Arc<Clash>) -> Router {
    let api = Router::new()
        .route("/", get(hello))
        .route("/version", get(configs::version))
        .route(
            "/configs",
            get(configs::get_configs)
                .patch(configs::patch_configs)
                .put(configs::put_configs),
        )
        .route("/proxies", get(proxies::list))
        .route(
            "/proxies/:name",
            get(proxies::one)
                .put(proxies::select)
                .delete(proxies::unfix),
        )
        .route("/proxies/:name/delay", get(proxies::delay))
        .route("/group", get(proxies::groups))
        .route("/group/:name", get(proxies::group))
        .route("/group/:name/delay", get(proxies::group_delay))
        .route("/providers/proxies", get(providers::proxy_providers))
        .route(
            "/providers/proxies/:name",
            get(providers::proxy_provider).put(providers::update_proxy_provider),
        )
        .route(
            "/providers/proxies/:name/healthcheck",
            get(providers::health_check),
        )
        .route("/providers/proxies/:name/:proxy", get(providers::member))
        .route(
            "/providers/proxies/:name/:proxy/healthcheck",
            get(providers::member_delay),
        )
        .route("/providers/rules", get(providers::rule_providers))
        .route(
            "/providers/rules/:name",
            axum::routing::put(providers::update_rule_provider),
        )
        .route(
            "/connections",
            get(connections::list).delete(connections::close_all),
        )
        .route("/connections/:id", delete(connections::close))
        .route("/rules", get(connections::rules))
        .route("/traffic", get(streams::traffic))
        .route("/memory", get(streams::memory))
        .route("/logs", get(streams::logs))
        .route("/dns/query", get(dns::query))
        .route("/cache/fakeip/flush", post(dns::flush_fake_ips))
        .route("/cache/dns/flush", post(dns::flush_dns))
        .route("/upgrade/ui", post(ui::upgrade))
        .route_layer(middleware::from_fn_with_state(clash.clone(), auth));
    Router::new()
        .route("/ui", get(ui::redirect))
        .route("/ui/", get(ui::file))
        .route("/ui/*path", get(ui::file))
        .merge(api)
        .fallback(not_found)
        .layer(middleware::from_fn_with_state(clash.clone(), cors))
        .with_state(clash)
}

async fn hello() -> Json<serde_json::Value> {
    Json(json!({ "hello": "clash" }))
}

async fn not_found() -> ApiError {
    ApiError::not_found()
}

/// Every call carries the secret: `Authorization: Bearer`, or, opening a
/// WebSocket, which browsers cannot give headers, `?token=`.
async fn auth(State(clash): State<Arc<Clash>>, req: Request, next: Next) -> Response {
    let websocket = req
        .headers()
        .get(header::UPGRADE)
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"));
    let token = websocket
        .then(|| query_value(req.uri().query().unwrap_or_default(), "token"))
        .flatten();
    let given = match token {
        Some(token) => Some(token),
        None => req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::to_owned),
    };
    let ok = given.is_some_and(|given| {
        given.len() == clash.secret.len()
            && given
                .bytes()
                .zip(clash.secret.bytes())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0
    });
    if !ok {
        return ApiError(StatusCode::UNAUTHORIZED, "Unauthorized".into()).into_response();
    }
    next.run(req).await
}

/// `name`'s value in the query string `query`, percent-decoded.
fn query_value(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        (key == name).then(|| percent_decode(value))
    })
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let decoded = (bytes[i] == b'%' && i + 2 < bytes.len())
            .then(|| std::str::from_utf8(&bytes[i + 1..i + 3]).ok())
            .flatten()
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        match decoded {
            Some(b) => {
                out.push(b);
                i += 3;
            }
            None => {
                out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Cross-origin calls, as Mihomo and sing-box answer them: the origins
/// allowed, the methods and headers dashboards use, and Private Network
/// Access when allowed. Preflights are answered here, before the secret
/// is asked for.
async fn cors(State(clash): State<Arc<Clash>>, req: Request, next: Next) -> Response {
    let origin = req.headers().get(header::ORIGIN).cloned();
    let preflight = req.method() == Method::OPTIONS
        && req
            .headers()
            .contains_key(header::ACCESS_CONTROL_REQUEST_METHOD);
    let private = req
        .headers()
        .get("access-control-request-private-network")
        .is_some_and(|v| v == "true");
    let mut response = if preflight {
        StatusCode::NO_CONTENT.into_response()
    } else {
        next.run(req).await
    };
    if let Some(origin) = origin {
        allow(&clash, &origin, preflight, private, response.headers_mut());
    }
    response
}

fn allow(clash: &Clash, origin: &HeaderValue, preflight: bool, private: bool, h: &mut HeaderMap) {
    let allowed = clash.origins.is_empty()
        || clash
            .origins
            .iter()
            .any(|o| o == "*" || origin.to_str().is_ok_and(|origin| origin == o));
    if !allowed {
        return;
    }
    h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.clone());
    h.insert(header::VARY, HeaderValue::from_static("Origin"));
    if preflight {
        h.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, POST, PUT, PATCH, DELETE"),
        );
        h.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("Content-Type, Authorization"),
        );
        h.insert(
            header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static("300"),
        );
        if private && clash.private_network {
            h.insert(
                "access-control-allow-private-network",
                HeaderValue::from_static("true"),
            );
        }
    }
}

/// An error, as Mihomo answers one: `{"message": ...}`.
pub(crate) struct ApiError(StatusCode, String);

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        ApiError(StatusCode::BAD_REQUEST, message.into())
    }

    fn not_found() -> Self {
        ApiError(StatusCode::NOT_FOUND, "Resource not found".into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "message": self.1 }))).into_response()
    }
}

#[cfg(test)]
mod tests;
