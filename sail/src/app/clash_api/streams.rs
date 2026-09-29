//! `/traffic`, `/memory` and `/logs`: what dashboards follow, as Mihomo
//! sends it, over a WebSocket, or, to a plain request, as a stream of JSON
//! lines.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::ws::{Message, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use futures::{Stream, StreamExt};
use serde_json::{json, Value};

use super::{ApiError, Clash};

/// `frames`, over the WebSocket asked for, or as JSON lines.
fn send<S>(ws: Option<WebSocketUpgrade>, frames: S) -> Response
where
    S: Stream<Item = Value> + Send + 'static,
{
    match ws {
        Some(ws) => ws
            .on_upgrade(|mut socket| async move {
                let mut frames = std::pin::pin!(frames);
                while let Some(frame) = frames.next().await {
                    let text = format!("{}\n", frame);
                    if socket.send(Message::Text(text)).await.is_err() {
                        break;
                    }
                }
            })
            .into_response(),
        None => (
            [(header::CONTENT_TYPE, "application/json")],
            Body::from_stream(frames.map(|frame| Ok::<_, Infallible>(format!("{}\n", frame)))),
        )
            .into_response(),
    }
}

/// Every second.
fn ticks() -> impl Stream<Item = ()> + Send {
    futures::stream::unfold(
        tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_secs(1),
            Duration::from_secs(1),
        ),
        |mut interval| async move {
            interval.tick().await;
            Some(((), interval))
        },
    )
}

/// What was sent and received each second, and in all.
pub(super) async fn traffic(
    State(clash): State<Arc<Clash>>,
    ws: Option<WebSocketUpgrade>,
) -> Response {
    let stats = clash.rm.stat_manager();
    let first = stats.read().await.totals();
    let frames = ticks()
        .then(move |()| {
            let stats = stats.clone();
            async move { stats.read().await.totals() }
        })
        .scan(first, |last, (up, down)| {
            let (up0, down0) = std::mem::replace(last, (up, down));
            futures::future::ready(Some(json!({
                "up": up.saturating_sub(up0),
                "down": down.saturating_sub(down0),
                "upTotal": up,
                "downTotal": down,
            })))
        });
    send(ws, frames)
}

/// The memory in use, every second; the first 0, as Mihomo and sing-box
/// send it, for the charts that take their scale from it.
pub(super) async fn memory(ws: Option<WebSocketUpgrade>) -> Response {
    let mut first = true;
    let frames = ticks().map(move |()| {
        let inuse = if std::mem::take(&mut first) {
            0
        } else {
            resident_memory()
        };
        json!({ "inuse": inuse, "oslimit": 0 })
    });
    send(ws, frames)
}

/// The process's resident memory, in bytes; 0 where it is not known.
fn resident_memory() -> u64 {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let pages = std::fs::read_to_string("/proc/self/statm")
            .ok()
            .and_then(|s| s.split_whitespace().nth(1)?.parse::<u64>().ok())
            .unwrap_or(0);
        // SAFETY: sysconf only reads a constant.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        pages * page.max(0) as u64
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
        // SAFETY: `info` is as large as the call is told it is.
        let read = unsafe {
            libc::proc_pidinfo(
                libc::getpid(),
                libc::PROC_PIDTASKINFO,
                0,
                &mut info as *mut _ as *mut libc::c_void,
                size,
            )
        };
        if read == size {
            info.pti_resident_size
        } else {
            0
        }
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    )))]
    {
        0
    }
}

/// The log lines at `?level=` (`info` when unset) and above, as they are
/// logged: `{"type": level, "payload": line}`.
pub(super) async fn logs(
    Query(params): Query<HashMap<String, String>>,
    ws: Option<WebSocketUpgrade>,
) -> Result<Response, ApiError> {
    use tracing::Level;
    let least = match params.get("level").map(String::as_str).unwrap_or("info") {
        "debug" | "trace" => Level::DEBUG,
        "info" => Level::INFO,
        "warning" | "warn" => Level::WARN,
        "error" | "fatal" | "panic" => Level::ERROR,
        "silent" => {
            return Ok(send(ws, futures::stream::pending()));
        }
        _ => return Err(ApiError::bad_request("Body invalid")),
    };
    let lines = crate::app::logger::follow();
    let frames = futures::stream::unfold(lines, move |mut lines| async move {
        loop {
            match lines.recv().await {
                // A lower level is more verbose.
                Ok(line) if line.level <= least => {
                    let kind = match line.level {
                        Level::ERROR => "error",
                        Level::WARN => "warning",
                        Level::INFO => "info",
                        _ => "debug",
                    };
                    let frame = json!({ "type": kind, "payload": line.message });
                    return Some((frame, lines));
                }
                Ok(_) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    Ok(send(ws, frames))
}
