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

/// `frames`, over the WebSocket asked for, or as JSON lines; either ends
/// when the instance stops, or the client goes.
pub(super) fn send<S>(ws: Option<WebSocketUpgrade>, frames: S) -> Response
where
    S: Stream<Item = Value> + Send + 'static,
{
    let frames = scoped(frames);
    match ws {
        Some(ws) => ws
            .on_upgrade(|mut socket| async move {
                let mut frames = std::pin::pin!(frames);
                loop {
                    // A client that closes is seen while no frame comes.
                    let frame = tokio::select! {
                        frame = frames.next() => frame,
                        message = socket.recv() => match message {
                            Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                            Some(Ok(_)) => continue,
                        },
                    };
                    let Some(frame) = frame else { break };
                    let text = format!("{}\n", frame);
                    if socket.send(Message::Text(text)).await.is_err() {
                        return;
                    }
                }
                // The frames ended, with the instance: said, not dropped.
                let _ = socket.send(Message::Close(None)).await;
            })
            .into_response(),
        None => (
            [(header::CONTENT_TYPE, "application/json")],
            Body::from_stream(frames.map(|frame| Ok::<_, Infallible>(format!("{}\n", frame)))),
        )
            .into_response(),
    }
}

/// `frames`, made by a task of the instance's scope: what reads them is
/// not the scope's (the task axum spawns for a WebSocket, a connection's
/// for a streamed body), so they end when the instance stops, which aborts
/// that task, and the task ends when the client goes.
fn scoped<S>(frames: S) -> impl Stream<Item = Value> + Send + 'static
where
    S: Stream<Item = Value> + Send + 'static,
{
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    crate::runtime::scope::spawn("clash api stream", async move {
        let mut frames = std::pin::pin!(frames);
        loop {
            let frame = tokio::select! {
                () = tx.closed() => return,
                frame = frames.next() => frame,
            };
            let Some(frame) = frame else { return };
            if tx.send(frame).await.is_err() {
                return;
            }
        }
    });
    futures::stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|f| (f, rx)) })
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
    let totals = |t: crate::control::Traffic| (t.up_total, t.down_total);
    let first = totals(clash.rm.traffic().await);
    let frames = ticks()
        .then(move |()| {
            let clash = clash.clone();
            async move { totals(clash.rm.traffic().await) }
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
            crate::control::resident_memory()
        };
        json!({ "inuse": inuse, "oslimit": 0 })
    });
    send(ws, frames)
}

/// The log lines at `?level=` (`info` when unset) and above, as they are
/// logged: `{"type": level, "payload": line}`.
pub(super) async fn logs(
    State(clash): State<Arc<Clash>>,
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
    // Those logged from now on, as Mihomo sends them: none kept before.
    let Some(log) = clash.rm.logs() else {
        return Ok(send(ws, futures::stream::pending()));
    };
    let (_, lines) = log.follow();
    let frames = futures::stream::unfold(lines, move |mut lines| async move {
        use crate::app::logger::LogEvent;
        loop {
            match lines.recv().await {
                // A lower level is more verbose.
                Ok(LogEvent::Line(line)) if line.level <= least => {
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
