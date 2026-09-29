//! `/ui/`: a dashboard's files, from `external_ui`, as Mihomo and sing-box
//! serve them, without the secret (the dashboard asks for it).

use std::path::{Component, Path as FsPath, PathBuf};
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};

use super::{ApiError, Clash};
#[cfg(feature = "http-client")]
use tracing::warn;

pub(super) async fn redirect() -> Redirect {
    Redirect::permanent("/ui/")
}

pub(super) async fn file(State(clash): State<Arc<Clash>>, path: Option<Path<String>>) -> Response {
    let Some(root) = &clash.ui else {
        return ApiError::not_found().into_response();
    };
    let wanted = path.map(|Path(p)| p).unwrap_or_default();
    let Some(file) = resolve(root, &wanted) else {
        return ApiError::not_found().into_response();
    };
    match tokio::task::spawn_blocking(move || std::fs::read(&file).map(|body| (file, body)))
        .await
        .unwrap_or_else(|e| Err(std::io::Error::other(e)))
    {
        Ok((file, body)) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, content_type(&file))],
            body,
        )
            .into_response(),
        Err(_) => ApiError::not_found().into_response(),
    }
}

/// The file `wanted` names under `root`: its `index.html` for a
/// directory; none for a path leaving `root`.
fn resolve(root: &FsPath, wanted: &str) -> Option<PathBuf> {
    let mut file = root.to_path_buf();
    for part in FsPath::new(wanted.trim_start_matches('/')).components() {
        match part {
            Component::Normal(part) => file.push(part),
            Component::CurDir => {}
            _ => return None,
        }
    }
    if file.is_dir() {
        file.push("index.html");
    }
    Some(file)
}

fn content_type(file: &FsPath) -> &'static str {
    match file
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
    {
        "html" | "htm" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json",
        "webmanifest" => "application/manifest+json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "txt" => "text/plain; charset=utf-8",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}

/// How long the dashboard's download may take, and how large it may be:
/// metacubexd's ZIP is some 5 MiB.
#[cfg(feature = "http-client")]
const DOWNLOAD: crate::app::http::Limits = crate::app::http::Limits {
    timeout: std::time::Duration::from_secs(120),
    max_body: 64 << 20,
};

/// Whether `root` has nothing to serve: missing, or empty.
#[cfg(feature = "http-client")]
fn is_empty(root: &FsPath) -> bool {
    std::fs::read_dir(root).map_or(true, |mut entries| entries.next().is_none())
}

/// Downloads the dashboard into an `external_ui` with nothing in it, as
/// sing-box does at start.
#[cfg(feature = "http-client")]
pub(super) async fn download_if_empty(clash: &Clash) {
    let Some(root) = &clash.ui else {
        return;
    };
    if !is_empty(root) {
        return;
    }
    if clash.ui_url.is_none() {
        warn!(
            "clash_api: external_ui {} is empty, and no dashboard is downloaded into it: \
             external_ui_download_url is unset",
            root.display()
        );
        return;
    }
    if let Err(e) = download(clash).await {
        warn!("clash_api: dashboard not downloaded: {:#}", e);
    }
}

/// Downloads the dashboard, a ZIP, and puts its files in place of those in
/// `external_ui`, all at once.
#[cfg(feature = "http-client")]
pub(super) async fn download(clash: &Clash) -> anyhow::Result<()> {
    use crate::app::http;
    use anyhow::anyhow;

    let _one = clash.ui_downloading.lock().await;
    let root = clash
        .ui
        .clone()
        .ok_or_else(|| anyhow!("external_ui is unset"))?;
    let url = clash
        .ui_url
        .as_deref()
        .ok_or_else(|| anyhow!("external_ui_download_url is unset"))?;
    let dispatcher = clash
        .rm
        .dispatcher()
        .ok_or_else(|| anyhow!("the instance is stopping"))?;
    let via = http::Via::Outbound(match &clash.ui_detour {
        Some(detour) => detour.clone(),
        None => dispatcher
            .default_outbound()
            .ok_or_else(|| anyhow!("no outbound to download through"))?,
    });
    let conn = http::Conn {
        dispatcher: Some(&dispatcher),
        dns: dispatcher.dns_client(),
        env: dispatcher.env(),
    };
    let data = match http::get_with(&conn, &via, &[], url, None, DOWNLOAD).await? {
        http::Response::Body { data, .. } => data,
        http::Response::NotModified => return Err(anyhow!("304 Not Modified, unasked")),
    };
    let files = super::zip::files(&data)?;
    if !files.iter().any(|(p, _)| p == FsPath::new("index.html")) {
        return Err(anyhow!("no index.html in the archive"));
    }
    let count = files.len();
    let placed = root.clone();
    tokio::task::spawn_blocking(move || place(&placed, files))
        .await
        .map_err(|e| anyhow!("{}", e))??;
    tracing::info!(
        "clash_api: dashboard downloaded into {}, {} files",
        root.display(),
        count
    );
    Ok(())
}

/// Writes `files` beside `root`, then puts them in its place.
#[cfg(feature = "http-client")]
fn place(root: &FsPath, files: Vec<(PathBuf, Vec<u8>)>) -> anyhow::Result<()> {
    use anyhow::Context;
    let name = root
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("{}: not a directory", root.display()))?
        .to_string_lossy();
    let fresh = root.with_file_name(format!(".{}.new", name));
    let old = root.with_file_name(format!(".{}.old", name));
    let _ = std::fs::remove_dir_all(&fresh);
    let _ = std::fs::remove_dir_all(&old);
    for (path, body) in files {
        let path = fresh.join(path);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| dir.display().to_string())?;
        }
        std::fs::write(&path, body).with_context(|| path.display().to_string())?;
    }
    if root.exists() {
        std::fs::rename(root, &old).with_context(|| root.display().to_string())?;
    }
    std::fs::rename(&fresh, root).with_context(|| root.display().to_string())?;
    let _ = std::fs::remove_dir_all(&old);
    Ok(())
}

/// Mihomo's `/upgrade/ui`: downloads the dashboard again.
pub(super) async fn upgrade(State(clash): State<Arc<Clash>>) -> Result<StatusCode, ApiError> {
    #[cfg(feature = "http-client")]
    {
        download(&clash)
            .await
            .map(|()| StatusCode::NO_CONTENT)
            .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("{:#}", e)))
    }
    #[cfg(not(feature = "http-client"))]
    {
        let _ = clash;
        Err(ApiError::bad_request(
            "not downloaded: sail is built without the http-client feature",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_stays_under_the_root() {
        let root = FsPath::new("/srv/ui");
        assert_eq!(
            resolve(root, "assets/app.js"),
            Some(PathBuf::from("/srv/ui/assets/app.js"))
        );
        assert_eq!(resolve(root, "../etc/passwd"), None);
        assert_eq!(resolve(root, "a/../../b"), None);
    }
}
