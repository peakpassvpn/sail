//! `/ui/`: a dashboard's files, from `external_ui`, as Mihomo and sing-box
//! serve them, without the secret (the dashboard asks for it).

use std::path::{Component, Path as FsPath, PathBuf};
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};

use super::{ApiError, Clash};

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
