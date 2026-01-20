#[cfg(feature = "embed-frontend")]
use axum::{
    body::Body,
    extract::Path,
    http::{header, HeaderValue, Response, StatusCode},
};
#[cfg(feature = "embed-frontend")]
use mime_guess::MimeGuess;

#[cfg(feature = "embed-frontend")]
use include_dir::{include_dir, Dir};

#[cfg(feature = "embed-frontend")]
static FRONTEND_DIST: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/../frontend/dist");

#[cfg(feature = "embed-frontend")]
fn cache_control_for(path: &str) -> HeaderValue {
    if path == "index.html" {
        HeaderValue::from_static("no-store")
    } else if path.starts_with("assets/") {
        HeaderValue::from_static("public, max-age=31536000, immutable")
    } else {
        HeaderValue::from_static("public, max-age=3600")
    }
}

#[cfg(feature = "embed-frontend")]
fn build_response(path: &str, bytes: &[u8]) -> Response<Body> {
    let mime = MimeGuess::from_path(path).first_or_octet_stream();
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime.as_ref())
        .header(header::CACHE_CONTROL, cache_control_for(path))
        .body(Body::from(bytes.to_vec()))
        .unwrap()
}

#[cfg(feature = "embed-frontend")]
fn not_found() -> Response<Body> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::empty())
        .unwrap()
}

#[cfg(feature = "embed-frontend")]
pub async fn spa_handler(Path(path): Path<String>) -> Response<Body> {
    let req_path = path.trim_start_matches('/').to_string();
    let req_path = if req_path.is_empty() { "index.html".to_string() } else { req_path };

    if let Some(file) = FRONTEND_DIST.get_file(&req_path) {
        return build_response(&req_path, file.contents());
    }

    if req_path.contains('.') {
        return not_found();
    }

    let index = FRONTEND_DIST.get_file("index.html");
    match index {
        Some(file) => build_response("index.html", file.contents()),
        None => not_found(),
    }
}

#[cfg(feature = "embed-frontend")]
pub async fn spa_root_handler() -> Response<Body> {
    let index = FRONTEND_DIST.get_file("index.html");
    match index {
        Some(file) => build_response("index.html", file.contents()),
        None => not_found(),
    }
}

#[cfg(not(feature = "embed-frontend"))]
pub fn spa_service(
) -> tower_http::services::ServeDir<tower_http::set_status::SetStatus<tower_http::services::ServeFile>> {
    use std::path::PathBuf;
    use tower_http::services::{ServeDir, ServeFile};

    let dist = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../frontend/dist");
    let index = dist.join("index.html");
    ServeDir::new(dist).not_found_service(ServeFile::new(index))
}
