use axum::{
    body::Body,
    extract::{Multipart, Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};

use crate::error::{ApiResponse, Result};
use crate::models::{ChangePasswordRequest, CurrentUser, UserResponse};
use crate::services::{AuthService, UserService};
use crate::services::user::StorageUsageResponse;
use crate::AppState;
use serde::Deserialize;
use bytes::BytesMut;
use rand::{distributions::Alphanumeric, Rng};
use std::path::PathBuf;
use tokio::fs;

/// Get current user profile
/// GET /api/v1/user/profile
pub async fn get_profile(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<ApiResponse<UserResponse>>> {
    let profile = UserService::get_profile(&state.db, &current_user.id).await?;
    Ok(Json(ApiResponse::success(profile)))
}

/// Change password
/// PUT /api/v1/user/password
pub async fn change_password(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<impl IntoResponse> {
    AuthService::change_password(
        &state.db,
        &current_user.id,
        &req.old_password,
        &req.new_password,
    )
    .await?;

    Ok(Json(ApiResponse::<()>::success_message(
        "Password changed successfully",
    )))
}

/// Get storage usage
/// GET /api/v1/user/storage
pub async fn get_storage_usage(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<StorageUsageQuery>,
) -> Result<Json<ApiResponse<StorageUsageResponse>>> {
    let usage = UserService::get_storage_usage(&state.db, &current_user.id, query.policy_id.as_deref())
        .await?;
    Ok(Json(ApiResponse::success(usage)))
}

#[derive(Debug, Deserialize)]
pub struct StorageUsageQuery {
    pub policy_id: Option<String>,
}

/// Upload avatar
/// POST /api/v1/user/avatar
pub async fn upload_avatar(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    mut multipart: Multipart,
) -> Result<Json<ApiResponse<UserResponse>>> {
    let mut file_data: Option<BytesMut> = None;
    let mut file_name: Option<String> = None;
    let mut content_type: Option<String> = None;

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        crate::error::AppError::BadRequest(format!("Failed to process multipart: {}", e))
    })? {
        let name = field.name().unwrap_or("").to_string();
        if name.as_str() != "file" {
            continue;
        }

        file_name = field.file_name().map(|s| s.to_string());
        content_type = field.content_type().map(|s| s.to_string());

        let data = field.bytes().await.map_err(|e| {
            crate::error::AppError::BadRequest(format!("Failed to read file: {}", e))
        })?;

        let mut buf = BytesMut::with_capacity(data.len());
        buf.extend_from_slice(&data);
        file_data = Some(buf);
    }

    let file_data = file_data.ok_or_else(|| crate::error::AppError::BadRequest("No file provided".to_string()))?;
    let file_name = file_name.unwrap_or_else(|| "avatar".to_string());
    let mime = content_type.unwrap_or_else(|| "application/octet-stream".to_string());

    let extension = std::path::Path::new(&file_name)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("bin");

    let key: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(6)
        .map(char::from)
        .collect::<String>()
        .to_lowercase();

    let file_basename = format!("{}.{}", key, extension);
    let mut avatar_dir = PathBuf::from(&state.config.storage.local_path).join("avatar");
    avatar_dir.push(&current_user.id);
    
    fs::create_dir_all(&avatar_dir).await.map_err(|e| {
        crate::error::AppError::Internal(format!("Failed to create avatar directory: {}", e))
    })?;
    
    let file_path = avatar_dir.join(&file_basename);

    fs::write(&file_path, file_data.freeze())
        .await
        .map_err(|e| crate::error::AppError::Internal(format!("Failed to write avatar: {}", e)))?;

    let db_path = format!("{}/{}", current_user.id, file_basename);

    sqlx::query("UPDATE users SET avatar_key = ?, avatar_path = ?, avatar_mime = ?, updated_at = datetime('now') WHERE id = ?")
        .bind(&key)
        .bind(&db_path)
        .bind(&mime)
        .bind(&current_user.id)
        .execute(state.db.pool())
        .await?;

    let profile = UserService::get_profile(&state.db, &current_user.id).await?;
    Ok(Json(ApiResponse::success(profile)))
}

/// Get avatar by short key (public)
/// GET /api/v1/a/:key
pub async fn get_avatar_by_key(
    State(state): State<AppState>,
    Path(key): Path<String>,
) -> Result<Response> {
    let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT avatar_path, avatar_mime FROM users WHERE avatar_key = ?",
    )
    .bind(&key)
    .fetch_optional(state.db.pool())
    .await?;

    let (avatar_path, avatar_mime) = row
        .ok_or_else(|| crate::error::AppError::NotFound("Avatar not found".to_string()))?;

    let avatar_path = avatar_path
        .ok_or_else(|| crate::error::AppError::NotFound("Avatar not found".to_string()))?;

    let bytes = fs::read(PathBuf::from(&state.config.storage.local_path).join("avatar").join(&avatar_path))
        .await
        .map_err(|_| crate::error::AppError::NotFound("Avatar not found".to_string()))?;

    let content_type = avatar_mime.unwrap_or_else(|| "application/octet-stream".to_string());

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "public, max-age=3600")
        .body(Body::from(bytes))
        .map_err(|e| crate::error::AppError::Internal(format!("Failed to build response: {}", e)))?;

    Ok(response)
}
