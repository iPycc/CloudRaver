use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, StatusCode},
    response::Response,
    Extension, Json,
};

use crate::error::{ApiResponse, AppError, Result};
use crate::models::{CreateShareRequest, CurrentUser, PublicShareInfo, Share, ShareListItem, VerifyShareRequest};
use crate::services::{FileService, ShareService, StoragePolicyService};
use crate::AppState;

/// Create a new share
/// POST /api/v1/shares
pub async fn create_share(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<CreateShareRequest>,
) -> Result<Json<ApiResponse<Share>>> {
    let share = ShareService::create_share(&state.db, &current_user.id, req).await?;
    Ok(Json(ApiResponse::success(share)))
}

/// List user's shares
/// GET /api/v1/shares/my
pub async fn list_my_shares(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<ApiResponse<Vec<ShareListItem>>>> {
    let shares = ShareService::list_user_share_items(&state.db, &current_user.id).await?;
    Ok(Json(ApiResponse::success(shares)))
}

/// Delete a share
/// DELETE /api/v1/shares/:id
pub async fn delete_share(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<()>>> {
    ShareService::delete_share(&state.db, &current_user.id, &id).await?;
    Ok(Json(ApiResponse::<()>::success_message("Share deleted")))
}

/// Get public share info
/// GET /api/v1/public/share/:token
pub async fn get_public_share(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<Json<ApiResponse<PublicShareInfo>>> {
    let info = ShareService::get_public_share_info(&state.db, &token).await?;
    Ok(Json(ApiResponse::success(info)))
}

/// Verify password and download/preview
/// POST /api/v1/public/share/:token/verify
pub async fn verify_share(
    State(state): State<AppState>,
    Path(token): Path<String>,
    Json(req): Json<VerifyShareRequest>,
) -> Result<Response> {
    let (_share, file) = ShareService::verify_share_access(&state.db, &token, Some(req.password)).await?;
    
    // Get file blob and provider (similar to download_file)
    let blob = FileService::get_file_blob(&state.db, &file.id).await?;
    let policy = StoragePolicyService::get_policy(&state.db, &blob.policy_id).await?;
    let provider = state.storage.get_provider(&policy)?;

    // Proxy the file content directly (avoids CORS issues with redirects)
    let data = provider.get(&blob.storage_path).await?;

    let content_type = file
        .mime_type
        .unwrap_or_else(|| "application/octet-stream".to_string());

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, data.len())
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", file.name),
        )
        .body(Body::from(data))
        .map_err(|e| AppError::Internal(format!("Failed to build response: {}", e)))?;

    Ok(response)
}

/// Download public share (no password required version)
/// GET /api/v1/public/share/:token/download
pub async fn download_public_share(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<Response> {
    let (share, file) = ShareService::verify_share_access(&state.db, &token, None).await?;
    
    if share.password_hash.is_some() {
        return Err(AppError::Forbidden("Password required".to_string()));
    }

    // Get file blob and provider
    let blob = FileService::get_file_blob(&state.db, &file.id).await?;
    let policy = StoragePolicyService::get_policy(&state.db, &blob.policy_id).await?;
    let provider = state.storage.get_provider(&policy)?;

    // Proxy the file content directly (avoids CORS issues with redirects)
    let data = provider.get(&blob.storage_path).await?;
    
    let content_type = file
        .mime_type
        .unwrap_or_else(|| "application/octet-stream".to_string());

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, data.len())
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", file.name),
        )
        .body(Body::from(data))
        .map_err(|e| AppError::Internal(format!("Failed to build response: {}", e)))?;

    Ok(response)
}
