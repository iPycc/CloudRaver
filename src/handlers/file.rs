use axum::{
    body::Body,
    extract::{Multipart, Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::error::{ApiResponse, AppError, Result};
use crate::models::{CreateDirectoryRequest, CurrentUser, File, FileListResponse, FileQuery, FileResponse, RenameFileRequest};
use crate::services::{FileService, StoragePolicyService};
use crate::AppState;

/// List files in a directory
/// GET /api/v1/files?parent_id=xxx&policy_id=xxx
pub async fn list_files(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<FileQuery>,
) -> Result<Json<ApiResponse<FileListResponse>>> {
    let files = FileService::list_files(&state.db, &current_user.id, query.parent_id, query.policy_id).await?;
    Ok(Json(ApiResponse::success(files)))
}

/// Get a specific file
/// GET /api/v1/files/:id
pub async fn get_file(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<File>>> {
    let file = FileService::get_file(&state.db, &id).await?;

    // Check ownership
    if !current_user.is_admin() && file.user_id != current_user.id {
        return Err(AppError::Forbidden("Access denied".to_string()));
    }

    Ok(Json(ApiResponse::success(file)))
}

/// Create a directory
/// POST /api/v1/files
pub async fn create_directory(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<CreateDirectoryRequest>,
) -> Result<Json<ApiResponse<FileResponse>>> {
    let file = FileService::create_directory(&state.db, &current_user.id, req).await?;
    Ok(Json(ApiResponse::success(file)))
}

/// Upload a file
/// POST /api/v1/files/upload
pub async fn upload_file(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    mut multipart: Multipart,
) -> Result<Json<ApiResponse<FileResponse>>> {
    let mut temp_file_path: Option<PathBuf> = None;
    let mut file_name: Option<String> = None;
    let mut content_type: Option<String> = None;
    let mut parent_id: Option<String> = None;
    let mut policy_id: Option<String> = None;

    // Process multipart fields
    while let Some(mut field) = multipart.next_field().await.map_err(|e| {
        AppError::BadRequest(format!("Failed to process multipart: {}", e))
    })? {
        let name = field.name().unwrap_or("").to_string();

        match name.as_str() {
            "file" => {
                file_name = field.file_name().map(|s| s.to_string());
                content_type = field.content_type().map(|s| s.to_string());

                // Create temp file for streaming upload
                let temp_dir = std::env::temp_dir();
                let temp_path = temp_dir.join(format!("cloudraver_upload_{}", Uuid::new_v4()));
                
                let mut file = tokio::fs::File::create(&temp_path).await.map_err(|e| {
                    AppError::Internal(format!("Failed to create temp file: {}", e))
                })?;

                while let Some(chunk) = field.chunk().await.map_err(|e| {
                    AppError::BadRequest(format!("Failed to read file chunk: {}", e))
                })? {
                    file.write_all(&chunk).await.map_err(|e| {
                        AppError::Internal(format!("Failed to write to temp file: {}", e))
                    })?;
                }
                
                file.flush().await.map_err(|e| {
                    AppError::Internal(format!("Failed to flush temp file: {}", e))
                })?;
                
                temp_file_path = Some(temp_path);
            }
            "parent_id" => {
                let text = field.text().await.unwrap_or_default();
                if !text.is_empty() {
                    parent_id = Some(text);
                }
            }
            "policy_id" => {
                let text = field.text().await.unwrap_or_default();
                if !text.is_empty() {
                    policy_id = Some(text);
                }
            }
            _ => {}
        }
    }

    // Validate file
    let temp_path = temp_file_path.ok_or_else(|| AppError::BadRequest("No file provided".to_string()))?;
    let file_name = file_name.ok_or_else(|| AppError::BadRequest("No file name provided".to_string()))?;

    // Upload file
    let result = FileService::upload_file(
        &state.db,
        &state.storage,
        &current_user.id,
        parent_id,
        policy_id,
        file_name,
        content_type,
        temp_path.clone(),
    )
    .await;

    // Cleanup temp file
    if let Err(e) = tokio::fs::remove_file(&temp_path).await {
        tracing::error!("Failed to remove temp file {:?}: {}", temp_path, e);
    }

    match result {
        Ok(file) => Ok(Json(ApiResponse::success(file))),
        Err(e) => Err(e),
    }
}

/// Download a file
/// GET /api/v1/files/:id/download
pub async fn download_file(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Response> {
    let file = FileService::get_file(&state.db, &id).await?;

    // Check ownership
    if !current_user.is_admin() && file.user_id != current_user.id {
        return Err(AppError::Forbidden("Access denied".to_string()));
    }

    // Cannot download directories
    if file.is_dir {
        return Err(AppError::BadRequest("Cannot download a directory".to_string()));
    }

    // Get file blob
    let blob = FileService::get_file_blob(&state.db, &id).await?;
    let policy = StoragePolicyService::get_policy(&state.db, &blob.policy_id).await?;
    let provider = state.storage.get_provider(&policy)?;

    let data = provider.get(&blob.storage_path).await?;

    let content_type = file
        .mime_type
        .unwrap_or_else(|| "application/octet-stream".to_string());

    let fallback_name = file.name.replace(['"', '\\'], "_");
    let encoded_name = urlencoding::encode(&file.name);

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, data.len())
        .header(
            header::CONTENT_DISPOSITION,
            format!(
                "attachment; filename=\"{}\"; filename*=UTF-8''{}",
                fallback_name, encoded_name
            ),
        )
        .body(Body::from(data))
        .map_err(|e| AppError::Internal(format!("Failed to build response: {}", e)))?;

    Ok(response)
}

/// Rename a file
/// PATCH /api/v1/files/:id
pub async fn rename_file(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
    Json(req): Json<RenameFileRequest>,
) -> Result<Json<ApiResponse<FileResponse>>> {
    let file = FileService::rename_file(
        &state.db,
        &current_user.id,
        &id,
        req.name,
        current_user.is_admin(),
    )
    .await?;
    Ok(Json(ApiResponse::success(file)))
}

/// Delete a file or directory
/// DELETE /api/v1/files/:id
pub async fn delete_file(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse> {
    FileService::delete_file(
        &state.db,
        &state.storage,
        &current_user.id,
        &id,
        current_user.is_admin(),
    )
    .await?;
    Ok(Json(ApiResponse::<()>::success_message("File deleted")))
}
