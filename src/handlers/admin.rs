use axum::{
    extract::{Path, State},
    Extension, Json,
};
use serde::Deserialize;

use crate::error::{ApiResponse, AppError, Result};
use crate::models::{CurrentUser, FileListResponse, StoragePolicyResponse, UserResponse};
use crate::services::{FileService, StoragePolicyService, UserService};
use crate::AppState;

/// Check if user is admin
fn require_admin(user: &CurrentUser) -> Result<()> {
    if !user.is_admin() {
        return Err(AppError::Forbidden(
            "Admin access required".to_string(),
        ));
    }
    Ok(())
}

/// List all users
/// GET /api/v1/admin/users
pub async fn list_users(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<ApiResponse<Vec<UserResponse>>>> {
    require_admin(&current_user)?;
    let users = UserService::list_users(&state.db).await?;
    Ok(Json(ApiResponse::success(users)))
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserStatusRequest {
    pub is_active: bool,
}

/// Update user status (enable/disable)
/// PUT /api/v1/admin/users/:id/status
pub async fn update_user_status(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
    Json(req): Json<UpdateUserStatusRequest>,
) -> Result<Json<ApiResponse<UserResponse>>> {
    require_admin(&current_user)?;

    // Cannot disable yourself
    if id == current_user.id {
        return Err(AppError::BadRequest(
            "Cannot change your own status".to_string(),
        ));
    }

    let user = UserService::update_user_status(&state.db, &id, req.is_active).await?;
    Ok(Json(ApiResponse::success(user)))
}

/// Get a user's files (admin access)
/// GET /api/v1/admin/users/:id/files
pub async fn get_user_files(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<FileListResponse>>> {
    require_admin(&current_user)?;

    let files = FileService::list_files(&state.db, &id, None, None).await?;
    Ok(Json(ApiResponse::success(files)))
}

/// Get a user's storage policies (admin access)
/// GET /api/v1/admin/users/:id/policies
pub async fn get_user_policies(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<Vec<StoragePolicyResponse>>>> {
    require_admin(&current_user)?;

    let policies = StoragePolicyService::list_policies(&state.db, &id).await?;
    Ok(Json(ApiResponse::success(policies)))
}

