use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Extension, Json,
};

use crate::error::{ApiResponse, AppError, Result};
use crate::models::{
    CreateStoragePolicyRequest, CurrentUser, StoragePolicyListResponse, 
    StoragePolicyResponse, UpdateStoragePolicyRequest, PolicyType, CosStorageConfig,
};
use crate::services::StoragePolicyService;
use crate::storage::cos::bucket::BucketOperations;
use crate::AppState;

/// List storage policies for current user
/// GET /api/v1/storage/policies
pub async fn list_policies(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<ApiResponse<StoragePolicyListResponse>>> {
    let policies = StoragePolicyService::list_policies(&state.db, &current_user.id).await?;
    Ok(Json(ApiResponse::success(StoragePolicyListResponse {
        policies,
    })))
}

/// Get a specific storage policy
/// GET /api/v1/storage/policies/:id
pub async fn get_policy(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<StoragePolicyResponse>>> {
    let policy = StoragePolicyService::get_policy(&state.db, &id).await?;

    // Check ownership (unless admin)
    if !current_user.is_admin() && policy.user_id != current_user.id {
        return Err(AppError::Forbidden("Access denied".to_string()));
    }

    Ok(Json(ApiResponse::success(policy.to_response())))
}

/// Validate storage policy configuration
/// POST /api/v1/storage/policies/validate
pub async fn validate_policy(
    Json(req): Json<CreateStoragePolicyRequest>,
) -> Result<impl IntoResponse> {
    if req.policy_type == "cos" {
        let config: CosStorageConfig = serde_json::from_value(req.config.clone())
            .map_err(|_| AppError::BadRequest("Invalid COS configuration".to_string()))?;

        let client = crate::storage::cos::client::Client::new(
            &config.secret_id,
            &config.secret_key,
            &config.bucket,
            &config.region,
        );

        let res = client.bucket_exists().await;
        if !res {
            return Err(AppError::Storage("Bucket does not exist or is not accessible".to_string()));
        }
    }
    
    Ok(Json(ApiResponse::<()>::success_message("Validation successful")))
}

/// Validate storage policy configuration (old version kept for compatibility)
async fn _validate_policy_old(
    Json(req): Json<CreateStoragePolicyRequest>,
) -> Result<impl IntoResponse> {
    if req.policy_type == "cos" {
        let config: CosStorageConfig = serde_json::from_value(req.config.clone())
            .map_err(|_| AppError::BadRequest("Invalid COS configuration".to_string()))?;

        let client = crate::storage::cos::client::Client::new(
            &config.secret_id,
            &config.secret_key,
            &config.bucket,
            &config.region,
        );

        let res = client.get_bucket_info().await;
        if res.error_no != crate::storage::cos::request::ErrNo::SUCCESS {
            return Err(AppError::Storage(format!(
                "Validation failed: [{}] {}",
                res.error_no, res.error_message
            )));
        }
    }
    
    Ok(Json(ApiResponse::<()>::success_message("Validation successful")))
}

/// Create a new storage policy
/// POST /api/v1/storage/policies
pub async fn create_policy(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<CreateStoragePolicyRequest>,
) -> Result<Json<ApiResponse<StoragePolicyResponse>>> {
    let policy =
        StoragePolicyService::create_policy(&state.db, &current_user.id, req).await?;
    Ok(Json(ApiResponse::success(policy)))
}

/// Update a storage policy
/// PUT /api/v1/storage/policies/:id
pub async fn update_policy(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
    Json(req): Json<UpdateStoragePolicyRequest>,
) -> Result<Json<ApiResponse<StoragePolicyResponse>>> {
    let policy = StoragePolicyService::update_policy(
        &state.db,
        &current_user.id,
        &id,
        req,
        current_user.is_admin(),
    )
    .await?;
    Ok(Json(ApiResponse::success(policy)))
}

/// Delete a storage policy
/// DELETE /api/v1/storage/policies/:id
pub async fn delete_policy(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse> {
    StoragePolicyService::delete_policy(
        &state.db,
        &current_user.id,
        &id,
        current_user.is_admin(),
    )
    .await?;
    Ok(Json(ApiResponse::<()>::success_message(
        "Storage policy deleted",
    )))
}

/// Set a policy as default
/// PUT /api/v1/storage/policies/:id/default
pub async fn set_default_policy(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<StoragePolicyResponse>>> {
    let policy =
        StoragePolicyService::set_default_policy(&state.db, &current_user.id, &id).await?;
    Ok(Json(ApiResponse::success(policy)))
}

/// Configure CORS for COS bucket
/// POST /api/v1/storage/policies/:id/cors
pub async fn configure_cors(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse> {
    let policy = StoragePolicyService::get_policy(&state.db, &id).await?;

    // Check ownership
    if !current_user.is_admin() && policy.user_id != current_user.id {
        return Err(AppError::Forbidden("Access denied".to_string()));
    }

    if policy.get_type() != Some(PolicyType::Cos) {
         return Err(AppError::BadRequest("Only COS policies support CORS configuration".to_string()));
    }

    let config: CosStorageConfig = serde_json::from_str(&policy.config)
        .map_err(|_| AppError::Internal("Invalid policy configuration".to_string()))?;

    let client = crate::storage::cos::client::Client::new(
        &config.secret_id,
        &config.secret_key,
        &config.bucket,
        &config.region,
    );

    let cors_config = crate::storage::cos::cors::CorsConfig::default_permissive();
    let res = client.put_bucket_cors(&cors_config).await;
    
    if res.error_no != crate::storage::cos::request::ErrNo::SUCCESS {
        let raw = String::from_utf8_lossy(&res.result).to_string();
        let code = raw
            .split("<Code>")
            .nth(1)
            .and_then(|s| s.split("</Code>").next())
            .map(|s| s.trim().to_string());
        let message = raw
            .split("<Message>")
            .nth(1)
            .and_then(|s| s.split("</Message>").next())
            .map(|s| s.trim().to_string());
        let detail = match (code, message) {
            (Some(c), Some(m)) => format!("{c}: {m}"),
            _ if !raw.is_empty() => raw,
            _ => res.error_message.clone(),
        };

        if res.error_message.starts_with("400") {
            return Err(AppError::BadRequest(format!("Failed to configure CORS: {}", detail)));
        }
        if res.error_message.starts_with("403") {
            return Err(AppError::Forbidden(format!("Failed to configure CORS: {}", detail)));
        }

        return Err(AppError::Storage(format!("Failed to configure CORS: {}", detail)));
    }

    Ok(Json(ApiResponse::<()>::success_message("CORS configured successfully")))
}
