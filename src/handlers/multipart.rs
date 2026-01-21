use axum::{
    extract::{Json, State},
    Extension,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use chrono::Utc;

use crate::error::{ApiResponse, AppError, Result};
use crate::models::{CurrentUser, PolicyType, StoragePolicy, File};
use crate::services::{MultipartService, StoragePolicyService};
// use crate::services::FileService;
use crate::AppState;

#[derive(Deserialize)]
pub struct InitMultipartRequest {
    pub path: String,
    pub filename: String,
    // pub size: i64,
    // pub parent_id: Option<String>,
    pub policy_id: Option<String>,
    pub mime_type: Option<String>,
}

#[derive(Serialize)]
pub struct InitMultipartResponse {
    pub upload_id: String,
    pub key: String,
    pub chunk_size: u64,
    pub policy_id: String,
}

#[derive(Deserialize)]
pub struct SignPartRequest {
    pub key: String,
    pub upload_id: String,
    pub part_number: u64,
    pub policy_id: String,
}

#[derive(Serialize)]
pub struct SignPartResponse {
    pub url: String,
    pub authorization: String,
}

#[derive(Deserialize)]
pub struct AbortMultipartRequest {
    pub key: String,
    pub upload_id: String,
    pub policy_id: String,
}

#[derive(Deserialize)]
pub struct PartInfo {
    pub part_number: u64,
    pub etag: String,
}

#[derive(Deserialize)]
pub struct CompleteMultipartRequest {
    pub key: String,
    pub upload_id: String,
    pub parts: Vec<PartInfo>,
    pub parent_id: Option<String>,
    pub filename: String,
    pub size: u64,
    pub mime_type: Option<String>,
    pub policy_id: String,
}

pub async fn init_multipart(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<InitMultipartRequest>,
) -> Result<Json<ApiResponse<InitMultipartResponse>>> {
    // 1. Get Policy
    let policy = if let Some(pid) = req.policy_id {
        StoragePolicyService::get_policy(&state.db, &pid).await?
    } else {
        // Find default
         sqlx::query_as::<_, StoragePolicy>("SELECT * FROM storage_policies WHERE user_id = ? AND is_default = 1")
            .bind(&current_user.id)
            .fetch_optional(state.db.pool())
            .await?
            .ok_or_else(|| AppError::BadRequest("未设置默认存储策略".to_string()))?
    };
    
    // Check if COS
    let config = match policy.get_type() {
        Some(PolicyType::Cos) => {
             serde_json::from_str::<crate::models::CosStorageConfig>(&policy.config)
                .map_err(|e| AppError::Internal(format!("Invalid COS config: {}", e)))?
        },
        _ => return Err(AppError::BadRequest("分片上传仅支持 COS 存储策略".to_string())),
    };
    
    // Generate Key: /{user_id}/{path}/{filename}
    // Cloudreve typically uses UUIDs, but user requested original filenames.
    // We will use the provided path structure.
    let path = req.path.trim().trim_matches('/');
    let key = if path.is_empty() {
        format!("{}/{}", current_user.id, req.filename)
    } else {
        format!("{}/{}/{}", current_user.id, path, req.filename)
    };
    
    // Initiate
    let upload_id = MultipartService::initiate_multipart(&config, &key, req.mime_type).await?;
    
    Ok(Json(ApiResponse::success(InitMultipartResponse {
        upload_id,
        key,
        chunk_size: 524288000, // 500MB as requested
        policy_id: policy.id,
    })))
}

pub async fn sign_part(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<SignPartRequest>,
) -> Result<Json<ApiResponse<SignPartResponse>>> {
    let policy = StoragePolicyService::get_policy(&state.db, &req.policy_id).await?;
    if policy.user_id != current_user.id { return Err(AppError::Forbidden("无权限访问该存储策略".to_string())); }
    
    let config = match policy.get_type() {
        Some(PolicyType::Cos) => serde_json::from_str::<crate::models::CosStorageConfig>(&policy.config)
            .map_err(|e| AppError::Internal(format!("COS 配置解析失败: {}", e)))?,
        _ => return Err(AppError::BadRequest("仅 COS 支持该操作".to_string())),
    };
    
    let (url, authorization) = MultipartService::sign_part(&config, &req.key, &req.upload_id, req.part_number)?;
    
    Ok(Json(ApiResponse::success(SignPartResponse {
        url,
        authorization,
    })))
}

pub async fn complete_multipart(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<CompleteMultipartRequest>,
) -> Result<Json<ApiResponse<()>>> {
     let policy = StoragePolicyService::get_policy(&state.db, &req.policy_id).await?;
    if policy.user_id != current_user.id { return Err(AppError::Forbidden("无权限访问该存储策略".to_string())); }
    
    let config = match policy.get_type() {
        Some(PolicyType::Cos) => serde_json::from_str::<crate::models::CosStorageConfig>(&policy.config)
            .map_err(|e| AppError::Internal(format!("COS 配置解析失败: {}", e)))?,
        _ => return Err(AppError::BadRequest("仅 COS 支持该操作".to_string())),
    };
    
    let mut etags = HashMap::new();
    for p in req.parts {
        etags.insert(p.part_number, p.etag);
    }
    
    // Complete in COS
    MultipartService::complete_multipart(&config, &req.key, &req.upload_id, etags).await?;
    
    // Save to DB
    let now = Utc::now().to_rfc3339();
    
    // Check if file exists
    let existing_file: Option<File> = if let Some(ref pid) = req.parent_id {
        sqlx::query_as(
            "SELECT * FROM files WHERE user_id = ? AND parent_id = ? AND name = ? AND is_dir = 0",
        )
        .bind(&current_user.id)
        .bind(pid)
        .bind(&req.filename)
        .fetch_optional(state.db.pool())
        .await?
    } else {
        sqlx::query_as(
            "SELECT * FROM files WHERE user_id = ? AND parent_id IS NULL AND name = ? AND is_dir = 0",
        )
        .bind(&current_user.id)
        .bind(&req.filename)
        .fetch_optional(state.db.pool())
        .await?
    };

    let file_id = if let Some(existing) = existing_file {
        // Update existing
        sqlx::query("UPDATE files SET size = ?, policy_id = ?, mime_type = ?, updated_at = ? WHERE id = ?")
            .bind(req.size as i64)
            .bind(&policy.id)
            .bind(&req.mime_type)
            .bind(&now)
            .bind(&existing.id)
            .execute(state.db.pool())
            .await?;
            
        // Delete old blobs
        sqlx::query("DELETE FROM file_blobs WHERE file_id = ?")
            .bind(&existing.id)
            .execute(state.db.pool())
            .await?;
            
        existing.id
    } else {
        // Create new
        let new_id = Uuid::new_v4().to_string();
        sqlx::query(
            r#"
            INSERT INTO files (id, user_id, parent_id, name, is_dir, size, policy_id, mime_type, created_at, updated_at)
            VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&new_id)
        .bind(&current_user.id)
        .bind(&req.parent_id)
        .bind(&req.filename)
        .bind(req.size as i64)
        .bind(&policy.id)
        .bind(&req.mime_type)
        .bind(&now)
        .bind(&now)
        .execute(state.db.pool())
        .await?;
        
        new_id
    };
    
    // Create Blob
    let blob_id = Uuid::new_v4().to_string();
    sqlx::query(
        r#"
        INSERT INTO file_blobs (id, file_id, policy_id, storage_path, size, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&blob_id)
    .bind(&file_id)
    .bind(&policy.id)
    .bind(&req.key) // Use the key as storage path (original path)
    .bind(req.size as i64)
    .bind(&now)
    .execute(state.db.pool())
    .await?;
    
    // Update user storage
    crate::services::user::UserService::update_storage_used(&state.db, &current_user.id, req.size as i64).await?;
    
    Ok(Json(ApiResponse::success(())))
}

pub async fn abort_multipart(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<AbortMultipartRequest>,
) -> Result<Json<ApiResponse<()>>> {
    let policy = StoragePolicyService::get_policy(&state.db, &req.policy_id).await?;
    if policy.user_id != current_user.id {
        return Err(AppError::Forbidden("无权限访问该存储策略".to_string()));
    }

    let config = match policy.get_type() {
        Some(PolicyType::Cos) => serde_json::from_str::<crate::models::CosStorageConfig>(&policy.config)
            .map_err(|e| AppError::Internal(format!("COS 配置解析失败: {}", e)))?,
        _ => return Err(AppError::BadRequest("仅 COS 支持该操作".to_string())),
    };

    MultipartService::abort_multipart(&config, &req.key, &req.upload_id).await?;
    Ok(Json(ApiResponse::success(())))
}
