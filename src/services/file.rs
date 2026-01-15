use chrono::Utc;
use uuid::Uuid;
use std::path::PathBuf;

use crate::db::Database;
use crate::error::{AppError, Result};
use crate::models::{
    CreateDirectoryRequest, File, FileBlob, FileListResponse, FileResponse, PathItem,
    StoragePolicy,
};
use crate::services::StoragePolicyService;
use crate::storage::StorageManager;

/// File service
pub struct FileService;

impl FileService {
    /// List files in a directory, optionally filtered by storage policy
    pub async fn list_files(
        db: &Database,
        user_id: &str,
        parent_id: Option<String>,
        policy_id: Option<String>,
    ) -> Result<FileListResponse> {
        let files: Vec<File> = match (&parent_id, &policy_id) {
            (Some(pid), Some(pol_id)) => {
                // Filter by parent and policy
                sqlx::query_as(
                    "SELECT * FROM files WHERE user_id = ? AND parent_id = ? AND (policy_id = ? OR (is_dir = 1 AND EXISTS (SELECT 1 FROM files AS f WHERE f.parent_id = files.id AND f.policy_id = ?))) ORDER BY is_dir DESC, name ASC",
                )
                .bind(user_id)
                .bind(pid)
                .bind(pol_id)
                .bind(pol_id)
                .fetch_all(db.pool())
                .await?
            }
            (Some(pid), None) => {
                // Filter by parent only
                sqlx::query_as(
                    "SELECT * FROM files WHERE user_id = ? AND parent_id = ? ORDER BY is_dir DESC, name ASC",
                )
                .bind(user_id)
                .bind(pid)
                .fetch_all(db.pool())
                .await?
            }
            (None, Some(pol_id)) => {
                // Filter by policy only (root level)
                sqlx::query_as(
                    "SELECT * FROM files WHERE user_id = ? AND parent_id IS NULL AND (policy_id = ? OR (is_dir = 1 AND EXISTS (SELECT 1 FROM files AS f WHERE f.parent_id = files.id AND f.policy_id = ?))) ORDER BY is_dir DESC, name ASC",
                )
                .bind(user_id)
                .bind(pol_id)
                .bind(pol_id)
                .fetch_all(db.pool())
                .await?
            }
            (None, None) => {
                // No filter
                sqlx::query_as(
                    "SELECT * FROM files WHERE user_id = ? AND parent_id IS NULL ORDER BY is_dir DESC, name ASC",
                )
                .bind(user_id)
                .fetch_all(db.pool())
                .await?
            }
        };

        // Build path (breadcrumb)
        let path = Self::build_path(db, parent_id.as_deref()).await?;

        Ok(FileListResponse {
            files: files.into_iter().map(FileResponse::from).collect(),
            path,
        })
    }

    /// Build breadcrumb path
    async fn build_path(db: &Database, file_id: Option<&str>) -> Result<Vec<PathItem>> {
        let mut path = Vec::new();
        let mut current_id = file_id.map(|s| s.to_string());

        while let Some(id) = current_id {
            let file: Option<File> = sqlx::query_as("SELECT * FROM files WHERE id = ?")
                .bind(&id)
                .fetch_optional(db.pool())
                .await?;

            if let Some(f) = file {
                path.push(PathItem {
                    id: f.id.clone(),
                    name: f.name.clone(),
                });
                current_id = f.parent_id;
            } else {
                break;
            }
        }

        path.reverse();
        Ok(path)
    }

    /// Get a file by ID
    pub async fn get_file(db: &Database, file_id: &str) -> Result<File> {
        let file: File = sqlx::query_as("SELECT * FROM files WHERE id = ?")
            .bind(file_id)
            .fetch_optional(db.pool())
            .await?
            .ok_or_else(|| AppError::NotFound("File not found".to_string()))?;

        Ok(file)
    }

    /// Create a directory
    pub async fn create_directory(
        db: &Database,
        user_id: &str,
        req: CreateDirectoryRequest,
    ) -> Result<FileResponse> {
        // Validate name
        if req.name.is_empty() || req.name.contains('/') || req.name.contains('\\') {
            return Err(AppError::BadRequest("Invalid directory name".to_string()));
        }

        // Check if parent exists and belongs to user
        if let Some(ref parent_id) = req.parent_id {
            let parent = Self::get_file(db, parent_id).await?;
            if parent.user_id != user_id {
                return Err(AppError::Forbidden("Access denied".to_string()));
            }
            if !parent.is_dir {
                return Err(AppError::BadRequest("Parent is not a directory".to_string()));
            }
        }

        // Check if name already exists in parent
        let existing = Self::check_name_exists(db, user_id, req.parent_id.as_deref(), &req.name).await?;
        if existing {
            return Err(AppError::Conflict(
                "A file or directory with this name already exists".to_string(),
            ));
        }

        let file_id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO files (id, user_id, parent_id, name, is_dir, size, policy_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, 1, 0, ?, ?, ?)
            "#,
        )
        .bind(&file_id)
        .bind(user_id)
        .bind(&req.parent_id)
        .bind(&req.name)
        .bind(&req.policy_id)
        .bind(&now)
        .bind(&now)
        .execute(db.pool())
        .await?;

        let file = Self::get_file(db, &file_id).await?;
        Ok(FileResponse::from(file))
    }

    /// Upload a file
    pub async fn upload_file(
        db: &Database,
        storage_manager: &StorageManager,
        user_id: &str,
        parent_id: Option<String>,
        policy_id: Option<String>,
        file_name: String,
        content_type: Option<String>,
        file_path: PathBuf,
    ) -> Result<FileResponse> {
        // Validate file name
        if file_name.is_empty() || file_name.contains('/') || file_name.contains('\\') {
            return Err(AppError::BadRequest("Invalid file name".to_string()));
        }

        // Check parent if specified
        if let Some(ref pid) = parent_id {
            let parent = Self::get_file(db, pid).await?;
            if parent.user_id != user_id {
                return Err(AppError::Forbidden("Access denied".to_string()));
            }
            if !parent.is_dir {
                return Err(AppError::BadRequest("Parent is not a directory".to_string()));
            }
        }

        // Get storage policy
        let policy = Self::get_user_policy(db, user_id, policy_id).await?;

        // Check if file already exists - if so, update it
        let existing_file: Option<File> = if let Some(ref pid) = parent_id {
            sqlx::query_as(
                "SELECT * FROM files WHERE user_id = ? AND parent_id = ? AND name = ? AND is_dir = 0",
            )
            .bind(user_id)
            .bind(pid)
            .bind(&file_name)
            .fetch_optional(db.pool())
            .await?
        } else {
            sqlx::query_as(
                "SELECT * FROM files WHERE user_id = ? AND parent_id IS NULL AND name = ? AND is_dir = 0",
            )
            .bind(user_id)
            .bind(&file_name)
            .fetch_optional(db.pool())
            .await?
        };

        // Get file size from metadata
        let metadata = tokio::fs::metadata(&file_path).await.map_err(|e| {
             AppError::BadRequest(format!("Failed to read file metadata: {}", e))
        })?;
        let file_size = metadata.len() as i64;
        
        let now = Utc::now().to_rfc3339();

        let file_id = if let Some(existing) = existing_file {
            // Update existing file
            sqlx::query("UPDATE files SET size = ?, policy_id = ?, mime_type = ?, updated_at = ? WHERE id = ?")
                .bind(file_size)
                .bind(&policy.id)
                .bind(&content_type)
                .bind(&now)
                .bind(&existing.id)
                .execute(db.pool())
                .await?;

            // Delete old blobs (they will be orphaned)
            sqlx::query("DELETE FROM file_blobs WHERE file_id = ?")
                .bind(&existing.id)
                .execute(db.pool())
                .await?;

            existing.id
        } else {
            // Create new file
            let new_id = Uuid::new_v4().to_string();
            sqlx::query(
                r#"
                INSERT INTO files (id, user_id, parent_id, name, is_dir, size, policy_id, mime_type, created_at, updated_at)
                VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(&new_id)
            .bind(user_id)
            .bind(&parent_id)
            .bind(&file_name)
            .bind(file_size)
            .bind(&policy.id)
            .bind(&content_type)
            .bind(&now)
            .bind(&now)
            .execute(db.pool())
            .await?;

            new_id
        };

        // Create blob and upload to storage
        let blob_id = Uuid::new_v4().to_string();
        
        // Build storage path using breadcrumb (original structure)
        // Format: {user_id}/{folder}/{subfolder}/{filename}
        let path_items = Self::build_path(db, parent_id.as_deref()).await?;
        let mut path_parts = Vec::new();
        path_parts.push(user_id.to_string());
        for item in path_items {
            path_parts.push(item.name);
        }
        path_parts.push(file_name.clone());
        let storage_path = path_parts.join("/");

        // Upload to storage
        let provider = storage_manager.get_provider(&policy)?;
        provider.put_file(&storage_path, &file_path).await?;

        // Create blob record
        sqlx::query(
            r#"
            INSERT INTO file_blobs (id, file_id, policy_id, storage_path, size, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&blob_id)
        .bind(&file_id)
        .bind(&policy.id)
        .bind(&storage_path)
        .bind(file_size)
        .bind(&now)
        .execute(db.pool())
        .await?;

        // Update user storage usage
        crate::services::user::UserService::update_storage_used(db, user_id, file_size).await?;

        let file = Self::get_file(db, &file_id).await?;
        Ok(FileResponse::from(file))
    }

    /// Get file blob for download
    pub async fn get_file_blob(db: &Database, file_id: &str) -> Result<FileBlob> {
        let blob: FileBlob = sqlx::query_as(
            "SELECT * FROM file_blobs WHERE file_id = ? ORDER BY created_at DESC LIMIT 1",
        )
        .bind(file_id)
        .fetch_optional(db.pool())
        .await?
        .ok_or_else(|| AppError::NotFound("File blob not found".to_string()))?;

        Ok(blob)
    }

    /// Rename a file
    pub async fn rename_file(
        db: &Database,
        user_id: &str,
        file_id: &str,
        new_name: String,
        is_admin: bool,
    ) -> Result<FileResponse> {
        let file = Self::get_file(db, file_id).await?;

        // Check ownership
        if !is_admin && file.user_id != user_id {
            return Err(AppError::Forbidden("Access denied".to_string()));
        }

        // Validate name
        if new_name.is_empty() || new_name.contains('/') || new_name.contains('\\') {
            return Err(AppError::BadRequest("Invalid name".to_string()));
        }

        // Check if name already exists in same directory
        let existing = Self::check_name_exists(db, &file.user_id, file.parent_id.as_deref(), &new_name).await?;
        if existing {
            return Err(AppError::Conflict(
                "A file or directory with this name already exists".to_string(),
            ));
        }

        let now = Utc::now().to_rfc3339();
        sqlx::query("UPDATE files SET name = ?, updated_at = ? WHERE id = ?")
            .bind(&new_name)
            .bind(&now)
            .bind(file_id)
            .execute(db.pool())
            .await?;

        let updated = Self::get_file(db, file_id).await?;
        Ok(FileResponse::from(updated))
    }

    /// Delete a file or directory
    pub async fn delete_file(
        db: &Database,
        storage_manager: &StorageManager,
        user_id: &str,
        file_id: &str,
        is_admin: bool,
    ) -> Result<()> {
        let file = Self::get_file(db, file_id).await?;

        // Check ownership
        if !is_admin && file.user_id != user_id {
            return Err(AppError::Forbidden("Access denied".to_string()));
        }

        // Delete from storage and database
        Self::delete_file_recursive(db, storage_manager, &file).await?;

        Ok(())
    }

    /// Recursively delete file and its children
    fn delete_file_recursive<'a>(
        db: &'a Database,
        storage_manager: &'a StorageManager,
        file: &'a File,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<i64>> + Send + 'a>> {
        Box::pin(async move {
            let mut total_size: i64 = 0;

            if file.is_dir {
                // Get all children
                let children: Vec<File> =
                    sqlx::query_as("SELECT * FROM files WHERE parent_id = ?")
                        .bind(&file.id)
                        .fetch_all(db.pool())
                        .await?;

                // Delete children recursively
                for child in children {
                    total_size += Self::delete_file_recursive(db, storage_manager, &child).await?;
                }
            } else {
                // Get blobs and delete from storage
                let blobs: Vec<FileBlob> =
                    sqlx::query_as("SELECT * FROM file_blobs WHERE file_id = ?")
                        .bind(&file.id)
                        .fetch_all(db.pool())
                        .await?;

                for blob in blobs {
                    let policy = StoragePolicyService::get_policy(db, &blob.policy_id).await?;
                    if let Ok(provider) = storage_manager.get_provider(&policy) {
                        let _ = provider.delete(&blob.storage_path).await;
                    }
                    total_size += blob.size;
                }
            }

            // Delete file record (cascades to blobs)
            sqlx::query("DELETE FROM files WHERE id = ?")
                .bind(&file.id)
                .execute(db.pool())
                .await?;

            // Update user storage
            if total_size > 0 {
                crate::services::user::UserService::update_storage_used(db, &file.user_id, -total_size).await?;
            }

            Ok(total_size)
        })
    }

    /// Check if a name exists in a directory
    async fn check_name_exists(
        db: &Database,
        user_id: &str,
        parent_id: Option<&str>,
        name: &str,
    ) -> Result<bool> {
        let count: (i64,) = if let Some(pid) = parent_id {
            sqlx::query_as(
                "SELECT COUNT(*) FROM files WHERE user_id = ? AND parent_id = ? AND name = ?",
            )
            .bind(user_id)
            .bind(pid)
            .bind(name)
            .fetch_one(db.pool())
            .await?
        } else {
            sqlx::query_as(
                "SELECT COUNT(*) FROM files WHERE user_id = ? AND parent_id IS NULL AND name = ?",
            )
            .bind(user_id)
            .bind(name)
            .fetch_one(db.pool())
            .await?
        };

        Ok(count.0 > 0)
    }

    /// Get user's storage policy (specified or default)
    async fn get_user_policy(
        db: &Database,
        user_id: &str,
        policy_id: Option<String>,
    ) -> Result<StoragePolicy> {
        if let Some(pid) = policy_id {
            let policy = StoragePolicyService::get_policy(db, &pid).await?;
            if policy.user_id != user_id {
                return Err(AppError::Forbidden(
                    "Storage policy does not belong to user".to_string(),
                ));
            }
            return Ok(policy);
        }

        // Get default policy
        let policy: StoragePolicy = sqlx::query_as(
            "SELECT * FROM storage_policies WHERE user_id = ? AND is_default = 1",
        )
        .bind(user_id)
        .fetch_optional(db.pool())
        .await?
        .ok_or_else(|| {
            AppError::BadRequest("No storage policy configured. Please add a storage policy first.".to_string())
        })?;

        Ok(policy)
    }
}
