use chrono::Utc;
use uuid::Uuid;
use std::path::PathBuf;

use crate::db::Database;
use crate::error::{AppError, Result};
use crate::models::{
    CreateDirectoryRequest, File, FileBlob, FileListResponse, FileResponse, PathItem,
    StoragePolicy, TrashItem,
};
use crate::services::StoragePolicyService;
use crate::storage::StorageManager;

/// File service
pub struct FileService;

impl FileService {
    /// List files in a directory, optionally filtered by storage policy
    /// Supports both parent_id and path-based queries
    pub async fn list_files(
        db: &Database,
        user_id: &str,
        parent_id: Option<String>,
        policy_id: Option<String>,
        path: Option<String>,
    ) -> Result<FileListResponse> {
        // Resolve path to parent_id if path is provided
        let resolved_parent_id = if let Some(ref p) = path {
            Self::resolve_path_to_id(db, user_id, p).await?
        } else {
            parent_id
        };

        let files: Vec<File> = match (&resolved_parent_id, &policy_id) {
            (Some(pid), Some(pol_id)) => {
                // Filter by parent and policy
                sqlx::query_as(
                    "SELECT * FROM files WHERE user_id = ? AND parent_id = ? AND deleted_at IS NULL AND (policy_id = ? OR (is_dir = 1 AND EXISTS (SELECT 1 FROM files AS f WHERE f.parent_id = files.id AND f.policy_id = ?))) ORDER BY is_dir DESC, name ASC",
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
                    "SELECT * FROM files WHERE user_id = ? AND parent_id = ? AND deleted_at IS NULL ORDER BY is_dir DESC, name ASC",
                )
                .bind(user_id)
                .bind(pid)
                .fetch_all(db.pool())
                .await?
            }
            (None, Some(pol_id)) => {
                // Filter by policy only (root level)
                sqlx::query_as(
                    "SELECT * FROM files WHERE user_id = ? AND parent_id IS NULL AND deleted_at IS NULL AND (policy_id = ? OR (is_dir = 1 AND EXISTS (SELECT 1 FROM files AS f WHERE f.parent_id = files.id AND f.policy_id = ?))) ORDER BY is_dir DESC, name ASC",
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
                    "SELECT * FROM files WHERE user_id = ? AND parent_id IS NULL AND deleted_at IS NULL ORDER BY is_dir DESC, name ASC",
                )
                .bind(user_id)
                .fetch_all(db.pool())
                .await?
            }
        };

        // Build path (breadcrumb)
        let path = Self::build_path(db, resolved_parent_id.as_deref()).await?;

        Ok(FileListResponse {
            files: files.into_iter().map(FileResponse::from).collect(),
            path,
        })
    }

    /// Resolve a path string to folder ID
    /// Path format: "/Documents/Projects" or "Documents/Projects"
    pub async fn resolve_path_to_id(
        db: &Database,
        user_id: &str,
        path: &str,
    ) -> Result<Option<String>> {
        // Normalize path: remove leading/trailing slashes, handle empty path
        let normalized = path.trim_matches('/');
        if normalized.is_empty() {
            return Ok(None); // Root directory
        }

        let parts: Vec<&str> = normalized.split('/').collect();
        let mut current_parent_id: Option<String> = None;

        for part in parts {
            if part.is_empty() {
                continue;
            }

            // Find folder with this name under current parent
            let folder: Option<File> = if let Some(ref pid) = current_parent_id {
                sqlx::query_as(
                    "SELECT * FROM files WHERE user_id = ? AND parent_id = ? AND name = ? AND is_dir = 1 AND deleted_at IS NULL",
                )
                .bind(user_id)
                .bind(pid)
                .bind(part)
                .fetch_optional(db.pool())
                .await?
            } else {
                sqlx::query_as(
                    "SELECT * FROM files WHERE user_id = ? AND parent_id IS NULL AND name = ? AND is_dir = 1 AND deleted_at IS NULL",
                )
                .bind(user_id)
                .bind(part)
                .fetch_optional(db.pool())
                .await?
            };

            match folder {
                Some(f) => {
                    current_parent_id = Some(f.id);
                }
                None => {
                    return Err(AppError::NotFound(format!(
                        "Folder not found: {}",
                        part
                    )));
                }
            }
        }

        Ok(current_parent_id)
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

        // Check if file already exists - if so, update it (excluding deleted files)
        let existing_file: Option<File> = if let Some(ref pid) = parent_id {
            sqlx::query_as(
                "SELECT * FROM files WHERE user_id = ? AND parent_id = ? AND name = ? AND is_dir = 0 AND deleted_at IS NULL",
            )
            .bind(user_id)
            .bind(pid)
            .bind(&file_name)
            .fetch_optional(db.pool())
            .await?
        } else {
            sqlx::query_as(
                "SELECT * FROM files WHERE user_id = ? AND parent_id IS NULL AND name = ? AND is_dir = 0 AND deleted_at IS NULL",
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

    /// Delete a file or directory (soft delete - move to trash)
    pub async fn delete_file(
        db: &Database,
        _storage_manager: &StorageManager,
        user_id: &str,
        file_id: &str,
        is_admin: bool,
    ) -> Result<()> {
        let file = Self::get_file(db, file_id).await?;

        // Check ownership
        if !is_admin && file.user_id != user_id {
            return Err(AppError::Forbidden("Access denied".to_string()));
        }

        // Soft delete - move to trash
        Self::move_to_trash(db, &file).await?;

        Ok(())
    }

    /// Move a file/directory to trash (soft delete)
    async fn move_to_trash(db: &Database, file: &File) -> Result<()> {
        let now = Utc::now().to_rfc3339();

        // Store original parent_id and set deleted_at
        sqlx::query(
            "UPDATE files SET deleted_at = ?, original_parent_id = parent_id, parent_id = NULL WHERE id = ?",
        )
        .bind(&now)
        .bind(&file.id)
        .execute(db.pool())
        .await?;

        // If it's a directory, recursively mark children as deleted
        if file.is_dir {
            Self::mark_children_deleted(db, &file.id, &now).await?;
        }

        Ok(())
    }

    /// Recursively mark children as deleted
    fn mark_children_deleted<'a>(
        db: &'a Database,
        parent_id: &'a str,
        deleted_at: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let children: Vec<File> =
                sqlx::query_as("SELECT * FROM files WHERE parent_id = ? AND deleted_at IS NULL")
                    .bind(parent_id)
                    .fetch_all(db.pool())
                    .await?;

            for child in children {
                // Mark child as deleted (keep parent_id for structure, don't set original_parent_id for children)
                sqlx::query("UPDATE files SET deleted_at = ? WHERE id = ?")
                    .bind(deleted_at)
                    .bind(&child.id)
                    .execute(db.pool())
                    .await?;

                if child.is_dir {
                    Self::mark_children_deleted(db, &child.id, deleted_at).await?;
                }
            }

            Ok(())
        })
    }

    /// Permanently delete a file or directory (used by trash operations)
    pub async fn permanent_delete(
        db: &Database,
        storage_manager: &StorageManager,
        file: &File,
    ) -> Result<i64> {
        Self::delete_file_recursive(db, storage_manager, file).await
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

    /// Check if a name exists in a directory (excluding deleted files)
    async fn check_name_exists(
        db: &Database,
        user_id: &str,
        parent_id: Option<&str>,
        name: &str,
    ) -> Result<bool> {
        let count: (i64,) = if let Some(pid) = parent_id {
            sqlx::query_as(
                "SELECT COUNT(*) FROM files WHERE user_id = ? AND parent_id = ? AND name = ? AND deleted_at IS NULL",
            )
            .bind(user_id)
            .bind(pid)
            .bind(name)
            .fetch_one(db.pool())
            .await?
        } else {
            sqlx::query_as(
                "SELECT COUNT(*) FROM files WHERE user_id = ? AND parent_id IS NULL AND name = ? AND deleted_at IS NULL",
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

    // ==================== Trash Operations ====================

    /// List items in trash for a user
    pub async fn list_trash(db: &Database, user_id: &str) -> Result<Vec<TrashItem>> {
        // Get top-level deleted items (those with original_parent_id set, meaning they were directly deleted)
        let files: Vec<File> = sqlx::query_as(
            "SELECT * FROM files WHERE user_id = ? AND deleted_at IS NOT NULL AND original_parent_id IS NOT NULL ORDER BY deleted_at DESC",
        )
        .bind(user_id)
        .fetch_all(db.pool())
        .await?;

        // Also get items where original_parent_id is explicitly set (root items moved to trash)
        let root_files: Vec<File> = sqlx::query_as(
            "SELECT * FROM files WHERE user_id = ? AND deleted_at IS NOT NULL AND parent_id IS NULL ORDER BY deleted_at DESC",
        )
        .bind(user_id)
        .fetch_all(db.pool())
        .await?;

        // Combine and deduplicate
        let mut all_files = files;
        for f in root_files {
            if !all_files.iter().any(|x| x.id == f.id) {
                all_files.push(f);
            }
        }

        let mut items = Vec::new();
        for file in all_files {
            // Build original path
            let original_path = Self::build_original_path(db, file.original_parent_id.as_deref()).await?;

            items.push(TrashItem {
                id: file.id,
                name: file.name,
                is_dir: file.is_dir,
                size: file.size,
                mime_type: file.mime_type,
                deleted_at: file.deleted_at.unwrap_or_default(),
                original_parent_id: file.original_parent_id,
                original_path,
            });
        }

        Ok(items)
    }

    /// Build original path from parent_id
    async fn build_original_path(db: &Database, parent_id: Option<&str>) -> Result<String> {
        if parent_id.is_none() {
            return Ok("/".to_string());
        }

        let mut path_parts = Vec::new();
        let mut current_id = parent_id.map(|s| s.to_string());

        while let Some(id) = current_id {
            let file: Option<File> = sqlx::query_as("SELECT * FROM files WHERE id = ?")
                .bind(&id)
                .fetch_optional(db.pool())
                .await?;

            if let Some(f) = file {
                path_parts.push(f.name.clone());
                // Use original_parent_id if available (for deleted items), otherwise parent_id
                current_id = f.original_parent_id.or(f.parent_id);
            } else {
                break;
            }
        }

        path_parts.reverse();
        if path_parts.is_empty() {
            Ok("/".to_string())
        } else {
            Ok(format!("/{}", path_parts.join("/")))
        }
    }

    /// Restore items from trash
    pub async fn restore_from_trash(
        db: &Database,
        user_id: &str,
        file_ids: &[String],
    ) -> Result<()> {
        for file_id in file_ids {
            let file = Self::get_file(db, file_id).await?;

            // Check ownership
            if file.user_id != user_id {
                return Err(AppError::Forbidden("Access denied".to_string()));
            }

            // Check if file is in trash
            if file.deleted_at.is_none() {
                return Err(AppError::BadRequest("File is not in trash".to_string()));
            }

            // Restore the file
            Self::restore_file(db, &file).await?;
        }

        Ok(())
    }

    /// Restore a single file from trash
    async fn restore_file(db: &Database, file: &File) -> Result<()> {
        let now = Utc::now().to_rfc3339();

        // Check if original parent still exists and is not deleted
        let can_restore_to_original = if let Some(ref original_parent_id) = file.original_parent_id {
            let parent: Option<File> = sqlx::query_as(
                "SELECT * FROM files WHERE id = ? AND deleted_at IS NULL",
            )
            .bind(original_parent_id)
            .fetch_optional(db.pool())
            .await?;
            parent.is_some()
        } else {
            true // Root level, always can restore
        };

        let restore_parent_id = if can_restore_to_original {
            file.original_parent_id.clone()
        } else {
            None // Restore to root if original parent is gone
        };

        // Check for name conflict at restore location
        let name_exists = Self::check_name_exists(
            db,
            &file.user_id,
            restore_parent_id.as_deref(),
            &file.name,
        )
        .await?;

        let final_name = if name_exists {
            // Generate unique name
            Self::generate_unique_name(db, &file.user_id, restore_parent_id.as_deref(), &file.name).await?
        } else {
            file.name.clone()
        };

        // Restore the file
        sqlx::query(
            "UPDATE files SET deleted_at = NULL, parent_id = ?, original_parent_id = NULL, name = ?, updated_at = ? WHERE id = ?",
        )
        .bind(&restore_parent_id)
        .bind(&final_name)
        .bind(&now)
        .bind(&file.id)
        .execute(db.pool())
        .await?;

        // If it's a directory, restore children
        if file.is_dir {
            Self::restore_children(db, &file.id, &now).await?;
        }

        Ok(())
    }

    /// Recursively restore children
    fn restore_children<'a>(
        db: &'a Database,
        parent_id: &'a str,
        updated_at: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let children: Vec<File> =
                sqlx::query_as("SELECT * FROM files WHERE parent_id = ? AND deleted_at IS NOT NULL")
                    .bind(parent_id)
                    .fetch_all(db.pool())
                    .await?;

            for child in children {
                sqlx::query("UPDATE files SET deleted_at = NULL, updated_at = ? WHERE id = ?")
                    .bind(updated_at)
                    .bind(&child.id)
                    .execute(db.pool())
                    .await?;

                if child.is_dir {
                    Self::restore_children(db, &child.id, updated_at).await?;
                }
            }

            Ok(())
        })
    }

    /// Generate a unique name by appending a number
    async fn generate_unique_name(
        db: &Database,
        user_id: &str,
        parent_id: Option<&str>,
        original_name: &str,
    ) -> Result<String> {
        let mut counter = 1;
        let (base_name, extension) = if let Some(dot_pos) = original_name.rfind('.') {
            (&original_name[..dot_pos], Some(&original_name[dot_pos..]))
        } else {
            (original_name, None)
        };

        loop {
            let new_name = match extension {
                Some(ext) => format!("{} ({}){}", base_name, counter, ext),
                None => format!("{} ({})", base_name, counter),
            };

            if !Self::check_name_exists(db, user_id, parent_id, &new_name).await? {
                return Ok(new_name);
            }

            counter += 1;
            if counter > 100 {
                return Err(AppError::Internal("Could not generate unique name".to_string()));
            }
        }
    }

    /// Permanently delete items from trash
    pub async fn delete_from_trash(
        db: &Database,
        storage_manager: &StorageManager,
        user_id: &str,
        file_ids: &[String],
    ) -> Result<()> {
        for file_id in file_ids {
            let file = Self::get_file(db, file_id).await?;

            // Check ownership
            if file.user_id != user_id {
                return Err(AppError::Forbidden("Access denied".to_string()));
            }

            // Check if file is in trash
            if file.deleted_at.is_none() {
                return Err(AppError::BadRequest("File is not in trash".to_string()));
            }

            // Permanently delete
            Self::permanent_delete(db, storage_manager, &file).await?;
        }

        Ok(())
    }

    /// Empty trash for a user
    pub async fn empty_trash(
        db: &Database,
        storage_manager: &StorageManager,
        user_id: &str,
    ) -> Result<()> {
        // Get all top-level trash items
        let trash_items: Vec<File> = sqlx::query_as(
            "SELECT * FROM files WHERE user_id = ? AND deleted_at IS NOT NULL AND parent_id IS NULL",
        )
        .bind(user_id)
        .fetch_all(db.pool())
        .await?;

        for file in trash_items {
            Self::permanent_delete(db, storage_manager, &file).await?;
        }

        Ok(())
    }
}
