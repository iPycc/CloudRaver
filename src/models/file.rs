use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// File model
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct File {
    pub id: String,
    pub user_id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub is_dir: bool,
    pub size: i64,
    pub policy_id: Option<String>,
    pub mime_type: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    /// Soft delete timestamp (NULL means not deleted)
    pub deleted_at: Option<String>,
    /// Original parent_id before moving to trash (for restore)
    pub original_parent_id: Option<String>,
}

/// File response with additional info
#[derive(Debug, Clone, Serialize)]
pub struct FileResponse {
    pub id: String,
    pub user_id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub is_dir: bool,
    pub size: i64,
    pub policy_id: Option<String>,
    pub mime_type: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub deleted_at: Option<String>,
    pub original_parent_id: Option<String>,
}

impl From<File> for FileResponse {
    fn from(file: File) -> Self {
        Self {
            id: file.id,
            user_id: file.user_id,
            parent_id: file.parent_id,
            name: file.name,
            is_dir: file.is_dir,
            size: file.size,
            policy_id: file.policy_id,
            mime_type: file.mime_type,
            created_at: file.created_at,
            updated_at: file.updated_at,
            deleted_at: file.deleted_at,
            original_parent_id: file.original_parent_id,
        }
    }
}

/// File list response
#[derive(Debug, Serialize)]
pub struct FileListResponse {
    pub files: Vec<FileResponse>,
    pub path: Vec<PathItem>,
}

/// Path item for breadcrumb
#[derive(Debug, Clone, Serialize)]
pub struct PathItem {
    pub id: String,
    pub name: String,
}

/// Create directory request
#[derive(Debug, Deserialize)]
pub struct CreateDirectoryRequest {
    pub parent_id: Option<String>,
    pub name: String,
    pub policy_id: Option<String>,
}

/// Rename file request
#[derive(Debug, Deserialize)]
pub struct RenameFileRequest {
    pub name: String,
}

/// File query parameters
#[derive(Debug, Deserialize)]
pub struct FileQuery {
    pub parent_id: Option<String>,
    pub policy_id: Option<String>,
    /// Path-based query (e.g., "/Documents/Projects")
    pub path: Option<String>,
}

/// Trash item response (for listing trash)
#[derive(Debug, Clone, Serialize)]
pub struct TrashItem {
    pub id: String,
    pub name: String,
    pub is_dir: bool,
    pub size: i64,
    pub mime_type: Option<String>,
    pub deleted_at: String,
    pub original_parent_id: Option<String>,
    pub original_path: String,
}

/// Trash action request (restore or permanent delete)
#[derive(Debug, Deserialize)]
pub struct TrashActionRequest {
    pub ids: Vec<String>,
}

