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

