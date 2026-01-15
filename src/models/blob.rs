use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// File blob model - represents actual file data storage
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct FileBlob {
    pub id: String,
    pub file_id: String,
    pub policy_id: String,
    pub storage_path: String,
    pub size: i64,
    pub hash: Option<String>,
    pub created_at: String,
}

/// Create blob request
#[derive(Debug, Deserialize)]
pub struct CreateBlobRequest {
    pub file_id: String,
    pub policy_id: String,
    pub storage_path: String,
    pub size: i64,
    pub hash: Option<String>,
}

