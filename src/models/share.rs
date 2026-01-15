use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// Share model
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Share {
    pub id: String,
    pub file_id: String,
    pub user_id: String,
    pub token: String,
    #[serde(skip_serializing)]
    pub password_hash: Option<String>,
    pub views: i64,
    pub max_views: Option<i64>,
    pub expires_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Request to create a share
#[derive(Debug, Deserialize)]
pub struct CreateShareRequest {
    pub file_id: String,
    pub password: Option<String>,
    pub max_views: Option<i64>,
    pub expires_at: Option<String>,
}

/// Request to verify share password
#[derive(Debug, Deserialize)]
pub struct VerifyShareRequest {
    pub password: String,
}

/// Public share info (safe to return to anyone with the token)
#[derive(Debug, Serialize)]
pub struct PublicShareInfo {
    pub token: String,
    pub file_name: String,
    pub file_size: i64,
    pub mime_type: Option<String>,
    pub has_password: bool,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub owner_name: String,
}

/// Share item for listing (includes file name)
#[derive(Debug, Serialize, FromRow)]
pub struct ShareListItem {
    pub id: String,
    pub file_id: String,
    pub file_name: String,
    pub is_dir: bool,
    pub token: String,
    pub views: i64,
    pub max_views: Option<i64>,
    pub expires_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}
