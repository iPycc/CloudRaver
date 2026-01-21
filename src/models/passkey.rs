use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PasskeyCredential {
    pub id: String,
    pub user_id: String,
    pub credential_id: String,
    pub credential_json: String,
    pub nickname: Option<String>,
    pub device_info: Option<String>,
    pub ip_address: Option<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct WebAuthnChallenge {
    pub id: String,
    pub user_id: Option<String>,
    pub flow: String, // "register" | "auth"
    pub state_json: String,
    pub expires_at: String,
    pub used_at: Option<String>,
    pub created_at: String,
}
