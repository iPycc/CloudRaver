use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// Storage policy type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyType {
    Local,
    Cos,
}

impl PolicyType {
    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyType::Local => "local",
            PolicyType::Cos => "cos",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "local" => Some(PolicyType::Local),
            "cos" => Some(PolicyType::Cos),
            _ => None,
        }
    }
}

/// Storage policy model
#[derive(Debug, Clone, FromRow)]
pub struct StoragePolicy {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub policy_type: String,
    pub config: String,  // JSON string
    pub is_default: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// Storage policy response
#[derive(Debug, Clone, Serialize)]
pub struct StoragePolicyResponse {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub policy_type: String,
    pub config: serde_json::Value,
    pub is_default: bool,
    pub created_at: String,
}

impl StoragePolicy {
    pub fn to_response(&self) -> StoragePolicyResponse {
        let config: serde_json::Value = serde_json::from_str(&self.config)
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
        
        StoragePolicyResponse {
            id: self.id.clone(),
            user_id: self.user_id.clone(),
            name: self.name.clone(),
            policy_type: self.policy_type.clone(),
            config,
            is_default: self.is_default,
            created_at: self.created_at.clone(),
        }
    }

    pub fn get_type(&self) -> Option<PolicyType> {
        PolicyType::from_str(&self.policy_type)
    }
}

/// Local storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalStorageConfig {
    #[serde(default = "default_local_path")]
    pub base_path: String,
}

fn default_local_path() -> String {
    "data/uploads".to_string()
}

impl Default for LocalStorageConfig {
    fn default() -> Self {
        Self {
            base_path: default_local_path(),
        }
    }
}

/// Tencent COS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CosStorageConfig {
    pub secret_id: String,
    pub secret_key: String,
    pub bucket: String,
    pub region: String,
    #[serde(default)]
    pub base_path: String,
    #[serde(default = "default_url_expire")]
    pub url_expire_seconds: u64,
}

fn default_url_expire() -> u64 {
    3600 // 1 hour
}

/// Create storage policy request
#[derive(Debug, Deserialize)]
pub struct CreateStoragePolicyRequest {
    pub name: String,
    pub policy_type: String,
    pub config: serde_json::Value,
}

/// Update storage policy request
#[derive(Debug, Deserialize)]
pub struct UpdateStoragePolicyRequest {
    pub name: Option<String>,
    pub config: Option<serde_json::Value>,
}

/// Storage policy list response
#[derive(Debug, Serialize)]
pub struct StoragePolicyListResponse {
    pub policies: Vec<StoragePolicyResponse>,
}

