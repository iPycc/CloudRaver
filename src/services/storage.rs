use chrono::Utc;
use uuid::Uuid;

use crate::db::Database;
use crate::error::{AppError, Result};
use crate::models::{
    CreateStoragePolicyRequest, PolicyType, StoragePolicy, StoragePolicyResponse,
    UpdateStoragePolicyRequest,
};
use aes::Aes256;
use cbc::{Decryptor, Encryptor};
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64::{Engine as _, engine::general_purpose};
use sha2::{Sha256, Digest};

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

/// Storage policy service
pub struct StoragePolicyService;

impl StoragePolicyService {
    /// Get AES key from JWT secret (hashed)
    fn get_aes_key() -> [u8; 32] {
        // Use a fixed salt or just hash the secret. 
        // In a real app, this should be a dedicated encryption key in config.
        let secret = std::env::var("CR_CONF_JWT_SECRET").unwrap_or_else(|_| "cloudraver-default-secret-key-change-me".to_string());
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }

    /// Helper to encrypt sensitive data using AES-256-CBC
    fn encrypt_config(config: &serde_json::Value) -> serde_json::Value {
        let mut new_config = config.clone();
        if let Some(obj) = new_config.as_object_mut() {
            if let Some(key_val) = obj.get_mut("secret_key") {
                if let Some(s) = key_val.as_str() {
                    let key = Self::get_aes_key();
                    let iv = [0u8; 16]; // In production, use a random IV and store it with the data
                    
                    let data = s.as_bytes();
                    let mut buf = vec![0u8; data.len() + 16];
                    buf[..data.len()].copy_from_slice(data);
                    
                    let ct = Aes256CbcEnc::new(&key.into(), &iv.into())
                        .encrypt_padded_mut::<Pkcs7>(&mut buf, data.len())
                        .unwrap();
                    
                    *key_val = serde_json::Value::String(general_purpose::STANDARD.encode(ct));
                }
            }
        }
        new_config
    }

    /// Helper to decrypt sensitive data
    fn decrypt_config(config_str: &str) -> serde_json::Value {
        let mut config: serde_json::Value = serde_json::from_str(config_str)
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
            
        if let Some(obj) = config.as_object_mut() {
            if let Some(key_val) = obj.get_mut("secret_key") {
                if let Some(s) = key_val.as_str() {
                    if let Ok(encrypted_data) = general_purpose::STANDARD.decode(s) {
                        let key = Self::get_aes_key();
                        let iv = [0u8; 16];
                        
                        let mut buf = encrypted_data.clone();
                        if let Ok(pt) = Aes256CbcDec::new(&key.into(), &iv.into())
                            .decrypt_padded_mut::<Pkcs7>(&mut buf) {
                            if let Ok(decrypted) = String::from_utf8(pt.to_vec()) {
                                *key_val = serde_json::Value::String(decrypted);
                            }
                        }
                    }
                }
            }
        }
        config
    }

    /// List storage policies for a user
    pub async fn list_policies(db: &Database, user_id: &str) -> Result<Vec<StoragePolicyResponse>> {
        let policies: Vec<StoragePolicy> = sqlx::query_as(
            "SELECT * FROM storage_policies WHERE user_id = ? ORDER BY created_at DESC",
        )
        .bind(user_id)
        .fetch_all(db.pool())
        .await?;

        // Decrypt configs before returning
        Ok(policies.iter().map(|p| {
            let mut resp = p.to_response();
            resp.config = Self::decrypt_config(&p.config);
            resp
        }).collect())
    }

    /// Get a specific policy
    pub async fn get_policy(db: &Database, policy_id: &str) -> Result<StoragePolicy> {
        let mut policy: StoragePolicy = sqlx::query_as("SELECT * FROM storage_policies WHERE id = ?")
            .bind(policy_id)
            .fetch_optional(db.pool())
            .await?
            .ok_or_else(|| AppError::NotFound("Storage policy not found".to_string()))?;

        // Decrypt config in memory so internal usage gets real keys
        let decrypted_json = Self::decrypt_config(&policy.config);
        policy.config = decrypted_json.to_string();

        Ok(policy)
    }

    /// Create a new storage policy
    pub async fn create_policy(
        db: &Database,
        user_id: &str,
        req: CreateStoragePolicyRequest,
    ) -> Result<StoragePolicyResponse> {
        // Validate policy type
        let policy_type = PolicyType::from_str(&req.policy_type)
            .ok_or_else(|| AppError::BadRequest("Invalid policy type".to_string()))?;

        // Validate config based on type
        Self::validate_config(&policy_type, &req.config)?;

        let policy_id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        
        // Encrypt config before storage
        let encrypted_config = Self::encrypt_config(&req.config);
        let config_str = encrypted_config.to_string();

        // Check if user has any policies (make first one default)
        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM storage_policies WHERE user_id = ?")
                .bind(user_id)
                .fetch_one(db.pool())
                .await?;

        let is_default = count.0 == 0;

        sqlx::query(
            r#"
            INSERT INTO storage_policies (id, user_id, name, policy_type, config, is_default, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&policy_id)
        .bind(user_id)
        .bind(&req.name)
        .bind(policy_type.as_str())
        .bind(&config_str)
        .bind(is_default)
        .bind(&now)
        .bind(&now)
        .execute(db.pool())
        .await?;

        // If this is the first policy, set it as user's default
        if is_default {
            sqlx::query("UPDATE users SET default_policy_id = ? WHERE id = ?")
                .bind(&policy_id)
                .bind(user_id)
                .execute(db.pool())
                .await?;
        }

        // Return with original (unencrypted) config for the response
        let policy = Self::get_policy(db, &policy_id).await?;
        // get_policy already decrypts it
        Ok(policy.to_response())
    }

    /// Update a storage policy
    pub async fn update_policy(
        db: &Database,
        user_id: &str,
        policy_id: &str,
        req: UpdateStoragePolicyRequest,
        is_admin: bool,
    ) -> Result<StoragePolicyResponse> {
        // We get the raw policy first (encrypted)
        let policy_raw: StoragePolicy = sqlx::query_as("SELECT * FROM storage_policies WHERE id = ?")
            .bind(policy_id)
            .fetch_optional(db.pool())
            .await?
            .ok_or_else(|| AppError::NotFound("Storage policy not found".to_string()))?;

        // Check ownership (unless admin)
        if !is_admin && policy_raw.user_id != user_id {
            return Err(AppError::Forbidden(
                "You don't have permission to update this policy".to_string(),
            ));
        }

        let now = Utc::now().to_rfc3339();
        let name = req.name.unwrap_or_else(|| policy_raw.name.clone());
        
        let config_str = match req.config {
            Some(config) => {
                // Validate new config
                if let Some(policy_type) = PolicyType::from_str(&policy_raw.policy_type) {
                    Self::validate_config(&policy_type, &config)?;
                }
                // Encrypt before saving
                let encrypted = Self::encrypt_config(&config);
                encrypted.to_string()
            }
            None => policy_raw.config.clone(),
        };

        sqlx::query(
            "UPDATE storage_policies SET name = ?, config = ?, updated_at = ? WHERE id = ?",
        )
        .bind(&name)
        .bind(&config_str)
        .bind(&now)
        .bind(policy_id)
        .execute(db.pool())
        .await?;

        let updated_policy = Self::get_policy(db, policy_id).await?;
        Ok(updated_policy.to_response())
    }

    /// Delete a storage policy
    pub async fn delete_policy(
        db: &Database,
        user_id: &str,
        policy_id: &str,
        is_admin: bool,
    ) -> Result<()> {
        let policy = Self::get_policy(db, policy_id).await?;

        // Check ownership (unless admin)
        if !is_admin && policy.user_id != user_id {
            return Err(AppError::Forbidden(
                "You don't have permission to delete this policy".to_string(),
            ));
        }

        // Check if there are files using this policy
        let file_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM files WHERE policy_id = ?")
            .bind(policy_id)
            .fetch_one(db.pool())
            .await?;

        if file_count.0 > 0 {
            return Err(AppError::Conflict(
                "Cannot delete policy that has files. Move or delete files first.".to_string(),
            ));
        }

        // Delete the policy
        sqlx::query("DELETE FROM storage_policies WHERE id = ?")
            .bind(policy_id)
            .execute(db.pool())
            .await?;

        // If this was the default, set another one as default
        if policy.is_default {
            // Find another policy to make default
            let other_policy: Option<StoragePolicy> = sqlx::query_as(
                "SELECT * FROM storage_policies WHERE user_id = ? LIMIT 1",
            )
            .bind(&policy.user_id)
            .fetch_optional(db.pool())
            .await?;

            if let Some(other) = other_policy {
                sqlx::query("UPDATE storage_policies SET is_default = 1 WHERE id = ?")
                    .bind(&other.id)
                    .execute(db.pool())
                    .await?;

                sqlx::query("UPDATE users SET default_policy_id = ? WHERE id = ?")
                    .bind(&other.id)
                    .bind(&policy.user_id)
                    .execute(db.pool())
                    .await?;
            } else {
                // No more policies, clear the default
                sqlx::query("UPDATE users SET default_policy_id = NULL WHERE id = ?")
                    .bind(&policy.user_id)
                    .execute(db.pool())
                    .await?;
            }
        }

        Ok(())
    }

    /// Set a policy as default
    pub async fn set_default_policy(
        db: &Database,
        user_id: &str,
        policy_id: &str,
    ) -> Result<StoragePolicyResponse> {
        let policy = Self::get_policy(db, policy_id).await?;

        // Check ownership
        if policy.user_id != user_id {
            return Err(AppError::Forbidden(
                "You don't have permission to modify this policy".to_string(),
            ));
        }

        let now = Utc::now().to_rfc3339();

        // Unset all other defaults for this user
        sqlx::query(
            "UPDATE storage_policies SET is_default = 0, updated_at = ? WHERE user_id = ?",
        )
        .bind(&now)
        .bind(user_id)
        .execute(db.pool())
        .await?;

        // Set this one as default
        sqlx::query("UPDATE storage_policies SET is_default = 1, updated_at = ? WHERE id = ?")
            .bind(&now)
            .bind(policy_id)
            .execute(db.pool())
            .await?;

        // Update user's default policy
        sqlx::query("UPDATE users SET default_policy_id = ?, updated_at = ? WHERE id = ?")
            .bind(policy_id)
            .bind(&now)
            .bind(user_id)
            .execute(db.pool())
            .await?;

        let updated_policy = Self::get_policy(db, policy_id).await?;
        Ok(updated_policy.to_response())
    }

    /// Validate storage config based on type
    fn validate_config(policy_type: &PolicyType, config: &serde_json::Value) -> Result<()> {
        match policy_type {
            PolicyType::Local => {
                // Local config just needs a base_path (optional, has default)
                Ok(())
            }
            PolicyType::Cos => {
                // COS requires secret_id, secret_key, bucket, region
                let obj = config
                    .as_object()
                    .ok_or_else(|| AppError::BadRequest("Config must be an object".to_string()))?;

                let required = ["secret_id", "secret_key", "bucket", "region"];
                for field in required {
                    if !obj.contains_key(field) || obj[field].as_str().map_or(true, |s| s.is_empty())
                    {
                        return Err(AppError::BadRequest(format!(
                            "COS config requires '{}'",
                            field
                        )));
                    }
                }

                Ok(())
            }
        }
    }
}

