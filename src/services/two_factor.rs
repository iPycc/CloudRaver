use aes::Aes256;
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64::{Engine as _, engine::general_purpose};
use cbc::{Decryptor, Encryptor};
use chrono::{Duration, Utc};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use totp_rs::{Algorithm, TOTP};
use uuid::Uuid;

use crate::config::Config;
use crate::db::Database;
use crate::error::{AppError, Result};
use crate::models::User;

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

pub struct TwoFactorService;

impl TwoFactorService {
    fn aes_key(config: &Config) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(config.jwt.secret.as_bytes());
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }

    fn encrypt_bytes(config: &Config, plaintext: &[u8]) -> Result<String> {
        let key = Self::aes_key(config);
        let mut iv = [0u8; 16];
        OsRng.fill_bytes(&mut iv);

        let mut buf = vec![0u8; plaintext.len() + 16];
        buf[..plaintext.len()].copy_from_slice(plaintext);

        let ct = Aes256CbcEnc::new(&key.into(), &iv.into())
            .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
            .map_err(|_| AppError::Internal("Encrypt failed".to_string()))?;

        let mut packed = Vec::with_capacity(16 + ct.len());
        packed.extend_from_slice(&iv);
        packed.extend_from_slice(ct);
        Ok(general_purpose::STANDARD.encode(packed))
    }

    fn decrypt_bytes(config: &Config, payload_b64: &str) -> Result<Vec<u8>> {
        let payload = general_purpose::STANDARD
            .decode(payload_b64)
            .map_err(|_| AppError::BadRequest("Invalid encrypted payload".to_string()))?;
        if payload.len() < 17 {
            return Err(AppError::BadRequest("Invalid encrypted payload".to_string()));
        }
        let (iv, ct) = payload.split_at(16);
        let key = Self::aes_key(config);

        let mut buf = ct.to_vec();
        let pt = Aes256CbcDec::new(&key.into(), iv.into())
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(|_| AppError::Internal("Decrypt failed".to_string()))?;
        Ok(pt.to_vec())
    }

    fn totp_from_secret(config: &Config, secret: Vec<u8>, account_name: &str) -> Result<TOTP> {
        let issuer = config.webauthn.rp_name.trim();
        let issuer = if issuer.is_empty() { "CloudRaver" } else { issuer };
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret,
            Some(issuer.to_string()),
            account_name.to_string(),
        )
        .map_err(|e| AppError::Internal(format!("TOTP init failed: {:?}", e)))?;
        Ok(totp)
    }

    pub async fn begin_totp_enroll(db: &Database, config: &Config, user_id: &str) -> Result<(String, String)> {
        let user: User = sqlx::query_as("SELECT * FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_one(db.pool())
            .await?;

        if user.totp_enabled != 0 {
            return Err(AppError::BadRequest("Two-factor authentication is already enabled".to_string()));
        }

        let mut secret_bytes = vec![0u8; 20];
        OsRng.fill_bytes(&mut secret_bytes);

        let secret_enc = Self::encrypt_bytes(config, &secret_bytes)?;
        let id = Uuid::new_v4().to_string();
        let expires_at = (Utc::now() + Duration::minutes(10)).to_rfc3339();

        sqlx::query("DELETE FROM totp_challenges WHERE user_id = ?")
            .bind(user_id)
            .execute(db.pool())
            .await?;

        sqlx::query(
            r#"
            INSERT INTO totp_challenges (id, user_id, secret_enc, expires_at, created_at)
            VALUES (?, ?, ?, ?, datetime('now'))
            "#,
        )
        .bind(&id)
        .bind(user_id)
        .bind(&secret_enc)
        .bind(&expires_at)
        .execute(db.pool())
        .await?;

        let totp = Self::totp_from_secret(config, secret_bytes, &user.email)?;
        let otpauth_url = totp.get_url();

        Ok((id, otpauth_url))
    }

    pub async fn enable_totp(db: &Database, config: &Config, user_id: &str, challenge_id: &str, code: &str) -> Result<()> {
        let row: Option<(String, String)> = sqlx::query_as(
            "SELECT secret_enc, expires_at FROM totp_challenges WHERE id = ? AND user_id = ?",
        )
        .bind(challenge_id)
        .bind(user_id)
        .fetch_optional(db.pool())
        .await?;

        let (secret_enc, expires_at) =
            row.ok_or_else(|| AppError::BadRequest("Challenge not found".to_string()))?;

        let exp = chrono::DateTime::parse_from_rfc3339(&expires_at)
            .map_err(|_| AppError::Internal("Invalid challenge expiry".to_string()))?;
        if exp < Utc::now() {
            return Err(AppError::BadRequest("Challenge expired".to_string()));
        }

        let user: User = sqlx::query_as("SELECT * FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_one(db.pool())
            .await?;
        if user.totp_enabled != 0 {
            return Err(AppError::BadRequest("Two-factor authentication is already enabled".to_string()));
        }

        let secret_bytes = Self::decrypt_bytes(config, &secret_enc)?;
        let totp = Self::totp_from_secret(config, secret_bytes, &user.email)?;
        let ok = totp
            .check_current(code)
            .map_err(|_| AppError::BadRequest("Invalid verification code".to_string()))?;
        if !ok {
            return Err(AppError::BadRequest("Invalid verification code".to_string()));
        }

        sqlx::query("UPDATE users SET totp_enabled = 1, totp_secret = ?, totp_last_step = NULL, updated_at = datetime('now') WHERE id = ?")
            .bind(&secret_enc)
            .bind(user_id)
            .execute(db.pool())
            .await?;

        sqlx::query("DELETE FROM totp_challenges WHERE id = ?")
            .bind(challenge_id)
            .execute(db.pool())
            .await?;

        Ok(())
    }

    pub async fn disable_totp(db: &Database, config: &Config, user_id: &str, code: &str) -> Result<()> {
        let user: User = sqlx::query_as("SELECT * FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_one(db.pool())
            .await?;
        if user.totp_enabled == 0 {
            return Err(AppError::BadRequest("Two-factor authentication is not enabled".to_string()));
        }
        let secret_enc = user
            .totp_secret
            .ok_or_else(|| AppError::Internal("Missing TOTP secret".to_string()))?;
        let secret_bytes = Self::decrypt_bytes(config, &secret_enc)?;
        let totp = Self::totp_from_secret(config, secret_bytes, &user.email)?;
        let ok = totp
            .check_current(code)
            .map_err(|_| AppError::BadRequest("Invalid verification code".to_string()))?;
        if !ok {
            return Err(AppError::BadRequest("Invalid verification code".to_string()));
        }

        sqlx::query("UPDATE users SET totp_enabled = 0, totp_secret = NULL, totp_last_step = NULL, updated_at = datetime('now') WHERE id = ?")
            .bind(user_id)
            .execute(db.pool())
            .await?;

        Ok(())
    }

    pub async fn verify_totp_for_user(db: &Database, config: &Config, user_id: &str, code: &str) -> Result<()> {
        let user: User = sqlx::query_as("SELECT * FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_one(db.pool())
            .await?;
        if user.totp_enabled == 0 {
            return Err(AppError::BadRequest("Two-factor authentication is not enabled".to_string()));
        }
        let secret_enc = user
            .totp_secret
            .ok_or_else(|| AppError::Internal("Missing TOTP secret".to_string()))?;
        let secret_bytes = Self::decrypt_bytes(config, &secret_enc)?;
        let totp = Self::totp_from_secret(config, secret_bytes, &user.email)?;
        let ok = totp
            .check_current(code)
            .map_err(|_| AppError::BadRequest("Invalid verification code".to_string()))?;
        if !ok {
            return Err(AppError::BadRequest("Invalid verification code".to_string()));
        }

        let step = Utc::now().timestamp() / 30;
        if user.totp_last_step == Some(step) {
            return Err(AppError::BadRequest("Verification code already used".to_string()));
        }
        sqlx::query("UPDATE users SET totp_last_step = ?, updated_at = datetime('now') WHERE id = ?")
            .bind(step)
            .bind(user_id)
            .execute(db.pool())
            .await?;

        Ok(())
    }
}
