use chrono::{Duration, Utc};
use uuid::Uuid;
use webauthn_rs::prelude::*;
use base64::Engine;

use crate::config::Config;
use crate::db::Database;
use crate::error::{AppError, Result};
use crate::models::{PasskeyCredential, WebAuthnChallenge, User};

pub struct PasskeyService;

impl PasskeyService {
    fn webauthn_from_config(config: &Config) -> Result<Webauthn> {
        let rp_origin_raw = config.webauthn.rp_origin.trim();
        let rp_origin = url::Url::parse(rp_origin_raw).or_else(|_| {
            if rp_origin_raw.contains("://") {
                Err(url::ParseError::RelativeUrlWithoutBase)
            } else {
                url::Url::parse(&format!("http://{}", rp_origin_raw))
            }
        });
        let rp_origin = rp_origin.map_err(|_| {
            AppError::BadRequest(format!(
                "Invalid rp_origin: {} (expected like http://localhost:3000)",
                rp_origin_raw
            ))
        })?;
        let builder = WebauthnBuilder::new(&config.webauthn.rp_id, &rp_origin).map_err(|_| {
            AppError::BadRequest(format!(
                "Invalid WebAuthn config (rp_id={}, rp_origin={})",
                config.webauthn.rp_id, rp_origin
            ))
        })?;
        let builder = builder.rp_name(&config.webauthn.rp_name);
        let webauthn = builder
            .build()
            .map_err(|e| AppError::Internal(format!("WebAuthn build error: {:?}", e)))?;
        Ok(webauthn)
    }

    pub async fn begin_register(db: &Database, config: &Config, user_id: &str, user_name: &str, display_name: &str) -> Result<(CreationChallengeResponse, PasskeyRegistration)> {
        let webauthn = Self::webauthn_from_config(config)?;
        let creds: Vec<PasskeyCredential> = sqlx::query_as("SELECT * FROM webauthn_passkeys WHERE user_id = ?")
            .bind(user_id)
            .fetch_all(db.pool())
            .await?;
        let mut exclude: Vec<CredentialID> = Vec::new();
        for c in creds {
            let pk: Passkey = serde_json::from_str(&c.credential_json)
                .map_err(|_| AppError::Internal("Deserialize passkey failed".to_string()))?;
            exclude.push(pk.cred_id().clone());
        }
        let uid = Uuid::parse_str(user_id).unwrap_or_else(|_| Uuid::new_v4());
        let exclude = if exclude.is_empty() { None } else { Some(exclude) };
        let (ccr, reg_state) = webauthn
            .start_passkey_registration(uid, user_name, display_name, exclude)
            .map_err(|e| AppError::BadRequest(format!("start registration failed: {:?}", e)))?;
        Ok((ccr, reg_state))
    }

    pub async fn finish_register(
        db: &Database,
        config: &Config,
        user_id: &str,
        reg: RegisterPublicKeyCredential,
        reg_state: PasskeyRegistration,
        nickname: Option<String>,
        device_info: Option<String>,
        ip_address: Option<String>,
    ) -> Result<PasskeyCredential> {
        let webauthn = Self::webauthn_from_config(config)?;
        let passkey = webauthn
            .finish_passkey_registration(&reg, &reg_state)
            .map_err(|e| AppError::BadRequest(format!("finish registration failed: {:?}", e)))?;
        let cred_id_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(passkey.cred_id());
        let now = Utc::now().to_rfc3339();
        let id = Uuid::new_v4().to_string();
        let credential_json = serde_json::to_string(&passkey).map_err(|_| AppError::Internal("Serialize passkey failed".to_string()))?;
        sqlx::query(
            r#"
            INSERT INTO webauthn_passkeys (id, user_id, credential_id, credential_json, nickname, device_info, ip_address, created_at, last_used_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
            "#,
        )
        .bind(&id)
        .bind(user_id)
        .bind(&cred_id_b64)
        .bind(&credential_json)
        .bind(nickname.as_ref().map(|s| s.as_str()))
        .bind(device_info.as_ref().map(|s| s.as_str()))
        .bind(ip_address.as_ref().map(|s| s.as_str()))
        .bind(&now)
        .execute(db.pool())
        .await?;
        let stored = PasskeyCredential {
            id,
            user_id: user_id.to_string(),
            credential_id: cred_id_b64,
            credential_json,
            nickname,
            device_info,
            ip_address,
            created_at: now,
            last_used_at: None,
        };
        Ok(stored)
    }

    pub async fn begin_authenticate(db: &Database, config: &Config, allow_user_id: Option<&str>) -> Result<(RequestChallengeResponse, PasskeyAuthentication)> {
        let webauthn = Self::webauthn_from_config(config)?;
        let mut passkeys: Vec<Passkey> = Vec::new();
        if let Some(uid) = allow_user_id {
            let creds: Vec<PasskeyCredential> = sqlx::query_as("SELECT * FROM webauthn_passkeys WHERE user_id = ?")
                .bind(uid)
                .fetch_all(db.pool())
                .await?;
            for c in creds {
                let pk: Passkey = serde_json::from_str(&c.credential_json)
                    .map_err(|_| AppError::Internal("Deserialize passkey failed".to_string()))?;
                passkeys.push(pk);
            }
        } else {
            let creds: Vec<PasskeyCredential> = sqlx::query_as(
                r#"
                SELECT p.id, p.user_id, p.credential_id, p.credential_json, p.nickname, p.device_info, p.ip_address, p.created_at, p.last_used_at
                FROM webauthn_passkeys p
                JOIN users u ON u.id = p.user_id
                WHERE u.is_active = 1
                ORDER BY p.last_used_at DESC NULLS LAST, p.created_at DESC
                LIMIT 200
                "#,
            )
            .fetch_all(db.pool())
            .await?;
            for c in creds {
                let pk: Passkey = serde_json::from_str(&c.credential_json)
                    .map_err(|_| AppError::Internal("Deserialize passkey failed".to_string()))?;
                passkeys.push(pk);
            }
        }
        if passkeys.is_empty() {
            return Err(AppError::BadRequest("No passkeys registered".to_string()));
        }
        let (req, auth_state) = webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|e| AppError::BadRequest(format!("start authentication failed: {:?}", e)))?;
        Ok((req, auth_state))
    }

    pub async fn finish_authenticate(db: &Database, config: &Config, rsp: PublicKeyCredential, auth_state: PasskeyAuthentication) -> Result<(User, String)> {
        let webauthn = Self::webauthn_from_config(config)?;
        let result = webauthn
            .finish_passkey_authentication(&rsp, &auth_state)
            .map_err(|e| AppError::Unauthorized(format!("authentication failed: {:?}", e)))?;
        let cred_id_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(result.cred_id());
        let mut cred: PasskeyCredential = sqlx::query_as("SELECT * FROM webauthn_passkeys WHERE credential_id = ?")
            .bind(&cred_id_b64)
            .fetch_optional(db.pool())
            .await?
            .ok_or_else(|| AppError::Unauthorized("Credential not found".to_string()))?;
        let mut passkey: Passkey = serde_json::from_str(&cred.credential_json)
            .map_err(|_| AppError::Internal("Deserialize passkey failed".to_string()))?;
        let updated = passkey.update_credential(&result);
        if let Some(true) = updated {
            cred.credential_json = serde_json::to_string(&passkey)
                .map_err(|_| AppError::Internal("Serialize passkey failed".to_string()))?;
            sqlx::query("UPDATE webauthn_passkeys SET credential_json = ? WHERE id = ?")
                .bind(&cred.credential_json)
                .bind(&cred.id)
                .execute(db.pool())
                .await?;
        }
        let user: User = sqlx::query_as("SELECT * FROM users WHERE id = ?")
            .bind(&cred.user_id)
            .fetch_one(db.pool())
            .await?;
        if !user.is_active {
            return Err(AppError::Forbidden("Account is disabled".to_string()));
        }
        let now = Utc::now().to_rfc3339();
        sqlx::query("UPDATE webauthn_passkeys SET last_used_at = ? WHERE id = ?")
            .bind(&now)
            .bind(&cred.id)
            .execute(db.pool())
            .await?;
        Ok((user, cred.id))
    }

    pub async fn store_challenge(db: &Database, user_id: Option<&str>, flow: &str, state_json: String, ttl_secs: i64) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let expires_at = (now + Duration::seconds(ttl_secs)).to_rfc3339();
        sqlx::query(
            r#"
            INSERT INTO webauthn_challenges (id, user_id, flow, state_json, expires_at, used_at, created_at)
            VALUES (?, ?, ?, ?, ?, NULL, ?)
            "#,
        )
        .bind(&id)
        .bind(user_id)
        .bind(flow)
        .bind(&state_json)
        .bind(&expires_at)
        .bind(&now.to_rfc3339())
        .execute(db.pool())
        .await?;
        Ok(id)
    }

    pub async fn load_challenge(db: &Database, id: &str, flow_expected: &str) -> Result<WebAuthnChallenge> {
        let ch: WebAuthnChallenge = sqlx::query_as("SELECT * FROM webauthn_challenges WHERE id = ?")
            .bind(id)
            .fetch_optional(db.pool())
            .await?
            .ok_or_else(|| AppError::BadRequest("Challenge not found".to_string()))?;
        if ch.used_at.is_some() {
            return Err(AppError::BadRequest("Challenge already used".to_string()));
        }
        let exp = chrono::DateTime::parse_from_rfc3339(&ch.expires_at)
            .map_err(|_| AppError::Internal("Invalid challenge expiry".to_string()))?;
        if exp < chrono::Utc::now() {
            return Err(AppError::BadRequest("Challenge expired".to_string()));
        }
        if ch.flow != flow_expected {
            return Err(AppError::BadRequest("Challenge flow mismatch".to_string()));
        }
        Ok(ch)
    }

    pub async fn mark_challenge_used(db: &Database, id: &str) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        sqlx::query("UPDATE webauthn_challenges SET used_at = ? WHERE id = ?")
            .bind(&now)
            .bind(id)
            .execute(db.pool())
            .await?;
        Ok(())
    }
}
