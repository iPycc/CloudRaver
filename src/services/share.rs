use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2, PasswordHash, PasswordVerifier,
};
use chrono::Utc;
use rand::{distributions::Alphanumeric, Rng};
use uuid::Uuid;

use crate::db::Database;
use crate::error::{AppError, Result};
use crate::models::{CreateShareRequest, File, PublicShareInfo, Share, ShareListItem, User};

pub struct ShareService;

impl ShareService {
    /// Create a new share link
    pub async fn create_share(
        db: &Database,
        user_id: &str,
        req: CreateShareRequest,
    ) -> Result<Share> {
        // Verify file exists and belongs to user
        let file: Option<File> = sqlx::query_as("SELECT * FROM files WHERE id = ?")
            .bind(&req.file_id)
            .fetch_optional(db.pool())
            .await?;

        let file = file.ok_or_else(|| AppError::NotFound("File not found".to_string()))?;

        if file.user_id != user_id {
            return Err(AppError::Forbidden("Access denied".to_string()));
        }

        if file.is_dir {
            return Err(AppError::BadRequest("Cannot share directories yet".to_string()));
        }

        let share_id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();

        // Hash password if provided
        let password_hash = if let Some(password) = req.password {
            if password.is_empty() {
                None
            } else {
                let salt = SaltString::generate(&mut OsRng);
                let argon2 = Argon2::default();
                Some(
                    argon2
                        .hash_password(password.as_bytes(), &salt)
                        .map_err(|e| AppError::Internal(format!("Password hashing failed: {}", e)))?
                        .to_string(),
                )
            }
        } else {
            None
        };

        let mut last_error: Option<sqlx::Error> = None;
        let mut token: Option<String> = None;
        for _ in 0..10 {
            let candidate: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(6)
                .map(char::from)
                .collect::<String>()
                .to_lowercase();

            let result = sqlx::query(
                r#"
                INSERT INTO shares (id, file_id, user_id, token, password_hash, max_views, expires_at, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(&share_id)
            .bind(&req.file_id)
            .bind(user_id)
            .bind(&candidate)
            .bind(&password_hash)
            .bind(req.max_views)
            .bind(&req.expires_at)
            .bind(&now)
            .bind(&now)
            .execute(db.pool())
            .await;

            match result {
                Ok(_) => {
                    token = Some(candidate);
                    last_error = None;
                    break;
                }
                Err(e) => {
                    let is_token_conflict = match &e {
                        sqlx::Error::Database(db_err) => {
                            db_err.message().contains("UNIQUE constraint failed: shares.token")
                        }
                        _ => false,
                    };
                    if is_token_conflict {
                        last_error = Some(e);
                        continue;
                    }
                    return Err(e.into());
                }
            }
        }

        if token.is_none() {
            return Err(AppError::Internal(format!(
                "Failed to generate unique share token: {}",
                last_error
                    .as_ref()
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            )));
        }

        let share = Self::get_share(db, &share_id).await?;
        Ok(share)
    }

    /// Get share by ID
    pub async fn get_share(db: &Database, id: &str) -> Result<Share> {
        sqlx::query_as("SELECT * FROM shares WHERE id = ?")
            .bind(id)
            .fetch_optional(db.pool())
            .await?
            .ok_or_else(|| AppError::NotFound("Share not found".to_string()))
    }

    /// Get user's shares
    pub async fn list_user_shares(db: &Database, user_id: &str) -> Result<Vec<Share>> {
        let shares = sqlx::query_as("SELECT * FROM shares WHERE user_id = ? ORDER BY created_at DESC")
            .bind(user_id)
            .fetch_all(db.pool())
            .await?;
        Ok(shares)
    }

    /// Get user's shares with file name for listing
    pub async fn list_user_share_items(db: &Database, user_id: &str) -> Result<Vec<ShareListItem>> {
        let items = sqlx::query_as(
            r#"
            SELECT
              s.id,
              s.file_id,
              f.name AS file_name,
              f.is_dir AS is_dir,
              s.token,
              s.views,
              s.max_views,
              s.expires_at,
              s.created_at,
              s.updated_at
            FROM shares s
            JOIN files f ON s.file_id = f.id
            WHERE s.user_id = ?
            ORDER BY s.created_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(db.pool())
        .await?;
        Ok(items)
    }

    /// Delete a share
    pub async fn delete_share(db: &Database, user_id: &str, share_id: &str) -> Result<()> {
        let result = sqlx::query("DELETE FROM shares WHERE id = ? AND user_id = ?")
            .bind(share_id)
            .bind(user_id)
            .execute(db.pool())
            .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Share not found".to_string()));
        }

        Ok(())
    }

    /// Get public share info by token (no auth required)
    pub async fn get_public_share_info(db: &Database, token: &str) -> Result<PublicShareInfo> {
        let share: Option<Share> = sqlx::query_as("SELECT * FROM shares WHERE token = ?")
            .bind(token)
            .fetch_optional(db.pool())
            .await?;

        let share = share.ok_or_else(|| AppError::NotFound("Share not found".to_string()))?;

        // Check expiration
        if let Some(expires_at) = &share.expires_at {
            if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(expires_at) {
                if Utc::now() > expiry {
                    return Err(AppError::NotFound("Share link expired".to_string()));
                }
            }
        }

        // Check view limit
        if let Some(max_views) = share.max_views {
            if share.views >= max_views {
                return Err(AppError::NotFound("Share link limit reached".to_string()));
            }
        }

        // Get file info
        let file: File = sqlx::query_as("SELECT * FROM files WHERE id = ?")
            .bind(&share.file_id)
            .fetch_one(db.pool())
            .await?;

        // Get owner info
        let owner: User = sqlx::query_as("SELECT * FROM users WHERE id = ?")
            .bind(&share.user_id)
            .fetch_one(db.pool())
            .await?;

        Ok(PublicShareInfo {
            token: share.token,
            file_name: file.name,
            file_size: file.size,
            mime_type: file.mime_type,
            has_password: share.password_hash.is_some(),
            created_at: share.created_at,
            expires_at: share.expires_at,
            owner_name: owner.name,
        })
    }

    /// Verify password and increment view count
    pub async fn verify_share_access(db: &Database, token: &str, password: Option<String>) -> Result<(Share, File)> {
        let share: Option<Share> = sqlx::query_as("SELECT * FROM shares WHERE token = ?")
            .bind(token)
            .fetch_optional(db.pool())
            .await?;

        let share = share.ok_or_else(|| AppError::NotFound("Share not found".to_string()))?;

        // Check expiration
        if let Some(expires_at) = &share.expires_at {
            if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(expires_at) {
                if Utc::now() > expiry {
                    return Err(AppError::NotFound("Share link expired".to_string()));
                }
            }
        }

        // Check view limit
        if let Some(max_views) = share.max_views {
            if share.views >= max_views {
                return Err(AppError::NotFound("Share link limit reached".to_string()));
            }
        }

        // Verify password if set
        if let Some(hash) = &share.password_hash {
            let password = password.ok_or_else(|| AppError::Forbidden("Password required".to_string()))?;
            let parsed_hash = PasswordHash::new(hash)
                .map_err(|e| AppError::Internal(format!("Password hash error: {}", e)))?;
            
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed_hash)
                .map_err(|_| AppError::Forbidden("Invalid password".to_string()))?;
        }

        // Increment views
        sqlx::query("UPDATE shares SET views = views + 1 WHERE id = ?")
            .bind(&share.id)
            .execute(db.pool())
            .await?;

        // Get file
        let file: File = sqlx::query_as("SELECT * FROM files WHERE id = ?")
            .bind(&share.file_id)
            .fetch_one(db.pool())
            .await?;

        Ok((share, file))
    }
}
