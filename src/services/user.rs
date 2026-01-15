use crate::db::Database;
use crate::error::{AppError, Result};
use crate::models::{User, UserResponse};

/// User service
pub struct UserService;

impl UserService {
    /// Get user by ID
    pub async fn get_user(db: &Database, user_id: &str) -> Result<User> {
        let user: User = sqlx::query_as("SELECT * FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_optional(db.pool())
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        Ok(user)
    }

    /// Get user profile
    pub async fn get_profile(db: &Database, user_id: &str) -> Result<UserResponse> {
        let user = Self::get_user(db, user_id).await?;
        Ok(UserResponse::from(user))
    }

    /// Get storage usage (optionally filtered by policy_id)
    pub async fn get_storage_usage(
        db: &Database,
        user_id: &str,
        policy_id: Option<&str>,
    ) -> Result<StorageUsageResponse> {
        let user = Self::get_user(db, user_id).await?;

        let used = match policy_id {
            Some(policy_id) => {
                let result: (i64,) = sqlx::query_as(
                    r#"
                    SELECT COALESCE(SUM(fb.size), 0)
                    FROM file_blobs fb
                    JOIN files f ON fb.file_id = f.id
                    WHERE f.user_id = ? AND fb.policy_id = ?
                    "#,
                )
                .bind(user_id)
                .bind(policy_id)
                .fetch_one(db.pool())
                .await?;
                result.0
            }
            None => {
                let result: (i64,) = sqlx::query_as(
                    r#"
                    SELECT COALESCE(SUM(fb.size), 0)
                    FROM file_blobs fb
                    JOIN files f ON fb.file_id = f.id
                    WHERE f.user_id = ?
                    "#,
                )
                .bind(user_id)
                .fetch_one(db.pool())
                .await?;
                result.0
            }
        };

        Ok(StorageUsageResponse {
            used,
            limit: user.storage_limit,
            percentage: if user.storage_limit > 0 {
                (used as f64 / user.storage_limit as f64 * 100.0).round() as u8
            } else {
                0
            },
        })
    }

    /// List all users (admin only)
    pub async fn list_users(db: &Database) -> Result<Vec<UserResponse>> {
        let users: Vec<User> = sqlx::query_as("SELECT * FROM users ORDER BY created_at DESC")
            .fetch_all(db.pool())
            .await?;

        Ok(users.into_iter().map(UserResponse::from).collect())
    }

    /// Update user status (admin only)
    pub async fn update_user_status(
        db: &Database,
        user_id: &str,
        is_active: bool,
    ) -> Result<UserResponse> {
        let now = chrono::Utc::now().to_rfc3339();

        sqlx::query("UPDATE users SET is_active = ?, updated_at = ? WHERE id = ?")
            .bind(is_active)
            .bind(&now)
            .bind(user_id)
            .execute(db.pool())
            .await?;

        let user = Self::get_user(db, user_id).await?;
        Ok(UserResponse::from(user))
    }

    /// Update user's storage usage
    pub async fn update_storage_used(db: &Database, user_id: &str, delta: i64) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE users 
            SET storage_used = MAX(0, storage_used + ?), 
                updated_at = datetime('now')
            WHERE id = ?
            "#,
        )
        .bind(delta)
        .bind(user_id)
        .execute(db.pool())
        .await?;

        Ok(())
    }
}

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct StorageUsageResponse {
    pub used: i64,
    pub limit: i64,
    pub percentage: u8,
}

