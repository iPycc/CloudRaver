use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand::rngs::OsRng;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use uuid::Uuid;

use crate::config::Config;
use crate::db::Database;
use crate::error::{AppError, Result};
use crate::models::{
    Claims, CreateUserRequest, LoginRequest, LoginResponse, RefreshToken, User, UserResponse,
    UserRole,
};

/// Authentication service
pub struct AuthService;

impl AuthService {
    /// Register a new user
    pub async fn register(db: &Database, req: CreateUserRequest) -> Result<UserResponse> {
        // Validate email
        if !req.email.contains('@') {
            return Err(AppError::BadRequest("Invalid email format".to_string()));
        }

        // Validate password
        if req.password.len() < 6 {
            return Err(AppError::BadRequest(
                "Password must be at least 6 characters".to_string(),
            ));
        }

        // Check if email already exists
        let existing: Option<User> = sqlx::query_as("SELECT * FROM users WHERE email = ?")
            .bind(&req.email)
            .fetch_optional(db.pool())
            .await?;

        if existing.is_some() {
            return Err(AppError::Conflict("Email already registered".to_string()));
        }

        // Check if this is the first user (will be admin)
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
            .fetch_one(db.pool())
            .await?;

        let role = if count.0 == 0 {
            UserRole::Admin
        } else {
            UserRole::User
        };

        // Hash password
        let password_hash = Self::hash_password(&req.password)?;

        // Create user
        let user_id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO users (id, email, name, password_hash, role, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&user_id)
        .bind(&req.email)
        .bind(&req.name)
        .bind(&password_hash)
        .bind(role.as_str())
        .bind(&now)
        .bind(&now)
        .execute(db.pool())
        .await?;

        // Fetch created user
        let user: User = sqlx::query_as("SELECT * FROM users WHERE id = ?")
            .bind(&user_id)
            .fetch_one(db.pool())
            .await?;

        // Create default local storage policy for the user
        Self::create_default_storage_policy(db, &user_id).await?;

        Ok(UserResponse::from(user))
    }

    /// Create default local storage policy for a new user
    async fn create_default_storage_policy(db: &Database, user_id: &str) -> Result<()> {
        let policy_id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        let config = serde_json::json!({
            "base_path": "data/uploads"
        });

        sqlx::query(
            r#"
            INSERT INTO storage_policies (id, user_id, name, policy_type, config, is_default, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&policy_id)
        .bind(user_id)
        .bind("Default Local Storage")
        .bind("local")
        .bind(config.to_string())
        .bind(true)
        .bind(&now)
        .bind(&now)
        .execute(db.pool())
        .await?;

        // Set as user's default policy
        sqlx::query("UPDATE users SET default_policy_id = ? WHERE id = ?")
            .bind(&policy_id)
            .bind(user_id)
            .execute(db.pool())
            .await?;

        Ok(())
    }

    /// Login user
    pub async fn login(
        db: &Database,
        config: &Config,
        req: LoginRequest,
    ) -> Result<LoginResponse> {
        // Find user
        let user: User = sqlx::query_as("SELECT * FROM users WHERE email = ?")
            .bind(&req.email)
            .fetch_optional(db.pool())
            .await?
            .ok_or_else(|| AppError::Unauthorized("Invalid email or password".to_string()))?;

        // Check if user is active
        if !user.is_active {
            return Err(AppError::Forbidden("Account is disabled".to_string()));
        }

        // Verify password
        if !Self::verify_password(&req.password, &user.password_hash)? {
            return Err(AppError::Unauthorized("Invalid email or password".to_string()));
        }

        // Generate tokens
        let access_token = Self::generate_access_token(&user, config)?;
        let refresh_token = Self::generate_refresh_token(db, &user.id, config).await?;

        Ok(LoginResponse {
            access_token,
            refresh_token: Some(refresh_token),
            token_type: "Bearer".to_string(),
            expires_in: config.jwt.access_token_expire_minutes * 60,
            user: UserResponse::from(user),
        })
    }

    /// Refresh access token
    pub async fn refresh_token(
        db: &Database,
        config: &Config,
        refresh_token: &str,
    ) -> Result<LoginResponse> {
        let mut tx = db.pool().begin().await?;

        // Hash the refresh token to compare
        let token_hash = Self::hash_token(refresh_token);

        // Find valid refresh token
        let stored_token: RefreshToken = sqlx::query_as("SELECT * FROM refresh_tokens WHERE token_hash = ?")
                .bind(&token_hash)
                .fetch_optional(tx.as_mut())
                .await?
                .ok_or_else(|| AppError::Unauthorized("Invalid refresh token".to_string()))?;

        // Check if token is expired
        let expires_at = chrono::DateTime::parse_from_rfc3339(&stored_token.expires_at)
            .map_err(|_| AppError::Internal("Invalid token expiry format".to_string()))?;

        if expires_at < Utc::now() {
            // Delete expired token
            sqlx::query("DELETE FROM refresh_tokens WHERE id = ?")
                .bind(&stored_token.id)
                .execute(tx.as_mut())
                .await?;
            tx.commit().await?;
            return Err(AppError::Unauthorized("Refresh token expired".to_string()));
        }

        // Get user
        let user: User = sqlx::query_as("SELECT * FROM users WHERE id = ?")
            .bind(&stored_token.user_id)
            .fetch_one(tx.as_mut())
            .await?;

        if !user.is_active {
            return Err(AppError::Forbidden("Account is disabled".to_string()));
        }

        // Generate new access token
        let access_token = Self::generate_access_token(&user, config)?;
        let new_refresh_token = Self::generate_refresh_token_tx(tx.as_mut(), &user.id, config).await?;

        sqlx::query("DELETE FROM refresh_tokens WHERE id = ?")
            .bind(&stored_token.id)
            .execute(tx.as_mut())
            .await?;

        tx.commit().await?;

        Ok(LoginResponse {
            access_token,
            refresh_token: Some(new_refresh_token),
            token_type: "Bearer".to_string(),
            expires_in: config.jwt.access_token_expire_minutes * 60,
            user: UserResponse::from(user),
        })
    }

    /// Logout user (invalidate refresh token)
    pub async fn logout(db: &Database, user_id: &str) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        sqlx::query("UPDATE users SET token_version = token_version + 1, updated_at = ? WHERE id = ?")
            .bind(&now)
            .bind(user_id)
            .execute(db.pool())
            .await?;
        sqlx::query("DELETE FROM refresh_tokens WHERE user_id = ?")
            .bind(user_id)
            .execute(db.pool())
            .await?;
        Ok(())
    }

    /// Generate access token (JWT)
    fn generate_access_token(user: &User, config: &Config) -> Result<String> {
        let now = Utc::now();
        let exp = now + Duration::minutes(config.jwt.access_token_expire_minutes as i64);

        let claims = Claims {
            sub: user.id.clone(),
            email: user.email.clone(),
            role: user.role.clone(),
            ver: user.token_version,
            jti: Uuid::new_v4().to_string(),
            exp: exp.timestamp() as usize,
            iat: now.timestamp() as usize,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(config.jwt.secret.as_bytes()),
        )?;

        Ok(token)
    }

    /// Generate refresh token
    async fn generate_refresh_token(
        db: &Database,
        user_id: &str,
        config: &Config,
    ) -> Result<String> {
        let mut tx = db.pool().begin().await?;
        let token = Self::generate_refresh_token_tx(tx.as_mut(), user_id, config).await?;
        tx.commit().await?;
        Ok(token)
    }

    async fn generate_refresh_token_tx(
        conn: &mut sqlx::SqliteConnection,
        user_id: &str,
        config: &Config,
    ) -> Result<String> {
        // Generate random token
        let token = Uuid::new_v4().to_string();
        let token_hash = Self::hash_token(&token);

        let id = Uuid::new_v4().to_string();
        let expires_at =
            (Utc::now() + Duration::days(config.jwt.refresh_token_expire_days as i64)).to_rfc3339();
        let now = Utc::now().to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(user_id)
        .bind(&token_hash)
        .bind(&expires_at)
        .bind(&now)
        .execute(conn)
        .await?;

        Ok(token)
    }

    /// Validate access token and extract claims
    pub fn validate_token(token: &str, config: &Config) -> Result<Claims> {
        let mut validation = Validation::default();
        validation.validate_exp = true;

        let keys = std::iter::once(config.jwt.secret.as_str())
            .chain(config.jwt.previous_secrets.iter().map(|s| s.as_str()));

        for secret in keys {
            if let Ok(token_data) = decode::<Claims>(
                token,
                &DecodingKey::from_secret(secret.as_bytes()),
                &validation,
            ) {
                return Ok(token_data.claims);
            }
        }

        Err(AppError::Unauthorized("Invalid token".to_string()))
    }

    /// Hash password using Argon2
    fn hash_password(password: &str) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AppError::Internal(format!("Password hashing failed: {}", e)))?
            .to_string();

        Ok(password_hash)
    }

    /// Verify password against hash
    fn verify_password(password: &str, hash: &str) -> Result<bool> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| AppError::Internal(format!("Invalid password hash: {}", e)))?;

        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }

    /// Hash token for storage
    fn hash_token(token: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Change user password
    pub async fn change_password(
        db: &Database,
        user_id: &str,
        old_password: &str,
        new_password: &str,
    ) -> Result<()> {
        // Get user
        let user: User = sqlx::query_as("SELECT * FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_one(db.pool())
            .await?;

        // Verify old password
        if !Self::verify_password(old_password, &user.password_hash)? {
            return Err(AppError::BadRequest("Invalid old password".to_string()));
        }

        // Validate new password
        if new_password.len() < 6 {
            return Err(AppError::BadRequest(
                "Password must be at least 6 characters".to_string(),
            ));
        }

        // Hash new password
        let new_hash = Self::hash_password(new_password)?;

        // Update password
        let now = Utc::now().to_rfc3339();
        sqlx::query("UPDATE users SET password_hash = ?, token_version = token_version + 1, updated_at = ? WHERE id = ?")
            .bind(&new_hash)
            .bind(&now)
            .bind(user_id)
            .execute(db.pool())
            .await?;

        // Invalidate all refresh tokens
        sqlx::query("DELETE FROM refresh_tokens WHERE user_id = ?")
            .bind(user_id)
            .execute(db.pool())
            .await?;

        Ok(())
    }
}
