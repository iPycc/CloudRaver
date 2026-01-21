use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// User role
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    Admin,
    User,
}

impl UserRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            UserRole::Admin => "admin",
            UserRole::User => "user",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "admin" => UserRole::Admin,
            _ => UserRole::User,
        }
    }

    pub fn is_admin(&self) -> bool {
        matches!(self, UserRole::Admin)
    }
}

/// User model
#[derive(Debug, Clone, FromRow)]
pub struct User {
    pub id: String,
    pub email: String,
    pub name: String,
    pub password_hash: String,
    pub role: String,
    pub default_policy_id: Option<String>,
    pub storage_used: i64,
    pub storage_limit: i64,
    pub is_active: bool,
    pub token_version: i64,
    pub totp_enabled: i64,
    pub totp_secret: Option<String>,
    pub totp_last_step: Option<i64>,
    pub avatar_key: Option<String>,
    pub avatar_path: Option<String>,
    pub avatar_mime: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl User {
    pub fn get_role(&self) -> UserRole {
        UserRole::from_str(&self.role)
    }

    pub fn is_admin(&self) -> bool {
        self.get_role().is_admin()
    }
}

/// User response (without sensitive data)
#[derive(Debug, Clone, Serialize)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    pub name: String,
    pub role: String,
    pub default_policy_id: Option<String>,
    pub storage_used: i64,
    pub storage_limit: i64,
    pub is_active: bool,
    pub totp_enabled: bool,
    pub avatar_url: Option<String>,
    pub created_at: String,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            email: user.email,
            name: user.name,
            role: user.role,
            default_policy_id: user.default_policy_id,
            storage_used: user.storage_used,
            storage_limit: user.storage_limit,
            is_active: user.is_active,
            totp_enabled: user.totp_enabled != 0,
            avatar_url: user
                .avatar_key
                .as_ref()
                .map(|k| format!("/api/v1/avatar/{}", k)),
            created_at: user.created_at,
        }
    }
}

/// Create user request
#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub name: String,
    pub password: String,
}

/// Login request
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

/// Login response
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub mfa_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    pub token_type: String,
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<UserResponse>,
}

/// Change password request
#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub reauth_token: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize)]
pub struct Login2faRequest {
    pub mfa_token: String,
    pub code: String,
}

#[derive(Debug, Serialize)]
pub struct TotpBeginResponse {
    pub challenge_id: String,
    pub otpauth_url: String,
}

#[derive(Debug, Deserialize)]
pub struct TotpEnableRequest {
    pub challenge_id: String,
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct TotpDisableRequest {
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct ReauthPasswordRequest {
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct ReauthResponse {
    pub reauth_token: String,
}

/// Update profile request
#[derive(Debug, Deserialize)]
pub struct UpdateProfileRequest {
    pub name: Option<String>,
}

/// Current authenticated user (extracted from JWT)
#[derive(Debug, Clone)]
pub struct CurrentUser {
    pub id: String,
    pub email: String,
    pub role: UserRole,
}

impl CurrentUser {
    pub fn is_admin(&self) -> bool {
        self.role.is_admin()
    }
}

/// JWT Claims
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,       // user id
    pub email: String,
    pub role: String,
    pub ver: i64,
    #[serde(default)]
    pub sid: Option<String>,
    pub jti: String,
    pub exp: usize,        // expiration time
    pub iat: usize,        // issued at
}

/// Refresh token model
#[derive(Debug, Clone, FromRow)]
pub struct RefreshToken {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub device_info: Option<String>,
    pub ip_address: Option<String>,
    pub expires_at: String,
    pub created_at: String,
}

/// Session info response
#[derive(Debug, Clone, Serialize)]
pub struct SessionInfo {
    pub id: String,
    pub device_info: String,
    pub ip_address: String,
    pub location: Option<String>,
    pub created_at: String,
    pub is_current: bool,
}
