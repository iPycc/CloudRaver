use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};

use crate::error::AppError;
use crate::models::{CurrentUser, UserRole};
use crate::services::AuthService;
use crate::AppState;

/// Authentication middleware
/// Extracts and validates JWT from Authorization header
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    // Get Authorization header
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok());

    let token = match auth_header {
        Some(header) if header.starts_with("Bearer ") => &header[7..],
        _ => {
            return Err(AppError::Unauthorized(
                "Missing or invalid Authorization header".to_string(),
            ));
        }
    };

    // Validate token
    let claims = AuthService::validate_token(token, &state.config)?;

    let (db_email, db_role, is_active, token_version): (String, String, i64, i64) =
        sqlx::query_as("SELECT email, role, is_active, token_version FROM users WHERE id = ?")
            .bind(&claims.sub)
            .fetch_one(state.db.pool())
            .await
            .map_err(|_| AppError::Unauthorized("Invalid token".to_string()))?;

    if is_active == 0 {
        return Err(AppError::Forbidden("Account is disabled".to_string()));
    }

    if token_version != claims.ver {
        return Err(AppError::Unauthorized("Session expired".to_string()));
    }

    // Create current user
    let current_user = CurrentUser {
        id: claims.sub,
        email: db_email,
        role: UserRole::from_str(&db_role),
    };

    // Insert current user into request extensions
    request.extensions_mut().insert(current_user);

    Ok(next.run(request).await)
}

/// Extension trait for extracting current user from request
pub trait CurrentUserExt {
    fn current_user(&self) -> Option<&CurrentUser>;
}

impl<B> CurrentUserExt for Request<B> {
    fn current_user(&self) -> Option<&CurrentUser> {
        self.extensions().get::<CurrentUser>()
    }
}
