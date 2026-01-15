use axum::{
    extract::State,
    http::HeaderMap,
    response::IntoResponse,
    Extension, Json,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};

use crate::error::{ApiResponse, AppError, Result};
use crate::models::{CreateUserRequest, CurrentUser, LoginRequest, UserResponse};
use crate::services::AuthService;
use crate::AppState;

/// Register a new user
/// POST /api/v1/auth/register
pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<CreateUserRequest>,
) -> Result<Json<ApiResponse<UserResponse>>> {
    let user = AuthService::register(&state.db, req).await?;
    Ok(Json(ApiResponse::success(user)))
}

/// Login user
/// POST /api/v1/auth/login
pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<impl IntoResponse> {
    let response = AuthService::login(&state.db, &state.config, req).await?;

    let jar = if let Some(refresh_token) = response.refresh_token.as_ref() {
        let cookie = Cookie::build(("cr_refresh", refresh_token.clone()))
            .http_only(true)
            .same_site(SameSite::Lax)
            .secure(state.config.jwt.cookie_secure)
            .path("/api/v1/auth")
            .build();
        CookieJar::new().add(cookie)
    } else {
        CookieJar::new()
    };

    Ok((jar, Json(ApiResponse::success(response))))
}

/// Refresh access token
/// POST /api/v1/auth/refresh
pub async fn refresh_token(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<impl IntoResponse> {
    let refresh_token = jar
        .get("cr_refresh")
        .map(|c| c.value().to_string())
        .or_else(|| {
            headers
                .get("X-Refresh-Token")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string())
        })
        .ok_or_else(|| AppError::Unauthorized("Missing refresh token".to_string()))?;

    let response = AuthService::refresh_token(&state.db, &state.config, &refresh_token).await?;

    let mut jar = jar;
    if let Some(refresh_token) = response.refresh_token.as_ref() {
        let cookie = Cookie::build(("cr_refresh", refresh_token.clone()))
            .http_only(true)
            .same_site(SameSite::Lax)
            .secure(state.config.jwt.cookie_secure)
            .path("/api/v1/auth")
            .build();
        jar = jar.add(cookie);
    }

    Ok((jar, Json(ApiResponse::success(response))))
}

/// Logout user
/// POST /api/v1/auth/logout
pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<impl IntoResponse> {
    AuthService::logout(&state.db, &current_user.id).await?;
    let remove = Cookie::build(("cr_refresh", ""))
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(state.config.jwt.cookie_secure)
        .path("/api/v1/auth")
        .build();
    Ok((
        jar.remove(remove),
        Json(ApiResponse::<()>::success_message("Logged out successfully")),
    ))
}
