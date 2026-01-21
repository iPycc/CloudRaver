use axum::{
    extract::{ConnectInfo, State},
    http::HeaderMap,
    response::IntoResponse,
    Extension, Json,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use std::net::SocketAddr;

use crate::error::{ApiResponse, AppError, Result};
use crate::models::{CreateUserRequest, CurrentUser, Login2faRequest, LoginRequest, UserResponse};
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
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Result<impl IntoResponse> {
    // Extract User-Agent
    let user_agent = headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("Unknown");

    let device_info = AuthService::parse_user_agent(user_agent);
    let ip_address = addr.ip().to_string();

    let response = AuthService::login(
        &state.db,
        &state.config,
        req,
        Some(device_info),
        Some(ip_address),
    )
    .await?;

    let jar = if let Some(refresh_token) = response.refresh_token.as_ref() {
        let cookie = Cookie::build(("cr_refresh", refresh_token.clone()))
            .http_only(true)
            .same_site(SameSite::Lax)
            .secure(state.config.jwt.cookie_secure)
            .path("/api/v1")
            .build();
        CookieJar::new().add(cookie)
    } else {
        CookieJar::new()
    };

    Ok((jar, Json(ApiResponse::success(response))))
}

/// Verify 2FA code for password login
/// POST /api/v1/auth/login/2fa
pub async fn login_2fa(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<Login2faRequest>,
) -> Result<impl IntoResponse> {
    let user_agent = headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("Unknown");
    let device_info = AuthService::parse_user_agent(user_agent);
    let ip_address = addr.ip().to_string();

    let response = AuthService::login_2fa(
        &state.db,
        &state.config,
        &req.mfa_token,
        &req.code,
        Some(device_info),
        Some(ip_address),
    )
    .await?;

    let jar = if let Some(refresh_token) = response.refresh_token.as_ref() {
        let cookie = Cookie::build(("cr_refresh", refresh_token.clone()))
            .http_only(true)
            .same_site(SameSite::Lax)
            .secure(state.config.jwt.cookie_secure)
            .path("/api/v1")
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
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<impl IntoResponse> {
    let user_agent = headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("Unknown");
    let device_info = AuthService::parse_user_agent(user_agent);
    let ip_address = addr.ip().to_string();

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

    let response = AuthService::refresh_token(
        &state.db,
        &state.config,
        &refresh_token,
        Some(device_info),
        Some(ip_address),
    )
    .await?;

    let mut jar = jar;
    let cookie = Cookie::build(("cr_refresh", refresh_token.clone()))
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(state.config.jwt.cookie_secure)
        .path("/api/v1")
        .build();
    jar = jar.add(cookie);

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
        .path("/api/v1")
        .build();
    Ok((
        jar.remove(remove),
        Json(ApiResponse::<()>::success_message("Logged out successfully")),
    ))
}

/// List user sessions
/// GET /api/v1/user/sessions
pub async fn list_sessions(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<ApiResponse<Vec<crate::models::SessionInfo>>>> {
    // Try to get current refresh token to mark current session
    let current_token = jar
        .get("cr_refresh")
        .map(|c| c.value().to_string())
        .or_else(|| {
            headers
                .get("X-Refresh-Token")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string())
        });

    let current_token_hash = current_token.map(|t| AuthService::hash_token(&t));

    let sessions = AuthService::list_sessions(&state.db, &current_user.id, current_token_hash).await?;
    Ok(Json(ApiResponse::success(sessions)))
}

/// Delete a specific session
/// DELETE /api/v1/user/sessions/:id
pub async fn delete_session(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    axum::extract::Path(session_id): axum::extract::Path<String>,
) -> Result<Json<ApiResponse<()>>> {
    AuthService::delete_session(&state.db, &current_user.id, &session_id).await?;
    Ok(Json(ApiResponse::<()>::success_message("Session deleted successfully")))
}

/// Delete all other sessions
/// DELETE /api/v1/user/sessions/others
pub async fn delete_other_sessions(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<ApiResponse<()>>> {
    // Get current refresh token
    let current_token = jar
        .get("cr_refresh")
        .map(|c| c.value().to_string())
        .or_else(|| {
            headers
                .get("X-Refresh-Token")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string())
        })
        .ok_or_else(|| AppError::Unauthorized("Missing refresh token".to_string()))?;

    let current_token_hash = AuthService::hash_token(&current_token);

    AuthService::delete_other_sessions(&state.db, &current_user.id, &current_token_hash).await?;
    Ok(Json(ApiResponse::<()>::success_message("Other sessions deleted successfully")))
}
