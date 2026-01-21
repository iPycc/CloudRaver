use axum::{
    extract::{ConnectInfo, State},
    http::HeaderMap,
    response::IntoResponse,
    Extension, Json,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use webauthn_rs::prelude::*;

use crate::error::{ApiResponse, AppError, Result};
use crate::models::{CurrentUser, PasskeyCredential, User};
use crate::services::{AuthService, PasskeyService};
use crate::AppState;

#[derive(Debug, Serialize)]
pub struct BeginPasskeyRegisterResponse {
    pub challenge_id: String,
    pub options: CreationChallengeResponse,
}

#[derive(Debug, Deserialize)]
pub struct FinishPasskeyRegisterRequest {
    pub challenge_id: String,
    pub credential: RegisterPublicKeyCredential,
    pub nickname: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct FinishPasskeyRegisterResponse {
    pub passkey_id: String,
}

#[derive(Debug, Deserialize)]
pub struct BeginPasskeyAuthRequest {
    pub email: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BeginPasskeyAuthResponse {
    pub challenge_id: String,
    pub options: RequestChallengeResponse,
}

#[derive(Debug, Deserialize)]
pub struct FinishPasskeyAuthRequest {
    pub challenge_id: String,
    pub credential: PublicKeyCredential,
}

#[derive(Debug, Serialize)]
pub struct ListPasskeysResponse {
    pub id: String,
    pub nickname: Option<String>,
    pub device_info: Option<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

pub async fn begin_register(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<ApiResponse<BeginPasskeyRegisterResponse>>> {
    let user: User = sqlx::query_as("SELECT * FROM users WHERE id = ?")
        .bind(&current_user.id)
        .fetch_one(state.db.pool())
        .await?;

    let (options, reg_state) = PasskeyService::begin_register(
        &state.db,
        &state.config,
        &user.id,
        &user.email,
        &user.name,
    )
    .await?;

    let state_json = serde_json::to_string(&reg_state)
        .map_err(|_| AppError::Internal("Serialize registration state failed".to_string()))?;
    let challenge_id =
        PasskeyService::store_challenge(&state.db, Some(&user.id), "register", state_json, 300)
            .await?;

    Ok(Json(ApiResponse::success(BeginPasskeyRegisterResponse {
        challenge_id,
        options,
    })))
}

pub async fn finish_register(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<FinishPasskeyRegisterRequest>,
) -> Result<Json<ApiResponse<FinishPasskeyRegisterResponse>>> {
    let ch = PasskeyService::load_challenge(&state.db, &req.challenge_id, "register").await?;
    if ch.user_id.as_deref() != Some(current_user.id.as_str()) {
        return Err(AppError::Forbidden("Forbidden".to_string()));
    }

    let reg_state: PasskeyRegistration = serde_json::from_str(&ch.state_json)
        .map_err(|_| AppError::Internal("Deserialize registration state failed".to_string()))?;

    let user_agent = headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("Unknown");
    let device_info = AuthService::parse_user_agent(user_agent);
    let ip_address = addr.ip().to_string();

    let stored = PasskeyService::finish_register(
        &state.db,
        &state.config,
        &current_user.id,
        req.credential,
        reg_state,
        req.nickname,
        Some(device_info),
        Some(ip_address),
    )
    .await?;

    PasskeyService::mark_challenge_used(&state.db, &req.challenge_id).await?;

    Ok(Json(ApiResponse::success(FinishPasskeyRegisterResponse {
        passkey_id: stored.id,
    })))
}

pub async fn begin_authenticate(
    State(state): State<AppState>,
    Json(req): Json<BeginPasskeyAuthRequest>,
) -> Result<Json<ApiResponse<BeginPasskeyAuthResponse>>> {
    let email = req.email.unwrap_or_default();
    let email = email.trim().to_string();

    let (options, auth_state, user_id) = if !email.is_empty() {
        let user: Option<User> = sqlx::query_as("SELECT * FROM users WHERE email = ?")
            .bind(&email)
            .fetch_optional(state.db.pool())
            .await?;

        let user =
            user.ok_or_else(|| AppError::Unauthorized("Unable to login with passkey".to_string()))?;
        if !user.is_active {
            return Err(AppError::Forbidden("Account is disabled".to_string()));
        }

        let (options, auth_state) =
            PasskeyService::begin_authenticate(&state.db, &state.config, Some(&user.id)).await?;
        (options, auth_state, Some(user.id))
    } else {
        let (options, auth_state) =
            PasskeyService::begin_authenticate(&state.db, &state.config, None).await?;
        (options, auth_state, None)
    };

    let state_json = serde_json::to_string(&auth_state)
        .map_err(|_| AppError::Internal("Serialize authentication state failed".to_string()))?;
    let challenge_id =
        PasskeyService::store_challenge(&state.db, user_id.as_deref(), "auth", state_json, 300)
            .await?;

    Ok(Json(ApiResponse::success(BeginPasskeyAuthResponse {
        challenge_id,
        options,
    })))
}

pub async fn finish_authenticate(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    _jar: CookieJar,
    Json(req): Json<FinishPasskeyAuthRequest>,
) -> Result<impl IntoResponse> {
    let user_agent = headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("Unknown");
    let device_info = AuthService::parse_user_agent(user_agent);
    let ip_address = addr.ip().to_string();

    let ch = PasskeyService::load_challenge(&state.db, &req.challenge_id, "auth").await?;
    let expected_user_id = ch.user_id.clone();

    let auth_state: PasskeyAuthentication = serde_json::from_str(&ch.state_json)
        .map_err(|_| AppError::Internal("Deserialize authentication state failed".to_string()))?;

    let (user, _passkey_id) =
        PasskeyService::finish_authenticate(&state.db, &state.config, req.credential, auth_state)
            .await?;
    if let Some(expected) = expected_user_id.as_deref() {
        if user.id != expected {
            return Err(AppError::Unauthorized("Unable to login with passkey".to_string()));
        }
    }

    PasskeyService::mark_challenge_used(&state.db, &req.challenge_id).await?;

    let response = AuthService::login_user(
        &state.db,
        &state.config,
        &user.id,
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

pub async fn list_passkeys(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<ApiResponse<Vec<ListPasskeysResponse>>>> {
    let keys: Vec<PasskeyCredential> = sqlx::query_as(
        r#"
        SELECT id, user_id, credential_id, credential_json, nickname, device_info, ip_address, created_at, last_used_at
        FROM webauthn_passkeys
        WHERE user_id = ?
        ORDER BY created_at DESC
        "#,
    )
    .bind(&current_user.id)
    .fetch_all(state.db.pool())
    .await?;

    let data = keys
        .into_iter()
        .map(|k| ListPasskeysResponse {
            id: k.id,
            nickname: k.nickname,
            device_info: k.device_info,
            created_at: k.created_at,
            last_used_at: k.last_used_at,
        })
        .collect();

    Ok(Json(ApiResponse::success(data)))
}

pub async fn delete_passkey(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    axum::extract::Path(passkey_id): axum::extract::Path<String>,
) -> Result<Json<ApiResponse<()>>> {
    let affected = sqlx::query("DELETE FROM webauthn_passkeys WHERE id = ? AND user_id = ?")
        .bind(&passkey_id)
        .bind(&current_user.id)
        .execute(state.db.pool())
        .await?
        .rows_affected();
    if affected == 0 {
        return Err(AppError::NotFound("Passkey not found".to_string()));
    }
    Ok(Json(ApiResponse::<()>::success_message("Passkey deleted successfully")))
}
