use axum::{Extension, Json, extract::State};
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;

use crate::error::{ApiResponse, AppError, Result};
use crate::models::{CurrentUser, ReauthPasswordRequest, ReauthResponse};
use crate::services::{AuthService, PasskeyService};
use crate::AppState;

#[derive(Debug, Serialize)]
pub struct BeginPasskeyReauthResponse {
    pub challenge_id: String,
    pub options: RequestChallengeResponse,
}

#[derive(Debug, Deserialize)]
pub struct FinishPasskeyReauthRequest {
    pub challenge_id: String,
    pub credential: PublicKeyCredential,
}

pub async fn reauth_password(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<ReauthPasswordRequest>,
) -> Result<Json<ApiResponse<ReauthResponse>>> {
    let token = AuthService::reauth_with_password(&state.db, &current_user.id, &req.password).await?;
    Ok(Json(ApiResponse::success(ReauthResponse { reauth_token: token })))
}

pub async fn begin_passkey_reauth(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<ApiResponse<BeginPasskeyReauthResponse>>> {
    let (options, auth_state) =
        PasskeyService::begin_authenticate(&state.db, &state.config, Some(&current_user.id)).await?;
    let state_json = serde_json::to_string(&auth_state)
        .map_err(|_| AppError::Internal("Serialize authentication state failed".to_string()))?;
    let challenge_id = PasskeyService::store_challenge(
        &state.db,
        Some(&current_user.id),
        "reauth",
        state_json,
        300,
    )
    .await?;

    Ok(Json(ApiResponse::success(BeginPasskeyReauthResponse {
        challenge_id,
        options,
    })))
}

pub async fn finish_passkey_reauth(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<FinishPasskeyReauthRequest>,
) -> Result<Json<ApiResponse<ReauthResponse>>> {
    let ch = PasskeyService::load_challenge(&state.db, &req.challenge_id, "reauth").await?;
    if ch.user_id.as_deref() != Some(current_user.id.as_str()) {
        return Err(AppError::Forbidden("Forbidden".to_string()));
    }

    let auth_state: PasskeyAuthentication = serde_json::from_str(&ch.state_json)
        .map_err(|_| AppError::Internal("Deserialize authentication state failed".to_string()))?;

    let (user, _passkey_id) =
        PasskeyService::finish_authenticate(&state.db, &state.config, req.credential, auth_state)
            .await?;
    if user.id != current_user.id {
        return Err(AppError::Unauthorized("Invalid reauth".to_string()));
    }
    PasskeyService::mark_challenge_used(&state.db, &req.challenge_id).await?;

    let token = AuthService::create_reauth_token(&state.db, &current_user.id).await?;
    Ok(Json(ApiResponse::success(ReauthResponse { reauth_token: token })))
}

