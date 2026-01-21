use axum::{Extension, Json, extract::State};

use crate::error::{ApiResponse, Result};
use crate::models::{CurrentUser, TotpBeginResponse, TotpDisableRequest, TotpEnableRequest};
use crate::services::TwoFactorService;
use crate::AppState;

pub async fn begin_totp(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<ApiResponse<TotpBeginResponse>>> {
    let (challenge_id, otpauth_url) =
        TwoFactorService::begin_totp_enroll(&state.db, &state.config, &current_user.id).await?;
    Ok(Json(ApiResponse::success(TotpBeginResponse {
        challenge_id,
        otpauth_url,
    })))
}

pub async fn enable_totp(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<TotpEnableRequest>,
) -> Result<Json<ApiResponse<()>>> {
    TwoFactorService::enable_totp(
        &state.db,
        &state.config,
        &current_user.id,
        &req.challenge_id,
        &req.code,
    )
    .await?;
    Ok(Json(ApiResponse::<()>::success_message(
        "Two-factor authentication enabled",
    )))
}

pub async fn disable_totp(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<TotpDisableRequest>,
) -> Result<Json<ApiResponse<()>>> {
    TwoFactorService::disable_totp(&state.db, &state.config, &current_user.id, &req.code).await?;
    Ok(Json(ApiResponse::<()>::success_message(
        "Two-factor authentication disabled",
    )))
}

