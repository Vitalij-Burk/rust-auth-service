use axum::{Json, extract::State, http::StatusCode};

use crate::{
    AppState, api::token::models::ClaimsDTO,
    application::services::token::token_manager::TokenManagerError, domain::models::claims::Claims,
};

pub async fn generate_tokens(
    State(mut state): State<AppState>,
    Json(claims): Json<ClaimsDTO>,
) -> Result<Json<(String, (String, String))>, (StatusCode, &'static str)> {
    let private_key = state
        .key_manager
        .get_private()
        .map_err(|error| match error {
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error"),
        })?;

    println!("Handler before generate");

    let (access_token, (encrypted_refresh_token, nonce)) = state
        .token_manager
        .generate_pair(&Claims::from(&claims), &private_key)
        .await
        .map_err(|error| match error {
            TokenManagerError::RedisError(_)
            | TokenManagerError::JwksTokenProvider(_)
            | TokenManagerError::JwksTokenValidator(_)
            | TokenManagerError::Crypto(_)
            | TokenManagerError::FromUTF8(_)
            | TokenManagerError::Cryptographer(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
            TokenManagerError::NotFound(_) | TokenManagerError::Unexpected(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error")
            }
        })?;

    println!("Handler after generate");

    Ok(Json((access_token, (encrypted_refresh_token, nonce))))
}

pub async fn verify_access_token(
    State(mut state): State<AppState>,
    Json(access): Json<String>,
) -> Result<Json<Claims>, (StatusCode, &'static str)> {
    let public_key = state
        .key_manager
        .get_public()
        .map_err(|error| match error {
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error"),
        })?;

    let claims = state
        .token_manager
        .verify_access(&access, &public_key)
        .await
        .map_err(|error| match error {
            TokenManagerError::RedisError(_)
            | TokenManagerError::JwksTokenProvider(_)
            | TokenManagerError::JwksTokenValidator(_)
            | TokenManagerError::Crypto(_)
            | TokenManagerError::FromUTF8(_)
            | TokenManagerError::Cryptographer(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
            TokenManagerError::NotFound(_) => (StatusCode::UNAUTHORIZED, "User unauthorized"),
            TokenManagerError::Unexpected(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error")
            }
        })?;

    Ok(Json(claims))
}

pub async fn refresh_token(
    State(mut state): State<AppState>,
    Json(((encrypted_refresh, nonce), access)): Json<((String, String), String)>,
) -> Result<Json<(String, (String, String))>, (StatusCode, &'static str)> {
    let private_key = state
        .key_manager
        .get_private()
        .map_err(|error| match error {
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error"),
        })?;
    let public_key = state
        .key_manager
        .get_public()
        .map_err(|error| match error {
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error"),
        })?;

    let (access_token, (encrypted_refresh_token, nonce)) = state
        .token_manager
        .refresh(
            &encrypted_refresh,
            &nonce,
            &access,
            &private_key,
            &public_key,
        )
        .await
        .map_err(|error| match error {
            TokenManagerError::RedisError(_)
            | TokenManagerError::JwksTokenProvider(_)
            | TokenManagerError::JwksTokenValidator(_)
            | TokenManagerError::Crypto(_)
            | TokenManagerError::FromUTF8(_)
            | TokenManagerError::Cryptographer(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
            TokenManagerError::NotFound(_) => (StatusCode::UNAUTHORIZED, "User unauthorized"),
            TokenManagerError::Unexpected(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error")
            }
        })?;

    Ok(Json((access_token, (encrypted_refresh_token, nonce))))
}

pub async fn revoke_refresh_token(
    State(mut state): State<AppState>,
    Json((encrypted_refresh, nonce)): Json<(String, String)>,
) -> Result<(), (StatusCode, &'static str)> {
    state
        .token_manager
        .revoke_refresh(&encrypted_refresh, &nonce)
        .await
        .map_err(|error| match error {
            TokenManagerError::RedisError(_)
            | TokenManagerError::JwksTokenProvider(_)
            | TokenManagerError::JwksTokenValidator(_)
            | TokenManagerError::Crypto(_)
            | TokenManagerError::FromUTF8(_)
            | TokenManagerError::Cryptographer(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
            TokenManagerError::NotFound(_) => (StatusCode::UNAUTHORIZED, "User wasn't authorized"),
            TokenManagerError::Unexpected(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error")
            }
        })?;

    Ok(())
}
