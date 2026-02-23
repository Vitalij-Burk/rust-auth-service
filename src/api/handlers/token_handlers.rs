use axum::{Json, extract::State, http::StatusCode};

use crate::{
    AppState, application::services::token::token_manager::TokenManagerError,
    domain::models::claims::Claims,
};

#[axum::debug_handler]
pub async fn generate_tokens(
    State(mut state): State<AppState>,
    Json(claims): Json<Claims>,
) -> Result<Json<(String, String)>, (StatusCode, &'static str)> {
    let private_key = state.key_manager.get_private().map_err(|error| match error {
        _ => {
            (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error")
        }
    })?;

    let (access_token, refresh_token) = state
        .token_manager
        .generate_pair(&claims, &private_key)
        .await
        .map_err(|error| match error {
            TokenManagerError::JwtError(_) | TokenManagerError::RedisError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
            TokenManagerError::NotFound(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error")
            }
        })?;

    Ok(Json((access_token, refresh_token)))
}

#[axum::debug_handler]
pub async fn verify_access_token(
    State(mut state): State<AppState>,
    Json(access): Json<String>,
) -> Result<Json<Claims>, (StatusCode, &'static str)> {
    let public_key = state.key_manager.get_public().map_err(|error| match error {
        _ => {
            (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error")
        }
    })?;

    println!("{}", public_key);

    let claims = state
        .token_manager
        .verify_access(&access, &public_key)
        .await
        .map_err(|error| match error {
            TokenManagerError::JwtError(_) | TokenManagerError::RedisError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
            TokenManagerError::NotFound(_) => (StatusCode::UNAUTHORIZED, "User unauthorized"),
        })?;

    Ok(Json(claims))
}

#[axum::debug_handler]
pub async fn refresh_token(
    State(mut state): State<AppState>,
    Json((refresh, access)): Json<(String, String)>,
) -> Result<Json<(String, String)>, (StatusCode, &'static str)> {
    let private_key = state.key_manager.get_private().map_err(|error| match error {
        _ => {
            (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error")
        }
    })?;
    let public_key = state.key_manager.get_public().map_err(|error| match error {
        _ => {
            (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error")
        }
    })?;

    let (access_token, refresh_token) = state
        .token_manager
        .refresh(&refresh, &access, &private_key, &public_key)
        .await
        .map_err(|error| match error {
            TokenManagerError::JwtError(_) | TokenManagerError::RedisError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
            TokenManagerError::NotFound(_) => (StatusCode::UNAUTHORIZED, "User unauthorized"),
        })?;

    Ok(Json((access_token, refresh_token)))
}

#[axum::debug_handler]
pub async fn revoke_access_token(
    State(mut state): State<AppState>,
    Json(access): Json<String>,
) -> Result<(), (StatusCode, &'static str)> {
    let public_key = state.key_manager.get_public().map_err(|error| match error {
        _ => {
            (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error")
        }
    })?;

    state
        .token_manager
        .revoke_access(&access, &public_key)
        .await
        .map_err(|error| match error {
            TokenManagerError::JwtError(_) | TokenManagerError::RedisError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
            TokenManagerError::NotFound(_) => (StatusCode::UNAUTHORIZED, "User wasn't authorized"),
        })?;

    Ok(())
}

#[axum::debug_handler]
pub async fn revoke_refresh_token(
    State(mut state): State<AppState>,
    Json(refresh): Json<String>,
) -> Result<(), (StatusCode, &'static str)> {
    state
        .token_manager
        .revoke_refresh(&refresh)
        .await
        .map_err(|error| match error {
            TokenManagerError::JwtError(_) | TokenManagerError::RedisError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
            TokenManagerError::NotFound(_) => (StatusCode::UNAUTHORIZED, "User wasn't authorized"),
        })?;

    Ok(())
}
