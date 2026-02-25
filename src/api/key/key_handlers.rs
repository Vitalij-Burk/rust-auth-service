use axum::{extract::State, http::StatusCode};

use crate::AppState;

#[axum::debug_handler]
pub async fn get_public_key(
    State(state): State<AppState>,
) -> Result<String, (StatusCode, &'static str)> {
    let public_key = state
        .key_manager
        .get_public()
        .map_err(|error| match error {
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error"),
        })?;

    Ok(public_key)
}
