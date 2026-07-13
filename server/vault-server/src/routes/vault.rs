use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

use crate::db;
use crate::error::ApiError;
use crate::state::{AppState, AuthSession};

/// GET /api/v1/vault/keys — the account's encrypted key blobs and KDF
/// parameters. Everything returned here is ciphertext or public parameters;
/// only the client can make use of it.
pub async fn get_keys(
    State(state): State<AppState>,
    session: AuthSession,
) -> Result<Json<Value>, ApiError> {
    let account = db::account_by_id(&state.db, session.account_id)
        .await?
        .ok_or(ApiError::Internal)?;

    fn parse(s: &str) -> Value {
        serde_json::from_str(s).unwrap_or(Value::Null)
    }

    Ok(Json(json!({
        "kdf_params": parse(&account.kdf_params),
        "master_wrapped_vault_key": parse(&account.master_wrapped_vault_key),
        "recovery_wrapped_vault_key": parse(&account.recovery_wrapped_vault_key),
    })))
}
