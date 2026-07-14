//! Session (device) management: list active logins and revoke them.
//!
//! Every response is non-secret metadata only — no token material. All
//! endpoints require a valid access token and act only on the caller's own
//! account. One row per active *family* (a login and its rotations) is one
//! device.

use axum::extract::{Path, State};
use axum::Json;
use serde::Serialize;
use serde_json::{json, Value};
use sqlx::Row;

use crate::error::ApiError;
use crate::security;
use crate::state::{AppState, AuthSession};

#[derive(Serialize)]
pub struct SessionInfo {
    /// The family identifier; the handle used to revoke this device. Not a
    /// credential (it authenticates nothing), safe to show the owner.
    pub id: String,
    pub device_name: String,
    pub created_at: i64,
    pub last_used_at: i64,
    /// True for the session making this request.
    pub current: bool,
}

/// GET /api/v1/sessions — the account's active devices.
pub async fn list(
    State(state): State<AppState>,
    session: AuthSession,
) -> Result<Json<Value>, ApiError> {
    let now = security::now();
    // One active row per family (rotation revokes predecessors); still within
    // the refresh window and the absolute ceiling.
    let rows = sqlx::query(
        "SELECT family_id, device_name, created_at,
                COALESCE(last_used_at, created_at) AS last_used_at
         FROM sessions
         WHERE account_id = ? AND revoked_at IS NULL AND refresh_expires_at > ?
           AND (absolute_expires_at IS NULL OR absolute_expires_at > ?)
         ORDER BY last_used_at DESC",
    )
    .bind(session.account_id)
    .bind(now)
    .bind(now)
    .fetch_all(&state.db)
    .await?;

    let sessions: Vec<SessionInfo> = rows
        .iter()
        .map(|r| {
            let family_id: String = r.get("family_id");
            let current = family_id == session.family_id;
            SessionInfo {
                id: family_id,
                device_name: r.get("device_name"),
                created_at: r.get("created_at"),
                last_used_at: r.get("last_used_at"),
                current,
            }
        })
        .collect();

    Ok(Json(json!({ "sessions": sessions })))
}

/// DELETE /api/v1/sessions/{family_id} — revoke one device (all its tokens).
pub async fn revoke(
    State(state): State<AppState>,
    session: AuthSession,
    Path(family_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let now = security::now();
    let result = sqlx::query(
        "UPDATE sessions SET revoked_at = ?
         WHERE account_id = ? AND family_id = ? AND revoked_at IS NULL",
    )
    .bind(now)
    .bind(session.account_id)
    .bind(&family_id)
    .execute(&state.db)
    .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(Json(json!({ "status": "ok" })))
}

/// POST /api/v1/sessions/revoke-others — log out every device except this one.
pub async fn revoke_others(
    State(state): State<AppState>,
    session: AuthSession,
) -> Result<Json<Value>, ApiError> {
    let now = security::now();
    let result = sqlx::query(
        "UPDATE sessions SET revoked_at = ?
         WHERE account_id = ? AND family_id != ? AND revoked_at IS NULL",
    )
    .bind(now)
    .bind(session.account_id)
    .bind(&session.family_id)
    .execute(&state.db)
    .await?;

    Ok(Json(json!({ "revoked": result.rows_affected() })))
}
