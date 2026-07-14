use axum::extract::State;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::error::ApiError;
use crate::state::{AppState, AuthSession, ClientIp};
use crate::{db, security};

pub const ACCESS_TOKEN_TTL_SECS: i64 = 15 * 60;
/// Device labels are echoed back in the device list; keep them a short,
/// printable handle so a client can't bloat the table or the response.
const MAX_DEVICE_NAME_LEN: usize = 64;
pub const REFRESH_TOKEN_TTL_SECS: i64 = 30 * 24 * 3600;
/// Hard ceiling on a session's lifetime regardless of activity. After this,
/// sliding refresh stops working and the user must log in again.
pub const ABSOLUTE_SESSION_TTL_SECS: i64 = 90 * 24 * 3600;

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    /// base64url of the 32-byte client AuthKey.
    pub auth_credential: String,
    /// 6-digit TOTP code, when MFA is enrolled.
    pub totp_code: Option<String>,
    /// Single-use MFA recovery code, as fallback for a lost authenticator.
    pub recovery_code: Option<String>,
    pub device_name: Option<String>,
}

/// Record a failed attempt: bump the per-account and per-IP counters, apply
/// progressive lockout, notify the owner when the threshold is crossed, and
/// serve the 250–300 ms mini-lockout before responding.
async fn fail(
    state: &AppState,
    ip: std::net::IpAddr,
    account: Option<&db::Account>,
    now: i64,
) -> ApiError {
    state.ip_limiter.record_failure(ip, now);

    if let Some(account) = account {
        let attempts = account.failed_attempts + 1;
        let lockout_until = security::lockout_duration(attempts).map(|d| now + d);
        let _ =
            sqlx::query("UPDATE accounts SET failed_attempts = ?, lockout_until = ? WHERE id = ?")
                .bind(attempts)
                .bind(lockout_until)
                .bind(account.id)
                .execute(&state.db)
                .await;

        if attempts == security::LOCKOUT_THRESHOLD {
            state
                .mailer
                .send(
                    &account.email,
                    "Basementen Vault: repeated failed login attempts",
                    "There have been repeated failed attempts to log in to your \
                     vault. Logins are now temporarily locked with increasing \
                     delays. If this was not you, no action is needed — your \
                     vault stays encrypted with your master password — but be \
                     alert for phishing attempts.",
                )
                .await;
        }
    }

    security::failure_delay().await;
    ApiError::InvalidCredentials
}

/// POST /api/v1/auth/login
pub async fn login(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<LoginRequest>,
) -> Result<Json<Value>, ApiError> {
    let now = security::now();

    if let Some(retry) = state.ip_limiter.check(ip, now) {
        return Err(ApiError::RateLimited {
            retry_after_secs: retry,
        });
    }

    let email = vault_core::kdf::normalize_email(&req.email);
    let account = db::account_by_email(&state.db, &email).await?;

    if let Some(acc) = &account {
        if let Some(until) = acc.lockout_until {
            if until > now {
                return Err(ApiError::LockedOut {
                    retry_after_secs: until - now,
                });
            }
        }
    }

    // Exactly one Argon2id verification happens on every path — against the
    // real hash when the account exists, against a dummy otherwise — so
    // response timing cannot reveal whether an e-mail is registered.
    use base64::Engine;
    let credential = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&req.auth_credential)
        .unwrap_or_default();
    let phc = account
        .as_ref()
        .map(|a| a.server_auth_hash.as_str())
        .unwrap_or(state.dummy_hash.as_str());
    let credential_ok = security::verify_credential(&credential, phc);

    let Some(account) = account else {
        return Err(fail(&state, ip, None, now).await);
    };
    if !credential_ok {
        return Err(fail(&state, ip, Some(&account), now).await);
    }

    if account.email_verified_at.is_none() {
        return Err(ApiError::EmailNotVerified);
    }

    // Second factor, when enrolled. TOTP codes are one-time-use (a code cannot
    // be replayed within its validity window); recovery codes are single-use.
    if crate::routes::mfa::is_totp_active(&state, account.id).await? {
        match (&req.totp_code, &req.recovery_code) {
            (Some(code), _) => {
                if !crate::routes::mfa::consume_totp(&state, account.id, code, now).await? {
                    return Err(fail(&state, ip, Some(&account), now).await);
                }
            }
            (None, Some(recovery)) => {
                if !consume_recovery_code(&state, account.id, recovery, now).await? {
                    return Err(fail(&state, ip, Some(&account), now).await);
                }
            }
            (None, None) => return Err(ApiError::MfaRequired),
        }
    }

    // Success: reset counters and open a session.
    sqlx::query("UPDATE accounts SET failed_attempts = 0, lockout_until = NULL WHERE id = ?")
        .bind(account.id)
        .execute(&state.db)
        .await?;

    let device_name = sanitize_device_name(req.device_name.as_deref());
    // "New device" = no other active session already carries this label. Check
    // before this login's row exists. A new device (or a re-login after the
    // previous session lapsed) alerts the owner; concurrent same-named devices
    // don't re-alarm.
    let is_new_device = !active_session_with_name(&state, account.id, &device_name, now).await?;
    let tokens = create_session(&state, account.id, &device_name, now).await?;
    if is_new_device {
        notify_new_sign_in(&state, &account, &device_name).await;
    }

    Ok(Json(json!({
        "access_token": tokens.0,
        "refresh_token": tokens.1,
        "access_expires_in": ACCESS_TOKEN_TTL_SECS,
        "kdf_params": parse_json(&account.kdf_params),
        "kdf_salt": crate::routes::accounts::encode_salt(&account.kdf_salt),
        "master_wrapped_vault_key": parse_json(&account.master_wrapped_vault_key),
    })))
}

fn parse_json(s: &str) -> Value {
    serde_json::from_str(s).unwrap_or(Value::Null)
}

async fn consume_recovery_code(
    state: &AppState,
    account_id: i64,
    code: &str,
    now: i64,
) -> Result<bool, ApiError> {
    let normalized: String = code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_uppercase();
    let hash = security::sha256(normalized.as_bytes());
    let updated = sqlx::query(
        "UPDATE recovery_codes SET used_at = ?
         WHERE account_id = ? AND code_hash = ? AND used_at IS NULL",
    )
    .bind(now)
    .bind(account_id)
    .bind(&hash)
    .execute(&state.db)
    .await?;
    Ok(updated.rows_affected() == 1)
}

#[allow(clippy::too_many_arguments)]
async fn insert_session_row(
    state: &AppState,
    account_id: i64,
    family_id: &str,
    device_name: &str,
    now: i64,
    // The family's original login time, carried unchanged through rotations so
    // the device list shows when the device logged in, not when it last refreshed.
    created_at: i64,
    absolute_expires_at: i64,
) -> Result<(String, String), ApiError> {
    let (access, access_hash) = security::new_token("bvat_");
    let (refresh, refresh_hash) = security::new_token("bvrt_");
    sqlx::query(
        "INSERT INTO sessions (account_id, family_id, access_token_hash, refresh_token_hash,
                               access_expires_at, refresh_expires_at, device_name, created_at,
                               last_used_at, absolute_expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(account_id)
    .bind(family_id)
    .bind(&access_hash)
    .bind(&refresh_hash)
    .bind(now + ACCESS_TOKEN_TTL_SECS)
    .bind(now + REFRESH_TOKEN_TTL_SECS)
    .bind(device_name)
    .bind(created_at)
    .bind(now)
    .bind(absolute_expires_at)
    .execute(&state.db)
    .await?;
    Ok((access, refresh))
}

async fn create_session(
    state: &AppState,
    account_id: i64,
    device_name: &str,
    now: i64,
) -> Result<(String, String), ApiError> {
    // Purge this account's dead sessions (past the refresh window, so beyond
    // any reuse-detection value) to keep the table from growing unbounded.
    let _ = sqlx::query("DELETE FROM sessions WHERE account_id = ? AND refresh_expires_at < ?")
        .bind(account_id)
        .bind(now)
        .execute(&state.db)
        .await;

    // Random family ID grouping every future rotation of this login.
    let (family_id, _) = security::new_token("fam_");
    insert_session_row(
        state,
        account_id,
        &family_id,
        device_name,
        now,
        now,
        now + ABSOLUTE_SESSION_TTL_SECS,
    )
    .await
}

/// Normalize a client-supplied device label: strip control characters, trim,
/// and cap the length. The result is stored and later echoed back to the owner.
fn sanitize_device_name(name: Option<&str>) -> String {
    name.unwrap_or("")
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .chars()
        .take(MAX_DEVICE_NAME_LEN)
        .collect()
}

/// Whether an active (non-revoked, unexpired) session already carries this
/// device label. Used to decide if a login is from a "new" device.
async fn active_session_with_name(
    state: &AppState,
    account_id: i64,
    device_name: &str,
    now: i64,
) -> Result<bool, ApiError> {
    let row: Option<(i64,)> = sqlx::query_as(
        "SELECT 1 FROM sessions
         WHERE account_id = ? AND revoked_at IS NULL AND refresh_expires_at > ?
           AND device_name = ? LIMIT 1",
    )
    .bind(account_id)
    .bind(now)
    .bind(device_name)
    .fetch_optional(&state.db)
    .await?;
    Ok(row.is_some())
}

/// Alert the account owner that a new device signed in. Sent to the primary
/// address only (the backup address is reserved for recovery events, not
/// routine sign-in notices). Best-effort: mail failures never block login.
async fn notify_new_sign_in(state: &AppState, account: &db::Account, device_name: &str) {
    let label = if device_name.is_empty() {
        "an unnamed device".to_string()
    } else {
        format!("\"{device_name}\"")
    };
    let body = format!(
        "A new device just signed in to your Basementen Vault account: {label}.\n\n\
         If this was you, no action is needed. If you don't recognise it, open \
         the app, go to Settings and revoke the device under \"Active devices\", \
         then change your master password immediately."
    );
    state
        .mailer
        .send(&account.email, "Basementen Vault: new sign-in", &body)
        .await;
}

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

/// POST /api/v1/auth/refresh — rotate both tokens; a refresh token is
/// single-use. Presenting an already-rotated (revoked) token is treated as
/// theft evidence: every session for the account is revoked.
pub async fn refresh(
    State(state): State<AppState>,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<Value>, ApiError> {
    let now = security::now();
    let hash = security::sha256(req.refresh_token.as_bytes());

    // (id, account_id, family_id, device_name, revoked_at, refresh_expires_at,
    //  absolute_expires_at, created_at)
    type RefreshRow = (i64, i64, String, String, Option<i64>, i64, Option<i64>, i64);
    let row: Option<RefreshRow> = sqlx::query_as(
        "SELECT id, account_id, family_id, device_name, revoked_at, refresh_expires_at,
                absolute_expires_at, created_at
         FROM sessions WHERE refresh_token_hash = ?",
    )
    .bind(&hash)
    .fetch_optional(&state.db)
    .await?;

    let Some((
        session_id,
        account_id,
        family_id,
        device_name,
        revoked_at,
        refresh_expires_at,
        absolute_expires_at,
        created_at,
    )) = row
    else {
        security::failure_delay().await;
        return Err(ApiError::InvalidToken);
    };

    if revoked_at.is_some() {
        // Token reuse after rotation: someone replayed an old refresh token,
        // which means it was stolen (the legitimate holder has the new one).
        // Kill every descendant of this login.
        sqlx::query(
            "UPDATE sessions SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL",
        )
        .bind(now)
        .bind(&family_id)
        .execute(&state.db)
        .await?;
        tracing::warn!(
            account_id,
            "refresh token reuse detected; session family revoked"
        );
        security::failure_delay().await;
        return Err(ApiError::InvalidToken);
    }
    // Refresh window expired, or the absolute session ceiling reached: the
    // user must log in again. The absolute cap is carried unchanged through
    // rotations, so sliding refresh cannot extend a session past it.
    if refresh_expires_at <= now || absolute_expires_at.is_some_and(|cap| cap <= now) {
        security::failure_delay().await;
        return Err(ApiError::InvalidToken);
    }
    // Carry the same ceiling forward (default for legacy rows without one).
    let absolute_expires_at = absolute_expires_at.unwrap_or(now + ABSOLUTE_SESSION_TTL_SECS);

    // Rotate: retire this row, issue a successor in the same family.
    sqlx::query("UPDATE sessions SET revoked_at = ? WHERE id = ?")
        .bind(now)
        .bind(session_id)
        .execute(&state.db)
        .await?;
    let (access, refresh) = insert_session_row(
        &state,
        account_id,
        &family_id,
        &device_name,
        now,
        created_at,
        absolute_expires_at,
    )
    .await?;

    Ok(Json(json!({
        "access_token": access,
        "refresh_token": refresh,
        "access_expires_in": ACCESS_TOKEN_TTL_SECS,
    })))
}

/// POST /api/v1/auth/logout
pub async fn logout(
    State(state): State<AppState>,
    session: AuthSession,
) -> Result<Json<Value>, ApiError> {
    sqlx::query("UPDATE sessions SET revoked_at = ? WHERE id = ?")
        .bind(security::now())
        .bind(session.session_id)
        .execute(&state.db)
        .await?;
    Ok(Json(json!({ "status": "ok" })))
}
