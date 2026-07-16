use axum::extract::State;
use axum::Json;
use data_encoding::BASE32_NOPAD;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::error::ApiError;
use crate::state::{AppState, AuthSession, ClientIp};
use crate::{db, security, totp};

/// Verify a fresh master-password confirmation (the client re-derives its
/// AuthKey) before any security-sensitive settings change, per the plan:
/// possessing a session token alone must not be enough to weaken MFA.
async fn confirm_credential(
    state: &AppState,
    account: &db::Account,
    auth_credential_b64: &str,
    ip: std::net::IpAddr,
) -> Result<(), ApiError> {
    use base64::Engine;
    let credential = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(auth_credential_b64)
        .unwrap_or_default();
    if !security::verify_credential(&credential, &account.server_auth_hash) {
        state.ip_limiter.record_failure(ip, security::now());
        security::failure_delay().await;
        return Err(ApiError::InvalidCredentials);
    }
    Ok(())
}

async fn load_account(state: &AppState, account_id: i64) -> Result<db::Account, ApiError> {
    db::account_by_id(&state.db, account_id)
        .await?
        .ok_or(ApiError::Internal)
}

#[derive(Deserialize)]
pub struct EnrollRequest {
    pub auth_credential: String,
}

/// POST /api/v1/mfa/totp/enroll — start TOTP enrollment. Returns the shared
/// secret; MFA only becomes required after `activate` proves the
/// authenticator works (otherwise a typo would lock the user out).
pub async fn totp_enroll(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: AuthSession,
    Json(req): Json<EnrollRequest>,
) -> Result<Json<Value>, ApiError> {
    let account = load_account(&state, session.account_id).await?;
    confirm_credential(&state, &account, &req.auth_credential, ip).await?;

    if is_totp_active(&state, account.id).await? {
        return Err(ApiError::BadRequest(
            "TOTP is already active; disable it before re-enrolling".into(),
        ));
    }

    let secret = totp::generate_secret();
    let now = security::now();
    sqlx::query(
        "INSERT INTO totp (account_id, secret_base32, created_at) VALUES (?, ?, ?)
         ON CONFLICT(account_id) DO UPDATE
         SET secret_base32 = excluded.secret_base32,
             activated_at = NULL, created_at = excluded.created_at",
    )
    .bind(account.id)
    .bind(&secret)
    .bind(now)
    .execute(&state.db)
    .await?;

    Ok(Json(json!({
        "secret_base32": secret,
        "otpauth_uri": totp::otpauth_uri("Basementen Vault", &account.email, &secret),
    })))
}

pub async fn is_totp_active(state: &AppState, account_id: i64) -> Result<bool, ApiError> {
    let row: Option<(i64,)> =
        sqlx::query_as("SELECT 1 FROM totp WHERE account_id = ? AND activated_at IS NOT NULL")
            .bind(account_id)
            .fetch_optional(&state.db)
            .await?;
    Ok(row.is_some())
}

/// Verify a code against the account's *activated* TOTP and enforce one-time
/// use (RFC 6238 §5.2): the code's 30-second time-step must be strictly newer
/// than the last one consumed, so a sniffed code cannot be replayed inside its
/// validity window (nor across the login and a follow-up sensitive action).
/// Records the consumed step on success. Returns `false` for an invalid or
/// replayed code, or when no active TOTP exists. Shared by every activated-
/// TOTP check (login, sensitive-action confirmation, disable, regenerate).
pub async fn consume_totp(
    state: &AppState,
    account_id: i64,
    code: &str,
    now: i64,
) -> Result<bool, ApiError> {
    let row: Option<(String, Option<i64>)> = sqlx::query_as(
        "SELECT secret_base32, last_used_step FROM totp
         WHERE account_id = ? AND activated_at IS NOT NULL",
    )
    .bind(account_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((secret, last_used_step)) = row else {
        return Ok(false);
    };
    let Some(step) = totp::verify_step(&secret, code, now) else {
        return Ok(false);
    };
    if last_used_step.is_some_and(|last| step <= last) {
        return Ok(false); // replay of an already-consumed (or older) code
    }
    // Guard the UPDATE with the same monotonic condition so two concurrent
    // requests presenting codes for the same step can't both win.
    let updated = sqlx::query(
        "UPDATE totp SET last_used_step = ?
         WHERE account_id = ? AND (last_used_step IS NULL OR last_used_step < ?)",
    )
    .bind(step)
    .bind(account_id)
    .bind(step)
    .execute(&state.db)
    .await?;
    Ok(updated.rows_affected() == 1)
}

#[derive(Deserialize)]
pub struct ActivateRequest {
    pub code: String,
}

/// POST /api/v1/mfa/totp/activate — confirm enrollment with a live code.
/// On success MFA becomes mandatory for logins, and the response carries the
/// user's single-use recovery codes (shown exactly once).
pub async fn totp_activate(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: AuthSession,
    Json(req): Json<ActivateRequest>,
) -> Result<Json<Value>, ApiError> {
    let now = security::now();
    let row: Option<(String, Option<i64>)> =
        sqlx::query_as("SELECT secret_base32, activated_at FROM totp WHERE account_id = ?")
            .bind(session.account_id)
            .fetch_optional(&state.db)
            .await?;

    let Some((secret, activated_at)) = row else {
        return Err(ApiError::BadRequest(
            "no TOTP enrollment in progress".into(),
        ));
    };
    if activated_at.is_some() {
        return Err(ApiError::BadRequest("TOTP is already active".into()));
    }
    if !totp::verify(&secret, &req.code, now) {
        state.ip_limiter.record_failure(ip, now);
        security::failure_delay().await;
        return Err(ApiError::InvalidCredentials);
    }

    // Activation confirms the authenticator works; one-time-use tracking starts
    // at the first real login (last_used_step stays NULL here) so the user can
    // enroll and immediately sign in with the code showing on their device.
    sqlx::query("UPDATE totp SET activated_at = ? WHERE account_id = ?")
        .bind(now)
        .bind(session.account_id)
        .execute(&state.db)
        .await?;

    let codes = issue_recovery_codes(&state, session.account_id).await?;
    Ok(Json(json!({
        "status": "ok",
        "recovery_codes": codes,
        "message": "Store these recovery codes somewhere safe; they are shown only once."
    })))
}

/// Replace all recovery codes with 10 fresh single-use codes.
async fn issue_recovery_codes(state: &AppState, account_id: i64) -> Result<Vec<String>, ApiError> {
    sqlx::query("DELETE FROM recovery_codes WHERE account_id = ?")
        .bind(account_id)
        .execute(&state.db)
        .await?;

    let mut codes = Vec::with_capacity(10);
    for _ in 0..10 {
        let mut bytes = [0u8; 5];
        getrandom::fill(&mut bytes).expect("OS CSPRNG unavailable");
        let raw = BASE32_NOPAD.encode(&bytes); // 8 chars
        let code = format!("{}-{}", &raw[..4], &raw[4..]);
        let normalized: String = code
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_ascii_uppercase();
        sqlx::query("INSERT INTO recovery_codes (account_id, code_hash) VALUES (?, ?)")
            .bind(account_id)
            .bind(security::sha256(normalized.as_bytes()))
            .execute(&state.db)
            .await?;
        codes.push(code);
    }
    Ok(codes)
}

#[derive(Deserialize)]
pub struct DisableRequest {
    pub auth_credential: String,
    pub totp_code: String,
}

/// POST /api/v1/mfa/totp/disable — requires both a fresh password
/// confirmation and a valid current code.
pub async fn totp_disable(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: AuthSession,
    Json(req): Json<DisableRequest>,
) -> Result<Json<Value>, ApiError> {
    let account = load_account(&state, session.account_id).await?;
    confirm_credential(&state, &account, &req.auth_credential, ip).await?;

    if !is_totp_active(&state, account.id).await? {
        return Err(ApiError::BadRequest("TOTP is not active".into()));
    }
    if !consume_totp(&state, account.id, &req.totp_code, security::now()).await? {
        state.ip_limiter.record_failure(ip, security::now());
        security::failure_delay().await;
        return Err(ApiError::InvalidCredentials);
    }

    sqlx::query("DELETE FROM totp WHERE account_id = ?")
        .bind(account.id)
        .execute(&state.db)
        .await?;
    sqlx::query("DELETE FROM recovery_codes WHERE account_id = ?")
        .bind(account.id)
        .execute(&state.db)
        .await?;

    Ok(Json(json!({ "status": "ok" })))
}

#[derive(Deserialize)]
pub struct RegenerateRequest {
    pub auth_credential: String,
    pub totp_code: String,
}

/// POST /api/v1/mfa/recovery-codes/regenerate — issue a fresh set of
/// single-use recovery codes, invalidating the previous set. Requires a fresh
/// password confirmation *and* a current TOTP code (a stolen session token
/// alone must not be able to mint MFA-bypass codes). This gives users a way
/// to replenish codes before the heavier account-recovery path is needed.
pub async fn regenerate_recovery_codes(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: AuthSession,
    Json(req): Json<RegenerateRequest>,
) -> Result<Json<Value>, ApiError> {
    let account = load_account(&state, session.account_id).await?;
    confirm_credential(&state, &account, &req.auth_credential, ip).await?;

    if !is_totp_active(&state, account.id).await? {
        return Err(ApiError::BadRequest("TOTP is not active".into()));
    }
    if !consume_totp(&state, account.id, &req.totp_code, security::now()).await? {
        state.ip_limiter.record_failure(ip, security::now());
        security::failure_delay().await;
        return Err(ApiError::InvalidCredentials);
    }

    let codes = issue_recovery_codes(&state, account.id).await?;
    Ok(Json(json!({
        "status": "ok",
        "recovery_codes": codes,
        "message": "New recovery codes generated; your previous codes no longer work."
    })))
}

/// GET /api/v1/mfa/status — whether TOTP is active and how many single-use
/// recovery codes remain, so the app can warn the user before they run out
/// (and offer regeneration). Non-secret metadata; requires a valid session.
pub async fn status(
    State(state): State<AppState>,
    session: AuthSession,
) -> Result<Json<Value>, ApiError> {
    let totp_active = is_totp_active(&state, session.account_id).await?;
    let remaining: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM recovery_codes WHERE account_id = ? AND used_at IS NULL",
    )
    .bind(session.account_id)
    .fetch_one(&state.db)
    .await?;
    Ok(Json(json!({
        "totp_active": totp_active,
        "recovery_codes_remaining": remaining,
    })))
}
