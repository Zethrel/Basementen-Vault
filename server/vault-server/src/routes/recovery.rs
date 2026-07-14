//! Account recovery and trusted backup e-mail.
//!
//! Threat model recap (plan §5): e-mail access alone must never silently
//! take over an account. Three defenses stack:
//!
//! 1. **Cooling-off**: a recovery request is inert for 72 h (configurable);
//!    the owner is notified immediately and can cancel with one click.
//! 2. **Recovery verifier**: completing a *data-preserving* recovery
//!    requires the verifier — an HKDF branch of the Vault Key that only
//!    someone holding the Recovery Kit can derive. The server stores only
//!    its SHA-256.
//! 3. **Explicit wipe**: without the kit, the only path is a reset that
//!    destroys all vault items — loudly, never as a side effect.

use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use subtle::ConstantTimeEq;
use vault_core::KdfParams;

use crate::error::ApiError;
use crate::state::{AppState, AuthSession, ClientIp};
use crate::{db, security, totp};

/// Completion tokens stay valid this long after the cooling-off ends.
const COMPLETION_WINDOW_SECS: i64 = 7 * 24 * 3600;

// ---------------------------------------------------------------------------
// Start

#[derive(Deserialize)]
pub struct StartRequest {
    pub email: String,
}

/// POST /api/v1/accounts/recovery/start
///
/// Anti-enumeration: always succeeds. Tokens travel only by e-mail.
/// A new request supersedes any pending one (cooling-off restarts).
pub async fn start(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<StartRequest>,
) -> Result<Json<Value>, ApiError> {
    let now = security::now();
    if let Some(retry) = state.ip_limiter.check(ip, now) {
        return Err(ApiError::RateLimited {
            retry_after_secs: retry,
        });
    }
    // Recovery starts are cheap for us and useful to attackers; meter them.
    state.ip_limiter.record_failure(ip, now);

    let response = json!({
        "status": "ok",
        "message": "If that address has an account, recovery instructions have been sent."
    });

    let email = vault_core::kdf::normalize_email(&req.email);
    let Some(account) = db::account_by_email(&state.db, &email).await? else {
        return Ok(Json(response));
    };

    // Supersede any pending request.
    sqlx::query(
        "UPDATE recovery_requests SET cancelled_at = ?
         WHERE account_id = ? AND cancelled_at IS NULL AND completed_at IS NULL",
    )
    .bind(now)
    .bind(account.id)
    .execute(&state.db)
    .await?;

    let (completion_token, completion_hash) = security::new_token("bvrec_");
    let (cancel_token, cancel_hash) = security::new_token("bvcan_");
    let usable_at = now + state.cfg.recovery_cooloff_secs;
    sqlx::query(
        "INSERT INTO recovery_requests
           (account_id, completion_token_hash, cancel_token_hash, created_at, usable_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(account.id)
    .bind(&completion_hash)
    .bind(&cancel_hash)
    .bind(now)
    .bind(usable_at)
    .bind(usable_at + COMPLETION_WINDOW_SECS)
    .execute(&state.db)
    .await?;

    let hours = (state.cfg.recovery_cooloff_secs + 3599) / 3600;
    let cancel_link = format!(
        "{}/api/v1/accounts/recovery/cancel?token={cancel_token}",
        state.cfg.base_url
    );
    let completion_body = format!(
        "A vault recovery was requested for this account.\n\n\
         After a {hours}-hour cooling-off period, open the Basementen Vault app, \
         choose \"Recover my vault\", and paste this recovery token:\n\n{completion_token}\n\n\
         You will also need your printed Recovery Kit code to restore your data.\n\n\
         If you did NOT request this, cancel it immediately:\n{cancel_link}"
    );

    // Completion instructions to the primary address…
    state
        .mailer
        .send(
            &account.email,
            "Basementen Vault: account recovery",
            &completion_body,
        )
        .await;
    // …and to the verified backup address, if one is configured.
    if let Some(backup) = backup_email_of(&state, account.id).await? {
        state
            .mailer
            .send(
                &backup,
                "Basementen Vault: account recovery",
                &completion_body,
            )
            .await;
    }

    Ok(Json(response))
}

async fn backup_email_of(state: &AppState, account_id: i64) -> Result<Option<String>, ApiError> {
    let row: Option<(Option<String>, Option<i64>)> =
        sqlx::query_as("SELECT backup_email, backup_email_verified_at FROM accounts WHERE id = ?")
            .bind(account_id)
            .fetch_optional(&state.db)
            .await?;
    Ok(row.and_then(|(email, verified)| match (email, verified) {
        (Some(e), Some(_)) => Some(e),
        _ => None,
    }))
}

// ---------------------------------------------------------------------------
// Token plumbing

struct RecoveryRequestRow {
    id: i64,
    account_id: i64,
    usable_at: i64,
}

/// Look up a completion token and enforce the request lifecycle
/// (not cancelled / completed / expired). Does NOT check cooling-off —
/// callers decide how to respond to a too-early token.
async fn find_active_request(
    state: &AppState,
    completion_token: &str,
    now: i64,
) -> Result<Option<RecoveryRequestRow>, ApiError> {
    let hash = security::sha256(completion_token.as_bytes());
    let row: Option<(i64, i64, i64)> = sqlx::query_as(
        "SELECT id, account_id, usable_at FROM recovery_requests
         WHERE completion_token_hash = ?
           AND cancelled_at IS NULL AND completed_at IS NULL AND expires_at > ?",
    )
    .bind(&hash)
    .bind(now)
    .fetch_optional(&state.db)
    .await?;
    Ok(row.map(|(id, account_id, usable_at)| RecoveryRequestRow {
        id,
        account_id,
        usable_at,
    }))
}

// ---------------------------------------------------------------------------
// Data (what the client needs before it can rebuild the hierarchy)

#[derive(Deserialize)]
pub struct DataQuery {
    pub token: String,
}

/// GET /api/v1/accounts/recovery/data?token=…
///
/// Releases the KDF parameters and the recovery-wrapped Vault Key to the
/// completion-token holder once the cooling-off has elapsed. Everything
/// returned is ciphertext or public parameters — useless without the
/// Recovery Kit code.
pub async fn data(
    State(state): State<AppState>,
    Query(q): Query<DataQuery>,
) -> Result<Json<Value>, ApiError> {
    let now = security::now();
    let Some(request) = find_active_request(&state, &q.token, now).await? else {
        security::failure_delay().await;
        return Err(ApiError::InvalidToken);
    };
    if request.usable_at > now {
        return Err(ApiError::CoolingOff {
            retry_after_secs: request.usable_at - now,
        });
    }

    let account = db::account_by_id(&state.db, request.account_id)
        .await?
        .ok_or(ApiError::Internal)?;
    let has_verifier: Option<(i64,)> = sqlx::query_as(
        "SELECT 1 FROM accounts WHERE id = ? AND recovery_verifier_hash IS NOT NULL",
    )
    .bind(account.id)
    .fetch_optional(&state.db)
    .await?;

    fn parse(s: &str) -> Value {
        serde_json::from_str(s).unwrap_or(Value::Null)
    }
    Ok(Json(json!({
        "email": account.email,
        "kdf_params": parse(&account.kdf_params),
        // The account's existing salt: recovery reuses it (account-lifetime).
        "kdf_salt": crate::routes::accounts::encode_salt(&account.kdf_salt),
        "recovery_wrapped_vault_key": parse(&account.recovery_wrapped_vault_key),
        "supports_data_recovery": has_verifier.is_some(),
    })))
}

// ---------------------------------------------------------------------------
// Complete

#[derive(Deserialize)]
pub struct CompleteRequest {
    pub token: String,
    /// base64url of the 32-byte recovery verifier, derivable only with the
    /// Recovery Kit. Presence selects data-preserving recovery.
    pub recovery_verifier: Option<String>,
    /// Explicit consent to destroy all vault items (the no-kit path).
    #[serde(default)]
    pub wipe: bool,
    // The replacement bundle, produced client-side under the new password:
    pub auth_credential: String,
    pub kdf_params: KdfParams,
    /// base64url of the new 16-byte random KDF salt.
    pub kdf_salt: String,
    pub master_wrapped_vault_key: Value,
    pub recovery_wrapped_vault_key: Value,
    pub new_recovery_verifier: String,
}

fn decode32(b64: &str, field: &str) -> Result<Vec<u8>, ApiError> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|_| ApiError::BadRequest(format!("{field} must be base64url")))?;
    if bytes.len() != 32 {
        return Err(ApiError::BadRequest(format!("{field} must be 32 bytes")));
    }
    Ok(bytes)
}

/// POST /api/v1/accounts/recovery/complete
pub async fn complete(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<CompleteRequest>,
) -> Result<Json<Value>, ApiError> {
    let now = security::now();
    if let Some(retry) = state.ip_limiter.check(ip, now) {
        return Err(ApiError::RateLimited {
            retry_after_secs: retry,
        });
    }

    let Some(request) = find_active_request(&state, &req.token, now).await? else {
        state.ip_limiter.record_failure(ip, now);
        security::failure_delay().await;
        return Err(ApiError::InvalidToken);
    };
    if request.usable_at > now {
        return Err(ApiError::CoolingOff {
            retry_after_secs: request.usable_at - now,
        });
    }

    req.kdf_params
        .validate()
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let credential = decode32(&req.auth_credential, "auth_credential")?;
    let new_verifier = decode32(&req.new_recovery_verifier, "new_recovery_verifier")?;
    let new_salt = {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&req.kdf_salt)
            .map_err(|_| ApiError::BadRequest("kdf_salt must be base64url".into()))?;
        if bytes.len() != 16 {
            return Err(ApiError::BadRequest("kdf_salt must be 16 bytes".into()));
        }
        bytes
    };

    // Decide the mode: data-preserving (kit proven) or explicit wipe.
    let preserve_data = match &req.recovery_verifier {
        Some(verifier_b64) => {
            let presented = decode32(verifier_b64, "recovery_verifier")?;
            let stored: Option<(Vec<u8>,)> = sqlx::query_as(
                "SELECT recovery_verifier_hash FROM accounts
                 WHERE id = ? AND recovery_verifier_hash IS NOT NULL",
            )
            .bind(request.account_id)
            .fetch_optional(&state.db)
            .await?;
            let ok = stored.is_some_and(|(hash,)| security::sha256(&presented).ct_eq(&hash).into());
            if !ok {
                state.ip_limiter.record_failure(ip, now);
                security::failure_delay().await;
                return Err(ApiError::InvalidCredentials);
            }
            true
        }
        None if req.wipe => false,
        None => {
            return Err(ApiError::BadRequest(
                "provide the recovery verifier (from your Recovery Kit), or set \
                 wipe=true to reset the account and DESTROY all stored items"
                    .into(),
            ))
        }
    };

    let mut tx = state.db.begin().await?;
    if !preserve_data {
        sqlx::query("DELETE FROM vault_items WHERE account_id = ?")
            .bind(request.account_id)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query(
        "UPDATE accounts SET
           server_auth_hash = ?, kdf_params = ?, kdf_salt = ?,
           master_wrapped_vault_key = ?, recovery_wrapped_vault_key = ?,
           recovery_verifier_hash = ?,
           failed_attempts = 0, lockout_until = NULL
         WHERE id = ?",
    )
    .bind(security::hash_credential(&credential))
    .bind(serde_json::to_string(&req.kdf_params).map_err(|_| ApiError::Internal)?)
    .bind(new_salt)
    .bind(req.master_wrapped_vault_key.to_string())
    .bind(req.recovery_wrapped_vault_key.to_string())
    .bind(security::sha256(&new_verifier))
    .bind(request.account_id)
    .execute(&mut *tx)
    .await?;
    // Every existing session belongs to whoever held the old password.
    sqlx::query("UPDATE sessions SET revoked_at = ? WHERE account_id = ? AND revoked_at IS NULL")
        .bind(now)
        .bind(request.account_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE recovery_requests SET completed_at = ? WHERE id = ?")
        .bind(now)
        .bind(request.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    let account = db::account_by_id(&state.db, request.account_id)
        .await?
        .ok_or(ApiError::Internal)?;
    let body = if preserve_data {
        "Your vault was recovered with a Recovery Kit and a new master password \
         was set. All previous sessions have been signed out. If this was not \
         you, contact your server administrator immediately."
    } else {
        "Your account was RESET without a Recovery Kit: a new master password \
         was set and all previously stored vault items were permanently deleted. \
         If this was not you, contact your server administrator immediately."
    };
    state
        .mailer
        .send(&account.email, "Basementen Vault: account recovered", body)
        .await;
    if let Some(backup) = backup_email_of(&state, account.id).await? {
        state
            .mailer
            .send(&backup, "Basementen Vault: account recovered", body)
            .await;
    }

    Ok(Json(
        json!({ "status": "ok", "data_preserved": preserve_data }),
    ))
}

// ---------------------------------------------------------------------------
// Cancel

#[derive(Deserialize)]
pub struct CancelQuery {
    pub token: String,
}

/// GET /api/v1/accounts/recovery/cancel?token=… (one-click link in the mail)
pub async fn cancel(
    State(state): State<AppState>,
    Query(q): Query<CancelQuery>,
) -> Result<&'static str, ApiError> {
    let now = security::now();
    let hash = security::sha256(q.token.as_bytes());
    let updated = sqlx::query(
        "UPDATE recovery_requests SET cancelled_at = ?
         WHERE cancel_token_hash = ? AND cancelled_at IS NULL AND completed_at IS NULL",
    )
    .bind(now)
    .bind(&hash)
    .execute(&state.db)
    .await?;
    if updated.rows_affected() == 0 {
        security::failure_delay().await;
        return Err(ApiError::InvalidToken);
    }
    Ok("Recovery cancelled. Your account is unchanged. \
        Consider changing your e-mail password if you did not start this recovery.")
}

// ---------------------------------------------------------------------------
// Trusted backup e-mail management

const BACKUP_VERIFY_TTL_SECS: i64 = 24 * 3600;

/// Fresh password confirmation + second factor (when enrolled) — required
/// for every backup-address change, since the backup address can initiate
/// recovery.
async fn confirm_sensitive(
    state: &AppState,
    account: &db::Account,
    auth_credential_b64: &str,
    totp_code: Option<&str>,
    ip: std::net::IpAddr,
) -> Result<(), ApiError> {
    let credential = decode32(auth_credential_b64, "auth_credential")?;
    if !security::verify_credential(&credential, &account.server_auth_hash) {
        state.ip_limiter.record_failure(ip, security::now());
        security::failure_delay().await;
        return Err(ApiError::InvalidCredentials);
    }
    let enrolled: Option<(String,)> = sqlx::query_as(
        "SELECT secret_base32 FROM totp WHERE account_id = ? AND activated_at IS NOT NULL",
    )
    .bind(account.id)
    .fetch_optional(&state.db)
    .await?;
    if let Some((secret,)) = enrolled {
        let Some(code) = totp_code else {
            return Err(ApiError::MfaRequired);
        };
        if !totp::verify(&secret, code, security::now()) {
            state.ip_limiter.record_failure(ip, security::now());
            security::failure_delay().await;
            return Err(ApiError::InvalidCredentials);
        }
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct SetBackupRequest {
    pub auth_credential: String,
    pub totp_code: Option<String>,
    pub backup_email: String,
}

/// POST /api/v1/account/backup-email
pub async fn set_backup_email(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: AuthSession,
    Json(req): Json<SetBackupRequest>,
) -> Result<Json<Value>, ApiError> {
    let account = db::account_by_id(&state.db, session.account_id)
        .await?
        .ok_or(ApiError::Internal)?;
    confirm_sensitive(
        &state,
        &account,
        &req.auth_credential,
        req.totp_code.as_deref(),
        ip,
    )
    .await?;

    let backup = vault_core::kdf::normalize_email(&req.backup_email);
    if backup == account.email {
        return Err(ApiError::BadRequest(
            "the backup address must differ from the account address".into(),
        ));
    }
    if !(backup.len() <= 254
        && backup
            .split_once('@')
            .is_some_and(|(l, d)| !l.is_empty() && d.contains('.')))
    {
        return Err(ApiError::BadRequest("invalid e-mail address".into()));
    }

    let now = security::now();
    sqlx::query(
        "UPDATE accounts SET backup_email = ?, backup_email_verified_at = NULL WHERE id = ?",
    )
    .bind(&backup)
    .bind(account.id)
    .execute(&state.db)
    .await?;

    let (token, token_hash) = security::new_token("bvbet_");
    sqlx::query(
        "INSERT INTO email_tokens (account_id, purpose, token_hash, expires_at)
         VALUES (?, 'verify_backup_email', ?, ?)",
    )
    .bind(account.id)
    .bind(&token_hash)
    .bind(now + BACKUP_VERIFY_TTL_SECS)
    .execute(&state.db)
    .await?;

    let link = format!(
        "{}/api/v1/accounts/verify-backup?token={token}",
        state.cfg.base_url
    );
    state
        .mailer
        .send(
            &backup,
            "Basementen Vault: confirm backup e-mail",
            &format!(
                "This address was chosen as the recovery backup for a Basementen \
                 Vault account. Confirm within 24 hours:\n\n{link}\n\n\
                 If you don't recognise this, ignore this message."
            ),
        )
        .await;
    state
        .mailer
        .send(
            &account.email,
            "Basementen Vault: backup e-mail changed",
            &format!(
                "A backup e-mail address ({backup}) was added to your account and \
                 awaits verification. It will be able to initiate account recovery. \
                 If this was not you, change your master password immediately."
            ),
        )
        .await;

    Ok(Json(json!({
        "status": "ok",
        "message": "Verification e-mail sent to the backup address."
    })))
}

#[derive(Deserialize)]
pub struct VerifyBackupQuery {
    pub token: String,
}

/// GET /api/v1/accounts/verify-backup?token=…
pub async fn verify_backup_email(
    State(state): State<AppState>,
    Query(q): Query<VerifyBackupQuery>,
) -> Result<&'static str, ApiError> {
    let now = security::now();
    let hash = security::sha256(q.token.as_bytes());
    let row: Option<(i64, i64)> = sqlx::query_as(
        "SELECT id, account_id FROM email_tokens
         WHERE token_hash = ? AND purpose = 'verify_backup_email'
           AND used_at IS NULL AND expires_at > ?",
    )
    .bind(&hash)
    .bind(now)
    .fetch_optional(&state.db)
    .await?;
    let Some((token_id, account_id)) = row else {
        security::failure_delay().await;
        return Err(ApiError::InvalidToken);
    };

    sqlx::query("UPDATE email_tokens SET used_at = ? WHERE id = ?")
        .bind(now)
        .bind(token_id)
        .execute(&state.db)
        .await?;
    sqlx::query("UPDATE accounts SET backup_email_verified_at = ? WHERE id = ?")
        .bind(now)
        .bind(account_id)
        .execute(&state.db)
        .await?;

    Ok("Backup e-mail verified. It can now be used to start account recovery.")
}

#[derive(Deserialize)]
pub struct RemoveBackupRequest {
    pub auth_credential: String,
    pub totp_code: Option<String>,
}

/// DELETE /api/v1/account/backup-email
pub async fn remove_backup_email(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: AuthSession,
    Json(req): Json<RemoveBackupRequest>,
) -> Result<Json<Value>, ApiError> {
    let account = db::account_by_id(&state.db, session.account_id)
        .await?
        .ok_or(ApiError::Internal)?;
    confirm_sensitive(
        &state,
        &account,
        &req.auth_credential,
        req.totp_code.as_deref(),
        ip,
    )
    .await?;

    let old_backup = backup_email_of(&state, account.id).await?;
    sqlx::query(
        "UPDATE accounts SET backup_email = NULL, backup_email_verified_at = NULL WHERE id = ?",
    )
    .bind(account.id)
    .execute(&state.db)
    .await?;

    let notice = "The backup e-mail address was removed from your Basementen Vault \
                  account. If this was not you, change your master password immediately.";
    state
        .mailer
        .send(
            &account.email,
            "Basementen Vault: backup e-mail removed",
            notice,
        )
        .await;
    if let Some(backup) = old_backup {
        state
            .mailer
            .send(&backup, "Basementen Vault: backup e-mail removed", notice)
            .await;
    }

    Ok(Json(json!({ "status": "ok" })))
}

// ---------------------------------------------------------------------------
// Change master password

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    /// base64url of the *current* auth credential — proof of the old password.
    pub auth_credential: String,
    pub totp_code: Option<String>,
    /// The replacement bundle, produced client-side under the new password.
    /// The KDF salt is deliberately absent: it is account-lifetime (I13) and
    /// never rotates on a password change.
    pub new_auth_credential: String,
    pub kdf_params: KdfParams,
    pub master_wrapped_vault_key: Value,
    pub recovery_wrapped_vault_key: Value,
    pub new_recovery_verifier: String,
}

/// POST /api/v1/account/change-password
///
/// Re-key the account under a new master password. Requires proof of the
/// current password (and TOTP when enrolled). The Vault Key is unchanged — the
/// client just re-wraps it — so vault items stay readable; a fresh Recovery Kit
/// is issued (new recovery-wrapped copy). Every *other* session is revoked; the
/// calling device stays signed in.
pub async fn change_password(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: AuthSession,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<Json<Value>, ApiError> {
    let account = db::account_by_id(&state.db, session.account_id)
        .await?
        .ok_or(ApiError::Internal)?;
    confirm_sensitive(
        &state,
        &account,
        &req.auth_credential,
        req.totp_code.as_deref(),
        ip,
    )
    .await?;

    req.kdf_params
        .validate()
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let new_credential = decode32(&req.new_auth_credential, "new_auth_credential")?;
    let new_verifier = decode32(&req.new_recovery_verifier, "new_recovery_verifier")?;
    let now = security::now();

    let mut tx = state.db.begin().await?;
    // Salt and Vault-Key identity are preserved; only the password-derived
    // wrapping (and the auth credential + recovery kit) change.
    sqlx::query(
        "UPDATE accounts SET
           server_auth_hash = ?, kdf_params = ?,
           master_wrapped_vault_key = ?, recovery_wrapped_vault_key = ?,
           recovery_verifier_hash = ?, failed_attempts = 0, lockout_until = NULL
         WHERE id = ?",
    )
    .bind(security::hash_credential(&new_credential))
    .bind(serde_json::to_string(&req.kdf_params).map_err(|_| ApiError::Internal)?)
    .bind(req.master_wrapped_vault_key.to_string())
    .bind(req.recovery_wrapped_vault_key.to_string())
    .bind(security::sha256(&new_verifier))
    .bind(account.id)
    .execute(&mut *tx)
    .await?;
    // Sign out every other device (the current family stays valid).
    sqlx::query(
        "UPDATE sessions SET revoked_at = ?
         WHERE account_id = ? AND family_id != ? AND revoked_at IS NULL",
    )
    .bind(now)
    .bind(account.id)
    .bind(&session.family_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let body = "Your Basementen Vault master password was changed and a new Recovery Kit \
                was issued. All your other devices have been signed out. If this was not \
                you, use your Recovery Kit to regain control and contact your server \
                administrator immediately.";
    state
        .mailer
        .send(
            &account.email,
            "Basementen Vault: master password changed",
            body,
        )
        .await;
    if let Some(backup) = backup_email_of(&state, account.id).await? {
        state
            .mailer
            .send(&backup, "Basementen Vault: master password changed", body)
            .await;
    }

    Ok(Json(json!({ "status": "ok" })))
}
