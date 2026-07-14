use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use vault_core::KdfParams;

use crate::error::ApiError;
use crate::state::AppState;
use crate::{db, security};

const VERIFY_TOKEN_TTL_SECS: i64 = 15 * 60;

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    /// base64url of the 32-byte client AuthKey.
    pub auth_credential: String,
    pub kdf_params: KdfParams,
    /// base64url of the 16-byte random per-account KDF salt (not secret).
    pub kdf_salt: String,
    /// base64url of the 32-byte recovery verifier (HKDF branch of the
    /// Vault Key); stored hashed, demanded for data-preserving recovery.
    pub recovery_verifier: String,
    /// Opaque WrappedKey JSON blobs; the server stores, never inspects.
    pub master_wrapped_vault_key: Value,
    pub recovery_wrapped_vault_key: Value,
}

fn decode_credential(b64: &str) -> Result<Vec<u8>, ApiError> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|_| ApiError::BadRequest("auth_credential must be base64url".into()))?;
    if bytes.len() != 32 {
        return Err(ApiError::BadRequest(
            "auth_credential must be 32 bytes".into(),
        ));
    }
    Ok(bytes)
}

fn decode_salt(b64: &str) -> Result<Vec<u8>, ApiError> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|_| ApiError::BadRequest("kdf_salt must be base64url".into()))?;
    if bytes.len() != 16 {
        return Err(ApiError::BadRequest("kdf_salt must be 16 bytes".into()));
    }
    Ok(bytes)
}

/// base64url-encode the account's stored salt for the wire.
pub(crate) fn encode_salt(salt: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(salt)
}

fn validate_email(email: &str) -> Result<(), ApiError> {
    let ok = email.len() <= 254
        && email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && domain.contains('.') && !domain.starts_with('.')
        });
    if ok {
        Ok(())
    } else {
        Err(ApiError::BadRequest("invalid e-mail address".into()))
    }
}

/// POST /api/v1/accounts/register
///
/// Anti-enumeration: succeeds with the same response whether or not the
/// e-mail is already registered. Existing accounts get a notification
/// instead of a duplicate account.
pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<Value>, ApiError> {
    if !state.cfg.registration_open {
        return Err(ApiError::BadRequest(
            "registration is closed on this server".into(),
        ));
    }

    let email = vault_core::kdf::normalize_email(&req.email);
    validate_email(&email)?;
    let credential = decode_credential(&req.auth_credential)?;
    let verifier = decode_credential(&req.recovery_verifier)?;
    let salt = decode_salt(&req.kdf_salt)?;
    req.kdf_params
        .validate()
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    let response = json!({
        "status": "ok",
        "message": "If this address is new, a verification e-mail has been sent."
    });

    if db::account_by_email(&state.db, &email).await?.is_some() {
        state
            .mailer
            .send(
                &email,
                "Basementen Vault: registration attempt",
                "Someone tried to register a new vault account with this e-mail \
                 address, but it already has an account. If this was not you, \
                 you can ignore this message — nothing has changed.",
            )
            .await;
        return Ok(Json(response));
    }

    let now = security::now();
    let hash = security::hash_credential(&credential);
    let account_id: i64 = sqlx::query_scalar(
        "INSERT INTO accounts (email, server_auth_hash, kdf_params, kdf_salt,
                               master_wrapped_vault_key, recovery_wrapped_vault_key,
                               recovery_verifier_hash, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(&email)
    .bind(&hash)
    .bind(serde_json::to_string(&req.kdf_params).map_err(|_| ApiError::Internal)?)
    .bind(salt)
    .bind(req.master_wrapped_vault_key.to_string())
    .bind(req.recovery_wrapped_vault_key.to_string())
    .bind(security::sha256(&verifier))
    .bind(now)
    .fetch_one(&state.db)
    .await?;

    send_verification_email(&state, account_id, &email).await?;
    Ok(Json(response))
}

async fn send_verification_email(
    state: &AppState,
    account_id: i64,
    email: &str,
) -> Result<(), ApiError> {
    let (token, token_hash) = security::new_token("bvet_");
    let now = security::now();
    sqlx::query(
        "INSERT INTO email_tokens (account_id, purpose, token_hash, expires_at)
         VALUES (?, 'verify_email', ?, ?)",
    )
    .bind(account_id)
    .bind(&token_hash)
    .bind(now + VERIFY_TOKEN_TTL_SECS)
    .execute(&state.db)
    .await?;

    let link = format!(
        "{}/api/v1/accounts/verify?token={token}",
        state.cfg.base_url
    );
    state
        .mailer
        .send(
            email,
            "Basementen Vault: verify your e-mail",
            &format!(
                "Welcome to Basementen Vault.\n\n\
                 Confirm this e-mail address by opening the link below within \
                 15 minutes:\n\n{link}\n\n\
                 If you did not create this account, ignore this message."
            ),
        )
        .await;
    Ok(())
}

#[derive(Deserialize)]
pub struct VerifyQuery {
    pub token: String,
}

/// GET /api/v1/accounts/verify?token=…
pub async fn verify(
    State(state): State<AppState>,
    Query(q): Query<VerifyQuery>,
) -> Result<&'static str, ApiError> {
    let hash = security::sha256(q.token.as_bytes());
    let now = security::now();

    let row: Option<(i64, i64)> = sqlx::query_as(
        "SELECT id, account_id FROM email_tokens
         WHERE token_hash = ? AND purpose = 'verify_email'
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
    sqlx::query(
        "UPDATE accounts SET email_verified_at = ? WHERE id = ? AND email_verified_at IS NULL",
    )
    .bind(now)
    .bind(account_id)
    .execute(&state.db)
    .await?;

    Ok("E-mail address verified. You can now log in from your Basementen Vault app.")
}

#[derive(Deserialize)]
pub struct PreloginQuery {
    pub email: String,
}

/// GET /api/v1/accounts/prelogin?email=…
///
/// Returns the KDF parameters and salt the client needs before it can derive
/// its login credential. Anti-enumeration: an unknown address receives the
/// default parameters and a *stable, unpredictable* dummy salt (HMAC of the
/// e-mail under a server secret), indistinguishable from a real account.
pub async fn prelogin(
    State(state): State<AppState>,
    Query(q): Query<PreloginQuery>,
) -> Result<Json<Value>, ApiError> {
    let email = vault_core::kdf::normalize_email(&q.email);
    let (params, salt) = match db::account_by_email(&state.db, &email).await? {
        Some(account) => {
            let params = serde_json::from_str(&account.kdf_params)
                .unwrap_or_else(|_| serde_json::to_value(KdfParams::desktop()).expect("static"));
            (params, account.kdf_salt)
        }
        None => (
            serde_json::to_value(KdfParams::desktop()).expect("static"),
            security::dummy_kdf_salt(&state.enumeration_secret, &email),
        ),
    };
    Ok(Json(json!({
        "kdf_params": params,
        "kdf_salt": encode_salt(&salt),
    })))
}
