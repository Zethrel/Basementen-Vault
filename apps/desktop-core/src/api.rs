//! HTTP client for the Basementen Vault server API, including the
//! [`SyncTransport`] implementation used by the sync engine.

use base64::Engine;
use serde_json::{json, Value};
use vault_core::{EncryptedItem, KdfParams, WrappedKey};
use vault_sync::{PullResponse, PushOutcome, SyncTransport, TransportError};

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("network error: {0}")]
    Network(String),
    #[error("invalid e-mail or master password")]
    InvalidCredentials,
    #[error("e-mail address not verified yet — check your inbox")]
    EmailNotVerified,
    #[error("two-factor code required")]
    MfaRequired,
    #[error("too many attempts — try again in {retry_after_secs}s")]
    RateLimited { retry_after_secs: i64 },
    #[error("recovery cooling-off: usable in {retry_after_secs}s")]
    CoolingOff { retry_after_secs: i64 },
    #[error("session expired — log in again")]
    SessionExpired,
    #[error("server error: {0}")]
    Server(String),
}

impl From<reqwest::Error> for ApiError {
    fn from(e: reqwest::Error) -> Self {
        ApiError::Network(e.to_string())
    }
}

pub struct LoginOutcome {
    pub access_token: String,
    pub refresh_token: String,
    pub kdf_params: KdfParams,
    pub kdf_salt: Vec<u8>,
    pub master_wrapped_vault_key: WrappedKey,
}

/// KDF parameters + salt returned by prelogin; both needed before deriving.
pub struct PreloginInfo {
    pub kdf_params: KdfParams,
    pub kdf_salt: Vec<u8>,
}

/// One active device, as returned by the session list. No secrets.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SessionInfo {
    pub id: String,
    pub device_name: String,
    pub created_at: i64,
    pub last_used_at: i64,
    pub current: bool,
}

/// Debug omits the wrapped key blob (it's ciphertext, but no need to log it).
#[derive(Debug)]
pub struct RecoveryData {
    pub email: String,
    pub kdf_params: KdfParams,
    /// The account's existing KDF salt; recovery reuses it (account-lifetime).
    pub kdf_salt: Vec<u8>,
    pub recovery_wrapped_vault_key: WrappedKey,
    pub supports_data_recovery: bool,
}

pub struct ApiClient {
    http: reqwest::Client,
    base_url: String,
    access_token: Option<String>,
    refresh_token: Option<String>,
}

/// Decode a base64url `kdf_salt` field from a server response.
fn decode_salt(body: &Value) -> Result<Vec<u8>, ApiError> {
    let s = body["kdf_salt"]
        .as_str()
        .ok_or_else(|| ApiError::Server("missing kdf_salt".into()))?;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| ApiError::Server("kdf_salt not base64url".into()))
}

fn b64_bytes(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn b64(credential: [u8; 32]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(credential)
}

/// Normalize a user-entered server address into a URL the HTTP client accepts.
///
/// Users naturally type a bare `host:port` (the login field even hints one), but
/// `reqwest` needs a scheme — without it `127.0.0.1:8080` parses as scheme
/// `127.0.0.1`, which is rejected ("builder error"). We add one when it's
/// missing: `http` for loopback / RFC 1918 LAN addresses (where plain HTTP is
/// acceptable per docs/SELF_HOSTING.md), `https` for anything else, so a bare
/// public host defaults to TLS rather than silently downgrading a
/// password-equivalent credential. An explicit scheme is always respected.
fn normalize_base_url(input: &str) -> String {
    let trimmed = input.trim().trim_end_matches('/');
    if trimmed.contains("://") {
        return trimmed.to_string();
    }
    // Host is everything before the first `:` (port) or `/` (path).
    let host = trimmed.split([':', '/']).next().unwrap_or(trimmed);
    let is_private_172 = host
        .strip_prefix("172.")
        .and_then(|rest| rest.split('.').next())
        .and_then(|octet| octet.parse::<u8>().ok())
        .is_some_and(|octet| (16..=31).contains(&octet));
    let is_local = matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
        || host.starts_with("127.")
        || host.starts_with("10.")
        || host.starts_with("192.168.")
        || is_private_172;
    let scheme = if is_local { "http" } else { "https" };
    format!("{scheme}://{trimmed}")
}

impl ApiClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: normalize_base_url(base_url),
            access_token: None,
            refresh_token: None,
        }
    }

    pub fn with_tokens(base_url: &str, access: Option<String>, refresh: Option<String>) -> Self {
        let mut client = Self::new(base_url);
        client.access_token = access;
        client.refresh_token = refresh;
        client
    }

    pub fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref()
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }

    /// Map an error response body onto the typed error surface.
    fn classify(status: reqwest::StatusCode, body: &Value) -> ApiError {
        let code = body["error"].as_str().unwrap_or("");
        match code {
            "email_not_verified" => ApiError::EmailNotVerified,
            "mfa_required" => ApiError::MfaRequired,
            "locked_out" | "rate_limited" => ApiError::RateLimited {
                retry_after_secs: body["retry_after_secs"].as_i64().unwrap_or(60),
            },
            "cooling_off" => ApiError::CoolingOff {
                retry_after_secs: body["retry_after_secs"].as_i64().unwrap_or(0),
            },
            "invalid_credentials" => ApiError::InvalidCredentials,
            "invalid_token" => ApiError::SessionExpired,
            _ => ApiError::Server(format!("{status}: {code}")),
        }
    }

    // --- account flows -------------------------------------------------

    pub async fn prelogin(&self, email: &str) -> Result<PreloginInfo, ApiError> {
        let resp = self
            .http
            .get(self.url("/api/v1/accounts/prelogin"))
            .query(&[("email", email)])
            .send()
            .await?;
        let body: Value = resp.json().await?;
        Ok(PreloginInfo {
            kdf_params: serde_json::from_value(body["kdf_params"].clone())
                .map_err(|e| ApiError::Server(e.to_string()))?,
            kdf_salt: decode_salt(&body)?,
        })
    }

    pub async fn register(
        &self,
        email: &str,
        bundle: &vault_core::RegistrationBundle,
    ) -> Result<(), ApiError> {
        let resp = self
            .http
            .post(self.url("/api/v1/accounts/register"))
            .json(&json!({
                "email": email,
                "auth_credential": b64(bundle.auth_credential),
                "recovery_verifier": b64(bundle.recovery_verifier),
                "kdf_params": bundle.kdf_params,
                "kdf_salt": b64_bytes(&bundle.kdf_salt),
                "master_wrapped_vault_key": bundle.master_wrapped_vault_key,
                "recovery_wrapped_vault_key": bundle.recovery_wrapped_vault_key,
            }))
            .send()
            .await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status();
            let body: Value = resp.json().await.unwrap_or(Value::Null);
            Err(Self::classify(status, &body))
        }
    }

    /// Ask the server to re-send the e-mail verification link. Anti-enumeration:
    /// always succeeds regardless of whether the address exists or is already
    /// verified, so the caller learns nothing from the result.
    pub async fn resend_verification(&self, email: &str) -> Result<(), ApiError> {
        let resp = self
            .http
            .post(self.url("/api/v1/accounts/resend-verification"))
            .json(&json!({ "email": email }))
            .send()
            .await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status();
            let body: Value = resp.json().await.unwrap_or(Value::Null);
            Err(Self::classify(status, &body))
        }
    }

    pub async fn login(
        &mut self,
        email: &str,
        auth_credential: [u8; 32],
        totp_code: Option<&str>,
        recovery_code: Option<&str>,
        device_name: &str,
    ) -> Result<LoginOutcome, ApiError> {
        let resp = self
            .http
            .post(self.url("/api/v1/auth/login"))
            .json(&json!({
                "email": email,
                "auth_credential": b64(auth_credential),
                "totp_code": totp_code,
                "recovery_code": recovery_code,
                "device_name": device_name,
            }))
            .send()
            .await?;
        let status = resp.status();
        let body: Value = resp.json().await?;
        if !status.is_success() {
            return Err(Self::classify(status, &body));
        }

        let outcome = LoginOutcome {
            access_token: body["access_token"]
                .as_str()
                .ok_or_else(|| ApiError::Server("missing access_token".into()))?
                .to_string(),
            refresh_token: body["refresh_token"]
                .as_str()
                .ok_or_else(|| ApiError::Server("missing refresh_token".into()))?
                .to_string(),
            kdf_params: serde_json::from_value(body["kdf_params"].clone())
                .map_err(|e| ApiError::Server(e.to_string()))?,
            kdf_salt: decode_salt(&body)?,
            master_wrapped_vault_key: serde_json::from_value(
                body["master_wrapped_vault_key"].clone(),
            )
            .map_err(|e| ApiError::Server(e.to_string()))?,
        };
        self.access_token = Some(outcome.access_token.clone());
        self.refresh_token = Some(outcome.refresh_token.clone());
        Ok(outcome)
    }

    /// Rotate the session. Returns the new refresh token so the caller can
    /// re-encrypt and persist it.
    pub async fn refresh_session(&mut self) -> Result<String, ApiError> {
        let refresh = self.refresh_token.clone().ok_or(ApiError::SessionExpired)?;
        let resp = self
            .http
            .post(self.url("/api/v1/auth/refresh"))
            .json(&json!({ "refresh_token": refresh }))
            .send()
            .await?;
        let status = resp.status();
        let body: Value = resp.json().await?;
        if !status.is_success() {
            self.access_token = None;
            self.refresh_token = None;
            return Err(ApiError::SessionExpired);
        }
        self.access_token = Some(
            body["access_token"]
                .as_str()
                .ok_or_else(|| ApiError::Server("missing access_token".into()))?
                .to_string(),
        );
        let new_refresh = body["refresh_token"]
            .as_str()
            .ok_or_else(|| ApiError::Server("missing refresh_token".into()))?
            .to_string();
        self.refresh_token = Some(new_refresh.clone());
        Ok(new_refresh)
    }

    pub async fn logout(&mut self) {
        if let Some(token) = &self.access_token {
            let _ = self
                .http
                .post(self.url("/api/v1/auth/logout"))
                .bearer_auth(token)
                .send()
                .await;
        }
        self.access_token = None;
        self.refresh_token = None;
    }

    // --- recovery --------------------------------------------------------

    pub async fn recovery_start(&self, email: &str) -> Result<(), ApiError> {
        let resp = self
            .http
            .post(self.url("/api/v1/accounts/recovery/start"))
            .json(&json!({ "email": email }))
            .send()
            .await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status();
            let body: Value = resp.json().await.unwrap_or(Value::Null);
            Err(Self::classify(status, &body))
        }
    }

    pub async fn recovery_data(&self, token: &str) -> Result<RecoveryData, ApiError> {
        let resp = self
            .http
            .get(self.url("/api/v1/accounts/recovery/data"))
            .query(&[("token", token)])
            .send()
            .await?;
        let status = resp.status();
        let body: Value = resp.json().await?;
        if !status.is_success() {
            return Err(Self::classify(status, &body));
        }
        Ok(RecoveryData {
            email: body["email"]
                .as_str()
                .ok_or_else(|| ApiError::Server("missing email".into()))?
                .to_string(),
            kdf_params: serde_json::from_value(body["kdf_params"].clone())
                .map_err(|e| ApiError::Server(e.to_string()))?,
            kdf_salt: decode_salt(&body)?,
            recovery_wrapped_vault_key: serde_json::from_value(
                body["recovery_wrapped_vault_key"].clone(),
            )
            .map_err(|e| ApiError::Server(e.to_string()))?,
            supports_data_recovery: body["supports_data_recovery"].as_bool().unwrap_or(false),
        })
    }

    /// Complete a recovery. `verifier` proves Recovery Kit possession
    /// (data-preserving); `wipe` is the explicit no-kit reset path.
    pub async fn recovery_complete(
        &self,
        token: &str,
        bundle: &vault_core::RegistrationBundle,
        verifier: Option<[u8; 32]>,
        wipe: bool,
    ) -> Result<(), ApiError> {
        let resp = self
            .http
            .post(self.url("/api/v1/accounts/recovery/complete"))
            .json(&json!({
                "token": token,
                "recovery_verifier": verifier.map(b64),
                "wipe": wipe,
                "auth_credential": b64(bundle.auth_credential),
                "kdf_params": bundle.kdf_params,
                "kdf_salt": b64_bytes(&bundle.kdf_salt),
                "master_wrapped_vault_key": bundle.master_wrapped_vault_key,
                "recovery_wrapped_vault_key": bundle.recovery_wrapped_vault_key,
                "new_recovery_verifier": b64(bundle.recovery_verifier),
            }))
            .send()
            .await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status();
            let body: Value = resp.json().await.unwrap_or(Value::Null);
            Err(Self::classify(status, &body))
        }
    }

    // --- backup e-mail -----------------------------------------------------

    pub async fn set_backup_email(
        &mut self,
        auth_credential: [u8; 32],
        totp_code: Option<&str>,
        backup_email: &str,
    ) -> Result<(), ApiError> {
        let payload = json!({
            "auth_credential": b64(auth_credential),
            "totp_code": totp_code,
            "backup_email": backup_email,
        });
        let (status, body) = self
            .authed(move |http, base, token| {
                http.post(format!("{base}/api/v1/account/backup-email"))
                    .json(&payload)
                    .bearer_auth(token)
            })
            .await?;
        if status.is_success() {
            Ok(())
        } else {
            Err(Self::classify(status, &body))
        }
    }

    pub async fn remove_backup_email(
        &mut self,
        auth_credential: [u8; 32],
        totp_code: Option<&str>,
    ) -> Result<(), ApiError> {
        let payload = json!({
            "auth_credential": b64(auth_credential),
            "totp_code": totp_code,
        });
        let (status, body) = self
            .authed(move |http, base, token| {
                http.delete(format!("{base}/api/v1/account/backup-email"))
                    .json(&payload)
                    .bearer_auth(token)
            })
            .await?;
        if status.is_success() {
            Ok(())
        } else {
            Err(Self::classify(status, &body))
        }
    }

    // --- MFA enrollment ---------------------------------------------------

    /// Begin TOTP enrollment: returns the shared secret (base32) and the
    /// `otpauth://` URI to render as a QR code. Requires a fresh password
    /// confirmation. MFA only becomes active after [`Self::totp_activate`].
    pub async fn totp_enroll(
        &mut self,
        auth_credential: [u8; 32],
    ) -> Result<(String, String), ApiError> {
        let payload = json!({ "auth_credential": b64(auth_credential) });
        let (status, body) = self
            .authed(move |http, base, token| {
                http.post(format!("{base}/api/v1/mfa/totp/enroll"))
                    .json(&payload)
                    .bearer_auth(token)
            })
            .await?;
        if !status.is_success() {
            return Err(Self::classify(status, &body));
        }
        Ok((
            body["secret_base32"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            body["otpauth_uri"].as_str().unwrap_or_default().to_string(),
        ))
    }

    /// Confirm enrollment with a live code; on success TOTP becomes required
    /// for login and the account's one-time recovery codes are returned.
    pub async fn totp_activate(&mut self, code: &str) -> Result<Vec<String>, ApiError> {
        let payload = json!({ "code": code });
        let (status, body) = self
            .authed(move |http, base, token| {
                http.post(format!("{base}/api/v1/mfa/totp/activate"))
                    .json(&payload)
                    .bearer_auth(token)
            })
            .await?;
        if !status.is_success() {
            return Err(Self::classify(status, &body));
        }
        Ok(body["recovery_codes"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Turn TOTP off. Requires a fresh password confirmation and a valid
    /// current code.
    pub async fn totp_disable(
        &mut self,
        auth_credential: [u8; 32],
        totp_code: &str,
    ) -> Result<(), ApiError> {
        let payload = json!({
            "auth_credential": b64(auth_credential),
            "totp_code": totp_code,
        });
        let (status, body) = self
            .authed(move |http, base, token| {
                http.post(format!("{base}/api/v1/mfa/totp/disable"))
                    .json(&payload)
                    .bearer_auth(token)
            })
            .await?;
        if status.is_success() {
            Ok(())
        } else {
            Err(Self::classify(status, &body))
        }
    }

    // --- change master password -------------------------------------------

    /// Re-key the account under a new master password. `current_auth_credential`
    /// proves the old password; `bundle` is the fresh registration produced by
    /// `vault_core::account::change_password` (re-wrapped Vault Key + new
    /// recovery kit). The server keeps the account-lifetime salt and revokes
    /// every other session.
    pub async fn change_password(
        &mut self,
        current_auth_credential: [u8; 32],
        totp_code: Option<&str>,
        bundle: &vault_core::RegistrationBundle,
    ) -> Result<(), ApiError> {
        let payload = json!({
            "auth_credential": b64(current_auth_credential),
            "totp_code": totp_code,
            "new_auth_credential": b64(bundle.auth_credential),
            "kdf_params": bundle.kdf_params,
            "master_wrapped_vault_key": bundle.master_wrapped_vault_key,
            "recovery_wrapped_vault_key": bundle.recovery_wrapped_vault_key,
            "new_recovery_verifier": b64(bundle.recovery_verifier),
        });
        let (status, body) = self
            .authed(move |http, base, token| {
                http.post(format!("{base}/api/v1/account/change-password"))
                    .json(&payload)
                    .bearer_auth(token)
            })
            .await?;
        if status.is_success() {
            Ok(())
        } else {
            Err(Self::classify(status, &body))
        }
    }

    // --- MFA maintenance --------------------------------------------------

    /// Whether TOTP is active and how many single-use recovery codes remain,
    /// so the app can warn the user before they run out.
    pub async fn mfa_status(&mut self) -> Result<(bool, i64), ApiError> {
        let (status, body) = self
            .authed(|http, base, token| {
                http.get(format!("{base}/api/v1/mfa/status"))
                    .bearer_auth(token)
            })
            .await?;
        if !status.is_success() {
            return Err(Self::classify(status, &body));
        }
        Ok((
            body["totp_active"].as_bool().unwrap_or(false),
            body["recovery_codes_remaining"].as_i64().unwrap_or(0),
        ))
    }

    /// Replace the account's single-use recovery codes with a fresh set,
    /// returned so the caller can show them exactly once. Requires a fresh
    /// password confirmation and a current TOTP code.
    pub async fn regenerate_recovery_codes(
        &mut self,
        auth_credential: [u8; 32],
        totp_code: &str,
    ) -> Result<Vec<String>, ApiError> {
        let payload = json!({
            "auth_credential": b64(auth_credential),
            "totp_code": totp_code,
        });
        let (status, body) = self
            .authed(move |http, base, token| {
                http.post(format!("{base}/api/v1/mfa/recovery-codes/regenerate"))
                    .json(&payload)
                    .bearer_auth(token)
            })
            .await?;
        if !status.is_success() {
            return Err(Self::classify(status, &body));
        }
        Ok(body["recovery_codes"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default())
    }

    // --- rollback checkpoint ---------------------------------------------

    /// Fetch the account's stored rollback checkpoint `(seq, tag)`, if any.
    pub async fn get_checkpoint(&mut self) -> Result<Option<(i64, Vec<u8>)>, ApiError> {
        let (status, body) = self
            .authed(|http, base, token| {
                http.get(format!("{base}/api/v1/vault/checkpoint"))
                    .bearer_auth(token)
            })
            .await?;
        if !status.is_success() {
            return Err(Self::classify(status, &body));
        }
        let cp = &body["checkpoint"];
        if cp.is_null() {
            return Ok(None);
        }
        let seq = cp["seq"]
            .as_i64()
            .ok_or_else(|| ApiError::Server("checkpoint missing seq".into()))?;
        let tag = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(cp["tag"].as_str().unwrap_or(""))
            .map_err(|_| ApiError::Server("checkpoint tag not base64url".into()))?;
        Ok(Some((seq, tag)))
    }

    /// Publish an updated rollback checkpoint (server keeps the highest).
    pub async fn put_checkpoint(&mut self, seq: i64, tag: &[u8]) -> Result<(), ApiError> {
        let payload = json!({ "seq": seq, "tag": b64_bytes(tag) });
        let (status, body) = self
            .authed(move |http, base, token| {
                http.put(format!("{base}/api/v1/vault/checkpoint"))
                    .json(&payload)
                    .bearer_auth(token)
            })
            .await?;
        if status.is_success() {
            Ok(())
        } else {
            Err(Self::classify(status, &body))
        }
    }

    // --- session (device) management -------------------------------------

    /// List the account's active devices (non-secret metadata).
    pub async fn list_sessions(&mut self) -> Result<Vec<SessionInfo>, ApiError> {
        let (status, body) = self
            .authed(|http, base, token| {
                http.get(format!("{base}/api/v1/sessions"))
                    .bearer_auth(token)
            })
            .await?;
        if !status.is_success() {
            return Err(Self::classify(status, &body));
        }
        serde_json::from_value(body["sessions"].clone())
            .map_err(|e| ApiError::Server(e.to_string()))
    }

    /// Revoke one device (by its family id from [`list_sessions`]).
    pub async fn revoke_session(&mut self, id: &str) -> Result<(), ApiError> {
        let id = id.to_string();
        let (status, body) = self
            .authed(move |http, base, token| {
                http.delete(format!("{base}/api/v1/sessions/{id}"))
                    .bearer_auth(token)
            })
            .await?;
        if status.is_success() {
            Ok(())
        } else {
            Err(Self::classify(status, &body))
        }
    }

    /// Log out every other device. Returns how many were revoked.
    pub async fn revoke_other_sessions(&mut self) -> Result<u64, ApiError> {
        let (status, body) = self
            .authed(|http, base, token| {
                http.post(format!("{base}/api/v1/sessions/revoke-others"))
                    .bearer_auth(token)
            })
            .await?;
        if status.is_success() {
            Ok(body["revoked"].as_u64().unwrap_or(0))
        } else {
            Err(Self::classify(status, &body))
        }
    }

    // --- authed requests with one automatic refresh-and-retry -----------

    async fn authed(
        &mut self,
        build: impl Fn(&reqwest::Client, &str, &str) -> reqwest::RequestBuilder,
    ) -> Result<(reqwest::StatusCode, Value), ApiError> {
        for attempt in 0..2 {
            let token = self.access_token.clone().ok_or(ApiError::SessionExpired)?;
            let resp = build(&self.http, &self.base_url, &token).send().await?;
            let status = resp.status();
            if status == reqwest::StatusCode::UNAUTHORIZED && attempt == 0 {
                // Access token likely expired; rotate and retry once.
                self.refresh_session().await?;
                continue;
            }
            let body: Value = resp.json().await.unwrap_or(Value::Null);
            return Ok((status, body));
        }
        Err(ApiError::SessionExpired)
    }
}

impl SyncTransport for ApiClient {
    async fn pull(&mut self, since: i64) -> Result<PullResponse, TransportError> {
        let (status, body) = self
            .authed(move |http, base, token| {
                http.get(format!("{base}/api/v1/vault/items"))
                    .query(&[("since", since)])
                    .bearer_auth(token)
            })
            .await
            .map_err(|e| TransportError::Network(e.to_string()))?;
        if status != reqwest::StatusCode::OK {
            return Err(TransportError::Rejected(format!("pull: {status}")));
        }
        serde_json::from_value(body).map_err(|e| TransportError::Rejected(e.to_string()))
    }

    async fn push_upsert(&mut self, item: &EncryptedItem) -> Result<PushOutcome, TransportError> {
        let payload =
            serde_json::to_value(item).map_err(|e| TransportError::Rejected(e.to_string()))?;
        let item_id = item.item_id.clone();
        let (status, body) = self
            .authed(move |http, base, token| {
                http.put(format!("{base}/api/v1/vault/items/{item_id}"))
                    .json(&payload)
                    .bearer_auth(token)
            })
            .await
            .map_err(|e| TransportError::Network(e.to_string()))?;
        match status {
            reqwest::StatusCode::OK => Ok(PushOutcome::Accepted {
                revision: body["revision"].as_i64().unwrap_or(0),
                seq: body["seq"].as_i64().unwrap_or(0),
            }),
            reqwest::StatusCode::CONFLICT => Ok(PushOutcome::Conflict {
                current: serde_json::from_value(body["current"].clone()).ok(),
            }),
            other => Err(TransportError::Rejected(format!("upsert: {other}"))),
        }
    }

    async fn push_delete(
        &mut self,
        item_id: &str,
        base_revision: i64,
    ) -> Result<PushOutcome, TransportError> {
        let item_id = item_id.to_string();
        let (status, body) = self
            .authed(move |http, base, token| {
                http.delete(format!("{base}/api/v1/vault/items/{item_id}"))
                    .query(&[("base_revision", base_revision)])
                    .bearer_auth(token)
            })
            .await
            .map_err(|e| TransportError::Network(e.to_string()))?;
        match status {
            reqwest::StatusCode::OK => Ok(PushOutcome::Accepted {
                revision: body["revision"].as_i64().unwrap_or(0),
                seq: body.get("seq").and_then(|v| v.as_i64()).unwrap_or(0),
            }),
            reqwest::StatusCode::CONFLICT => Ok(PushOutcome::Conflict {
                current: serde_json::from_value(body["current"].clone()).ok(),
            }),
            reqwest::StatusCode::NOT_FOUND => Ok(PushOutcome::Conflict { current: None }),
            other => Err(TransportError::Rejected(format!("delete: {other}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_base_url;

    #[test]
    fn scheme_less_local_gets_http() {
        // The exact input from the setup screen that produced "builder error".
        assert_eq!(
            normalize_base_url("127.0.0.1:8080"),
            "http://127.0.0.1:8080"
        );
        assert_eq!(
            normalize_base_url("localhost:8080"),
            "http://localhost:8080"
        );
        assert_eq!(
            normalize_base_url("192.168.1.20:8080"),
            "http://192.168.1.20:8080"
        );
        assert_eq!(normalize_base_url("10.0.0.5:8080"), "http://10.0.0.5:8080");
        assert_eq!(
            normalize_base_url("172.16.0.9:8080"),
            "http://172.16.0.9:8080"
        );
        assert_eq!(normalize_base_url("172.31.255.1"), "http://172.31.255.1");
    }

    #[test]
    fn scheme_less_public_defaults_to_https() {
        // A bare public host must not silently downgrade to plain HTTP.
        assert_eq!(
            normalize_base_url("vault.example.com"),
            "https://vault.example.com"
        );
        assert_eq!(
            normalize_base_url("vault.example.com:8080"),
            "https://vault.example.com:8080"
        );
        // 172.32.x is outside the private 172.16–31 range → public.
        assert_eq!(normalize_base_url("172.32.0.1"), "https://172.32.0.1");
    }

    #[test]
    fn explicit_scheme_is_respected() {
        assert_eq!(
            normalize_base_url("https://vault.example.com"),
            "https://vault.example.com"
        );
        // Even an "insecure" explicit choice for a public host is the user's to make.
        assert_eq!(
            normalize_base_url("http://vault.example.com"),
            "http://vault.example.com"
        );
        assert_eq!(
            normalize_base_url("http://127.0.0.1:8080"),
            "http://127.0.0.1:8080"
        );
    }

    #[test]
    fn trims_whitespace_and_trailing_slash() {
        assert_eq!(
            normalize_base_url("  http://127.0.0.1:8080/  "),
            "http://127.0.0.1:8080"
        );
        assert_eq!(
            normalize_base_url("127.0.0.1:8080/"),
            "http://127.0.0.1:8080"
        );
    }
}
