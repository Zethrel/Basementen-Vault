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

impl ApiClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
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
