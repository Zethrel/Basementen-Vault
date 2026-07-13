use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use sqlx::SqlitePool;
use tokio::sync::broadcast;

use crate::config::Config;
use crate::error::ApiError;
use crate::mailer::Mailer;
use crate::rate_limit::IpLimiter;
use crate::security;

/// Per-account change notification fan-out. Carries only the new sequence
/// number — "something changed, pull now" — never data.
#[derive(Default)]
pub struct ChangeNotifier {
    channels: Mutex<HashMap<i64, broadcast::Sender<i64>>>,
}

impl ChangeNotifier {
    pub fn subscribe(&self, account_id: i64) -> broadcast::Receiver<i64> {
        let mut map = self.channels.lock().expect("notifier mutex poisoned");
        map.entry(account_id)
            .or_insert_with(|| broadcast::channel(16).0)
            .subscribe()
    }

    pub fn notify(&self, account_id: i64, seq: i64) {
        let map = self.channels.lock().expect("notifier mutex poisoned");
        if let Some(tx) = map.get(&account_id) {
            // Nobody listening is fine; the receiver count just hits zero.
            let _ = tx.send(seq);
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    pub cfg: Arc<Config>,
    pub mailer: Arc<Mailer>,
    pub ip_limiter: Arc<IpLimiter>,
    pub notifier: Arc<ChangeNotifier>,
    /// Random-credential hash verified for unknown accounts so login cost is
    /// identical whether or not an e-mail exists.
    pub dummy_hash: Arc<String>,
}

impl AppState {
    pub fn new(db: SqlitePool, cfg: Config, mailer: Mailer) -> Self {
        Self {
            db,
            cfg: Arc::new(cfg),
            mailer: Arc::new(mailer),
            ip_limiter: Arc::new(IpLimiter::default()),
            notifier: Arc::new(ChangeNotifier::default()),
            dummy_hash: Arc::new(security::make_dummy_hash()),
        }
    }
}

/// Client IP for rate limiting: `X-Forwarded-For` when behind a trusted
/// reverse proxy, else the socket peer address.
pub struct ClientIp(pub IpAddr);

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        if state.cfg.trust_proxy {
            if let Some(xff) = parts.headers.get("x-forwarded-for") {
                if let Ok(s) = xff.to_str() {
                    // First hop is the original client (proxy appends).
                    if let Some(ip) = s.split(',').next().and_then(|p| p.trim().parse().ok()) {
                        return Ok(ClientIp(ip));
                    }
                }
            }
        }
        let ip = parts
            .extensions
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|ci| ci.0.ip())
            .unwrap_or(IpAddr::from([0, 0, 0, 0]));
        Ok(ClientIp(ip))
    }
}

/// Authenticated session, extracted from `Authorization: Bearer <access token>`.
pub struct AuthSession {
    pub account_id: i64,
    pub session_id: i64,
}

impl FromRequestParts<AppState> for AuthSession {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(ApiError::InvalidToken)?;

        let hash = security::sha256(token.as_bytes());
        let now = security::now();

        let row: Option<(i64, i64)> = sqlx::query_as(
            "SELECT id, account_id FROM sessions
             WHERE access_token_hash = ? AND revoked_at IS NULL AND access_expires_at > ?",
        )
        .bind(&hash)
        .bind(now)
        .fetch_optional(&state.db)
        .await?;

        let (session_id, account_id) = row.ok_or(ApiError::InvalidToken)?;
        Ok(AuthSession {
            account_id,
            session_id,
        })
    }
}
