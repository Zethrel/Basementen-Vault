//! Basementen Vault API server.
//!
//! A deliberately small, self-hostable service: it authenticates accounts
//! (stacked Argon2id + optional TOTP), enforces abuse controls (250–300 ms
//! failure delay, per-account progressive lockout, per-IP rate limiting),
//! and stores opaque encrypted blobs. It holds no key material and can
//! decrypt nothing.

pub mod config;
pub mod db;
pub mod error;
pub mod mailer;
pub mod rate_limit;
pub mod routes;
pub mod security;
pub mod state;
pub mod totp;

use axum::http::header::{HeaderName, HeaderValue};
use axum::routing::{get, post, put};
use axum::Router;

use crate::state::AppState;

/// Baseline security headers on every response. The API serves JSON to
/// native clients, so the browser-oriented headers are pure defense in
/// depth (e.g. if a response ever gets opened in a browser tab).
async fn security_headers(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    let set = |headers: &mut axum::http::HeaderMap, name: &'static str, value: &'static str| {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    };
    // Responses carry secrets (wrapped keys, tokens): never cache.
    set(headers, "cache-control", "no-store");
    set(headers, "x-content-type-options", "nosniff");
    set(headers, "x-frame-options", "DENY");
    set(headers, "referrer-policy", "no-referrer");
    set(
        headers,
        "content-security-policy",
        "default-src 'none'; frame-ancestors 'none'",
    );
    response
}

pub fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/health", get(|| async { "ok" }))
        .route(
            "/api/v1/accounts/register",
            post(routes::accounts::register),
        )
        .route("/api/v1/accounts/verify", get(routes::accounts::verify))
        .route("/api/v1/accounts/prelogin", get(routes::accounts::prelogin))
        .route("/api/v1/auth/login", post(routes::auth::login))
        .route("/api/v1/auth/refresh", post(routes::auth::refresh))
        .route("/api/v1/auth/logout", post(routes::auth::logout))
        .route("/api/v1/mfa/totp/enroll", post(routes::mfa::totp_enroll))
        .route(
            "/api/v1/mfa/totp/activate",
            post(routes::mfa::totp_activate),
        )
        .route("/api/v1/mfa/totp/disable", post(routes::mfa::totp_disable))
        .route("/api/v1/vault/keys", get(routes::vault::get_keys))
        .route("/api/v1/vault/items", get(routes::items::list_items))
        .route(
            "/api/v1/vault/items/{item_id}",
            put(routes::items::put_item).delete(routes::items::delete_item),
        )
        .route("/api/v1/vault/events", get(routes::items::events))
        .route(
            "/api/v1/accounts/recovery/start",
            post(routes::recovery::start),
        )
        .route(
            "/api/v1/accounts/recovery/data",
            get(routes::recovery::data),
        )
        .route(
            "/api/v1/accounts/recovery/complete",
            post(routes::recovery::complete),
        )
        .route(
            "/api/v1/accounts/recovery/cancel",
            get(routes::recovery::cancel),
        )
        .route(
            "/api/v1/account/backup-email",
            post(routes::recovery::set_backup_email).delete(routes::recovery::remove_backup_email),
        )
        .route(
            "/api/v1/accounts/verify-backup",
            get(routes::recovery::verify_backup_email),
        )
        .layer(axum::middleware::from_fn(security_headers))
        .with_state(state)
}
