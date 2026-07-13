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

use axum::routing::{get, post, put};
use axum::Router;

use crate::state::AppState;

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
        .with_state(state)
}
