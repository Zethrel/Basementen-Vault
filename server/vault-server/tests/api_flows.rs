//! Integration tests: a real vault-core client driving the API end to end
//! (register → verify e-mail → login → MFA → tokens → key retrieval),
//! plus the abuse controls: failure delay, progressive lockout, and
//! anti-enumeration behaviour.

use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Instant;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use base64::Engine;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use vault_server::config::{Config, MailConfig};
use vault_server::mailer::Mailer;
use vault_server::state::AppState;
use vault_server::{build_app, db, security, totp};

const EMAIL: &str = "sig@example.com";
const PASSWORD: &str = "a strong master password";

struct TestServer {
    app: Router,
    state: AppState,
}

async fn test_server() -> TestServer {
    let pool = db::connect_in_memory().await.expect("in-memory db");
    let cfg = Config {
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        db_path: ":memory:".into(),
        base_url: "http://vault.test".into(),
        registration_open: true,
        trust_proxy: false,
        recovery_cooloff_secs: 72 * 3600,
        mail: MailConfig::Console,
    };
    let state = AppState::new(pool, cfg, Mailer::Memory(Mutex::new(Vec::new())));
    TestServer {
        app: build_app(state.clone()),
        state,
    }
}

impl TestServer {
    async fn request(
        &self,
        method: &str,
        path: &str,
        bearer: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder().method(method).uri(path);
        if let Some(token) = bearer {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let request = match body {
            Some(v) => builder
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(v.to_string())),
            None => builder.body(Body::empty()),
        }
        .expect("request build");

        let response = self.app.clone().oneshot(request).await.expect("response");
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes) }));
        (status, value)
    }

    /// Pull the last verification link token out of the captured e-mails.
    fn last_email_token(&self, to: &str) -> String {
        let mails = self.state.mailer.sent();
        let mail = mails
            .iter()
            .rev()
            .find(|m| m.to == to && m.body.contains("verify?token="))
            .expect("verification e-mail sent");
        let start = mail.body.find("verify?token=").unwrap() + "verify?token=".len();
        mail.body[start..]
            .split_whitespace()
            .next()
            .unwrap()
            .to_string()
    }
}

fn client_bundle(email: &str, password: &str) -> (vault_core::account::Registration, Value) {
    let reg = vault_core::account::register(password, email, vault_core::KdfParams::mobile_floor())
        .expect("client-side registration");
    let body = json!({
        "email": email,
        "auth_credential": base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(reg.bundle.auth_credential),
        "recovery_verifier": base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(reg.bundle.recovery_verifier),
        "kdf_params": reg.bundle.kdf_params,
        "master_wrapped_vault_key": serde_json::to_value(&reg.bundle.master_wrapped_vault_key).unwrap(),
        "recovery_wrapped_vault_key": serde_json::to_value(&reg.bundle.recovery_wrapped_vault_key).unwrap(),
    });
    (reg, body)
}

fn credential_b64(reg: &vault_core::account::Registration) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(reg.bundle.auth_credential)
}

/// Register + verify e-mail, returning the client-side registration.
async fn register_and_verify(server: &TestServer) -> vault_core::account::Registration {
    let (reg, body) = client_bundle(EMAIL, PASSWORD);
    let (status, _) = server
        .request("POST", "/api/v1/accounts/register", None, Some(body))
        .await;
    assert_eq!(status, StatusCode::OK);

    let token = server.last_email_token(EMAIL);
    let (status, _) = server
        .request(
            "GET",
            &format!("/api/v1/accounts/verify?token={token}"),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    reg
}

async fn login(
    server: &TestServer,
    reg: &vault_core::account::Registration,
    extra: Value,
) -> (StatusCode, Value) {
    let mut body = json!({
        "email": EMAIL,
        "auth_credential": credential_b64(reg),
    });
    if let (Value::Object(base), Value::Object(more)) = (&mut body, extra) {
        base.extend(more);
    }
    server
        .request("POST", "/api/v1/auth/login", None, Some(body))
        .await
}

// ---------------------------------------------------------------------------

#[tokio::test]
async fn register_verify_login_and_unlock_vault() {
    let server = test_server().await;
    let reg = register_and_verify(&server).await;

    let (status, body) = login(&server, &reg, json!({})).await;
    assert_eq!(status, StatusCode::OK, "login response: {body}");
    assert!(body["access_token"].as_str().unwrap().starts_with("bvat_"));
    assert!(body["refresh_token"].as_str().unwrap().starts_with("bvrt_"));

    // The wrapped key from the login response actually unlocks the vault.
    let wrapped: vault_core::WrappedKey =
        serde_json::from_value(body["master_wrapped_vault_key"].clone()).unwrap();
    let params: vault_core::KdfParams = serde_json::from_value(body["kdf_params"].clone()).unwrap();
    let secrets = vault_core::account::unlock(PASSWORD, EMAIL, &params, &wrapped).unwrap();
    assert_eq!(secrets.vault_key, reg.secrets.vault_key);

    // Access token works against an authenticated endpoint.
    let token = body["access_token"].as_str().unwrap();
    let (status, keys) = server
        .request("GET", "/api/v1/vault/keys", Some(token), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(keys["recovery_wrapped_vault_key"].is_object());
}

#[tokio::test]
async fn login_requires_verified_email() {
    let server = test_server().await;
    let (reg, body) = client_bundle(EMAIL, PASSWORD);
    server
        .request("POST", "/api/v1/accounts/register", None, Some(body))
        .await;

    let (status, body) = login(&server, &reg, json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "email_not_verified");
}

#[tokio::test]
async fn failed_login_is_delayed_and_counted() {
    let server = test_server().await;
    let reg = register_and_verify(&server).await;

    let mut wrong = reg.bundle.auth_credential;
    wrong[0] ^= 0xff;
    let wrong_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(wrong);

    let started = Instant::now();
    let (status, body) = server
        .request(
            "POST",
            "/api/v1/auth/login",
            None,
            Some(json!({ "email": EMAIL, "auth_credential": wrong_b64 })),
        )
        .await;
    let elapsed = started.elapsed();

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_credentials");
    assert!(
        elapsed.as_millis() >= security::FAILURE_DELAY_MIN_MS as u128,
        "failure must take at least {}ms, took {}ms",
        security::FAILURE_DELAY_MIN_MS,
        elapsed.as_millis()
    );

    // Correct credentials still work afterwards.
    let (status, _) = login(&server, &reg, json!({})).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn unknown_email_fails_indistinguishably() {
    let server = test_server().await;
    register_and_verify(&server).await;

    let fake = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);
    let (status, body) = server
        .request(
            "POST",
            "/api/v1/auth/login",
            None,
            Some(json!({ "email": "nobody@example.com", "auth_credential": fake })),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_credentials");

    // Prelogin returns plausible default params for unknown accounts.
    let (status, body) = server
        .request(
            "GET",
            "/api/v1/accounts/prelogin?email=nobody@example.com",
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["kdf_params"]["version"], 1);
}

#[tokio::test]
async fn repeated_failures_lock_the_account_and_notify() {
    let server = test_server().await;
    let reg = register_and_verify(&server).await;

    let mut wrong = reg.bundle.auth_credential;
    wrong[0] ^= 0xff;
    let wrong_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(wrong);

    for _ in 0..security::LOCKOUT_THRESHOLD {
        server
            .request(
                "POST",
                "/api/v1/auth/login",
                None,
                Some(json!({ "email": EMAIL, "auth_credential": wrong_b64 })),
            )
            .await;
    }

    // The next attempt — even with the right password — is locked out.
    let (status, body) = login(&server, &reg, json!({})).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["error"], "locked_out");
    assert!(body["retry_after_secs"].as_i64().unwrap() >= 1);

    // The owner was warned.
    let mails = server.state.mailer.sent();
    assert!(mails
        .iter()
        .any(|m| m.to == EMAIL && m.subject.contains("failed login")));
}

#[tokio::test]
async fn registering_existing_email_does_not_leak_or_overwrite() {
    let server = test_server().await;
    let reg = register_and_verify(&server).await;

    // Second registration with the same address and a different password.
    let (_reg2, body2) = client_bundle(EMAIL, "attacker chosen password");
    let (status, body) = server
        .request("POST", "/api/v1/accounts/register", None, Some(body2))
        .await;
    // Indistinguishable from a fresh registration...
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");

    // ...but the original credentials still work: nothing was overwritten.
    let (status, _) = login(&server, &reg, json!({})).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn totp_enroll_activate_and_login() {
    let server = test_server().await;
    let reg = register_and_verify(&server).await;

    let (_, body) = login(&server, &reg, json!({})).await;
    let access = body["access_token"].as_str().unwrap().to_string();

    // Enrollment requires a fresh credential confirmation.
    let (status, body) = server
        .request(
            "POST",
            "/api/v1/mfa/totp/enroll",
            Some(&access),
            Some(json!({ "auth_credential": credential_b64(&reg) })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let secret = body["secret_base32"].as_str().unwrap().to_string();
    assert!(body["otpauth_uri"]
        .as_str()
        .unwrap()
        .starts_with("otpauth://totp/"));

    // Activate with a live code; recovery codes are issued once.
    let code = totp::code_at(&secret, security::now()).unwrap();
    let (status, body) = server
        .request(
            "POST",
            "/api/v1/mfa/totp/activate",
            Some(&access),
            Some(json!({ "code": code })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let recovery_codes: Vec<String> = body["recovery_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(recovery_codes.len(), 10);

    // Password alone no longer logs in.
    let (status, body) = login(&server, &reg, json!({})).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "mfa_required");

    // Wrong TOTP code fails; right code succeeds.
    let (status, _) = login(&server, &reg, json!({ "totp_code": "000000" })).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let code = totp::code_at(&secret, security::now()).unwrap();
    let (status, body) = login(&server, &reg, json!({ "totp_code": code })).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // A recovery code works exactly once.
    let rc = &recovery_codes[0];
    let (status, _) = login(&server, &reg, json!({ "recovery_code": rc })).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = login(&server, &reg, json!({ "recovery_code": rc })).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn refresh_rotates_and_detects_reuse() {
    let server = test_server().await;
    let reg = register_and_verify(&server).await;

    let (_, body) = login(&server, &reg, json!({})).await;
    let refresh1 = body["refresh_token"].as_str().unwrap().to_string();

    // Rotate.
    let (status, body) = server
        .request(
            "POST",
            "/api/v1/auth/refresh",
            None,
            Some(json!({ "refresh_token": refresh1 })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let access2 = body["access_token"].as_str().unwrap().to_string();
    let refresh2 = body["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(refresh1, refresh2);

    // New access token is live.
    let (status, _) = server
        .request("GET", "/api/v1/vault/keys", Some(&access2), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    // Replaying the old refresh token is treated as theft: everything dies.
    let (status, _) = server
        .request(
            "POST",
            "/api/v1/auth/refresh",
            None,
            Some(json!({ "refresh_token": refresh1 })),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = server
        .request(
            "POST",
            "/api/v1/auth/refresh",
            None,
            Some(json!({ "refresh_token": refresh2 })),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "rotated family must be revoked"
    );
    let (status, _) = server
        .request("GET", "/api/v1/vault/keys", Some(&access2), None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn logout_revokes_the_session() {
    let server = test_server().await;
    let reg = register_and_verify(&server).await;

    let (_, body) = login(&server, &reg, json!({})).await;
    let access = body["access_token"].as_str().unwrap().to_string();

    let (status, _) = server
        .request("POST", "/api/v1/auth/logout", Some(&access), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = server
        .request("GET", "/api/v1/vault/keys", Some(&access), None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn expired_verification_token_is_rejected() {
    let server = test_server().await;
    let (_reg, body) = client_bundle(EMAIL, PASSWORD);
    server
        .request("POST", "/api/v1/accounts/register", None, Some(body))
        .await;

    let token = server.last_email_token(EMAIL);
    // Force-expire the token in the database.
    sqlx::query("UPDATE email_tokens SET expires_at = 0")
        .execute(&server.state.db)
        .await
        .unwrap();

    let (status, _) = server
        .request(
            "GET",
            &format!("/api/v1/accounts/verify?token={token}"),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Vault items (protocol edge cases; full sync behaviour is tested in the
// vault-sync crate against this same server).

#[tokio::test]
async fn item_envelope_is_validated() {
    let server = test_server().await;
    let reg = register_and_verify(&server).await;
    let (_, body) = login(&server, &reg, json!({})).await;
    let access = body["access_token"].as_str().unwrap().to_string();

    let item = reg
        .secrets
        .vault_key
        .encrypt_item("item-1", 1, b"x")
        .unwrap();

    // Envelope id must match the URL path.
    let (status, _) = server
        .request(
            "PUT",
            "/api/v1/vault/items/other-id",
            Some(&access),
            Some(serde_json::to_value(&item).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Garbage body is rejected.
    let (status, _) = server
        .request(
            "PUT",
            "/api/v1/vault/items/item-1",
            Some(&access),
            Some(json!({ "not": "an envelope" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Valid write succeeds and bumps the account seq.
    let (status, body) = server
        .request(
            "PUT",
            "/api/v1/vault/items/item-1",
            Some(&access),
            Some(serde_json::to_value(&item).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["revision"], 1);
    assert_eq!(body["seq"], 1);

    // Stale write (same revision again) conflicts and returns current state.
    let (status, body) = server
        .request(
            "PUT",
            "/api/v1/vault/items/item-1",
            Some(&access),
            Some(serde_json::to_value(&item).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["current"]["revision"], 1);
}

#[tokio::test]
async fn writes_nudge_change_subscribers() {
    let server = test_server().await;
    let reg = register_and_verify(&server).await;
    let (_, body) = login(&server, &reg, json!({})).await;
    let access = body["access_token"].as_str().unwrap().to_string();

    // Subscribe the way the SSE handler does, then write.
    let account_id: i64 = sqlx::query_scalar("SELECT id FROM accounts LIMIT 1")
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    let mut rx = server.state.notifier.subscribe(account_id);

    let item = reg
        .secrets
        .vault_key
        .encrypt_item("item-1", 1, b"x")
        .unwrap();
    let (status, _) = server
        .request(
            "PUT",
            "/api/v1/vault/items/item-1",
            Some(&access),
            Some(serde_json::to_value(&item).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let seq = rx.try_recv().expect("a change nudge should have been sent");
    assert_eq!(seq, 1);
}

#[tokio::test]
async fn responses_carry_security_headers() {
    let server = test_server().await;
    let request = Request::builder()
        .method("GET")
        .uri("/api/v1/health")
        .body(Body::empty())
        .unwrap();
    let response = server.app.clone().oneshot(request).await.unwrap();
    let headers = response.headers();
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(headers["x-content-type-options"], "nosniff");
    assert_eq!(headers["x-frame-options"], "DENY");
    assert_eq!(headers["referrer-policy"], "no-referrer");
}
