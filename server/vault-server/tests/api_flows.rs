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
    let state = AppState::new(pool, cfg, Mailer::Memory(Mutex::new(Vec::new()))).await;
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
    let reg = vault_core::account::register(password, vault_core::KdfParams::mobile_floor())
        .expect("client-side registration");
    let _ = email;
    let body = json!({
        "email": email,
        "auth_credential": base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(reg.bundle.auth_credential),
        "recovery_verifier": base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(reg.bundle.recovery_verifier),
        "kdf_salt": base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(reg.bundle.kdf_salt),
        "kdf_params": reg.bundle.kdf_params,
        "master_wrapped_vault_key": serde_json::to_value(&reg.bundle.master_wrapped_vault_key).unwrap(),
        "recovery_wrapped_vault_key": serde_json::to_value(&reg.bundle.recovery_wrapped_vault_key).unwrap(),
    });
    (reg, body)
}

fn credential_b64(reg: &vault_core::account::Registration) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(reg.bundle.auth_credential)
}

fn b64(bytes: impl AsRef<[u8]>) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
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
// Upgrade-in-place / restart safety helpers (file-backed DB)

fn unique_db_path() -> std::path::PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("bv-migration-{}-{}.db", std::process::id(), nanos))
}

fn file_config(db_path: &str) -> Config {
    Config {
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        db_path: db_path.into(),
        base_url: "http://vault.test".into(),
        registration_open: true,
        trust_proxy: false,
        recovery_cooloff_secs: 72 * 3600,
        mail: MailConfig::Console,
    }
}

/// A server backed by a real file DB (so its data persists across pool drops).
async fn file_server(db_path: &str) -> TestServer {
    let pool = db::connect(db_path)
        .await
        .expect("file db connects + migrates");
    let state = AppState::new(
        pool,
        file_config(db_path),
        Mailer::Memory(Mutex::new(Vec::new())),
    )
    .await;
    TestServer {
        app: build_app(state.clone()),
        state,
    }
}

async fn prelogin_salt(server: &TestServer, email: &str) -> String {
    let (status, body) = server
        .request(
            "GET",
            &format!("/api/v1/accounts/prelogin?email={email}"),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    body["kdf_salt"].as_str().unwrap().to_string()
}

/// Upgrade-in-place proxy (RELEASE_CHECKLIST §2): migrations must apply cleanly
/// on a *populated* database, not just an empty one, and data must survive a
/// restart. Populate a file-backed DB through the real API, drop it (server
/// stops), reopen the same file (`connect()` re-runs `migrate!()`), and confirm
/// the account, its account-lifetime KDF salt, and its credentials all survive.
#[tokio::test]
async fn data_survives_restart_and_remigration() {
    let db_path = unique_db_path();
    let db_str = db_path.to_str().unwrap().to_string();

    // Phase 1: populate (account + verified e-mail + a login session), then let
    // the pool + state drop — simulating the server process stopping.
    let reg;
    let salt_before;
    {
        let server = file_server(&db_str).await;
        reg = register_and_verify(&server).await;
        let (status, _) = login(&server, &reg, json!({})).await;
        assert_eq!(status, StatusCode::OK);
        salt_before = prelogin_salt(&server, EMAIL).await;
    }

    // Phase 2: reopen the SAME file. Re-running migrations on the populated DB
    // must be a clean no-op, and everything must still be there.
    {
        let server = file_server(&db_str).await;
        let salt_after = prelogin_salt(&server, EMAIL).await;
        assert_eq!(
            salt_before, salt_after,
            "the account's KDF salt must survive a restart"
        );
        let (status, body) = login(&server, &reg, json!({})).await;
        assert_eq!(status, StatusCode::OK, "login after restart: {body}");
        assert!(body["access_token"].as_str().unwrap().starts_with("bvat_"));
    }

    // Best-effort cleanup of the temp DB and its WAL/SHM sidecars.
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{db_str}{suffix}"));
    }
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

    // The wrapped key + salt from the login response actually unlock the vault.
    let wrapped: vault_core::WrappedKey =
        serde_json::from_value(body["master_wrapped_vault_key"].clone()).unwrap();
    let params: vault_core::KdfParams = serde_json::from_value(body["kdf_params"].clone()).unwrap();
    let salt = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(body["kdf_salt"].as_str().unwrap())
        .unwrap();
    let secrets = vault_core::account::unlock(PASSWORD, &salt, &params, &wrapped).unwrap();
    assert_eq!(secrets.vault_key, reg.secrets.vault_key);
    assert_eq!(salt, reg.bundle.kdf_salt, "login returns the stored salt");

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

    // Prelogin returns plausible default params AND a salt for unknown
    // accounts, and that dummy salt is STABLE across repeated queries — an
    // attacker cannot tell "unknown" (would otherwise re-randomize) from a
    // real account (stable stored salt).
    let prelogin = |email: &'static str| {
        let server = &server;
        async move {
            server
                .request(
                    "GET",
                    &format!("/api/v1/accounts/prelogin?email={email}"),
                    None,
                    None,
                )
                .await
                .1
        }
    };
    let a = prelogin("nobody@example.com").await;
    let b = prelogin("nobody@example.com").await;
    assert_eq!(a["kdf_params"]["version"], 1);
    assert!(a["kdf_salt"].as_str().unwrap().len() >= 20, "salt present");
    assert_eq!(
        a["kdf_salt"], b["kdf_salt"],
        "dummy salt for an unknown account must be stable across queries"
    );
    // A different unknown e-mail gets a different dummy salt.
    let c = prelogin("someone-else@example.com").await;
    assert_ne!(a["kdf_salt"], c["kdf_salt"]);
    // A real account's prelogin returns a salt too.
    let real = prelogin(EMAIL).await;
    assert!(real["kdf_salt"].as_str().is_some());
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
async fn resend_verification_issues_a_fresh_working_link() {
    let server = test_server().await;

    // Register but do NOT verify (simulating a lapsed 15-minute token).
    let (reg, body) = client_bundle(EMAIL, PASSWORD);
    let (status, _) = server
        .request("POST", "/api/v1/accounts/register", None, Some(body))
        .await;
    assert_eq!(status, StatusCode::OK);

    // Ask for a new link.
    let (status, body) = server
        .request(
            "POST",
            "/api/v1/accounts/resend-verification",
            None,
            Some(json!({ "email": EMAIL })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");

    // The freshest token verifies, and the account can then log in.
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
    let (status, _) = login(&server, &reg, json!({})).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn resend_verification_is_throttled_within_cooldown() {
    let server = test_server().await;

    // Registration already sends one verification e-mail.
    let (_reg, body) = client_bundle(EMAIL, PASSWORD);
    let (status, _) = server
        .request("POST", "/api/v1/accounts/register", None, Some(body))
        .await;
    assert_eq!(status, StatusCode::OK);

    let verify_mails = |s: &TestServer| {
        s.state
            .mailer
            .sent()
            .iter()
            .filter(|m| m.to == EMAIL && m.subject.contains("verify your e-mail"))
            .count()
    };
    assert_eq!(verify_mails(&server), 1);

    // An immediate resend is coalesced: same OK response, but no second e-mail.
    let (status, body) = server
        .request(
            "POST",
            "/api/v1/accounts/resend-verification",
            None,
            Some(json!({ "email": EMAIL })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
    assert_eq!(
        verify_mails(&server),
        1,
        "a resend within the cooldown must not send another e-mail"
    );
}

#[tokio::test]
async fn resend_verification_is_anti_enumeration() {
    let server = test_server().await;

    // Unknown address: same OK response, and crucially no e-mail is sent
    // (so nothing distinguishes it from a real pending account).
    let (status, body) = server
        .request(
            "POST",
            "/api/v1/accounts/resend-verification",
            None,
            Some(json!({ "email": "nobody@example.com" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
    assert!(
        !server
            .state
            .mailer
            .sent()
            .iter()
            .any(|m| m.to == "nobody@example.com"),
        "no e-mail should be sent to an unknown address"
    );

    // Already-verified account: also a no-op (no new verification e-mail).
    register_and_verify(&server).await;
    let before = server.state.mailer.sent().len();
    let (status, _) = server
        .request(
            "POST",
            "/api/v1/accounts/resend-verification",
            None,
            Some(json!({ "email": EMAIL })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        server.state.mailer.sent().len(),
        before,
        "a verified account must not receive another verification e-mail"
    );
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

// ---------------------------------------------------------------------------
// Session (device) management

/// Log in a second "device" for the already-verified account and return its
/// access + refresh tokens.
async fn login_device(
    server: &TestServer,
    reg: &vault_core::account::Registration,
    device: &str,
) -> (String, String) {
    let (status, body) = server
        .request(
            "POST",
            "/api/v1/auth/login",
            None,
            Some(json!({
                "email": EMAIL,
                "auth_credential": base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(reg.secrets.auth_key.to_server_credential()),
                "device_name": device,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    (
        body["access_token"].as_str().unwrap().to_string(),
        body["refresh_token"].as_str().unwrap().to_string(),
    )
}

#[tokio::test]
async fn sessions_list_shows_devices_and_current() {
    let server = test_server().await;
    let reg = register_and_verify(&server).await;

    let (access_a, _) = login_device(&server, &reg, "laptop").await;
    let (_access_b, _) = login_device(&server, &reg, "phone").await;

    let (status, body) = server
        .request("GET", "/api/v1/sessions", Some(&access_a), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let sessions = body["sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 2, "two active devices");

    let names: Vec<&str> = sessions
        .iter()
        .map(|s| s["device_name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"laptop") && names.contains(&"phone"));

    // Exactly one is flagged current, and it's the laptop (the caller).
    let current: Vec<&Value> = sessions.iter().filter(|s| s["current"] == true).collect();
    assert_eq!(current.len(), 1);
    assert_eq!(current[0]["device_name"], "laptop");
}

#[tokio::test]
async fn revoke_one_device_kills_only_that_session() {
    let server = test_server().await;
    let reg = register_and_verify(&server).await;

    let (access_a, _) = login_device(&server, &reg, "laptop").await;
    let (access_b, refresh_b) = login_device(&server, &reg, "phone").await;

    // Find the phone's family id from A's session list.
    let (_, body) = server
        .request("GET", "/api/v1/sessions", Some(&access_a), None)
        .await;
    let phone = body["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["device_name"] == "phone")
        .unwrap();
    let phone_family = phone["id"].as_str().unwrap();

    // Revoke the phone from the laptop.
    let (status, _) = server
        .request(
            "DELETE",
            &format!("/api/v1/sessions/{phone_family}"),
            Some(&access_a),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // Phone's access token no longer works, and its refresh is dead too.
    let (status, _) = server
        .request("GET", "/api/v1/vault/keys", Some(&access_b), None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = server
        .request(
            "POST",
            "/api/v1/auth/refresh",
            None,
            Some(json!({ "refresh_token": refresh_b })),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // The laptop is still alive.
    let (status, _) = server
        .request("GET", "/api/v1/vault/keys", Some(&access_a), None)
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn revoke_others_logs_out_everyone_else() {
    let server = test_server().await;
    let reg = register_and_verify(&server).await;

    let (access_a, _) = login_device(&server, &reg, "laptop").await;
    let (access_b, _) = login_device(&server, &reg, "phone").await;
    let (access_c, _) = login_device(&server, &reg, "tablet").await;

    let (status, body) = server
        .request(
            "POST",
            "/api/v1/sessions/revoke-others",
            Some(&access_a),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["revoked"], 2);

    // The caller survives; the others are gone.
    for (token, expected) in [
        (&access_a, StatusCode::OK),
        (&access_b, StatusCode::UNAUTHORIZED),
        (&access_c, StatusCode::UNAUTHORIZED),
    ] {
        let (status, _) = server
            .request("GET", "/api/v1/vault/keys", Some(token), None)
            .await;
        assert_eq!(status, expected);
    }

    // Only one session remains.
    let (_, body) = server
        .request("GET", "/api/v1/sessions", Some(&access_a), None)
        .await;
    assert_eq!(body["sessions"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn cannot_revoke_another_accounts_session() {
    let server = test_server().await;
    let reg = register_and_verify(&server).await;
    let (access_a, _) = login_device(&server, &reg, "laptop").await;

    // A second, separate account.
    let (other_reg, body) = client_bundle("intruder@example.com", "another password");
    server
        .request("POST", "/api/v1/accounts/register", None, Some(body))
        .await;
    sqlx::query("UPDATE accounts SET email_verified_at = 1 WHERE email = 'intruder@example.com'")
        .execute(&server.state.db)
        .await
        .unwrap();
    let (status, other_login) = server
        .request(
            "POST",
            "/api/v1/auth/login",
            None,
            Some(json!({
                "email": "intruder@example.com",
                "auth_credential": base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(other_reg.secrets.auth_key.to_server_credential()),
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let other_access = other_login["access_token"].as_str().unwrap();

    // The intruder learns account A's family id (as if leaked) and tries to
    // revoke it with the intruder's own valid token. Scoped to account_id,
    // so it's a no-op → NotFound.
    let (_, a_sessions) = server
        .request("GET", "/api/v1/sessions", Some(&access_a), None)
        .await;
    let a_family = a_sessions["sessions"][0]["id"].as_str().unwrap();
    let (status, _) = server
        .request(
            "DELETE",
            &format!("/api/v1/sessions/{a_family}"),
            Some(other_access),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Account A is untouched.
    let (status, _) = server
        .request("GET", "/api/v1/vault/keys", Some(&access_a), None)
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn absolute_lifetime_cap_stops_sliding_refresh() {
    let server = test_server().await;
    let reg = register_and_verify(&server).await;
    let (_access, refresh) = login_device(&server, &reg, "laptop").await;

    // A normal refresh works.
    let (status, body) = server
        .request(
            "POST",
            "/api/v1/auth/refresh",
            None,
            Some(json!({ "refresh_token": refresh })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let refresh2 = body["refresh_token"].as_str().unwrap().to_string();

    // Force the absolute ceiling into the past for this account's sessions.
    sqlx::query("UPDATE sessions SET absolute_expires_at = 1")
        .execute(&server.state.db)
        .await
        .unwrap();

    // Now even a valid, unexpired refresh token is refused — re-login required.
    let (status, _) = server
        .request(
            "POST",
            "/api/v1/auth/refresh",
            None,
            Some(json!({ "refresh_token": refresh2 })),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn refresh_updates_last_used_at() {
    let server = test_server().await;
    let reg = register_and_verify(&server).await;
    let (access, refresh) = login_device(&server, &reg, "laptop").await;

    let _ = access; // the original access token dies on rotation; use the new one

    // Backdate the session so "now" is clearly newer than created_at.
    sqlx::query("UPDATE sessions SET created_at = 1, last_used_at = 1")
        .execute(&server.state.db)
        .await
        .unwrap();

    let (_, refreshed) = server
        .request(
            "POST",
            "/api/v1/auth/refresh",
            None,
            Some(json!({ "refresh_token": refresh })),
        )
        .await;
    let new_access = refreshed["access_token"].as_str().unwrap();

    let (_, body) = server
        .request("GET", "/api/v1/sessions", Some(new_access), None)
        .await;
    let s = &body["sessions"][0];
    // created_at carried forward (the original login, backdated to 1);
    // last_used_at advanced to the refresh time.
    assert_eq!(s["created_at"].as_i64().unwrap(), 1, "login time preserved");
    assert!(
        s["last_used_at"].as_i64().unwrap() > s["created_at"].as_i64().unwrap(),
        "refresh advances last_used_at past created_at"
    );
}

// ---------------------------------------------------------------------------
// Recovery / device-enrollment hardening

/// Enroll + activate TOTP for the already-verified account, returning the
/// shared secret and the one-time recovery codes.
async fn activate_totp(
    server: &TestServer,
    reg: &vault_core::account::Registration,
    access: &str,
) -> (String, Vec<String>) {
    let (status, body) = server
        .request(
            "POST",
            "/api/v1/mfa/totp/enroll",
            Some(access),
            Some(json!({ "auth_credential": credential_b64(reg) })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let secret = body["secret_base32"].as_str().unwrap().to_string();

    let code = totp::code_at(&secret, security::now()).unwrap();
    let (status, body) = server
        .request(
            "POST",
            "/api/v1/mfa/totp/activate",
            Some(access),
            Some(json!({ "code": code })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let codes = body["recovery_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    (secret, codes)
}

#[tokio::test]
async fn totp_code_cannot_be_replayed() {
    let server = test_server().await;
    let reg = register_and_verify(&server).await;
    let (_, body) = login(&server, &reg, json!({})).await;
    let access = body["access_token"].as_str().unwrap().to_string();
    let (secret, _codes) = activate_totp(&server, &reg, &access).await;

    // One-time-use tracking starts at first login, so the current code is fine.
    let code = totp::code_at(&secret, security::now()).unwrap();

    // A single live code logs in once…
    let (status, _) = login(&server, &reg, json!({ "totp_code": code })).await;
    assert_eq!(status, StatusCode::OK, "first use of the code succeeds");

    // …and is refused on replay, even though it is still within its window.
    let (status, _) = login(&server, &reg, json!({ "totp_code": code })).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the same TOTP code must not be accepted twice"
    );
}

#[tokio::test]
async fn new_device_login_notifies_owner_once_per_device() {
    let server = test_server().await;
    let reg = register_and_verify(&server).await;

    let sign_in_mails = |server: &TestServer| {
        server
            .state
            .mailer
            .sent()
            .iter()
            .filter(|m| m.to == EMAIL && m.subject.contains("new sign-in"))
            .count()
    };

    login_device(&server, &reg, "laptop").await;
    assert_eq!(sign_in_mails(&server), 1, "first device alerts the owner");

    // A second login from the same still-active device does not re-alarm.
    login_device(&server, &reg, "laptop").await;
    assert_eq!(
        sign_in_mails(&server),
        1,
        "same active device: no new alert"
    );

    // A different device does.
    login_device(&server, &reg, "phone").await;
    assert_eq!(sign_in_mails(&server), 2, "a new device alerts the owner");
}

#[tokio::test]
async fn oversized_device_name_is_bounded_and_sanitized() {
    let server = test_server().await;
    let reg = register_and_verify(&server).await;

    let nasty = format!("ab\u{0007}\tcd{}", "x".repeat(500));
    let (access, _) = login_device(&server, &reg, &nasty).await;

    let (status, body) = server
        .request("GET", "/api/v1/sessions", Some(&access), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let stored = body["sessions"][0]["device_name"].as_str().unwrap();
    assert!(stored.chars().count() <= 64, "device name is length-capped");
    assert!(
        !stored.chars().any(|c| c.is_control()),
        "control characters are stripped"
    );
}

#[tokio::test]
async fn recovery_codes_status_and_regeneration() {
    let server = test_server().await;
    let reg = register_and_verify(&server).await;
    let (_, body) = login(&server, &reg, json!({})).await;
    let access = body["access_token"].as_str().unwrap().to_string();
    let (secret, codes) = activate_totp(&server, &reg, &access).await;

    // Status reflects an active TOTP and a full complement of codes.
    let (status, body) = server
        .request("GET", "/api/v1/mfa/status", Some(&access), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["totp_active"], true);
    assert_eq!(body["recovery_codes_remaining"], 10);

    // Spending one code drops the remaining count.
    let (status, _) = login(&server, &reg, json!({ "recovery_code": codes[0] })).await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = server
        .request("GET", "/api/v1/mfa/status", Some(&access), None)
        .await;
    assert_eq!(body["recovery_codes_remaining"], 9);

    // Regeneration needs a fresh credential + a current (unused) TOTP code.
    let code = totp::code_at(&secret, security::now()).unwrap();
    let (status, body) = server
        .request(
            "POST",
            "/api/v1/mfa/recovery-codes/regenerate",
            Some(&access),
            Some(json!({ "auth_credential": credential_b64(&reg), "totp_code": code })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let fresh: Vec<String> = body["recovery_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(fresh.len(), 10);

    // Count is restored, an old code no longer works, and a new one does.
    let (_, body) = server
        .request("GET", "/api/v1/mfa/status", Some(&access), None)
        .await;
    assert_eq!(body["recovery_codes_remaining"], 10);
    let (status, _) = login(&server, &reg, json!({ "recovery_code": codes[1] })).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "old codes are invalidated"
    );
    let (status, _) = login(&server, &reg, json!({ "recovery_code": fresh[0] })).await;
    assert_eq!(status, StatusCode::OK, "fresh codes work");
}

#[tokio::test]
async fn enumeration_secret_persists_across_restarts() {
    // The enumeration secret must be stable across server restarts so an
    // unregistered address's dummy prelogin salt looks identical before and
    // after a reboot (closing a cross-restart enumeration signal).
    fn cfg() -> Config {
        Config {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            db_path: ":memory:".into(),
            base_url: "http://vault.test".into(),
            registration_open: true,
            trust_proxy: false,
            recovery_cooloff_secs: 72 * 3600,
            mail: MailConfig::Console,
        }
    }

    let pool = db::connect_in_memory().await.expect("db");
    let boot = |p| async { AppState::new(p, cfg(), Mailer::Memory(Mutex::new(Vec::new()))).await };

    // Two "boots" against the same database converge on the same secret.
    let s1 = boot(pool.clone()).await;
    let s2 = boot(pool.clone()).await;
    assert_eq!(
        *s1.enumeration_secret, *s2.enumeration_secret,
        "the persisted secret survives a restart"
    );

    // A different database mints an independent secret (proving it's persisted,
    // not a hard-coded constant).
    let other_pool = db::connect_in_memory().await.expect("db");
    let s3 = boot(other_pool).await;
    assert_ne!(
        *s1.enumeration_secret, *s3.enumeration_secret,
        "a separate database has its own secret"
    );
}

#[tokio::test]
async fn change_password_rewraps_preserves_data_and_revokes_others() {
    let server = test_server().await;
    let reg = register_and_verify(&server).await;

    // Two devices logged in; stash an item under the current Vault Key.
    let (access_a, _) = login_device(&server, &reg, "laptop").await;
    let (access_b, _) = login_device(&server, &reg, "phone").await;
    let item = reg
        .secrets
        .vault_key
        .encrypt_item("note", 1, b"survives")
        .unwrap();
    let (status, _) = server
        .request(
            "PUT",
            "/api/v1/vault/items/note",
            Some(&access_a),
            Some(serde_json::to_value(&item).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // Build the new bundle client-side (same Vault Key, new password).
    const NEW_PW: &str = "an entirely different master password";
    let new_reg = vault_core::account::change_password(
        &reg.secrets,
        NEW_PW,
        &reg.bundle.kdf_salt,
        vault_core::KdfParams::mobile_floor(),
    )
    .unwrap();
    let cp_body = |cred: [u8; 32]| {
        json!({
            "auth_credential": b64(cred),
            "new_auth_credential": b64(new_reg.bundle.auth_credential),
            "kdf_params": new_reg.bundle.kdf_params,
            "master_wrapped_vault_key": serde_json::to_value(&new_reg.bundle.master_wrapped_vault_key).unwrap(),
            "recovery_wrapped_vault_key": serde_json::to_value(&new_reg.bundle.recovery_wrapped_vault_key).unwrap(),
            "new_recovery_verifier": b64(new_reg.bundle.recovery_verifier),
        })
    };

    // Wrong current password is rejected.
    let (status, _) = server
        .request(
            "POST",
            "/api/v1/account/change-password",
            Some(&access_a),
            Some(cp_body([0u8; 32])),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Correct current credential succeeds.
    let (status, body) = server
        .request(
            "POST",
            "/api/v1/account/change-password",
            Some(&access_a),
            Some(cp_body(reg.secrets.auth_key.to_server_credential())),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // The other device is signed out; the current device keeps working.
    let (status, _) = server
        .request("GET", "/api/v1/vault/keys", Some(&access_b), None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "other device revoked");
    let (status, _) = server
        .request("GET", "/api/v1/vault/keys", Some(&access_a), None)
        .await;
    assert_eq!(status, StatusCode::OK, "current device stays signed in");

    // Old password no longer logs in; the new one does.
    let (status, _) = login(&server, &reg, json!({})).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "old password rejected");
    let (status, body) = server
        .request(
            "POST",
            "/api/v1/auth/login",
            None,
            Some(json!({
                "email": EMAIL,
                "auth_credential": b64(new_reg.secrets.auth_key.to_server_credential()),
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Salt is unchanged (account-lifetime), and the item still decrypts under
    // the same Vault Key that the new password now unwraps.
    let salt = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(body["kdf_salt"].as_str().unwrap())
        .unwrap();
    assert_eq!(salt, reg.bundle.kdf_salt, "salt is account-lifetime");
    let access_new = body["access_token"].as_str().unwrap().to_string();
    let (_, items) = server
        .request(
            "GET",
            "/api/v1/vault/items?since=0",
            Some(&access_new),
            None,
        )
        .await;
    let stored: vault_core::EncryptedItem =
        serde_json::from_value(items["items"][0]["content"].clone()).unwrap();
    assert_eq!(
        new_reg
            .secrets
            .vault_key
            .decrypt_item(&stored)
            .unwrap()
            .as_slice(),
        b"survives",
        "vault data survives a password change"
    );
}
