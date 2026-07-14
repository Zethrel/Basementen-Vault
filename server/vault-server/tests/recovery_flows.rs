//! Recovery + backup e-mail flows, end to end with real client crypto:
//! Recovery Kit restore, cooling-off, cancellation, verifier enforcement,
//! wipe-reset, and trusted backup e-mail lifecycle.

use std::net::SocketAddr;
use std::sync::Mutex;

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
use vault_server::{build_app, db, totp};

const EMAIL: &str = "owner@example.com";
const BACKUP_EMAIL: &str = "backup@example.com";
const PASSWORD: &str = "original master password";
const NEW_PASSWORD: &str = "brand new master password";

fn b64(bytes: impl AsRef<[u8]>) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

struct Server {
    app: Router,
    state: AppState,
}

impl Server {
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
        .unwrap();
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes) }));
        (status, value)
    }

    /// Extract a token with the given prefix from the most recent mail to `to`.
    fn mail_token(&self, to: &str, prefix: &str) -> String {
        let mails = self.state.mailer.sent();
        let mail = mails
            .iter()
            .rev()
            .find(|m| m.to == to && m.body.contains(prefix))
            .unwrap_or_else(|| panic!("no mail to {to} containing {prefix}"));
        let start = mail.body.find(prefix).unwrap();
        mail.body[start..]
            .split(|c: char| c.is_whitespace() || c == '"')
            .next()
            .unwrap()
            .trim_end_matches(['.', ','])
            .to_string()
    }

    /// Let the cooling-off period elapse by rewinding the request clock.
    async fn elapse_cooloff(&self) {
        sqlx::query("UPDATE recovery_requests SET usable_at = 0")
            .execute(&self.state.db)
            .await
            .unwrap();
    }
}

async fn setup() -> (Server, vault_core::account::Registration) {
    let pool = db::connect_in_memory().await.unwrap();
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
    let server = Server {
        app: build_app(state.clone()),
        state,
    };

    let reg =
        vault_core::account::register(PASSWORD, vault_core::KdfParams::mobile_floor()).unwrap();
    let (status, _) = server
        .request(
            "POST",
            "/api/v1/accounts/register",
            None,
            Some(json!({
                "email": EMAIL,
                "auth_credential": b64(reg.bundle.auth_credential),
                "recovery_verifier": b64(reg.bundle.recovery_verifier),
                "kdf_salt": b64(reg.bundle.kdf_salt),
                "kdf_params": reg.bundle.kdf_params,
                "master_wrapped_vault_key": serde_json::to_value(&reg.bundle.master_wrapped_vault_key).unwrap(),
                "recovery_wrapped_vault_key": serde_json::to_value(&reg.bundle.recovery_wrapped_vault_key).unwrap(),
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    sqlx::query("UPDATE accounts SET email_verified_at = 1")
        .execute(&server.state.db)
        .await
        .unwrap();
    (server, reg)
}

async fn login(server: &Server, reg: &vault_core::account::Registration) -> String {
    let (status, body) = server
        .request(
            "POST",
            "/api/v1/auth/login",
            None,
            Some(json!({
                "email": EMAIL,
                "auth_credential": b64(reg.secrets.auth_key.to_server_credential()),
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["access_token"].as_str().unwrap().to_string()
}

async fn put_item(server: &Server, token: &str, secrets: &vault_core::account::AccountSecrets) {
    let item = secrets
        .vault_key
        .encrypt_item("precious", 1, b"do not lose")
        .unwrap();
    let (status, _) = server
        .request(
            "PUT",
            "/api/v1/vault/items/precious",
            Some(token),
            Some(serde_json::to_value(&item).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
}

fn complete_body(
    new_reg: &vault_core::account::Registration,
    token: &str,
    verifier: Option<[u8; 32]>,
    wipe: bool,
) -> Value {
    json!({
        "token": token,
        "recovery_verifier": verifier.map(b64),
        "wipe": wipe,
        "auth_credential": b64(new_reg.bundle.auth_credential),
        "kdf_params": new_reg.bundle.kdf_params,
        "kdf_salt": b64(new_reg.bundle.kdf_salt),
        "master_wrapped_vault_key": serde_json::to_value(&new_reg.bundle.master_wrapped_vault_key).unwrap(),
        "recovery_wrapped_vault_key": serde_json::to_value(&new_reg.bundle.recovery_wrapped_vault_key).unwrap(),
        "new_recovery_verifier": b64(new_reg.bundle.recovery_verifier),
    })
}

// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_recovery_with_kit_preserves_vault() {
    let (server, reg) = setup().await;
    let access = login(&server, &reg).await;
    put_item(&server, &access, &reg.secrets).await;

    // Owner forgets the password; anyone can start recovery with the e-mail.
    let (status, _) = server
        .request(
            "POST",
            "/api/v1/accounts/recovery/start",
            None,
            Some(json!({ "email": EMAIL })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let token = server.mail_token(EMAIL, "bvrec_");

    // Cooling-off: the token is inert at first.
    let (status, body) = server
        .request(
            "GET",
            &format!("/api/v1/accounts/recovery/data?token={token}"),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::TOO_EARLY, "{body}");
    assert_eq!(body["error"], "cooling_off");
    assert!(body["retry_after_secs"].as_i64().unwrap() > 71 * 3600);

    server.elapse_cooloff().await;

    // Fetch the recovery data and rebuild the account client-side with the kit.
    let (status, data) = server
        .request(
            "GET",
            &format!("/api/v1/accounts/recovery/data?token={token}"),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(data["supports_data_recovery"], true);
    let wrapped: vault_core::WrappedKey =
        serde_json::from_value(data["recovery_wrapped_vault_key"].clone()).unwrap();

    let new_reg = vault_core::account::recover_and_rekey(
        &reg.recovery_code,
        &wrapped,
        NEW_PASSWORD,
        vault_core::KdfParams::mobile_floor(),
    )
    .unwrap();
    // Verifier proving Recovery Kit possession:
    let verifier = new_reg.secrets.vault_key.recovery_verifier();

    let (status, body) = server
        .request(
            "POST",
            "/api/v1/accounts/recovery/complete",
            None,
            Some(complete_body(&new_reg, &token, Some(verifier), false)),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data_preserved"], true);

    // Old sessions are dead; the old password no longer works.
    let (status, _) = server
        .request("GET", "/api/v1/vault/keys", Some(&access), None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = server
        .request(
            "POST",
            "/api/v1/auth/login",
            None,
            Some(json!({
                "email": EMAIL,
                "auth_credential": b64(reg.secrets.auth_key.to_server_credential()),
            })),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // New password logs in, and the pre-recovery item still decrypts.
    let access = login(&server, &new_reg).await;
    let (status, body) = server
        .request("GET", "/api/v1/vault/items?since=0", Some(&access), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let item: vault_core::EncryptedItem =
        serde_json::from_value(body["items"][0]["content"].clone()).unwrap();
    assert_eq!(
        new_reg.secrets.vault_key.decrypt_item(&item).unwrap(),
        b"do not lose"
    );

    // The completion token is spent.
    let (status, _) = server
        .request(
            "GET",
            &format!("/api/v1/accounts/recovery/data?token={token}"),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn cancel_link_stops_recovery() {
    let (server, reg) = setup().await;
    login(&server, &reg).await;

    server
        .request(
            "POST",
            "/api/v1/accounts/recovery/start",
            None,
            Some(json!({ "email": EMAIL })),
        )
        .await;
    let completion = server.mail_token(EMAIL, "bvrec_");
    let cancel = server.mail_token(EMAIL, "bvcan_");

    let (status, _) = server
        .request(
            "GET",
            &format!("/api/v1/accounts/recovery/cancel?token={cancel}"),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    server.elapse_cooloff().await;
    let (status, _) = server
        .request(
            "GET",
            &format!("/api/v1/accounts/recovery/data?token={completion}"),
            None,
            None,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "cancelled token must be dead"
    );
}

#[tokio::test]
async fn without_kit_requires_explicit_wipe_and_destroys_items() {
    let (server, reg) = setup().await;
    let access = login(&server, &reg).await;
    put_item(&server, &access, &reg.secrets).await;

    server
        .request(
            "POST",
            "/api/v1/accounts/recovery/start",
            None,
            Some(json!({ "email": EMAIL })),
        )
        .await;
    let token = server.mail_token(EMAIL, "bvrec_");
    server.elapse_cooloff().await;

    // Attacker-style completion: fresh bundle, no verifier, no wipe consent.
    let intruder =
        vault_core::account::register(NEW_PASSWORD, vault_core::KdfParams::mobile_floor()).unwrap();
    let (status, body) = server
        .request(
            "POST",
            "/api/v1/accounts/recovery/complete",
            None,
            Some(complete_body(&intruder, &token, None, false)),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // A wrong verifier is rejected as invalid credentials.
    let (status, _) = server
        .request(
            "POST",
            "/api/v1/accounts/recovery/complete",
            None,
            Some(complete_body(&intruder, &token, Some([9u8; 32]), false)),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Explicit wipe works — and the vault is empty afterwards.
    let (status, body) = server
        .request(
            "POST",
            "/api/v1/accounts/recovery/complete",
            None,
            Some(complete_body(&intruder, &token, None, true)),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data_preserved"], false);

    let access = login(&server, &intruder).await;
    let (_, body) = server
        .request("GET", "/api/v1/vault/items?since=0", Some(&access), None)
        .await;
    assert_eq!(
        body["items"].as_array().unwrap().len(),
        0,
        "items destroyed"
    );
}

#[tokio::test]
async fn backup_email_lifecycle_and_dual_delivery() {
    let (server, reg) = setup().await;
    let access = login(&server, &reg).await;

    // Setting a backup address needs a fresh credential.
    let (status, _) = server
        .request(
            "POST",
            "/api/v1/account/backup-email",
            Some(&access),
            Some(json!({
                "auth_credential": b64([0u8; 32]),
                "backup_email": BACKUP_EMAIL,
            })),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "wrong credential rejected"
    );

    let (status, body) = server
        .request(
            "POST",
            "/api/v1/account/backup-email",
            Some(&access),
            Some(json!({
                "auth_credential": b64(reg.secrets.auth_key.to_server_credential()),
                "backup_email": BACKUP_EMAIL,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // The primary is notified; the backup gets a verification link.
    let verify_token = server.mail_token(BACKUP_EMAIL, "bvbet_");
    let (status, _) = server
        .request(
            "GET",
            &format!("/api/v1/accounts/verify-backup?token={verify_token}"),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // Recovery instructions now reach BOTH addresses.
    server
        .request(
            "POST",
            "/api/v1/accounts/recovery/start",
            None,
            Some(json!({ "email": EMAIL })),
        )
        .await;
    let t_primary = server.mail_token(EMAIL, "bvrec_");
    let t_backup = server.mail_token(BACKUP_EMAIL, "bvrec_");
    assert_eq!(
        t_primary, t_backup,
        "same completion token to both addresses"
    );

    // Removing the backup address also needs a fresh credential.
    let (status, _) = server
        .request(
            "DELETE",
            "/api/v1/account/backup-email",
            Some(&access),
            Some(json!({
                "auth_credential": b64(reg.secrets.auth_key.to_server_credential()),
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // Next recovery only mails the primary.
    let before = server.state.mailer.sent().len();
    server
        .request(
            "POST",
            "/api/v1/accounts/recovery/start",
            None,
            Some(json!({ "email": EMAIL })),
        )
        .await;
    let new_mails: Vec<_> = server.state.mailer.sent()[before..].to_vec();
    assert!(new_mails.iter().any(|m| m.to == EMAIL));
    assert!(!new_mails.iter().any(|m| m.to == BACKUP_EMAIL));
}

#[tokio::test]
async fn backup_email_requires_mfa_when_enrolled() {
    let (server, reg) = setup().await;
    let access = login(&server, &reg).await;

    // Enroll + activate TOTP.
    let (_, body) = server
        .request(
            "POST",
            "/api/v1/mfa/totp/enroll",
            Some(&access),
            Some(json!({ "auth_credential": b64(reg.secrets.auth_key.to_server_credential()) })),
        )
        .await;
    let secret = body["secret_base32"].as_str().unwrap().to_string();
    let code = totp::code_at(&secret, vault_server::security::now()).unwrap();
    let (status, _) = server
        .request(
            "POST",
            "/api/v1/mfa/totp/activate",
            Some(&access),
            Some(json!({ "code": code })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // Without a TOTP code the change is refused…
    let (status, body) = server
        .request(
            "POST",
            "/api/v1/account/backup-email",
            Some(&access),
            Some(json!({
                "auth_credential": b64(reg.secrets.auth_key.to_server_credential()),
                "backup_email": BACKUP_EMAIL,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "mfa_required");

    // …with it, accepted.
    let code = totp::code_at(&secret, vault_server::security::now()).unwrap();
    let (status, _) = server
        .request(
            "POST",
            "/api/v1/account/backup-email",
            Some(&access),
            Some(json!({
                "auth_credential": b64(reg.secrets.auth_key.to_server_credential()),
                "totp_code": code,
                "backup_email": BACKUP_EMAIL,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn recovery_start_does_not_leak_account_existence() {
    let (server, _reg) = setup().await;
    let before = server.state.mailer.sent().len();
    let (status, body) = server
        .request(
            "POST",
            "/api/v1/accounts/recovery/start",
            None,
            Some(json!({ "email": "ghost@example.com" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
    assert_eq!(
        server.state.mailer.sent().len(),
        before,
        "no mail for unknown accounts"
    );
}
