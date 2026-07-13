//! End-to-end sync tests: the vault-sync engine driving the real
//! vault-server API (in-memory axum router), with real vault-core crypto.
//! Two `MemoryVault`s play the role of two devices on one account.

use std::net::SocketAddr;
use std::sync::Mutex;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use base64::Engine;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use vault_core::EncryptedItem;
use vault_server::config::{Config, MailConfig};
use vault_server::mailer::Mailer;
use vault_server::state::AppState;
use vault_server::{build_app, db};
use vault_sync::{
    sync, LocalVault, MemoryVault, PendingOp, PullResponse, PushOutcome, SyncTransport,
    TransportError,
};

const EMAIL: &str = "sync@example.com";
const PASSWORD: &str = "master password for sync tests";

// ---------------------------------------------------------------------------
// HTTP transport over the in-memory router (what a real app implements with
// its platform HTTP client).

struct HttpTransport {
    app: Router,
    access_token: String,
}

impl HttpTransport {
    async fn call(&self, method: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        let builder = Request::builder().method(method).uri(path).header(
            header::AUTHORIZATION,
            format!("Bearer {}", self.access_token),
        );
        let request = match body {
            Some(v) => builder
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(v.to_string())),
            None => builder.body(Body::empty()),
        }
        .expect("request");
        let response = self.app.clone().oneshot(request).await.expect("response");
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, value)
    }
}

impl SyncTransport for HttpTransport {
    async fn pull(&mut self, since: i64) -> Result<PullResponse, TransportError> {
        let (status, body) = self
            .call("GET", &format!("/api/v1/vault/items?since={since}"), None)
            .await;
        if status != StatusCode::OK {
            return Err(TransportError::Rejected(format!("pull: {status}")));
        }
        serde_json::from_value(body).map_err(|e| TransportError::Rejected(e.to_string()))
    }

    async fn push_upsert(&mut self, item: &EncryptedItem) -> Result<PushOutcome, TransportError> {
        let (status, body) = self
            .call(
                "PUT",
                &format!("/api/v1/vault/items/{}", item.item_id),
                Some(serde_json::to_value(item).expect("serialize")),
            )
            .await;
        match status {
            StatusCode::OK => Ok(PushOutcome::Accepted {
                revision: body["revision"].as_i64().unwrap(),
                seq: body["seq"].as_i64().unwrap(),
            }),
            StatusCode::CONFLICT => Ok(PushOutcome::Conflict {
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
        let (status, body) = self
            .call(
                "DELETE",
                &format!("/api/v1/vault/items/{item_id}?base_revision={base_revision}"),
                None,
            )
            .await;
        match status {
            StatusCode::OK => Ok(PushOutcome::Accepted {
                revision: body["revision"].as_i64().unwrap(),
                seq: body.get("seq").and_then(|v| v.as_i64()).unwrap_or(0),
            }),
            StatusCode::CONFLICT => Ok(PushOutcome::Conflict {
                current: serde_json::from_value(body["current"].clone()).ok(),
            }),
            // Deleting something the server never saw: treat as conflict with
            // no server state (the engine will drop the local ghost).
            StatusCode::NOT_FOUND => Ok(PushOutcome::Conflict { current: None }),
            other => Err(TransportError::Rejected(format!("delete: {other}"))),
        }
    }
}

// ---------------------------------------------------------------------------
// Account bootstrap (same steps a real app performs).

struct TestAccount {
    app: Router,
    state: AppState,
    secrets: vault_core::account::AccountSecrets,
}

async fn bootstrap() -> TestAccount {
    let pool = db::connect_in_memory().await.expect("db");
    let cfg = Config {
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        db_path: ":memory:".into(),
        base_url: "http://vault.test".into(),
        registration_open: true,
        trust_proxy: false,
        mail: MailConfig::Console,
    };
    let state = AppState::new(pool, cfg, Mailer::Memory(Mutex::new(Vec::new())));
    let app = build_app(state.clone());

    let reg = vault_core::account::register(PASSWORD, EMAIL, vault_core::KdfParams::mobile_floor())
        .expect("client registration");

    let post = |app: Router, path: &'static str, body: Value| async move {
        let request = Request::builder()
            .method("POST")
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, value)
    };

    let (status, _) = post(
        app.clone(),
        "/api/v1/accounts/register",
        json!({
            "email": EMAIL,
            "auth_credential": base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(reg.bundle.auth_credential),
            "kdf_params": reg.bundle.kdf_params,
            "master_wrapped_vault_key": serde_json::to_value(&reg.bundle.master_wrapped_vault_key).unwrap(),
            "recovery_wrapped_vault_key": serde_json::to_value(&reg.bundle.recovery_wrapped_vault_key).unwrap(),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Verify e-mail directly in the database (tested properly in the server suite).
    sqlx::query("UPDATE accounts SET email_verified_at = 1")
        .execute(&state.db)
        .await
        .unwrap();

    TestAccount {
        app,
        state,
        secrets: reg.secrets,
    }
}

impl TestAccount {
    /// Log in as a new "device" and return its transport.
    async fn device(&self) -> HttpTransport {
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/login")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "email": EMAIL,
                    "auth_credential": base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .encode(self.secrets.auth_key.to_server_credential()),
                })
                .to_string(),
            ))
            .unwrap();
        let response = self.app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        HttpTransport {
            app: self.app.clone(),
            access_token: body["access_token"].as_str().unwrap().to_string(),
        }
    }

    fn encrypt(&self, item_id: &str, revision: u64, plaintext: &[u8]) -> EncryptedItem {
        self.secrets
            .vault_key
            .encrypt_item(item_id, revision, plaintext)
            .expect("encrypt")
    }

    fn decrypt(&self, item: &EncryptedItem) -> Vec<u8> {
        self.secrets.vault_key.decrypt_item(item).expect("decrypt")
    }
}

// ---------------------------------------------------------------------------

#[tokio::test]
async fn two_devices_converge() {
    let account = bootstrap().await;
    let mut device_a = (MemoryVault::new(), account.device().await);
    let mut device_b = (MemoryVault::new(), account.device().await);

    // Device A creates two items offline, then syncs.
    device_a.0.stage(PendingOp::Upsert(account.encrypt(
        "login-1",
        1,
        b"github password",
    )));
    device_a.0.stage(PendingOp::Upsert(account.encrypt(
        "note-1",
        1,
        b"wifi code",
    )));
    let report = sync(&mut device_a.0, &mut device_a.1).await.unwrap();
    assert_eq!(report.pushed, 2);
    assert!(report.conflicts.is_empty());

    // Device B syncs from nothing and can decrypt everything.
    let report = sync(&mut device_b.0, &mut device_b.1).await.unwrap();
    assert_eq!(report.pulled, 2);
    let got = device_b.0.get("login-1").unwrap();
    assert_eq!(
        account.decrypt(got.content.as_ref().unwrap()),
        b"github password"
    );
    assert_eq!(device_b.0.list().len(), 2);
    assert_eq!(device_a.0.last_seq(), device_b.0.last_seq());
}

#[tokio::test]
async fn edits_and_deletes_propagate() {
    let account = bootstrap().await;
    let mut device_a = (MemoryVault::new(), account.device().await);
    let mut device_b = (MemoryVault::new(), account.device().await);

    device_a
        .0
        .stage(PendingOp::Upsert(account.encrypt("item", 1, b"v1")));
    sync(&mut device_a.0, &mut device_a.1).await.unwrap();
    sync(&mut device_b.0, &mut device_b.1).await.unwrap();

    // B edits (revision 2), A receives.
    device_b
        .0
        .stage(PendingOp::Upsert(account.encrypt("item", 2, b"v2")));
    sync(&mut device_b.0, &mut device_b.1).await.unwrap();
    sync(&mut device_a.0, &mut device_a.1).await.unwrap();
    let stored = device_a.0.get("item").unwrap();
    assert_eq!(stored.revision, 2);
    assert_eq!(account.decrypt(stored.content.as_ref().unwrap()), b"v2");

    // A deletes, B receives the tombstone.
    device_a.0.stage(PendingOp::Delete {
        item_id: "item".into(),
        base_revision: 2,
    });
    sync(&mut device_a.0, &mut device_a.1).await.unwrap();
    sync(&mut device_b.0, &mut device_b.1).await.unwrap();
    assert!(device_b.0.get("item").unwrap().deleted);
}

#[tokio::test]
async fn concurrent_edits_resolve_server_wins_and_preserve_loser() {
    let account = bootstrap().await;
    let mut device_a = (MemoryVault::new(), account.device().await);
    let mut device_b = (MemoryVault::new(), account.device().await);

    device_a
        .0
        .stage(PendingOp::Upsert(account.encrypt("shared", 1, b"base")));
    sync(&mut device_a.0, &mut device_a.1).await.unwrap();
    sync(&mut device_b.0, &mut device_b.1).await.unwrap();

    // Both edit revision 1 → 2 while offline. A reaches the server first.
    device_a
        .0
        .stage(PendingOp::Upsert(account.encrypt("shared", 2, b"A's edit")));
    device_b
        .0
        .stage(PendingOp::Upsert(account.encrypt("shared", 2, b"B's edit")));
    sync(&mut device_a.0, &mut device_a.1).await.unwrap();

    let report = sync(&mut device_b.0, &mut device_b.1).await.unwrap();

    // Server (A's edit) wins in B's replica…
    let stored = device_b.0.get("shared").unwrap();
    assert_eq!(
        account.decrypt(stored.content.as_ref().unwrap()),
        b"A's edit"
    );
    // …but B's losing edit is preserved for the app to surface.
    assert_eq!(report.conflicts.len(), 1);
    let conflict = &report.conflicts[0];
    assert_eq!(conflict.item_id, "shared");
    match &conflict.losing_op {
        PendingOp::Upsert(envelope) => {
            assert_eq!(account.decrypt(envelope), b"B's edit");
        }
        other => panic!("expected losing upsert, got {other:?}"),
    }
    // Queue is drained; a follow-up sync is clean and stable.
    let report = sync(&mut device_b.0, &mut device_b.1).await.unwrap();
    assert!(report.conflicts.is_empty());
    assert_eq!(report.pushed, 0);
}

#[tokio::test]
async fn client_behind_purge_horizon_gets_full_resync() {
    let account = bootstrap().await;
    let mut device_a = (MemoryVault::new(), account.device().await);
    let mut device_b = (MemoryVault::new(), account.device().await);

    device_a
        .0
        .stage(PendingOp::Upsert(account.encrypt("keep", 1, b"stays")));
    device_a
        .0
        .stage(PendingOp::Upsert(account.encrypt("doomed", 1, b"goes")));
    sync(&mut device_a.0, &mut device_a.1).await.unwrap();
    sync(&mut device_b.0, &mut device_b.1).await.unwrap();
    assert_eq!(device_b.0.list().len(), 2);

    // A deletes "doomed"; B does NOT sync and misses the tombstone.
    device_a.0.stage(PendingOp::Delete {
        item_id: "doomed".into(),
        base_revision: 1,
    });
    sync(&mut device_a.0, &mut device_a.1).await.unwrap();

    // 31 days pass; the tombstone ages out (simulated by rewinding its clock).
    sqlx::query("UPDATE vault_items SET updated_at = updated_at - 2678400 WHERE deleted = 1")
        .execute(&account.state.db)
        .await
        .unwrap();
    // Any pull triggers the lazy purge.
    sync(&mut device_a.0, &mut device_a.1).await.unwrap();

    // B is now behind the purge horizon → full resync rebuilds its replica.
    let report = sync(&mut device_b.0, &mut device_b.1).await.unwrap();
    assert!(report.did_full_resync);
    let live: Vec<_> = device_b
        .0
        .list()
        .into_iter()
        .filter(|i| !i.deleted)
        .collect();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].item_id, "keep");
}

#[tokio::test]
async fn accounts_are_isolated() {
    // Two separate servers-worth of state isn't the point — one server, two
    // accounts must never see each other's items.
    let account = bootstrap().await;
    let mut device = (MemoryVault::new(), account.device().await);
    device
        .0
        .stage(PendingOp::Upsert(account.encrypt("secret", 1, b"mine")));
    sync(&mut device.0, &mut device.1).await.unwrap();

    // Second account on the same server.
    let reg2 = vault_core::account::register(
        "other password",
        "other@example.com",
        vault_core::KdfParams::mobile_floor(),
    )
    .unwrap();
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/accounts/register")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "email": "other@example.com",
                "auth_credential": base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(reg2.bundle.auth_credential),
                "kdf_params": reg2.bundle.kdf_params,
                "master_wrapped_vault_key": serde_json::to_value(&reg2.bundle.master_wrapped_vault_key).unwrap(),
                "recovery_wrapped_vault_key": serde_json::to_value(&reg2.bundle.recovery_wrapped_vault_key).unwrap(),
            })
            .to_string(),
        ))
        .unwrap();
    let response = account.app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    sqlx::query("UPDATE accounts SET email_verified_at = 1 WHERE email = 'other@example.com'")
        .execute(&account.state.db)
        .await
        .unwrap();

    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "email": "other@example.com",
                "auth_credential": base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(reg2.bundle.auth_credential),
            })
            .to_string(),
        ))
        .unwrap();
    let response = account.app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();

    let mut other_device = (
        MemoryVault::new(),
        HttpTransport {
            app: account.app.clone(),
            access_token: body["access_token"].as_str().unwrap().to_string(),
        },
    );
    let report = sync(&mut other_device.0, &mut other_device.1)
        .await
        .unwrap();
    assert_eq!(report.pulled, 0);
    assert!(other_device.0.list().is_empty());
}
