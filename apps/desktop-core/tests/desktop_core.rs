//! desktop-core tests: SQLite replica semantics, generator guarantees,
//! item search — plus a full end-to-end run of the ApiClient against a real
//! vault-server listening on a TCP port (register → login → sync → refresh).

use std::net::SocketAddr;
use std::sync::Mutex;

use desktop_core::store::AccountMeta;
use desktop_core::{generate_password, ApiClient, GeneratorOptions, Item, SqliteVault};
use vault_sync::{sync, LocalVault, PendingOp};

// ---------------------------------------------------------------------------
// Store

#[test]
fn sqlite_vault_persists_items_ops_and_cursor() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault-local.db");
    let reg = vault_core::account::register("pw", vault_core::KdfParams::mobile_floor()).unwrap();
    let envelope = reg
        .secrets
        .vault_key
        .encrypt_item("item-1", 1, b"data")
        .unwrap();

    {
        let mut vault = SqliteVault::open(&path).unwrap();
        vault.stage(PendingOp::Upsert(envelope.clone()));
        vault.set_last_seq(7);
        vault
            .set_account_meta(&AccountMeta {
                server_url: "http://home:8080".into(),
                email: "store@example.com".into(),
                kdf_params: reg.bundle.kdf_params.clone(),
                kdf_salt: reg.bundle.kdf_salt.to_vec(),
                master_wrapped_vault_key: reg.bundle.master_wrapped_vault_key.clone(),
            })
            .unwrap();
    }

    // Reopen: everything survived the process "restart".
    let vault = SqliteVault::open(&path).unwrap();
    assert_eq!(vault.last_seq(), 7);
    assert_eq!(vault.pending_ops().len(), 1);
    let stored = vault.get("item-1").unwrap();
    assert!(!stored.deleted);
    assert_eq!(
        reg.secrets
            .vault_key
            .decrypt_item(stored.content.as_ref().unwrap())
            .unwrap(),
        b"data"
    );
    let meta = vault.account_meta().unwrap();
    assert_eq!(meta.email, "store@example.com");

    // The cached salt + wrapped key unlock offline.
    let secrets = vault_core::account::unlock(
        "pw",
        &meta.kdf_salt,
        &meta.kdf_params,
        &meta.master_wrapped_vault_key,
    )
    .unwrap();
    assert_eq!(secrets.vault_key, reg.secrets.vault_key);
}

#[test]
fn sqlite_vault_stage_delete_then_pop() {
    let mut vault = SqliteVault::open_in_memory().unwrap();
    let reg = vault_core::account::register("pw", vault_core::KdfParams::mobile_floor()).unwrap();
    let envelope = reg.secrets.vault_key.encrypt_item("x", 1, b"v").unwrap();

    vault.stage(PendingOp::Upsert(envelope));
    vault.stage(PendingOp::Delete {
        item_id: "x".into(),
        base_revision: 1,
    });
    assert!(
        vault.get("x").unwrap().deleted,
        "delete reflects immediately"
    );
    assert_eq!(vault.pending_ops().len(), 2);

    vault.pop_front_op();
    let remaining = vault.pending_ops();
    assert_eq!(remaining.len(), 1);
    assert!(
        matches!(remaining[0], PendingOp::Delete { .. }),
        "FIFO order"
    );
}

// ---------------------------------------------------------------------------
// Generator

#[test]
fn generator_honours_classes_and_length() {
    let opts = GeneratorOptions {
        length: 32,
        lowercase: true,
        uppercase: true,
        digits: true,
        symbols: true,
        exclude_ambiguous: true,
    };
    for _ in 0..50 {
        let (pw, entropy) = generate_password(&opts).unwrap();
        assert_eq!(pw.chars().count(), 32);
        assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
        assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
        assert!(pw.chars().any(|c| c.is_ascii_digit()));
        assert!(pw.chars().any(|c| !c.is_ascii_alphanumeric()));
        assert!(!pw.contains(['I', 'l', '1', 'O', '0', 'o']));
        assert!(entropy > 128.0, "32 chars over a big pool is > 128 bits");
    }
}

#[test]
fn generator_rejects_empty_selection_and_produces_unique_outputs() {
    let none = GeneratorOptions {
        lowercase: false,
        uppercase: false,
        digits: false,
        symbols: false,
        ..Default::default()
    };
    assert!(generate_password(&none).is_err());

    let opts = GeneratorOptions::default();
    let a = generate_password(&opts).unwrap().0;
    let b = generate_password(&opts).unwrap().0;
    assert_ne!(*a, *b, "two generations must (overwhelmingly) differ");
}

// ---------------------------------------------------------------------------
// Items

#[test]
fn item_roundtrip_and_search() {
    let item = Item::Login {
        name: "GitHub".into(),
        username: "sig".into(),
        password: "hunter2".into(),
        url: "https://github.com".into(),
        notes: String::new(),
        tags: vec!["dev".into()],
    };
    let bytes = item.to_plaintext().unwrap();
    let back = Item::from_plaintext(&bytes).unwrap();
    assert_eq!(back.name(), "GitHub");

    assert!(back.matches("git"));
    assert!(back.matches("SIG"));
    assert!(back.matches("dev"));
    assert!(back.matches(""));
    assert!(!back.matches("hunter2"), "passwords are not searchable");

    let summary = desktop_core::ItemSummary::of("id-1", &back);
    assert_eq!(summary.kind, "login");
    assert_eq!(summary.subtitle, "sig");
}

// ---------------------------------------------------------------------------
// End-to-end: ApiClient against a real server over TCP

async fn spawn_server() -> (String, vault_server::state::AppState) {
    let pool = vault_server::db::connect_in_memory().await.unwrap();
    let cfg = vault_server::config::Config {
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        db_path: ":memory:".into(),
        base_url: "http://vault.test".into(),
        registration_open: true,
        trust_proxy: false,
        recovery_cooloff_secs: 72 * 3600,
        mail: vault_server::config::MailConfig::Console,
    };
    let state = vault_server::state::AppState::new(
        pool,
        cfg,
        vault_server::mailer::Mailer::Memory(Mutex::new(Vec::new())),
    );
    let app = vault_server::build_app(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), state)
}

#[tokio::test]
async fn api_client_full_lifecycle() {
    let (base_url, state) = spawn_server().await;
    let email = "desktop@example.com";
    let password = "desktop master password";

    // Client-side registration + server account creation.
    let reg =
        vault_core::account::register(password, vault_core::KdfParams::mobile_floor()).unwrap();
    let mut api = ApiClient::new(&base_url);
    api.register(email, &reg.bundle).await.unwrap();

    // "Click" the verification link.
    sqlx::query("UPDATE accounts SET email_verified_at = 1")
        .execute(&state.db)
        .await
        .unwrap();

    // Prelogin gives back our KDF params AND the stored salt.
    let prelogin = api.prelogin(email).await.unwrap();
    assert_eq!(prelogin.kdf_params, reg.bundle.kdf_params);
    assert_eq!(prelogin.kdf_salt, reg.bundle.kdf_salt);

    // Login; unlock the vault with what the server returns.
    let outcome = api
        .login(
            email,
            reg.secrets.auth_key.to_server_credential(),
            None,
            None,
            "test-desktop",
        )
        .await
        .unwrap();
    let secrets = vault_core::account::unlock(
        password,
        &outcome.kdf_salt,
        &outcome.kdf_params,
        &outcome.master_wrapped_vault_key,
    )
    .unwrap();

    // Stage two items locally and sync them up.
    let mut vault = SqliteVault::open_in_memory().unwrap();
    let item = Item::Login {
        name: "Router".into(),
        username: "admin".into(),
        password: "s3cret".into(),
        url: "http://192.168.1.1".into(),
        notes: String::new(),
        tags: vec![],
    };
    let envelope = secrets
        .vault_key
        .encrypt_item("router", 1, &item.to_plaintext().unwrap())
        .unwrap();
    vault.stage(PendingOp::Upsert(envelope));
    let report = sync(&mut vault, &mut api).await.unwrap();
    assert_eq!(report.pushed, 1);

    // Session refresh rotates tokens and keeps working.
    let old_refresh = api.refresh_token().unwrap().to_string();
    let new_refresh = api.refresh_session().await.unwrap();
    assert_ne!(old_refresh, new_refresh);
    let report = sync(&mut vault, &mut api).await.unwrap();
    assert_eq!(report.pushed, 0);

    // A second device sees the item and decrypts it.
    let mut api2 = ApiClient::new(&base_url);
    api2.login(
        email,
        reg.secrets.auth_key.to_server_credential(),
        None,
        None,
        "second-device",
    )
    .await
    .unwrap();
    let mut vault2 = SqliteVault::open_in_memory().unwrap();
    let report = sync(&mut vault2, &mut api2).await.unwrap();
    assert_eq!(report.pulled, 1);
    let stored = vault2.get("router").unwrap();
    let plain = secrets
        .vault_key
        .decrypt_item(stored.content.as_ref().unwrap())
        .unwrap();
    let back = Item::from_plaintext(&plain).unwrap();
    assert_eq!(back.name(), "Router");

    // Logout kills the session.
    api.logout().await;
    assert!(sync(&mut vault, &mut api).await.is_err());
}

#[tokio::test]
async fn api_client_recovery_lifecycle() {
    let (base_url, state) = spawn_server().await;
    let email = "recover-me@example.com";

    let reg = vault_core::account::register(
        "password before amnesia",
        vault_core::KdfParams::mobile_floor(),
    )
    .unwrap();
    let mut api = ApiClient::new(&base_url);
    api.register(email, &reg.bundle).await.unwrap();
    sqlx::query("UPDATE accounts SET email_verified_at = 1")
        .execute(&state.db)
        .await
        .unwrap();
    api.login(
        email,
        reg.secrets.auth_key.to_server_credential(),
        None,
        None,
        "d",
    )
    .await
    .unwrap();

    // Store an item, then "forget" the password.
    let mut vault = SqliteVault::open_in_memory().unwrap();
    let envelope = reg
        .secrets
        .vault_key
        .encrypt_item("keepsake", 1, b"survives recovery")
        .unwrap();
    vault.stage(PendingOp::Upsert(envelope));
    sync(&mut vault, &mut api).await.unwrap();

    // Start recovery; pull the token out of the captured mail.
    api.recovery_start(email).await.unwrap();
    let mails = state.mailer.sent();
    let body = &mails
        .iter()
        .rev()
        .find(|m| m.body.contains("bvrec_"))
        .unwrap()
        .body;
    let start = body.find("bvrec_").unwrap();
    let token: String = body[start..].split_whitespace().next().unwrap().to_string();

    // Cooling-off is enforced through the client error surface.
    let err = api.recovery_data(&token).await.unwrap_err();
    assert!(matches!(
        err,
        desktop_core::ApiError::CoolingOff { retry_after_secs } if retry_after_secs > 0
    ));
    sqlx::query("UPDATE recovery_requests SET usable_at = 0")
        .execute(&state.db)
        .await
        .unwrap();

    // Recover with the kit, under a new password.
    let data = api.recovery_data(&token).await.unwrap();
    assert!(data.supports_data_recovery);
    assert_eq!(
        data.kdf_salt, reg.bundle.kdf_salt,
        "salt is account-lifetime"
    );
    let new_reg = vault_core::account::recover_and_rekey(
        &reg.recovery_code,
        &data.recovery_wrapped_vault_key,
        "password after recovery",
        &data.kdf_salt,
        vault_core::KdfParams::mobile_floor(),
    )
    .unwrap();
    api.recovery_complete(
        &token,
        &new_reg.bundle,
        Some(new_reg.secrets.vault_key.recovery_verifier()),
        false,
    )
    .await
    .unwrap();

    // Fresh login with the new password on a fresh device; data intact.
    let mut api2 = ApiClient::new(&base_url);
    api2.login(
        email,
        new_reg.secrets.auth_key.to_server_credential(),
        None,
        None,
        "post-recovery",
    )
    .await
    .unwrap();
    let mut vault2 = SqliteVault::open_in_memory().unwrap();
    sync(&mut vault2, &mut api2).await.unwrap();
    let stored = vault2.get("keepsake").unwrap();
    assert_eq!(
        new_reg
            .secrets
            .vault_key
            .decrypt_item(stored.content.as_ref().unwrap())
            .unwrap(),
        b"survives recovery"
    );
}

// ---------------------------------------------------------------------------
// Export / import

#[test]
fn encrypted_export_roundtrip_and_wrong_passphrase() {
    let items = vec![
        Item::Login {
            name: "GitHub".into(),
            username: "sig".into(),
            password: "hunter2".into(),
            url: "https://github.com".into(),
            notes: String::new(),
            tags: vec![],
        },
        Item::Note {
            name: "Wi-Fi".into(),
            notes: "the code is on the router".into(),
            tags: vec![],
        },
    ];

    let file = desktop_core::export_encrypted(&items, "export passphrase").unwrap();
    assert!(file.contains("basementen-vault-export"));
    assert!(
        !file.contains("hunter2"),
        "plaintext must never appear in the export file"
    );

    let back = desktop_core::import_encrypted(&file, "export passphrase").unwrap();
    assert_eq!(back.len(), 2);
    assert_eq!(back[0].name(), "GitHub");

    assert!(matches!(
        desktop_core::import_encrypted(&file, "wrong passphrase").unwrap_err(),
        desktop_core::TransferError::Decrypt
    ));
    assert!(matches!(
        desktop_core::import_encrypted("{\"not\":\"an export\"}", "x").unwrap_err(),
        desktop_core::TransferError::BadFormat
    ));
}

#[test]
fn csv_import_generic_and_bitwarden() {
    let generic = "name,url,username,password,notes\n\
                   GitHub,https://github.com,sig,hunter2,work\n\
                   \"Comma, Inc\",https://comma.example,me,\"p,w\",";
    let items = desktop_core::import_csv(generic).unwrap();
    assert_eq!(items.len(), 2);
    match &items[1] {
        Item::Login { name, password, .. } => {
            assert_eq!(name, "Comma, Inc");
            assert_eq!(password, "p,w");
        }
        other => panic!("expected login, got {other:?}"),
    }

    let bitwarden = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
                     ,,login,Router,,,0,http://192.168.1.1,admin,s3cret,\n\
                     ,,note,Some note,text,,0,,,,";
    let items = desktop_core::import_csv(bitwarden).unwrap();
    assert_eq!(items.len(), 1, "non-login rows are skipped");
    match &items[0] {
        Item::Login { name, username, .. } => {
            assert_eq!(name, "Router");
            assert_eq!(username, "admin");
        }
        other => panic!("expected login, got {other:?}"),
    }

    assert!(desktop_core::import_csv("just,some,random\ndata,x,y").is_err());
}

#[tokio::test]
async fn api_client_session_management() {
    let (base_url, state) = spawn_server().await;
    let email = "sessions@example.com";
    let password = "session master password";

    let reg =
        vault_core::account::register(password, vault_core::KdfParams::mobile_floor()).unwrap();
    let mut api_a = ApiClient::new(&base_url);
    api_a.register(email, &reg.bundle).await.unwrap();
    sqlx::query("UPDATE accounts SET email_verified_at = 1")
        .execute(&state.db)
        .await
        .unwrap();
    api_a
        .login(
            email,
            reg.secrets.auth_key.to_server_credential(),
            None,
            None,
            "laptop",
        )
        .await
        .unwrap();

    // A second device.
    let mut api_b = ApiClient::new(&base_url);
    api_b
        .login(
            email,
            reg.secrets.auth_key.to_server_credential(),
            None,
            None,
            "phone",
        )
        .await
        .unwrap();

    // Device A sees both, with itself flagged current.
    let sessions = api_a.list_sessions().await.unwrap();
    assert_eq!(sessions.len(), 2);
    let current: Vec<_> = sessions.iter().filter(|s| s.current).collect();
    assert_eq!(current.len(), 1);
    assert_eq!(current[0].device_name, "laptop");

    // Revoke the phone; it can no longer list sessions.
    let phone = sessions.iter().find(|s| s.device_name == "phone").unwrap();
    api_a.revoke_session(&phone.id).await.unwrap();
    assert!(api_b.list_sessions().await.is_err());

    // Only the laptop remains.
    assert_eq!(api_a.list_sessions().await.unwrap().len(), 1);
}
