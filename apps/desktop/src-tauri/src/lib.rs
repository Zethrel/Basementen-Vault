//! Basementen Vault desktop shell: a thin Tauri command layer over
//! `desktop-core`. All crypto and sync logic lives in the core crates; this
//! file only manages the unlocked-session lifecycle and marshals data to the
//! web UI.

use std::path::PathBuf;
use std::time::Duration;

use desktop_core::store::AccountMeta;
use desktop_core::{ApiClient, AutoLock, GeneratorOptions, Item, ItemSummary, SqliteVault};
use serde::Serialize;
use tauri::{Manager, State};
use tauri_plugin_clipboard_manager::ClipboardExt;
use tauri_plugin_dialog::DialogExt;
use vault_core::account::AccountSecrets;
use vault_sync::{LocalVault, PendingOp};
use zeroize::Zeroizing;

/// Everything that exists only while the vault is unlocked. Dropping this
/// struct locks the vault: `AccountSecrets` zeroizes its keys on drop.
struct Unlocked {
    secrets: AccountSecrets,
    api: ApiClient,
    vault: SqliteVault,
    autolock: AutoLock,
    email: String,
}

#[derive(Default)]
struct AppStateInner {
    session: Option<Unlocked>,
}

struct AppState {
    inner: tokio::sync::Mutex<AppStateInner>,
    db_path: PathBuf,
}

type Ctx<'a> = State<'a, AppState>;

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

const REFRESH_TOKEN_ID: &str = "__meta/refresh_token";

fn encrypt_refresh_token(
    secrets: &AccountSecrets,
    token: &str,
) -> Option<vault_core::EncryptedItem> {
    secrets
        .vault_key
        .encrypt_item(REFRESH_TOKEN_ID, 1, token.as_bytes())
        .ok()
}

fn decrypt_refresh_token(secrets: &AccountSecrets, vault: &SqliteVault) -> Option<String> {
    let envelope = vault.encrypted_refresh_token()?;
    // `bytes` is `Zeroizing`: the decrypted token buffer is scrubbed on drop.
    // The returned String (and its copy inside the ApiClient / reqwest headers)
    // is a session credential, not a vault secret — see THREAT_MODEL §A6.
    let bytes = secrets.vault_key.decrypt_item(&envelope).ok()?;
    std::str::from_utf8(&bytes).ok().map(String::from)
}

/// Outcome of a best-effort sync.
enum SyncOutcome {
    Synced(vault_sync::SyncReport),
    /// Offline / transient network or session error — benign, the queue waits.
    Offline,
    /// A rollback / withholding / forged-checkpoint alarm. Never silently
    /// swallowed: the server may be compromised or restored from an old backup.
    Alert(String),
}

/// Rollback-protected best-effort sync. Distinguishes benign offline from a
/// security alert that must reach the user.
async fn try_sync(unlocked: &mut Unlocked) -> SyncOutcome {
    match desktop_core::synchronize(
        &mut unlocked.vault,
        &mut unlocked.api,
        &unlocked.secrets.vault_key,
    )
    .await
    {
        Ok(report) => SyncOutcome::Synced(report),
        Err(
            e @ desktop_core::SyncError::Engine(vault_sync::SyncEngineError::RollbackDetected {
                ..
            }),
        )
        | Err(e @ desktop_core::SyncError::CheckpointForged)
        | Err(e @ desktop_core::SyncError::Withholding { .. }) => SyncOutcome::Alert(e.to_string()),
        // Transport / network / session errors: treat as offline; the op queue
        // and local replica are intact and will sync when connectivity returns.
        Err(_) => SyncOutcome::Offline,
    }
}

fn persist_rotated_refresh_token(unlocked: &Unlocked) {
    if let Some(token) = unlocked.api.refresh_token() {
        if let Some(envelope) = encrypt_refresh_token(&unlocked.secrets, token) {
            let _ = unlocked.vault.set_encrypted_refresh_token(Some(&envelope));
        }
    }
}

// ---------------------------------------------------------------------------
// Status / lifecycle

#[derive(Serialize)]
struct Status {
    state: &'static str, // "needs_setup" | "locked" | "unlocked"
    email: Option<String>,
}

#[tauri::command]
async fn status(ctx: Ctx<'_>) -> Result<Status, String> {
    let inner = ctx.inner.lock().await;
    if let Some(unlocked) = &inner.session {
        return Ok(Status {
            state: "unlocked",
            email: Some(unlocked.email.clone()),
        });
    }
    drop(inner);
    let vault = SqliteVault::open(&ctx.db_path).map_err(err)?;
    match vault.account_meta() {
        Some(meta) => Ok(Status {
            state: "locked",
            email: Some(meta.email),
        }),
        None => Ok(Status {
            state: "needs_setup",
            email: None,
        }),
    }
}

#[derive(Serialize)]
struct RegisterResult {
    recovery_code: String,
}

/// Create the account on the server. The user must then click the
/// verification link in their inbox and log in.
#[tauri::command]
async fn register(
    server_url: String,
    email: String,
    password: String,
) -> Result<RegisterResult, String> {
    let password = Zeroizing::new(password);
    if password.chars().count() < 12 {
        return Err("master password must be at least 12 characters".into());
    }
    let reg =
        vault_core::account::register(&password, vault_core::KdfParams::desktop()).map_err(err)?;
    let api = ApiClient::new(&server_url);
    api.register(&email, &reg.bundle).await.map_err(err)?;
    Ok(RegisterResult {
        recovery_code: reg.recovery_code.to_string(),
    })
}

#[tauri::command]
async fn login(
    ctx: Ctx<'_>,
    server_url: String,
    email: String,
    password: String,
    totp_code: Option<String>,
) -> Result<Status, String> {
    let password = Zeroizing::new(password);
    let mut api = ApiClient::new(&server_url);
    let prelogin = api.prelogin(&email).await.map_err(err)?;
    let credential =
        vault_core::account::login_credential(&password, &prelogin.kdf_salt, &prelogin.kdf_params)
            .map_err(err)?
            .to_server_credential();

    let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "desktop".into());
    let outcome = api
        .login(&email, credential, totp_code.as_deref(), None, &hostname)
        .await
        .map_err(err)?;

    let secrets = vault_core::account::unlock(
        &password,
        &outcome.kdf_salt,
        &outcome.kdf_params,
        &outcome.master_wrapped_vault_key,
    )
    .map_err(err)?;

    let vault = SqliteVault::open(&ctx.db_path).map_err(err)?;
    vault
        .set_account_meta(&AccountMeta {
            server_url: server_url.clone(),
            email: email.clone(),
            kdf_params: outcome.kdf_params.clone(),
            kdf_salt: outcome.kdf_salt.clone(),
            master_wrapped_vault_key: outcome.master_wrapped_vault_key.clone(),
        })
        .map_err(err)?;

    let mut unlocked = Unlocked {
        secrets,
        api,
        vault,
        autolock: AutoLock::new(AutoLock::DEFAULT_TIMEOUT),
        email: email.clone(),
    };
    persist_rotated_refresh_token(&unlocked);
    try_sync(&mut unlocked).await;

    let mut inner = ctx.inner.lock().await;
    inner.session = Some(unlocked);
    Ok(Status {
        state: "unlocked",
        email: Some(email),
    })
}

/// Offline unlock with the cached account metadata; restores the server
/// session from the encrypted refresh token when the network allows.
#[tauri::command]
async fn unlock(ctx: Ctx<'_>, password: String) -> Result<Status, String> {
    let password = Zeroizing::new(password);
    let vault = SqliteVault::open(&ctx.db_path).map_err(err)?;
    let meta = vault
        .account_meta()
        .ok_or("no account on this device — log in first")?;

    let secrets = vault_core::account::unlock(
        &password,
        &meta.kdf_salt,
        &meta.kdf_params,
        &meta.master_wrapped_vault_key,
    )
    .map_err(|_| "wrong master password".to_string())?;

    let refresh = decrypt_refresh_token(&secrets, &vault);
    let api = ApiClient::with_tokens(&meta.server_url, None, refresh);

    let mut unlocked = Unlocked {
        secrets,
        api,
        vault,
        autolock: AutoLock::new(AutoLock::DEFAULT_TIMEOUT),
        email: meta.email.clone(),
    };

    // Best effort: rotate the session and pull changes. Offline is fine.
    if unlocked.api.refresh_token().is_some() && unlocked.api.refresh_session().await.is_ok() {
        persist_rotated_refresh_token(&unlocked);
        try_sync(&mut unlocked).await;
    }

    let mut inner = ctx.inner.lock().await;
    inner.session = Some(unlocked);
    Ok(Status {
        state: "unlocked",
        email: Some(meta.email),
    })
}

#[tauri::command]
async fn lock(ctx: Ctx<'_>) -> Result<(), String> {
    let mut inner = ctx.inner.lock().await;
    inner.session = None; // drop zeroizes keys
    Ok(())
}

// ---------------------------------------------------------------------------
// Items

/// Run `f` against the unlocked session (bumping the auto-lock clock).
async fn with_session<R>(
    ctx: &Ctx<'_>,
    f: impl FnOnce(&mut Unlocked) -> Result<R, String>,
) -> Result<R, String> {
    let mut inner = ctx.inner.lock().await;
    let unlocked = inner.session.as_mut().ok_or("vault is locked")?;
    unlocked.autolock.touch();
    f(unlocked)
}

#[tauri::command]
async fn list_items(ctx: Ctx<'_>, query: String) -> Result<Vec<ItemSummary>, String> {
    with_session(&ctx, |u| {
        let mut out = Vec::new();
        for stored in u.vault.list() {
            if stored.deleted || stored.item_id.starts_with("__meta/") {
                continue;
            }
            let Some(content) = &stored.content else {
                continue;
            };
            let Ok(plain) = u.secrets.vault_key.decrypt_item(content) else {
                continue;
            };
            let Ok(item) = Item::from_plaintext(&plain) else {
                continue;
            };
            if item.matches(&query) {
                out.push(ItemSummary::of(&stored.item_id, &item));
            }
        }
        out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        Ok(out)
    })
    .await
}

#[tauri::command]
async fn get_item(ctx: Ctx<'_>, item_id: String) -> Result<Item, String> {
    with_session(&ctx, |u| {
        let stored = u.vault.get(&item_id).ok_or("item not found")?;
        let content = stored.content.as_ref().ok_or("item deleted")?;
        let plain = u
            .secrets
            .vault_key
            .decrypt_item(content)
            .map_err(|_| "decryption failed")?;
        Item::from_plaintext(&plain).map_err(err)
    })
    .await
}

#[derive(Serialize)]
struct SaveResult {
    item_id: String,
}

#[tauri::command]
async fn save_item(
    ctx: Ctx<'_>,
    item_id: Option<String>,
    item: Item,
) -> Result<SaveResult, String> {
    let id = with_session(&ctx, |u| {
        let id = item_id.unwrap_or_else(|| uuid::Uuid::now_v7().to_string());
        let base_revision = u.vault.get(&id).map(|s| s.revision).unwrap_or(0);
        let plain = item.to_plaintext().map_err(err)?;
        let envelope = u
            .secrets
            .vault_key
            .encrypt_item(&id, (base_revision + 1) as u64, &plain)
            .map_err(err)?;
        u.vault.stage(PendingOp::Upsert(envelope));
        Ok(id)
    })
    .await?;

    sync_now(ctx).await.ok();
    Ok(SaveResult { item_id: id })
}

#[tauri::command]
async fn delete_item(ctx: Ctx<'_>, item_id: String) -> Result<(), String> {
    with_session(&ctx, |u| {
        let stored = u.vault.get(&item_id).ok_or("item not found")?;
        u.vault.stage(PendingOp::Delete {
            item_id,
            base_revision: stored.revision,
        });
        Ok(())
    })
    .await?;
    sync_now(ctx).await.ok();
    Ok(())
}

#[derive(Serialize)]
struct SyncSummary {
    pushed: usize,
    pulled: usize,
    conflicts: usize,
    offline: bool,
}

#[tauri::command]
async fn sync_now(ctx: Ctx<'_>) -> Result<SyncSummary, String> {
    let mut inner = ctx.inner.lock().await;
    let unlocked = inner.session.as_mut().ok_or("vault is locked")?;
    unlocked.autolock.touch();
    match try_sync(unlocked).await {
        // A rollback/withholding/forgery alarm is surfaced as a hard error so
        // the UI shows it prominently instead of pretending all is well.
        SyncOutcome::Alert(msg) => Err(format!(
            "⚠ Sync stopped: {msg}. Your local vault is unchanged. If you did \
             not restore the server from a backup, treat this as a possible \
             compromise."
        )),
        SyncOutcome::Synced(report) => {
            persist_rotated_refresh_token(unlocked);
            // Materialize losing edits as "(conflicted copy)" items so no
            // keystroke is ever silently discarded. The copies are new items
            // and will reach the server on the next sync pass below.
            let mut copies = 0;
            for conflict in &report.conflicts {
                let vault_sync::PendingOp::Upsert(envelope) = &conflict.losing_op else {
                    continue; // a losing delete: server state stands, nothing to save
                };
                let Ok(plain) = unlocked.secrets.vault_key.decrypt_item(envelope) else {
                    continue;
                };
                let Ok(mut item) = Item::from_plaintext(&plain) else {
                    continue;
                };
                match &mut item {
                    Item::Login { name, .. }
                    | Item::Note { name, .. }
                    | Item::Card { name, .. } => {
                        name.push_str(" (conflicted copy)");
                    }
                }
                let id = uuid::Uuid::now_v7().to_string();
                if let Ok(plain) = item.to_plaintext() {
                    if let Ok(new_envelope) =
                        unlocked.secrets.vault_key.encrypt_item(&id, 1, &plain)
                    {
                        unlocked.vault.stage(PendingOp::Upsert(new_envelope));
                        copies += 1;
                    }
                }
            }
            if copies > 0 {
                try_sync(unlocked).await;
            }
            Ok(SyncSummary {
                pushed: report.pushed,
                pulled: report.pulled,
                conflicts: report.conflicts.len(),
                offline: false,
            })
        }
        SyncOutcome::Offline => Ok(SyncSummary {
            pushed: 0,
            pulled: 0,
            conflicts: 0,
            offline: true,
        }),
    }
}

// ---------------------------------------------------------------------------
// Recovery & backup e-mail

/// Kick off account recovery: the server e-mails instructions (with a
/// cooling-off period) to the account's addresses.
#[tauri::command]
async fn recover_start(server_url: String, email: String) -> Result<String, String> {
    let api = ApiClient::new(&server_url);
    api.recovery_start(&email).await.map_err(err)?;
    Ok(
        "If that address has an account, recovery instructions were e-mailed. \
        The recovery token becomes usable after the cooling-off period."
            .into(),
    )
}

#[derive(Serialize)]
struct RecoverResult {
    /// The NEW Recovery Kit code (the old kit is spent). Empty for wipes.
    recovery_code: String,
    data_preserved: bool,
}

/// Complete recovery with the e-mailed token. With a Recovery Kit code the
/// vault is fully restored; with `wipe` (and no code) the account is reset
/// and all stored items are destroyed.
#[tauri::command]
async fn recover_complete(
    ctx: Ctx<'_>,
    server_url: String,
    token: String,
    recovery_code: Option<String>,
    new_password: String,
    wipe: bool,
) -> Result<RecoverResult, String> {
    let new_password = Zeroizing::new(new_password);
    let recovery_code = recovery_code.map(Zeroizing::new);
    if new_password.chars().count() < 12 {
        return Err("master password must be at least 12 characters".into());
    }
    let api = ApiClient::new(&server_url);
    let data = api.recovery_data(&token).await.map_err(|e| match e {
        desktop_core::ApiError::CoolingOff { retry_after_secs } => format!(
            "this recovery is still in its cooling-off period — usable in about {} hours",
            (retry_after_secs + 3599) / 3600
        ),
        other => other.to_string(),
    })?;

    let (new_reg, preserved) = match recovery_code {
        Some(code) if !code.trim().is_empty() => {
            let reg = vault_core::account::recover_and_rekey(
                &code,
                &data.recovery_wrapped_vault_key,
                &new_password,
                &data.kdf_salt,
                vault_core::KdfParams::desktop(),
            )
            .map_err(|_| "recovery failed — check the Recovery Kit code for typos".to_string())?;
            let verifier = reg.secrets.vault_key.recovery_verifier();
            api.recovery_complete(&token, &reg.bundle, Some(verifier), false)
                .await
                .map_err(err)?;
            (reg, true)
        }
        _ if wipe => {
            let reg =
                vault_core::account::register(&new_password, vault_core::KdfParams::desktop())
                    .map_err(err)?;
            api.recovery_complete(&token, &reg.bundle, None, true)
                .await
                .map_err(err)?;
            (reg, false)
        }
        _ => {
            return Err("enter your Recovery Kit code, or explicitly choose the \
                        reset-and-wipe option"
                .into())
        }
    };

    // The local replica belongs to the pre-recovery account state; start
    // clean and let the first login resync (or stay empty after a wipe).
    if let Ok(mut vault) = SqliteVault::open(&ctx.db_path) {
        vault.clear_items();
        vault.set_last_seq(0);
        let _ = vault.set_encrypted_refresh_token(None);
    }

    Ok(RecoverResult {
        recovery_code: new_reg.recovery_code.to_string(),
        data_preserved: preserved,
    })
}

/// Set or replace the trusted backup e-mail (fresh password + TOTP gated).
#[tauri::command]
async fn set_backup_email(
    ctx: Ctx<'_>,
    password: String,
    totp_code: Option<String>,
    backup_email: String,
) -> Result<String, String> {
    let password = Zeroizing::new(password);
    let mut inner = ctx.inner.lock().await;
    let unlocked = inner.session.as_mut().ok_or("vault is locked")?;
    unlocked.autolock.touch();
    let meta = unlocked.vault.account_meta().ok_or("no account metadata")?;
    let credential =
        vault_core::account::login_credential(&password, &meta.kdf_salt, &meta.kdf_params)
            .map_err(err)?
            .to_server_credential();
    unlocked
        .api
        .set_backup_email(credential, totp_code.as_deref(), &backup_email)
        .await
        .map_err(err)?;
    Ok("Verification e-mail sent to the backup address.".into())
}

/// Remove the trusted backup e-mail (fresh password + TOTP gated).
#[tauri::command]
async fn remove_backup_email(
    ctx: Ctx<'_>,
    password: String,
    totp_code: Option<String>,
) -> Result<(), String> {
    let password = Zeroizing::new(password);
    let mut inner = ctx.inner.lock().await;
    let unlocked = inner.session.as_mut().ok_or("vault is locked")?;
    unlocked.autolock.touch();
    let meta = unlocked.vault.account_meta().ok_or("no account metadata")?;
    let credential =
        vault_core::account::login_credential(&password, &meta.kdf_salt, &meta.kdf_params)
            .map_err(err)?
            .to_server_credential();
    unlocked
        .api
        .remove_backup_email(credential, totp_code.as_deref())
        .await
        .map_err(err)
}

// ---------------------------------------------------------------------------
// Export / import

fn decrypted_items(unlocked: &Unlocked) -> Vec<Item> {
    let mut items = Vec::new();
    for stored in unlocked.vault.list() {
        if stored.deleted || stored.item_id.starts_with("__meta/") {
            continue;
        }
        let Some(content) = &stored.content else {
            continue;
        };
        let Ok(plain) = unlocked.secrets.vault_key.decrypt_item(content) else {
            continue;
        };
        if let Ok(item) = Item::from_plaintext(&plain) {
            items.push(item);
        }
    }
    items
}

/// Export the whole vault as an encrypted backup file.
#[tauri::command]
async fn export_vault(
    app: tauri::AppHandle,
    ctx: Ctx<'_>,
    passphrase: String,
) -> Result<String, String> {
    let passphrase = Zeroizing::new(passphrase);
    if passphrase.chars().count() < 12 {
        return Err("export passphrase must be at least 12 characters".into());
    }
    let file_contents = {
        let mut inner = ctx.inner.lock().await;
        let unlocked = inner.session.as_mut().ok_or("vault is locked")?;
        unlocked.autolock.touch();
        desktop_core::export_encrypted(&decrypted_items(unlocked), &passphrase).map_err(err)?
    };

    let path = app
        .dialog()
        .file()
        .set_file_name("basementen-vault-backup.bvexport")
        .blocking_save_file()
        .and_then(|p| p.into_path().ok())
        .ok_or("export cancelled")?;
    std::fs::write(&path, file_contents).map_err(err)?;
    Ok(format!("Encrypted backup written to {}", path.display()))
}

#[derive(Serialize)]
struct ImportResult {
    imported: usize,
}

/// Import items from a file: an encrypted .bvexport (needs its passphrase)
/// or a CSV export from another password manager.
#[tauri::command]
async fn import_vault(
    app: tauri::AppHandle,
    ctx: Ctx<'_>,
    passphrase: Option<String>,
) -> Result<ImportResult, String> {
    let path = app
        .dialog()
        .file()
        .add_filter("Vault import", &["bvexport", "csv", "json"])
        .blocking_pick_file()
        .and_then(|p| p.into_path().ok())
        .ok_or("import cancelled")?;
    let contents = std::fs::read_to_string(&path).map_err(err)?;

    let items = if contents.contains("basementen-vault-export") {
        let passphrase = Zeroizing::new(
            passphrase
                .filter(|p| !p.is_empty())
                .ok_or("this is an encrypted backup — enter its passphrase")?,
        );
        desktop_core::import_encrypted(&contents, &passphrase).map_err(err)?
    } else {
        desktop_core::import_csv(&contents).map_err(err)?
    };

    let imported = items.len();
    {
        let mut inner = ctx.inner.lock().await;
        let unlocked = inner.session.as_mut().ok_or("vault is locked")?;
        unlocked.autolock.touch();
        for item in items {
            let id = uuid::Uuid::now_v7().to_string();
            let plain = item.to_plaintext().map_err(err)?;
            let envelope = unlocked
                .secrets
                .vault_key
                .encrypt_item(&id, 1, &plain)
                .map_err(err)?;
            unlocked.vault.stage(PendingOp::Upsert(envelope));
        }
    }
    sync_now(ctx).await.ok();
    Ok(ImportResult { imported })
}

// ---------------------------------------------------------------------------
// Session (device) management

#[tauri::command]
async fn list_sessions(ctx: Ctx<'_>) -> Result<Vec<desktop_core::SessionInfo>, String> {
    let mut inner = ctx.inner.lock().await;
    let unlocked = inner.session.as_mut().ok_or("vault is locked")?;
    unlocked.autolock.touch();
    unlocked.api.list_sessions().await.map_err(err)
}

#[tauri::command]
async fn revoke_session(ctx: Ctx<'_>, id: String) -> Result<(), String> {
    let mut inner = ctx.inner.lock().await;
    let unlocked = inner.session.as_mut().ok_or("vault is locked")?;
    unlocked.autolock.touch();
    unlocked.api.revoke_session(&id).await.map_err(err)
}

#[tauri::command]
async fn revoke_other_sessions(ctx: Ctx<'_>) -> Result<u64, String> {
    let mut inner = ctx.inner.lock().await;
    let unlocked = inner.session.as_mut().ok_or("vault is locked")?;
    unlocked.autolock.touch();
    unlocked.api.revoke_other_sessions().await.map_err(err)
}

// ---------------------------------------------------------------------------
// Generator & clipboard

#[derive(Serialize)]
struct GeneratedPassword {
    password: String,
    entropy_bits: f64,
}

#[tauri::command]
fn generate(options: GeneratorOptions) -> Result<GeneratedPassword, String> {
    let (password, entropy_bits) = desktop_core::generate_password(&options).map_err(err)?;
    Ok(GeneratedPassword {
        password: password.to_string(),
        entropy_bits,
    })
}

/// Copy a secret and clear the clipboard 30 seconds later (only if it still
/// holds the same secret — never clobber something the user copied since).
#[tauri::command]
async fn copy_secret(app: tauri::AppHandle, text: String) -> Result<(), String> {
    app.clipboard().write_text(text.clone()).map_err(err)?;
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_secs(30)).await;
        if let Ok(current) = app.clipboard().read_text() {
            if current == text {
                let _ = app.clipboard().write_text(String::new());
            }
        }
    });
    Ok(())
}

// ---------------------------------------------------------------------------

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&dir)?;
            app.manage(AppState {
                inner: tokio::sync::Mutex::new(AppStateInner::default()),
                db_path: dir.join("vault-local.db"),
            });

            // Auto-lock watchdog: drop the session once idle time expires.
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    let state: State<AppState> = handle.state();
                    let mut inner = state.inner.lock().await;
                    if inner
                        .session
                        .as_ref()
                        .is_some_and(|u| u.autolock.should_lock())
                    {
                        inner.session = None;
                    }
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            status,
            register,
            login,
            unlock,
            lock,
            list_items,
            get_item,
            save_item,
            delete_item,
            sync_now,
            generate,
            copy_secret,
            recover_start,
            recover_complete,
            set_backup_email,
            remove_backup_email,
            list_sessions,
            revoke_session,
            revoke_other_sessions,
            export_vault,
            import_vault,
        ])
        .run(tauri::generate_context!())
        .expect("error while running application");
}
