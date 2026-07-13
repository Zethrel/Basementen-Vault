//! SQLite-backed local replica: encrypted items, the offline op queue, the
//! sync cursor, and account metadata for offline unlock.
//!
//! Every value in this database is either public metadata (server URL,
//! e-mail, KDF parameters) or ciphertext (wrapped vault key, item envelopes,
//! the encrypted refresh token). Stealing the file yields nothing without
//! the master password.

use rusqlite::{params, Connection, OptionalExtension};
use vault_core::EncryptedItem;
use vault_sync::{LocalVault, PendingOp, RemoteItem, StoredItem};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("corrupt store: {0}")]
    Corrupt(String),
}

pub struct SqliteVault {
    conn: Connection,
}

/// Account metadata cached locally so the vault can be unlocked offline.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AccountMeta {
    pub server_url: String,
    pub email: String,
    pub kdf_params: vault_core::KdfParams,
    pub master_wrapped_vault_key: vault_core::WrappedKey,
}

impl SqliteVault {
    pub fn open(path: &std::path::Path) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> Result<Self, StoreError> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self, StoreError> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS meta (
                 key   TEXT PRIMARY KEY,
                 value TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS items (
                 item_id  TEXT PRIMARY KEY,
                 revision INTEGER NOT NULL,
                 deleted  INTEGER NOT NULL DEFAULT 0,
                 content  TEXT
             );
             CREATE TABLE IF NOT EXISTS ops (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 op TEXT NOT NULL
             );",
        )?;
        Ok(Self { conn })
    }

    // --- metadata ----------------------------------------------------

    fn meta_get(&self, key: &str) -> Option<String> {
        self.conn
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
            .optional()
            .ok()
            .flatten()
    }

    fn meta_set(&self, key: &str, value: &str) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn account_meta(&self) -> Option<AccountMeta> {
        self.meta_get("account")
            .and_then(|s| serde_json::from_str(&s).ok())
    }

    pub fn set_account_meta(&self, meta: &AccountMeta) -> Result<(), StoreError> {
        let json = serde_json::to_string(meta).map_err(|e| StoreError::Corrupt(e.to_string()))?;
        self.meta_set("account", &json)
    }

    /// The refresh token, encrypted under the vault key (an attacker with
    /// the database file but no master password cannot resume the session).
    pub fn encrypted_refresh_token(&self) -> Option<EncryptedItem> {
        self.meta_get("refresh_token")
            .and_then(|s| serde_json::from_str(&s).ok())
    }

    pub fn set_encrypted_refresh_token(
        &self,
        token: Option<&EncryptedItem>,
    ) -> Result<(), StoreError> {
        match token {
            Some(t) => {
                let json =
                    serde_json::to_string(t).map_err(|e| StoreError::Corrupt(e.to_string()))?;
                self.meta_set("refresh_token", &json)
            }
            None => {
                self.conn
                    .execute("DELETE FROM meta WHERE key = 'refresh_token'", [])?;
                Ok(())
            }
        }
    }

    fn row_to_stored(
        item_id: String,
        revision: i64,
        deleted: i64,
        content: Option<String>,
    ) -> StoredItem {
        StoredItem {
            item_id,
            revision,
            deleted: deleted != 0,
            content: content.and_then(|c| serde_json::from_str(&c).ok()),
        }
    }
}

impl LocalVault for SqliteVault {
    fn last_seq(&self) -> i64 {
        self.meta_get("last_seq")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }

    fn set_last_seq(&mut self, seq: i64) {
        let _ = self.meta_set("last_seq", &seq.to_string());
    }

    fn get(&self, item_id: &str) -> Option<StoredItem> {
        self.conn
            .query_row(
                "SELECT item_id, revision, deleted, content FROM items WHERE item_id = ?1",
                [item_id],
                |r| {
                    Ok(Self::row_to_stored(
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                    ))
                },
            )
            .optional()
            .ok()
            .flatten()
    }

    fn list(&self) -> Vec<StoredItem> {
        let mut stmt = match self
            .conn
            .prepare("SELECT item_id, revision, deleted, content FROM items ORDER BY item_id")
        {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map([], |r| {
            Ok(Self::row_to_stored(
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
            ))
        });
        match rows {
            Ok(rows) => rows.flatten().collect(),
            Err(_) => Vec::new(),
        }
    }

    fn apply_remote(&mut self, item: &RemoteItem) {
        let content = item
            .content
            .as_ref()
            .and_then(|c| serde_json::to_string(c).ok());
        let _ = self.conn.execute(
            "INSERT INTO items (item_id, revision, deleted, content)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(item_id) DO UPDATE SET
               revision = excluded.revision, deleted = excluded.deleted,
               content = excluded.content",
            params![item.item_id, item.revision, item.deleted as i64, content],
        );
    }

    fn clear_items(&mut self) {
        let _ = self.conn.execute("DELETE FROM items", []);
    }

    fn stage(&mut self, op: PendingOp) {
        // Mirror the op into the replica so the UI shows the change
        // immediately, then persist it in the queue — atomically.
        let tx = match self.conn.transaction() {
            Ok(tx) => tx,
            Err(_) => return,
        };
        let ok = (|| -> Result<(), rusqlite::Error> {
            match &op {
                PendingOp::Upsert(envelope) => {
                    let content = serde_json::to_string(envelope).unwrap_or_default();
                    tx.execute(
                        "INSERT INTO items (item_id, revision, deleted, content)
                         VALUES (?1, ?2, 0, ?3)
                         ON CONFLICT(item_id) DO UPDATE SET
                           revision = excluded.revision, deleted = 0,
                           content = excluded.content",
                        params![envelope.item_id, envelope.revision as i64, content],
                    )?;
                }
                PendingOp::Delete {
                    item_id,
                    base_revision,
                } => {
                    tx.execute(
                        "INSERT INTO items (item_id, revision, deleted, content)
                         VALUES (?1, ?2, 1, NULL)
                         ON CONFLICT(item_id) DO UPDATE SET
                           revision = ?2, deleted = 1, content = NULL",
                        params![item_id, base_revision + 1],
                    )?;
                }
            }
            let op_json = serde_json::to_string(&op).unwrap_or_default();
            tx.execute("INSERT INTO ops (op) VALUES (?1)", [op_json])?;
            Ok(())
        })();
        if ok.is_ok() {
            let _ = tx.commit();
        }
    }

    fn pending_ops(&self) -> Vec<PendingOp> {
        let mut stmt = match self.conn.prepare("SELECT op FROM ops ORDER BY id") {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map([], |r| r.get::<_, String>(0));
        match rows {
            Ok(rows) => rows
                .flatten()
                .filter_map(|s| serde_json::from_str(&s).ok())
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    fn pop_front_op(&mut self) {
        let _ = self
            .conn
            .execute("DELETE FROM ops WHERE id = (SELECT MIN(id) FROM ops)", []);
    }
}
