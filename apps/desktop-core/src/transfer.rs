//! Vault export/import: encrypted backups and CSV migration from other
//! password managers.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::items::Item;

#[derive(Debug, thiserror::Error)]
pub enum TransferError {
    #[error("wrong passphrase or corrupted file")]
    Decrypt,
    #[error("not a Basementen Vault export file")]
    BadFormat,
    #[error("CSV error: {0}")]
    Csv(String),
    #[error("{0}")]
    Other(String),
}

/// What goes inside the encrypted envelope.
#[derive(Serialize, Deserialize)]
struct ExportPayload {
    exported_at_unix: i64,
    items: Vec<Item>,
}

/// Serialize and encrypt all items under an export passphrase.
/// Returns the JSON file contents.
pub fn export_encrypted(items: &[Item], passphrase: &str) -> Result<String, TransferError> {
    let payload = ExportPayload {
        exported_at_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        items: items.to_vec(),
    };
    let plaintext = Zeroizing::new(
        serde_json::to_vec(&payload).map_err(|e| TransferError::Other(e.to_string()))?,
    );
    let envelope = vault_core::encrypt_export(&plaintext, passphrase)
        .map_err(|e| TransferError::Other(e.to_string()))?;
    serde_json::to_string_pretty(&envelope).map_err(|e| TransferError::Other(e.to_string()))
}

/// Decrypt an encrypted export file back into items.
pub fn import_encrypted(file_contents: &str, passphrase: &str) -> Result<Vec<Item>, TransferError> {
    let envelope: vault_core::ExportEnvelope =
        serde_json::from_str(file_contents).map_err(|_| TransferError::BadFormat)?;
    if envelope.format != "basementen-vault-export" {
        return Err(TransferError::BadFormat);
    }
    let plaintext =
        vault_core::decrypt_export(&envelope, passphrase).map_err(|_| TransferError::Decrypt)?;
    let payload: ExportPayload =
        serde_json::from_slice(&plaintext).map_err(|_| TransferError::BadFormat)?;
    Ok(payload.items)
}

/// Import logins from a CSV file exported by another password manager.
///
/// Column mapping is by header name, case-insensitive, accepting both the
/// generic convention (`name,url,username,password,notes`) and Bitwarden's
/// (`login_uri,login_username,login_password`, `type` filtering to `login`).
pub fn import_csv(file_contents: &str) -> Result<Vec<Item>, TransferError> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(file_contents.as_bytes());

    let headers = reader
        .headers()
        .map_err(|e| TransferError::Csv(e.to_string()))?
        .clone();
    let find = |candidates: &[&str]| -> Option<usize> {
        headers.iter().position(|h| {
            let h = h.trim().to_lowercase();
            candidates.iter().any(|c| h == *c)
        })
    };

    let col_name = find(&["name", "title", "account"]);
    let col_url = find(&["url", "login_uri", "website", "web site", "uris"]);
    let col_user = find(&["username", "login_username", "user", "login name"]);
    let col_pass = find(&["password", "login_password", "pass"]);
    let col_notes = find(&["notes", "note", "comments", "extra"]);
    let col_type = find(&["type"]);

    if col_pass.is_none() && col_user.is_none() {
        return Err(TransferError::Csv(
            "no recognizable columns — expected headers like name,url,username,password,notes"
                .into(),
        ));
    }

    let get = |record: &csv::StringRecord, idx: Option<usize>| -> String {
        idx.and_then(|i| record.get(i))
            .unwrap_or("")
            .trim()
            .to_string()
    };

    let mut items = Vec::new();
    for record in reader.records() {
        let record = record.map_err(|e| TransferError::Csv(e.to_string()))?;
        // Bitwarden exports mix logins and notes; only take logins when a
        // type column exists.
        if let Some(t) = col_type {
            let kind = record.get(t).unwrap_or("").trim().to_lowercase();
            if !kind.is_empty() && kind != "login" {
                continue;
            }
        }
        let name = {
            let n = get(&record, col_name);
            if n.is_empty() {
                let u = get(&record, col_url);
                if u.is_empty() {
                    "Imported login".to_string()
                } else {
                    u
                }
            } else {
                n
            }
        };
        items.push(Item::Login {
            name,
            username: get(&record, col_user),
            password: get(&record, col_pass),
            url: get(&record, col_url),
            notes: get(&record, col_notes),
            tags: vec!["imported".into()],
        });
    }
    Ok(items)
}
