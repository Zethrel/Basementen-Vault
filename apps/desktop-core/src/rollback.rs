//! Rollback-protected sync: wraps the crypto-agnostic [`vault_sync`] engine
//! with vault-key-authenticated checkpoint verification.
//!
//! The [`vault_sync`] engine already refuses a pull whose global sequence
//! regressed below the device's durable high-water mark (per-device rollback
//! protection). This layer adds the cross-device / reinstall dimension: a
//! MAC'd checkpoint, stored server-side, that any device holding the Vault
//! Key can verify. See `docs/THREAT_MODEL.md` §A2.

use vault_core::VaultKey;
use vault_sync::{sync, LocalVault, SyncEngineError, SyncReport};

use crate::api::ApiClient;

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error(transparent)]
    Engine(#[from] SyncEngineError),
    #[error("sync transport error: {0}")]
    Api(String),
    /// The server presented a checkpoint whose tag does not verify under the
    /// Vault Key — it was forged or corrupted. Treat as server compromise.
    #[error("checkpoint failed authentication — the server may be compromised")]
    CheckpointForged,
    /// The server presented an authentic checkpoint for a sequence *higher*
    /// than the data it actually served: it is withholding committed writes.
    #[error("server is withholding data (checkpoint seq {checkpoint} > served {served})")]
    Withholding { checkpoint: i64, served: i64 },
}

/// Run one rollback-protected sync cycle.
pub async fn synchronize<V: LocalVault>(
    vault: &mut V,
    api: &mut ApiClient,
    vault_key: &VaultKey,
) -> Result<SyncReport, SyncError> {
    let floor = vault.last_seq();

    // 1. Verify any server-stored checkpoint *before* trusting a pull.
    let verified_checkpoint_seq = match api
        .get_checkpoint()
        .await
        .map_err(|e| SyncError::Api(e.to_string()))?
    {
        Some((seq, tag)) => {
            if !vault_key.verify_sync_checkpoint(seq, &tag) {
                return Err(SyncError::CheckpointForged);
            }
            // An authentic checkpoint below our durable floor is a rollback;
            // the engine also catches this via latest_seq, but failing here
            // gives a precise error before any network round-trips mutate state.
            if seq < floor {
                return Err(SyncError::Engine(SyncEngineError::RollbackDetected {
                    local_seq: floor,
                    server_seq: seq,
                }));
            }
            seq
        }
        None => 0,
    };

    // 2. Engine sync (its own monotonic latest_seq rollback guard runs here).
    let report = sync(vault, api).await?;

    // 3. Withholding check: the server must have served data at least up to
    //    the checkpoint it vouched for. After sync, last_seq == served latest.
    let served = vault.last_seq();
    if verified_checkpoint_seq > served {
        return Err(SyncError::Withholding {
            checkpoint: verified_checkpoint_seq,
            served,
        });
    }

    // 4. Publish an updated checkpoint for the new high-water mark, so other
    //    devices (and future reinstalls) inherit an authenticated floor.
    if served > verified_checkpoint_seq {
        let tag = vault_key.sync_checkpoint_tag(served);
        let _ = api.put_checkpoint(served, &tag).await; // best-effort
    }

    Ok(report)
}
