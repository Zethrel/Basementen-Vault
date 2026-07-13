//! The sync algorithm: pull → merge → push, server-wins on conflict.

use crate::types::{
    Conflict, LocalVault, PendingOp, PushOutcome, SyncReport, SyncTransport, TransportError,
};

#[derive(Debug, thiserror::Error)]
pub enum SyncEngineError {
    #[error(transparent)]
    Transport(#[from] TransportError),
}

/// Run one full sync cycle.
///
/// 1. **Pull** every remote change since the local cursor and apply it to
///    the replica — except items that have queued local ops, which are
///    settled during push so local edits aren't clobbered before they get
///    their chance to win.
/// 2. **Push** the op queue in order. Accepted ops update the replica's
///    revision; rejected ops mean the server moved first — the server state
///    is applied and the losing payload is preserved in the report.
/// 3. Advance the cursor only after both phases succeed, so an interrupted
///    sync simply re-runs (every step is idempotent).
pub async fn sync<V: LocalVault, T: SyncTransport>(
    vault: &mut V,
    transport: &mut T,
) -> Result<SyncReport, SyncEngineError> {
    let mut report = SyncReport::default();

    // --- Pull ---------------------------------------------------------
    let pull = transport.pull(vault.last_seq()).await?;
    if pull.full_resync {
        // Replica may contain items whose deletion we never heard about.
        // Rebuild from the snapshot — but keep the op queue: local edits
        // still deserve their push (they'll conflict naturally if stale).
        vault.clear_items();
        report.did_full_resync = true;
    }

    let dirty: std::collections::HashSet<String> = vault
        .pending_ops()
        .iter()
        .map(|op| op.item_id().to_string())
        .collect();

    for item in &pull.items {
        if dirty.contains(&item.item_id) {
            continue; // settled during push
        }
        vault.apply_remote(item);
        report.pulled += 1;
    }

    // --- Push ---------------------------------------------------------
    // Ops are pushed strictly in order; each op is popped only after the
    // server has answered (accepted or conflicted), so a crash mid-push
    // never loses an op — the survivor re-pushes and hits idempotent
    // revision checks.
    while let Some(op) = vault.pending_ops().first().cloned() {
        let outcome = match &op {
            PendingOp::Upsert(envelope) => transport.push_upsert(envelope).await?,
            PendingOp::Delete {
                item_id,
                base_revision,
            } => transport.push_delete(item_id, *base_revision).await?,
        };

        match outcome {
            PushOutcome::Accepted { revision, seq } => {
                report.pushed += 1;
                // Reflect the server-assigned revision/seq locally.
                if let Some(mut stored) = vault.get(op.item_id()) {
                    stored.revision = revision;
                    vault.apply_remote(&crate::types::RemoteItem {
                        item_id: stored.item_id.clone(),
                        revision,
                        seq,
                        deleted: stored.deleted,
                        content: stored.content.clone(),
                    });
                }
            }
            PushOutcome::Conflict { current } => {
                // Server wins: adopt its state, surface the losing local op.
                match &current {
                    Some(remote) => vault.apply_remote(remote),
                    None => {
                        // Item is gone server-side (purged tombstone).
                        if let Some(stored) = vault.get(op.item_id()) {
                            vault.apply_remote(&crate::types::RemoteItem {
                                item_id: stored.item_id.clone(),
                                revision: stored.revision,
                                seq: vault.last_seq(),
                                deleted: true,
                                content: None,
                            });
                        }
                    }
                }
                report.conflicts.push(Conflict {
                    item_id: op.item_id().to_string(),
                    losing_op: op.clone(),
                    server_state: current,
                });
            }
        }
        vault.pop_front_op();
    }

    // --- Cursor -------------------------------------------------------
    // Our own pushes advanced the server seq past pull.latest_seq; a final
    // cheap pull picks up the authoritative cursor (and anything a second
    // device wrote mid-sync).
    let tail = transport.pull(pull.latest_seq).await?;
    if !tail.full_resync {
        for item in &tail.items {
            vault.apply_remote(item);
        }
        vault.set_last_seq(tail.latest_seq);
    } else {
        vault.set_last_seq(pull.latest_seq);
    }

    Ok(report)
}
