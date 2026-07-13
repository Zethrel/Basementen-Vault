use serde::{Deserialize, Serialize};
use vault_core::EncryptedItem;

/// One item as the server reports it (mirrors the server's wire format).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteItem {
    pub item_id: String,
    pub revision: i64,
    pub seq: i64,
    pub deleted: bool,
    pub content: Option<EncryptedItem>,
}

/// Response to a delta pull.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullResponse {
    pub items: Vec<RemoteItem>,
    pub latest_seq: i64,
    /// True when the client was behind the tombstone purge horizon and the
    /// response is the full current state instead of a delta.
    pub full_resync: bool,
}

/// A local change waiting to reach the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PendingOp {
    /// Create or update. The envelope's `revision` is base revision + 1.
    Upsert(EncryptedItem),
    /// Tombstone the item as seen at `base_revision`.
    Delete { item_id: String, base_revision: i64 },
}

impl PendingOp {
    pub fn item_id(&self) -> &str {
        match self {
            PendingOp::Upsert(item) => &item.item_id,
            PendingOp::Delete { item_id, .. } => item_id,
        }
    }
}

/// Result of pushing one op.
#[derive(Debug, Clone)]
pub enum PushOutcome {
    Accepted {
        revision: i64,
        seq: i64,
    },
    /// Optimistic check failed; `current` is the server's present state
    /// (None if the item never existed server-side).
    Conflict {
        current: Option<RemoteItem>,
    },
}

/// A local change that lost against newer server state during sync.
#[derive(Debug, Clone)]
pub struct Conflict {
    pub item_id: String,
    /// The op that could not be applied — hand its payload to the user as a
    /// "conflicted copy" rather than dropping it on the floor.
    pub losing_op: PendingOp,
    /// What the server holds instead (None: item purged/never existed).
    pub server_state: Option<RemoteItem>,
}

/// Outcome of one sync run.
#[derive(Debug, Default)]
pub struct SyncReport {
    pub pulled: usize,
    pub pushed: usize,
    pub conflicts: Vec<Conflict>,
    pub did_full_resync: bool,
}

/// Errors a transport can produce.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// Network unreachable, timeout, etc. Sync aborts and retries later;
    /// queued ops stay queued.
    #[error("network error: {0}")]
    Network(String),
    /// Server said no in a way that retrying won't fix (auth expired, bad
    /// request). The app must intervene (e.g. refresh the session).
    #[error("request rejected: {0}")]
    Rejected(String),
}

/// Transport abstraction over the server's sync API. Implementations wrap
/// whatever HTTP client the platform uses.
pub trait SyncTransport {
    fn pull(
        &mut self,
        since: i64,
    ) -> impl std::future::Future<Output = Result<PullResponse, TransportError>> + Send;

    fn push_upsert(
        &mut self,
        item: &EncryptedItem,
    ) -> impl std::future::Future<Output = Result<PushOutcome, TransportError>> + Send;

    fn push_delete(
        &mut self,
        item_id: &str,
        base_revision: i64,
    ) -> impl std::future::Future<Output = Result<PushOutcome, TransportError>> + Send;
}

/// One item in the local replica.
#[derive(Debug, Clone)]
pub struct StoredItem {
    pub item_id: String,
    pub revision: i64,
    pub deleted: bool,
    pub content: Option<EncryptedItem>,
}

/// The on-device replica: encrypted items, the op queue, and the sync cursor.
/// Implementations must persist all three atomically where possible.
pub trait LocalVault {
    /// Highest server seq this replica has fully applied.
    fn last_seq(&self) -> i64;
    fn set_last_seq(&mut self, seq: i64);

    fn get(&self, item_id: &str) -> Option<StoredItem>;
    fn list(&self) -> Vec<StoredItem>;

    /// Apply a remote change verbatim (server is authoritative).
    fn apply_remote(&mut self, item: &RemoteItem);
    /// Drop everything and start over (full resync).
    fn clear_items(&mut self);

    /// Record a local edit: update the replica AND enqueue the op.
    fn stage(&mut self, op: PendingOp);
    fn pending_ops(&self) -> Vec<PendingOp>;
    /// Remove the queue's front op (after it was pushed or lost a conflict).
    fn pop_front_op(&mut self);
}
