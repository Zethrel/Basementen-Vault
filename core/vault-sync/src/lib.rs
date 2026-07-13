//! # vault-sync
//!
//! Offline-first sync engine for Basementen Vault clients.
//!
//! Design (see `docs/IMPLEMENTATION_PLAN.md` §6):
//!
//! - Every client keeps a full local replica of the (encrypted) vault and an
//!   **op queue** of local changes made while offline.
//! - Sync is pull-then-push against a per-account sequence number: pull all
//!   remote changes with `seq > last_seen`, merge, then replay queued local
//!   ops with optimistic revisions.
//! - Conflicts (a queued op built on a revision the server has moved past)
//!   resolve **server-wins**: the server state is kept, and the losing local
//!   payload is returned to the app in the [`SyncReport`] so nothing is
//!   silently destroyed — the app can offer it as a "conflicted copy".
//!
//! The engine is deliberately agnostic to both storage and transport:
//! [`LocalVault`] abstracts the on-device replica (apps provide SQLite;
//! [`MemoryVault`] ships for tests and prototyping) and [`SyncTransport`]
//! abstracts the HTTP layer, so the engine itself contains no I/O and the
//! protocol logic is testable end-to-end.

pub mod engine;
pub mod memory;
pub mod types;

pub use engine::{sync, SyncEngineError};
pub use memory::MemoryVault;
pub use types::{
    Conflict, LocalVault, PendingOp, PullResponse, PushOutcome, RemoteItem, StoredItem, SyncReport,
    SyncTransport, TransportError,
};
