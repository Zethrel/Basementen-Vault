//! # desktop-core
//!
//! Everything the desktop app does except pixels: the SQLite-backed local
//! replica, the HTTP API client, session/auto-lock management, the item
//! schema, and the password generator. The Tauri shell is a thin command
//! layer over this crate, which keeps all behaviour testable headlessly.

pub mod api;
pub mod generator;
pub mod items;
pub mod session;
pub mod store;
pub mod transfer;

pub use api::{ApiClient, ApiError, LoginOutcome, PreloginInfo, RecoveryData, SessionInfo};
pub use generator::{generate_password, GeneratorOptions};
pub use items::{Item, ItemSummary};
pub use session::AutoLock;
pub use store::SqliteVault;
pub use transfer::{export_encrypted, import_csv, import_encrypted, TransferError};
