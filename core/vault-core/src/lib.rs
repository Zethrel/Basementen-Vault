//! # vault-core
//!
//! Zero-knowledge cryptographic core for Basementen Vault.
//!
//! Implements the key hierarchy described in `docs/IMPLEMENTATION_PLAN.md`:
//!
//! ```text
//! master password + email (salt input)
//!         │
//!         ▼  Argon2id (client-side, versioned params)
//!    Master Key (MK, 256-bit)
//!         │
//!         ├── HKDF(MK, "auth") → AuthKey     → sent to server for login
//!         └── HKDF(MK, "enc")  → WrappingKey → wraps the random Vault Key
//!                                                │
//!                                  Vault Key (VK, random 256-bit)
//!                                                │
//!                                                ▼
//!                                  per-item XChaCha20-Poly1305
//! ```
//!
//! Invariants enforced by this crate:
//!
//! - The master password and Master Key never leave this library unencrypted;
//!   all secret material is zeroized on drop.
//! - The AuthKey (sent to the server) and the WrappingKey (used for
//!   encryption) are derived through domain-separated HKDF invocations and
//!   are cryptographically independent.
//! - All ciphertexts are authenticated (AEAD); item ciphertexts additionally
//!   bind the item ID and revision as associated data so records cannot be
//!   swapped or replayed across items.
//! - KDF parameters are versioned and validated against the OWASP floor.

pub mod account;
pub mod envelope;
pub mod error;
pub mod export;
pub mod harden;
pub mod item;
pub mod kdf;
pub mod keys;
pub mod recovery;
mod secmem;

pub use account::{AccountSecrets, RegistrationBundle};
pub use envelope::WrappedKey;
pub use error::CryptoError;
pub use export::{decrypt_export, encrypt_export, ExportEnvelope};
pub use item::EncryptedItem;
pub use kdf::{generate_salt, KdfParams};
pub use keys::{AuthKey, MasterKey, RecoveryKey, VaultKey, WrappingKey};
