use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{AeadCore, KeyInit, XChaCha20Poly1305, XNonce};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use crate::error::CryptoError;
use crate::keys::VaultKey;

const NONCE_LEN: usize = 24;
const AAD_CONTEXT: &[u8] = b"basementen-vault/v1/item";

/// A single encrypted vault item as stored locally and synced to the server.
///
/// Each item is encrypted independently under the Vault Key with a fresh
/// random 192-bit nonce. The item ID and revision are bound as associated
/// data, so the server (or an attacker with database access) cannot swap
/// ciphertexts between items or roll an item back to an older revision
/// without detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedItem {
    pub version: u16,
    /// Stable item identifier (UUIDv7 in the sync layer).
    pub item_id: String,
    /// Monotonically increasing per-item revision, managed by the sync layer.
    pub revision: u64,
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

fn aad_for(version: u16, item_id: &str, revision: u64) -> Vec<u8> {
    // Bind the record version (crypto-agility: a v2 item can never be passed
    // off as v1) plus the item ID and revision. Length-prefix the
    // variable-length field so (id="a", rev bytes) can never collide with a
    // different (id, rev) pair.
    let id = item_id.as_bytes();
    let mut aad = Vec::with_capacity(AAD_CONTEXT.len() + 2 + 8 + id.len() + 8);
    aad.extend_from_slice(AAD_CONTEXT);
    aad.extend_from_slice(&version.to_le_bytes());
    aad.extend_from_slice(&(id.len() as u64).to_le_bytes());
    aad.extend_from_slice(id);
    aad.extend_from_slice(&revision.to_le_bytes());
    aad
}

const ITEM_VERSION: u16 = 1;

impl VaultKey {
    /// Encrypt one vault item's serialized plaintext.
    pub fn encrypt_item(
        &self,
        item_id: &str,
        revision: u64,
        plaintext: &[u8],
    ) -> Result<EncryptedItem, CryptoError> {
        let cipher = XChaCha20Poly1305::new(self.as_bytes().into());
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad_for(ITEM_VERSION, item_id, revision),
                },
            )
            .map_err(|_| CryptoError::Encrypt)?;
        Ok(EncryptedItem {
            version: ITEM_VERSION,
            item_id: item_id.to_owned(),
            revision,
            nonce: nonce.into(),
            ciphertext,
        })
    }

    /// Decrypt one vault item. Fails if the key is wrong, the ciphertext was
    /// tampered with, or the item ID / revision don't match what was bound
    /// at encryption time.
    pub fn decrypt_item(&self, item: &EncryptedItem) -> Result<Vec<u8>, CryptoError> {
        if item.version != 1 {
            return Err(CryptoError::UnsupportedVersion(item.version));
        }
        let cipher = XChaCha20Poly1305::new(self.as_bytes().into());
        let nonce = XNonce::from(item.nonce);
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: item.ciphertext.as_slice(),
                    aad: &aad_for(item.version, &item.item_id, item.revision),
                },
            )
            .map_err(|_| CryptoError::Decrypt)
    }
}
