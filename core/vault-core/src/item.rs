use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{AeadCore, KeyInit, XChaCha20Poly1305, XNonce};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::keys::VaultKey;

const NONCE_LEN: usize = 24;
const AAD_CONTEXT: &[u8] = b"basementen-vault/v1/item";

/// Padding block for v2 items. Plaintext is padded to a multiple of this so
/// the ciphertext length reveals only which bucket the item falls in, not its
/// exact size (metadata hardening; see `docs/METADATA.md`). 256 bytes collapses
/// every ordinary login/card into a single length while bounding overhead to
/// under one block.
const PAD_BLOCK: usize = 256;
/// Bytes of little-endian length prefix in the padded plaintext.
const LEN_PREFIX: usize = 4;

/// Wrap plaintext in the v2 padded layout: `u32-LE real length ‖ plaintext ‖
/// zero padding` rounded up to the next [`PAD_BLOCK`] multiple (at least one
/// block). Returned in a `Zeroizing` buffer — it is plaintext.
fn pad_plaintext(plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if plaintext.len() > u32::MAX as usize {
        return Err(CryptoError::Malformed("item plaintext too large".into()));
    }
    let padded_len = (LEN_PREFIX + plaintext.len()).next_multiple_of(PAD_BLOCK);
    let mut buf = Zeroizing::new(Vec::with_capacity(padded_len));
    buf.extend_from_slice(&(plaintext.len() as u32).to_le_bytes());
    buf.extend_from_slice(plaintext);
    buf.resize(padded_len, 0);
    Ok(buf)
}

/// Reverse [`pad_plaintext`]: read the length prefix and return exactly that
/// many bytes, rejecting a length that overruns the buffer.
fn unpad_plaintext(padded: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if padded.len() < LEN_PREFIX {
        return Err(CryptoError::Malformed(
            "padded item shorter than prefix".into(),
        ));
    }
    let real_len = u32::from_le_bytes(padded[..LEN_PREFIX].try_into().expect("4 bytes")) as usize;
    let end = LEN_PREFIX
        .checked_add(real_len)
        .filter(|&e| e <= padded.len())
        .ok_or_else(|| CryptoError::Malformed("padded length overruns buffer".into()))?;
    Ok(Zeroizing::new(padded[LEN_PREFIX..end].to_vec()))
}

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

/// Current item format. v2 pads plaintext to a size bucket before encryption
/// (metadata hardening); v1 (unpadded) is still accepted on decrypt so
/// pre-existing items remain readable and migrate lazily on their next write.
const ITEM_VERSION: u16 = 2;

impl VaultKey {
    /// Encrypt one vault item's serialized plaintext, padding it to a size
    /// bucket (v2) so the stored ciphertext length no longer approximates the
    /// content length.
    pub fn encrypt_item(
        &self,
        item_id: &str,
        revision: u64,
        plaintext: &[u8],
    ) -> Result<EncryptedItem, CryptoError> {
        let padded = pad_plaintext(plaintext)?;
        let cipher = XChaCha20Poly1305::new(self.as_bytes().into());
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &padded,
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
    /// at encryption time. Accepts both v1 (unpadded) and v2 (padded) records;
    /// the version is authenticated via the AAD (I12), so it can't be swapped.
    ///
    /// The plaintext is returned in a [`Zeroizing`] buffer so it is scrubbed
    /// from memory when the caller drops it (in-memory-plaintext hygiene; see
    /// `docs/THREAT_MODEL.md` §A6).
    pub fn decrypt_item(&self, item: &EncryptedItem) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        if !matches!(item.version, 1 | 2) {
            return Err(CryptoError::UnsupportedVersion(item.version));
        }
        let cipher = XChaCha20Poly1305::new(self.as_bytes().into());
        let nonce = XNonce::from(item.nonce);
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: item.ciphertext.as_slice(),
                        aad: &aad_for(item.version, &item.item_id, item.revision),
                    },
                )
                .map_err(|_| CryptoError::Decrypt)?,
        );
        match item.version {
            2 => unpad_plaintext(&plain),
            _ => Ok(plain), // v1: no padding layer
        }
    }

    /// Encrypt in the legacy v1 (unpadded) wire format. Test-only: production
    /// code always writes v2, but we must prove old records still decrypt.
    #[cfg(test)]
    fn encrypt_item_v1(&self, item_id: &str, revision: u64, plaintext: &[u8]) -> EncryptedItem {
        let cipher = XChaCha20Poly1305::new(self.as_bytes().into());
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad_for(1, item_id, revision),
                },
            )
            .expect("encrypt");
        EncryptedItem {
            version: 1,
            item_id: item_id.to_owned(),
            revision,
            nonce: nonce.into(),
            ciphertext,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::VaultKey;

    #[test]
    fn pad_roundtrip_and_bucketing() {
        for len in [0usize, 1, 10, 251, 252, 253, 300, 512, 1000] {
            let data = vec![0xabu8; len];
            let padded = pad_plaintext(&data).unwrap();
            assert_eq!(padded.len() % PAD_BLOCK, 0, "padded to a block multiple");
            assert!(padded.len() >= PAD_BLOCK, "at least one block");
            assert_eq!(
                unpad_plaintext(&padded).unwrap().as_slice(),
                data.as_slice()
            );
        }
    }

    #[test]
    fn unpad_rejects_overrun_length() {
        // A length prefix claiming more bytes than the buffer holds must error,
        // not panic or read out of bounds.
        let mut bad = vec![0u8; PAD_BLOCK];
        bad[..LEN_PREFIX].copy_from_slice(&(u32::MAX).to_le_bytes());
        assert!(unpad_plaintext(&bad).is_err());
    }

    #[test]
    fn v1_legacy_item_decrypts_and_v2_is_padded() {
        let vk = VaultKey::generate();
        let v1 = vk.encrypt_item_v1("legacy", 3, b"old secret");
        assert_eq!(v1.version, 1);
        // v1 ciphertext tracks plaintext length (the leak we're fixing).
        assert!(v1.ciphertext.len() < PAD_BLOCK);
        assert_eq!(vk.decrypt_item(&v1).unwrap().as_slice(), b"old secret");

        // v2 pads the same content up to a full bucket.
        let v2 = vk.encrypt_item("legacy", 3, b"old secret").unwrap();
        assert_eq!(v2.version, 2);
        assert!(v2.ciphertext.len() >= PAD_BLOCK);
        assert_eq!(vk.decrypt_item(&v2).unwrap().as_slice(), b"old secret");
    }
}
