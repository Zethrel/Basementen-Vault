use chacha20poly1305::aead::Generate;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::keys::VaultKey;

const NONCE_LEN: usize = 24;
const AAD_CONTEXT: &[u8] = b"basementen-vault/v1/item";

/// Minimum padding block for v2 items, and the single bucket every small item
/// collapses into. 256 bytes hides every ordinary login/card behind one length
/// while bounding small-item overhead to under one block (metadata hardening;
/// see `docs/METADATA.md`).
const PAD_BLOCK: usize = 256;
/// Bytes of little-endian length prefix in the padded plaintext.
const LEN_PREFIX: usize = 4;

/// Padded length for a `total`-byte (prefix + plaintext) buffer under a
/// **graduated** bucket schedule: small items collapse to a single
/// [`PAD_BLOCK`] bucket, while larger items round up to a block that grows with
/// their magnitude — `2^(⌊log2 total⌋ − 4)`, floored at [`PAD_BLOCK`].
///
/// This tightens the residual metadata leak the old fixed-256 scheme left on
/// large items (`docs/THREAT_MODEL.md` — item-size metadata): the number of
/// distinct observable lengths now grows only ~logarithmically with size (a
/// long note reveals its size only to a coarse power-of-two block, not to
/// 256 bytes), while padding overhead stays ≤ ~1/16 above the small-item floor.
/// Every block is a power-of-two multiple of [`PAD_BLOCK`], so small/mid items
/// bucket exactly as before — no regression, and (crucially) decrypt reads only
/// the length prefix and ignores padding, so this schedule can change with no
/// format-version bump and old fixed-256 v2 records still decrypt.
fn bucketed_len(total: usize) -> usize {
    let block = if total <= PAD_BLOCK {
        PAD_BLOCK
    } else {
        let msb = (usize::BITS - 1 - total.leading_zeros()) as usize; // ⌊log2 total⌋
        PAD_BLOCK.max(1usize << msb.saturating_sub(4))
    };
    total.next_multiple_of(block)
}

/// Wrap plaintext in the v2 padded layout: `u32-LE real length ‖ plaintext ‖
/// zero padding`, sized by [`bucketed_len`]. Returned in a `Zeroizing` buffer —
/// it is plaintext.
fn pad_plaintext(plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if plaintext.len() > u32::MAX as usize {
        return Err(CryptoError::Malformed("item plaintext too large".into()));
    }
    let padded_len = bucketed_len(LEN_PREFIX + plaintext.len());
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
        let cipher =
            XChaCha20Poly1305::new_from_slice(self.as_bytes()).expect("key is KEY_LEN bytes");
        let nonce = XNonce::generate();
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
        let cipher =
            XChaCha20Poly1305::new_from_slice(self.as_bytes()).expect("key is KEY_LEN bytes");
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
        let cipher =
            XChaCha20Poly1305::new_from_slice(self.as_bytes()).expect("key is KEY_LEN bytes");
        let nonce = XNonce::generate();
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
    fn graduated_bucketing_properties() {
        // Small items all collapse to the single 256 bucket (no size signal).
        for total in [1usize, 100, 200, 256] {
            assert_eq!(bucketed_len(total), 256);
        }
        // Mid items bucket exactly as the old fixed-256 scheme did (no regression).
        assert_eq!(bucketed_len(257), 512);
        assert_eq!(bucketed_len(300), 512);
        assert_eq!(bucketed_len(1000), 1024);
        assert_eq!(bucketed_len(4096), 4096);

        // Every bucket is a multiple of 256, is ≥ the input (plaintext fits),
        // never shrinks as the item grows, and adds ≤ ~1/16 overhead on large
        // items (a long note reveals its size only coarsely).
        let mut prev = 0;
        for total in (256..200_000).step_by(97) {
            let b = bucketed_len(total);
            assert!(b >= total, "bucket must fit the plaintext");
            assert_eq!(b % PAD_BLOCK, 0, "bucket is a 256 multiple");
            assert!(b >= prev, "bucketing must be monotonic");
            prev = b;
            // Overhead bound: block ≤ total/16 above the floor, so padded is
            // within one block; comfortably under 2x and ~6% for large sizes.
            assert!(b <= total + total / 16 + PAD_BLOCK);
        }

        // Large items get coarse (power-of-two) blocks, not 256-byte precision.
        assert_eq!(bucketed_len(50_000), 51_200); // block 2048 → multiple of 2048
        assert_eq!(bucketed_len(50_000) % 2048, 0);
    }

    #[test]
    fn large_item_padding_roundtrips() {
        for len in [4096usize, 10_000, 50_000, 131_072] {
            let data = vec![0x5au8; len];
            let padded = pad_plaintext(&data).unwrap();
            assert!(padded.len() >= LEN_PREFIX + len);
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
