use chacha20poly1305::aead::Generate;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

use serde::{Deserialize, Serialize};

use crate::error::CryptoError;
use crate::keys::{RecoveryKey, VaultKey, WrappingKey, KEY_LEN};

const NONCE_LEN: usize = 24;

/// What a wrapped key blob protects and which key class wraps it. Bound into
/// the AEAD as associated data so a recovery-wrapped blob can never be passed
/// off as a master-wrapped one (or vice versa).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WrapPurpose {
    /// Vault Key wrapped by the master-password-derived WrappingKey.
    MasterWrap,
    /// Vault Key wrapped by the Recovery Kit's RecoveryKey.
    RecoveryWrap,
}

impl WrapPurpose {
    fn aad(self) -> &'static [u8] {
        match self {
            WrapPurpose::MasterWrap => b"basementen-vault/v1/wrap/master",
            WrapPurpose::RecoveryWrap => b"basementen-vault/v1/wrap/recovery",
        }
    }
}

/// An encrypted copy of the Vault Key, safe to store on the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedKey {
    pub version: u16,
    pub purpose: WrapPurpose,
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

const WRAP_VERSION: u16 = 1;

/// Bind the wrap version + purpose into the AEAD associated data, so a blob
/// can be confused across neither purpose nor future format versions.
fn wrap_aad(version: u16, purpose: WrapPurpose) -> Vec<u8> {
    let mut aad = Vec::with_capacity(purpose.aad().len() + 2);
    aad.extend_from_slice(purpose.aad());
    aad.extend_from_slice(&version.to_le_bytes());
    aad
}

fn wrap(key_bytes: &[u8; KEY_LEN], vk: &VaultKey, purpose: WrapPurpose) -> WrappedKey {
    let cipher = XChaCha20Poly1305::new_from_slice(key_bytes).expect("key is KEY_LEN bytes");
    let nonce = XNonce::generate();
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: vk.as_bytes(),
                aad: &wrap_aad(WRAP_VERSION, purpose),
            },
        )
        .expect("XChaCha20-Poly1305 encryption of 32 bytes cannot fail");
    WrappedKey {
        version: WRAP_VERSION,
        purpose,
        nonce: nonce.into(),
        ciphertext,
    }
}

fn unwrap(
    key_bytes: &[u8; KEY_LEN],
    wrapped: &WrappedKey,
    expected: WrapPurpose,
) -> Result<VaultKey, CryptoError> {
    if wrapped.version != 1 {
        return Err(CryptoError::UnsupportedVersion(wrapped.version));
    }
    if wrapped.purpose != expected {
        return Err(CryptoError::Malformed("wrap purpose mismatch".into()));
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key_bytes).expect("key is KEY_LEN bytes");
    let nonce = XNonce::from(wrapped.nonce);
    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: wrapped.ciphertext.as_slice(),
                aad: &wrap_aad(wrapped.version, expected),
            },
        )
        .map_err(|_| CryptoError::Decrypt)?;
    let bytes: [u8; KEY_LEN] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::Decrypt)?;
    Ok(VaultKey::from_bytes(bytes))
}

impl WrappingKey {
    pub fn wrap_vault_key(&self, vk: &VaultKey) -> WrappedKey {
        wrap(self.as_bytes(), vk, WrapPurpose::MasterWrap)
    }

    pub fn unwrap_vault_key(&self, wrapped: &WrappedKey) -> Result<VaultKey, CryptoError> {
        unwrap(self.as_bytes(), wrapped, WrapPurpose::MasterWrap)
    }
}

impl RecoveryKey {
    pub fn wrap_vault_key(&self, vk: &VaultKey) -> WrappedKey {
        wrap(self.as_bytes(), vk, WrapPurpose::RecoveryWrap)
    }

    pub fn unwrap_vault_key(&self, wrapped: &WrappedKey) -> Result<VaultKey, CryptoError> {
        unwrap(self.as_bytes(), wrapped, WrapPurpose::RecoveryWrap)
    }
}
