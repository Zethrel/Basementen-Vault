use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{AeadCore, KeyInit, XChaCha20Poly1305, XNonce};
use rand_core::OsRng;
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

fn wrap(key_bytes: &[u8; KEY_LEN], vk: &VaultKey, purpose: WrapPurpose) -> WrappedKey {
    let cipher = XChaCha20Poly1305::new(key_bytes.into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: vk.as_bytes(),
                aad: purpose.aad(),
            },
        )
        .expect("XChaCha20-Poly1305 encryption of 32 bytes cannot fail");
    WrappedKey {
        version: 1,
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
    let cipher = XChaCha20Poly1305::new(key_bytes.into());
    let nonce = XNonce::from(wrapped.nonce);
    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: wrapped.ciphertext.as_slice(),
                aad: expected.aad(),
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
