//! Encrypted vault export: a portable, self-contained backup file that can
//! be restored without the server (and without the account's master
//! password — it has its own passphrase).
//!
//! Format: JSON envelope carrying versioned Argon2id parameters, a random
//! salt (unlike login KDF, there is no e-mail to derive from — and exports
//! must not be linkable to accounts), an XChaCha20-Poly1305 nonce, and the
//! ciphertext of whatever payload the caller serialized.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{AeadCore, KeyInit, XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::kdf::KdfParams;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const AAD: &[u8] = b"basementen-vault/v1/export";

#[derive(Debug, Serialize, Deserialize)]
pub struct ExportEnvelope {
    /// Format marker so other tools can recognize the file.
    pub format: String,
    pub version: u16,
    pub kdf_params: KdfParams,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

fn derive_export_key(
    passphrase: &str,
    salt: &[u8; SALT_LEN],
    params: &KdfParams,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    params.validate()?;
    let argon_params = argon2::Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|e| CryptoError::InvalidKdfParams(e.to_string()))?;
    let argon = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon_params,
    );
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase.as_bytes(), salt, out.as_mut())
        .map_err(|_| CryptoError::KeyDerivation)?;
    Ok(out)
}

/// Encrypt an export payload under a passphrase.
pub fn encrypt_export(plaintext: &[u8], passphrase: &str) -> Result<ExportEnvelope, CryptoError> {
    let params = KdfParams::desktop();
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let key = derive_export_key(passphrase, &salt, &params)?;

    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: AAD,
            },
        )
        .map_err(|_| CryptoError::Encrypt)?;

    Ok(ExportEnvelope {
        format: "basementen-vault-export".into(),
        version: 1,
        kdf_params: params,
        salt,
        nonce: nonce.into(),
        ciphertext,
    })
}

/// Decrypt an export file. Fails on a wrong passphrase or any tampering.
pub fn decrypt_export(
    envelope: &ExportEnvelope,
    passphrase: &str,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if envelope.version != 1 {
        return Err(CryptoError::UnsupportedVersion(envelope.version));
    }
    let key = derive_export_key(passphrase, &envelope.salt, &envelope.kdf_params)?;
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    let plaintext = cipher
        .decrypt(
            &XNonce::from(envelope.nonce),
            Payload {
                msg: envelope.ciphertext.as_slice(),
                aad: AAD,
            },
        )
        .map_err(|_| CryptoError::Decrypt)?;
    Ok(Zeroizing::new(plaintext))
}
