use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::keys::{MasterKey, KEY_LEN};

/// OWASP Password Storage Cheat Sheet floor for Argon2id.
/// The server must also enforce this; clients never negotiate below it.
pub const MIN_MEMORY_KIB: u32 = 19 * 1024;
pub const MIN_ITERATIONS: u32 = 2;
pub const MIN_PARALLELISM: u32 = 1;

const SALT_LEN: usize = 16;
const INFO_KDF_SALT: &[u8] = b"basementen-vault/v1/kdf-salt";

/// Versioned Argon2id parameters, stored per-account so they can be raised
/// over time without breaking existing vaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Schema version of this parameter block. Currently always 1.
    pub version: u16,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl KdfParams {
    /// Recommended parameters for desktop-class hardware.
    pub fn desktop() -> Self {
        Self {
            version: 1,
            memory_kib: 64 * 1024,
            iterations: 3,
            parallelism: 4,
        }
    }

    /// Minimum acceptable parameters (OWASP floor) for constrained mobile
    /// devices. Never go below this.
    pub fn mobile_floor() -> Self {
        Self {
            version: 1,
            memory_kib: MIN_MEMORY_KIB,
            iterations: MIN_ITERATIONS,
            parallelism: MIN_PARALLELISM,
        }
    }

    pub fn validate(&self) -> Result<(), CryptoError> {
        if self.version != 1 {
            return Err(CryptoError::UnsupportedVersion(self.version));
        }
        if self.memory_kib < MIN_MEMORY_KIB
            || self.iterations < MIN_ITERATIONS
            || self.parallelism < MIN_PARALLELISM
        {
            return Err(CryptoError::InvalidKdfParams(format!(
                "below security floor (m>={MIN_MEMORY_KIB} KiB, t>={MIN_ITERATIONS}, p>={MIN_PARALLELISM})"
            )));
        }
        Ok(())
    }
}

/// Normalize an e-mail address for use as KDF salt input.
///
/// Trim ASCII whitespace and lowercase. Deliberately conservative: any change
/// to this normalization is a breaking change (users could no longer derive
/// their Master Key), so it must stay frozen for version 1.
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// Derive the deterministic per-account KDF salt from the normalized e-mail.
///
/// Deriving the salt from the e-mail lets the client compute its keys before
/// first contact with the server. It is not secret — its only job is to make
/// the Argon2id output account-specific so identical passwords on different
/// accounts produce unrelated keys.
fn email_salt(email: &str) -> [u8; SALT_LEN] {
    let normalized = normalize_email(email);
    let hk = Hkdf::<Sha256>::new(None, normalized.as_bytes());
    let mut salt = [0u8; SALT_LEN];
    hk.expand(INFO_KDF_SALT, &mut salt)
        .expect("16 bytes is a valid HKDF-SHA256 output length");
    salt
}

/// Derive the Master Key from the master password and account e-mail using
/// Argon2id with the account's stored parameters.
///
/// This is the single most expensive operation in the client by design; it
/// runs on unlock and login only.
pub fn derive_master_key(
    password: &str,
    email: &str,
    params: &KdfParams,
) -> Result<MasterKey, CryptoError> {
    params.validate()?;

    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|e| CryptoError::InvalidKdfParams(e.to_string()))?;

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let salt = email_salt(email);

    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password.as_bytes(), &salt, out.as_mut())
        .map_err(|_| CryptoError::KeyDerivation)?;

    Ok(MasterKey::from_bytes(*out))
}
