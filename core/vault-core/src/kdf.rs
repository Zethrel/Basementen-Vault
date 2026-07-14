use argon2::{Algorithm, Argon2, Params, Version};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::keys::{MasterKey, KEY_LEN};

/// OWASP Password Storage Cheat Sheet floor for Argon2id.
/// The server must also enforce this; clients never negotiate below it.
pub const MIN_MEMORY_KIB: u32 = 19 * 1024;
pub const MIN_ITERATIONS: u32 = 2;
pub const MIN_PARALLELISM: u32 = 1;

/// Length of the per-account KDF salt (128 bits).
pub const SALT_LEN: usize = 16;

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

/// Normalize an e-mail address for use as the account *identifier*.
///
/// Trim ASCII whitespace and lowercase. Since v2 of the KDF design the e-mail
/// no longer participates in key derivation (the salt is random, [`generate_salt`]),
/// so this normalization is no longer security-critical for key agreement — it
/// only affects account lookup/dedup on the server. A user could even change
/// their e-mail without touching their keys.
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// Generate a fresh random 128-bit per-account KDF salt from the OS CSPRNG.
///
/// Created once at registration and stored (server-side and cached locally),
/// then supplied to every derivation. A random salt is independent of user
/// identity: it removes cross-client e-mail-normalization fragility and lets
/// the account e-mail change freely. See `docs/CRYPTOGRAPHIC_INVARIANTS.md`.
pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Derive the Master Key from the master password and the account's stored
/// random salt using Argon2id with the account's stored parameters.
///
/// This is the single most expensive operation in the client by design; it
/// runs on unlock and login only. The `salt` is the per-account random value
/// from [`generate_salt`], fetched from the server (prelogin/login) or the
/// local cache before deriving.
pub fn derive_master_key(
    password: &str,
    salt: &[u8],
    params: &KdfParams,
) -> Result<MasterKey, CryptoError> {
    params.validate()?;
    if salt.len() < 8 {
        return Err(CryptoError::InvalidKdfParams("salt too short".into()));
    }

    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|e| CryptoError::InvalidKdfParams(e.to_string()))?;

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password.as_bytes(), salt, out.as_mut())
        .map_err(|_| CryptoError::KeyDerivation)?;

    Ok(MasterKey::from_bytes(*out))
}
