use argon2::{Algorithm, Argon2, Params, Version};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::keys::{MasterKey, KEY_LEN};

/// OWASP Password Storage Cheat Sheet floor for Argon2id.
/// The server must also enforce this; clients never negotiate below it.
pub const MIN_MEMORY_KIB: u32 = 19 * 1024;
pub const MIN_ITERATIONS: u32 = 2;
pub const MIN_PARALLELISM: u32 = 1;

/// Upper ceilings. Params travel *inside* untrusted data (an export file's
/// envelope, a prelogin response), and `validate()` gates every derivation, so
/// without a ceiling a crafted `KdfParams` could drive Argon2 into a
/// multi-gigabyte allocation or a multi-minute hash — a memory/CPU
/// denial-of-service on import or unlock. These bounds leave generous headroom
/// over any real configuration (desktop is 64 MiB / t=3 / p=4) while capping the
/// worst case at ~1 GiB and a bounded iteration/lane count.
pub const MAX_MEMORY_KIB: u32 = 1024 * 1024; // 1 GiB
pub const MAX_ITERATIONS: u32 = 64;
pub const MAX_PARALLELISM: u32 = 64;

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
        // Ceiling: params ride inside untrusted data, so reject values that would
        // turn a derivation into a memory/CPU denial-of-service.
        if self.memory_kib > MAX_MEMORY_KIB
            || self.iterations > MAX_ITERATIONS
            || self.parallelism > MAX_PARALLELISM
        {
            return Err(CryptoError::InvalidKdfParams(format!(
                "above safe ceiling (m<={MAX_MEMORY_KIB} KiB, t<={MAX_ITERATIONS}, p<={MAX_PARALLELISM})"
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
    getrandom::fill(&mut salt).expect("OS CSPRNG failure");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_recommended_and_floor_params() {
        assert!(KdfParams::desktop().validate().is_ok());
        assert!(KdfParams::mobile_floor().validate().is_ok());
    }

    #[test]
    fn rejects_params_below_the_floor() {
        let mut p = KdfParams::desktop();
        p.memory_kib = MIN_MEMORY_KIB - 1;
        assert!(p.validate().is_err());
    }

    #[test]
    fn rejects_params_above_the_ceiling() {
        // A crafted export/prelogin block must not be able to request a
        // multi-gigabyte / runaway Argon2 derivation (memory/CPU DoS).
        let mut p = KdfParams::desktop();
        p.memory_kib = MAX_MEMORY_KIB + 1;
        assert!(p.validate().is_err(), "over-large memory must be rejected");

        let mut p = KdfParams::desktop();
        p.iterations = MAX_ITERATIONS + 1;
        assert!(
            p.validate().is_err(),
            "over-large iterations must be rejected"
        );

        let mut p = KdfParams::desktop();
        p.parallelism = MAX_PARALLELISM + 1;
        assert!(
            p.validate().is_err(),
            "over-large parallelism must be rejected"
        );

        // The exact ceiling is still accepted.
        let p = KdfParams {
            version: 1,
            memory_kib: MAX_MEMORY_KIB,
            iterations: MAX_ITERATIONS,
            parallelism: MAX_PARALLELISM,
        };
        assert!(p.validate().is_ok(), "the ceiling itself is valid");
    }
}
