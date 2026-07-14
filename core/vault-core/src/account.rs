//! High-level client flows: registration, unlock/login, and recovery.
//!
//! These functions are the intended public surface for the apps; they compose
//! the KDF, key hierarchy, and envelope modules so UI code never touches raw
//! key bytes or nonce handling.
//!
//! The account e-mail is an *identifier* only — it does not enter key
//! derivation. Every derivation uses the account's random per-account salt
//! (`kdf_salt`), generated once at registration and supplied on each unlock.

use zeroize::Zeroizing;

use crate::envelope::WrappedKey;
use crate::error::CryptoError;
use crate::kdf::{derive_master_key, generate_salt, KdfParams, SALT_LEN};
use crate::keys::{AuthKey, RecoveryKey, VaultKey};

/// The in-memory secrets of an unlocked vault. Everything here is zeroized
/// on drop; drop this struct to lock the vault.
pub struct AccountSecrets {
    pub auth_key: AuthKey,
    pub vault_key: VaultKey,
}

impl core::fmt::Debug for AccountSecrets {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AccountSecrets(<redacted>)")
    }
}

/// Everything the server needs to create an account. Contains no plaintext
/// key material: the auth credential is a one-way branch of the hierarchy
/// (and the server re-hashes it), the wrapped keys are ciphertext, and the
/// salt is public-by-design (not secret).
pub struct RegistrationBundle {
    pub kdf_params: KdfParams,
    /// Random 128-bit per-account KDF salt. Not secret; stored server-side
    /// and returned by prelogin so any client can derive.
    pub kdf_salt: [u8; SALT_LEN],
    pub auth_credential: [u8; 32],
    /// HKDF branch of the Vault Key; the server stores its hash and requires
    /// the preimage for data-preserving recovery (proof of Recovery Kit
    /// possession). See [`crate::keys::VaultKey::recovery_verifier`].
    pub recovery_verifier: [u8; 32],
    pub master_wrapped_vault_key: WrappedKey,
    pub recovery_wrapped_vault_key: WrappedKey,
}

/// Output of local registration: what to send to the server, the live
/// secrets for immediate use, and the recovery code to render into the
/// user's Recovery Kit (shown exactly once, never stored).
pub struct Registration {
    pub bundle: RegistrationBundle,
    pub secrets: AccountSecrets,
    pub recovery_code: Zeroizing<String>,
}

fn to_salt(salt: &[u8]) -> Result<[u8; SALT_LEN], CryptoError> {
    salt.try_into()
        .map_err(|_| CryptoError::InvalidKdfParams(format!("salt must be {SALT_LEN} bytes")))
}

/// Assemble a bundle + secrets from a freshly derived hierarchy over an
/// existing Vault Key (shared by register / recover / change-password).
fn build_registration(
    params: KdfParams,
    salt: [u8; SALT_LEN],
    new_password: &str,
    vault_key: VaultKey,
) -> Result<Registration, CryptoError> {
    let master_key = derive_master_key(new_password, &salt, &params)?;
    let (auth_key, wrapping_key) = master_key.derive_subkeys();
    let recovery_key = RecoveryKey::generate();

    let bundle = RegistrationBundle {
        kdf_params: params,
        kdf_salt: salt,
        auth_credential: auth_key.to_server_credential(),
        recovery_verifier: vault_key.recovery_verifier(),
        master_wrapped_vault_key: wrapping_key.wrap_vault_key(&vault_key),
        recovery_wrapped_vault_key: recovery_key.wrap_vault_key(&vault_key),
    };
    Ok(Registration {
        bundle,
        secrets: AccountSecrets {
            auth_key,
            vault_key,
        },
        recovery_code: Zeroizing::new(recovery_key.to_recovery_code()),
    })
}

/// Create all cryptographic material for a new account, entirely client-side.
/// Generates a fresh random Vault Key and a fresh random KDF salt.
pub fn register(password: &str, params: KdfParams) -> Result<Registration, CryptoError> {
    build_registration(params, generate_salt(), password, VaultKey::generate())
}

/// Derive the login credential only (for authenticating before the wrapped
/// Vault Key has been fetched). The `salt` comes from prelogin.
pub fn login_credential(
    password: &str,
    salt: &[u8],
    params: &KdfParams,
) -> Result<AuthKey, CryptoError> {
    let master_key = derive_master_key(password, salt, params)?;
    let (auth_key, _) = master_key.derive_subkeys();
    Ok(auth_key)
}

/// Unlock the vault: derive keys from the password + salt and unwrap the
/// Vault Key fetched from the server (or the local replica).
///
/// Fails with [`CryptoError::Decrypt`] on a wrong password.
pub fn unlock(
    password: &str,
    salt: &[u8],
    params: &KdfParams,
    master_wrapped_vault_key: &WrappedKey,
) -> Result<AccountSecrets, CryptoError> {
    let master_key = derive_master_key(password, salt, params)?;
    let (auth_key, wrapping_key) = master_key.derive_subkeys();
    let vault_key = wrapping_key.unwrap_vault_key(master_wrapped_vault_key)?;
    Ok(AccountSecrets {
        auth_key,
        vault_key,
    })
}

/// Recover the Vault Key from a Recovery Kit code, then re-establish the
/// account under a new master password.
///
/// Returns a fresh [`Registration`] whose bundle the server should store in
/// place of the old one (same Vault Key, so all existing items remain
/// readable; new auth credential, new wrapped copies, new recovery code —
/// the used kit is considered spent).
///
/// The `salt` is the account's existing KDF salt (from `recovery/data`).
/// The salt is **not** rotated: it is not secret, and the derived key already
/// changes because the password changed. Keeping it account-lifetime removes
/// a piece of state that would otherwise have to stay synchronized.
pub fn recover_and_rekey(
    recovery_code: &str,
    recovery_wrapped_vault_key: &WrappedKey,
    new_password: &str,
    salt: &[u8],
    params: KdfParams,
) -> Result<Registration, CryptoError> {
    let recovery_key = RecoveryKey::from_recovery_code(recovery_code)?;
    let vault_key = recovery_key.unwrap_vault_key(recovery_wrapped_vault_key)?;
    build_registration(params, to_salt(salt)?, new_password, vault_key)
}

/// Change the master password: re-derive the hierarchy under the new password
/// and re-wrap the existing Vault Key. Vault items are untouched (envelope
/// encryption is what makes this cheap). A fresh Recovery Kit is issued — the
/// caller must show the new recovery code to the user, as the old kit stops
/// working the moment the server stores the new bundle.
///
/// The account's existing `salt` is reused (see [`recover_and_rekey`] on why
/// the salt is account-lifetime).
pub fn change_password(
    secrets: &AccountSecrets,
    new_password: &str,
    salt: &[u8],
    params: KdfParams,
) -> Result<Registration, CryptoError> {
    build_registration(
        params,
        to_salt(salt)?,
        new_password,
        secrets.vault_key.clone(),
    )
}
