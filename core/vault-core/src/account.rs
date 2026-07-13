//! High-level client flows: registration, unlock/login, and recovery.
//!
//! These functions are the intended public surface for the apps; they compose
//! the KDF, key hierarchy, and envelope modules so UI code never touches raw
//! key bytes or nonce handling.

use zeroize::Zeroizing;

use crate::envelope::WrappedKey;
use crate::error::CryptoError;
use crate::kdf::{derive_master_key, KdfParams};
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
/// (and the server re-hashes it), the wrapped keys are ciphertext.
pub struct RegistrationBundle {
    pub kdf_params: KdfParams,
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

/// Create all cryptographic material for a new account, entirely client-side.
pub fn register(
    password: &str,
    email: &str,
    params: KdfParams,
) -> Result<Registration, CryptoError> {
    let master_key = derive_master_key(password, email, &params)?;
    let (auth_key, wrapping_key) = master_key.derive_subkeys();

    let vault_key = VaultKey::generate();
    let recovery_key = RecoveryKey::generate();

    let bundle = RegistrationBundle {
        kdf_params: params,
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

/// Derive the login credential only (for authenticating before the wrapped
/// Vault Key has been fetched).
pub fn login_credential(
    password: &str,
    email: &str,
    params: &KdfParams,
) -> Result<AuthKey, CryptoError> {
    let master_key = derive_master_key(password, email, params)?;
    let (auth_key, _) = master_key.derive_subkeys();
    Ok(auth_key)
}

/// Unlock the vault: derive keys from the password and unwrap the Vault Key
/// fetched from the server (or the local replica).
///
/// Fails with [`CryptoError::Decrypt`] on a wrong password.
pub fn unlock(
    password: &str,
    email: &str,
    params: &KdfParams,
    master_wrapped_vault_key: &WrappedKey,
) -> Result<AccountSecrets, CryptoError> {
    let master_key = derive_master_key(password, email, params)?;
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
pub fn recover_and_rekey(
    recovery_code: &str,
    recovery_wrapped_vault_key: &WrappedKey,
    new_password: &str,
    email: &str,
    params: KdfParams,
) -> Result<Registration, CryptoError> {
    let recovery_key = RecoveryKey::from_recovery_code(recovery_code)?;
    let vault_key = recovery_key.unwrap_vault_key(recovery_wrapped_vault_key)?;

    let master_key = derive_master_key(new_password, email, &params)?;
    let (auth_key, wrapping_key) = master_key.derive_subkeys();
    let new_recovery_key = RecoveryKey::generate();

    let bundle = RegistrationBundle {
        kdf_params: params,
        auth_credential: auth_key.to_server_credential(),
        recovery_verifier: vault_key.recovery_verifier(),
        master_wrapped_vault_key: wrapping_key.wrap_vault_key(&vault_key),
        recovery_wrapped_vault_key: new_recovery_key.wrap_vault_key(&vault_key),
    };

    Ok(Registration {
        bundle,
        secrets: AccountSecrets {
            auth_key,
            vault_key,
        },
        recovery_code: Zeroizing::new(new_recovery_key.to_recovery_code()),
    })
}

/// Change the master password: re-derive the hierarchy under the new password
/// and re-wrap the existing Vault Key. Vault items are untouched (envelope
/// encryption is what makes this cheap). A fresh Recovery Kit is issued —
/// the caller must show the new recovery code to the user, as the old kit
/// stops working the moment the server stores the new bundle.
pub fn change_password(
    secrets: &AccountSecrets,
    new_password: &str,
    email: &str,
    params: KdfParams,
) -> Result<Registration, CryptoError> {
    let master_key = derive_master_key(new_password, email, &params)?;
    let (auth_key, wrapping_key) = master_key.derive_subkeys();
    let recovery_key = RecoveryKey::generate();

    let bundle = RegistrationBundle {
        kdf_params: params,
        auth_credential: auth_key.to_server_credential(),
        recovery_verifier: secrets.vault_key.recovery_verifier(),
        master_wrapped_vault_key: wrapping_key.wrap_vault_key(&secrets.vault_key),
        recovery_wrapped_vault_key: recovery_key.wrap_vault_key(&secrets.vault_key),
    };

    Ok(Registration {
        bundle,
        secrets: AccountSecrets {
            auth_key,
            vault_key: secrets.vault_key.clone(),
        },
        recovery_code: Zeroizing::new(recovery_key.to_recovery_code()),
    })
}
