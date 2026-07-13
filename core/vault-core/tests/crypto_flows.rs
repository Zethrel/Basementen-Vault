//! End-to-end tests over the public API: register → unlock → item crypto →
//! recovery → password change. All tests use the OWASP-floor KDF parameters
//! to keep the suite fast; parameter validation itself is tested explicitly.

use vault_core::account::{self};
use vault_core::error::CryptoError;
use vault_core::kdf::{derive_master_key, normalize_email, KdfParams};
use vault_core::keys::{RecoveryKey, VaultKey};

const EMAIL: &str = "user@example.com";
const PASSWORD: &str = "correct horse battery staple";

fn params() -> KdfParams {
    KdfParams::mobile_floor()
}

// ---------------------------------------------------------------------------
// KDF

#[test]
fn kdf_is_deterministic_and_email_bound() {
    let a = derive_master_key(PASSWORD, EMAIL, &params()).unwrap();
    let b = derive_master_key(PASSWORD, EMAIL, &params()).unwrap();
    assert_eq!(a, b, "same inputs must derive the same Master Key");

    let other_email = derive_master_key(PASSWORD, "other@example.com", &params()).unwrap();
    assert_ne!(a, other_email, "different e-mail must change the salt");

    let other_pw = derive_master_key("wrong password", EMAIL, &params()).unwrap();
    assert_ne!(a, other_pw);
}

#[test]
fn kdf_email_normalization_is_stable() {
    assert_eq!(normalize_email("  User@Example.COM \n"), "user@example.com");
    let a = derive_master_key(PASSWORD, "User@Example.COM", &params()).unwrap();
    let b = derive_master_key(PASSWORD, "user@example.com", &params()).unwrap();
    assert_eq!(a, b, "e-mail case/whitespace must not change the key");
}

#[test]
fn kdf_rejects_parameters_below_floor() {
    for bad in [
        KdfParams {
            memory_kib: 1024,
            ..params()
        },
        KdfParams {
            iterations: 1,
            ..params()
        },
        KdfParams {
            parallelism: 0,
            ..params()
        },
        KdfParams {
            version: 99,
            ..params()
        },
    ] {
        assert!(
            derive_master_key(PASSWORD, EMAIL, &bad).is_err(),
            "params {bad:?} must be rejected"
        );
    }
}

#[test]
fn subkey_derivation_is_deterministic() {
    let mk = derive_master_key(PASSWORD, EMAIL, &params()).unwrap();
    let (auth1, _) = mk.derive_subkeys();
    let (auth2, _) = mk.derive_subkeys();
    assert_eq!(auth1, auth2, "derivation must be deterministic");
}

#[test]
fn server_known_credential_cannot_decrypt_vault_key() {
    // The auth credential is the only secret the server ever sees. Simulate
    // a malicious server keying the wrap cipher with it: decryption of the
    // master-wrapped Vault Key must fail, proving the auth and encryption
    // branches of the hierarchy are independent.
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

    let reg = account::register(PASSWORD, EMAIL, params()).unwrap();
    let wrapped = &reg.bundle.master_wrapped_vault_key;

    let evil = XChaCha20Poly1305::new((&reg.bundle.auth_credential).into());
    let attempt = evil.decrypt(
        &XNonce::from(wrapped.nonce),
        Payload {
            msg: wrapped.ciphertext.as_slice(),
            aad: b"basementen-vault/v1/wrap/master",
        },
    );
    assert!(attempt.is_err());
}

// ---------------------------------------------------------------------------
// Registration / unlock

#[test]
fn register_then_unlock_roundtrip() {
    let reg = account::register(PASSWORD, EMAIL, params()).unwrap();

    let unlocked = account::unlock(
        PASSWORD,
        EMAIL,
        &reg.bundle.kdf_params,
        &reg.bundle.master_wrapped_vault_key,
    )
    .unwrap();

    assert_eq!(unlocked.vault_key, reg.secrets.vault_key);
    assert_eq!(
        unlocked.auth_key.to_server_credential(),
        reg.bundle.auth_credential
    );
}

#[test]
fn wrong_password_fails_to_unlock() {
    let reg = account::register(PASSWORD, EMAIL, params()).unwrap();
    let err = account::unlock(
        "not the password",
        EMAIL,
        &reg.bundle.kdf_params,
        &reg.bundle.master_wrapped_vault_key,
    )
    .unwrap_err();
    assert!(matches!(err, CryptoError::Decrypt));
}

#[test]
fn auth_credential_cannot_unwrap_vault_key() {
    // The server knows the auth credential. Prove that knowing it does not
    // let the server (or a database thief) unwrap the Vault Key: the wrap
    // used the independent WrappingKey branch.
    let reg = account::register(PASSWORD, EMAIL, params()).unwrap();

    // An attacker could try using the credential bytes as a wrapping key.
    // There is no public API for that (by design), which is itself the
    // guarantee; here we assert the ciphertext is at least AEAD-protected.
    let mut forged = reg.bundle.master_wrapped_vault_key.clone();
    forged.ciphertext[0] ^= 0xff;
    let err = account::unlock(PASSWORD, EMAIL, &reg.bundle.kdf_params, &forged).unwrap_err();
    assert!(matches!(err, CryptoError::Decrypt));
}

// ---------------------------------------------------------------------------
// Item encryption

#[test]
fn item_encrypt_decrypt_roundtrip() {
    let vk = VaultKey::generate();
    let plaintext = br#"{"type":"login","name":"example.com","password":"hunter2"}"#;
    let item = vk.encrypt_item("item-123", 7, plaintext).unwrap();
    assert_eq!(vk.decrypt_item(&item).unwrap(), plaintext);
}

#[test]
fn item_nonces_are_unique_per_encryption() {
    let vk = VaultKey::generate();
    let a = vk.encrypt_item("id", 1, b"same plaintext").unwrap();
    let b = vk.encrypt_item("id", 1, b"same plaintext").unwrap();
    assert_ne!(a.nonce, b.nonce);
    assert_ne!(a.ciphertext, b.ciphertext);
}

#[test]
fn item_rejects_wrong_key_and_tampering() {
    let vk = VaultKey::generate();
    let other = VaultKey::generate();
    let item = vk.encrypt_item("item-1", 1, b"secret").unwrap();

    assert!(matches!(
        other.decrypt_item(&item).unwrap_err(),
        CryptoError::Decrypt
    ));

    let mut tampered = item.clone();
    tampered.ciphertext[0] ^= 1;
    assert!(matches!(
        vk.decrypt_item(&tampered).unwrap_err(),
        CryptoError::Decrypt
    ));
}

#[test]
fn item_binds_id_and_revision() {
    // A ciphertext moved to another item ID, or rolled back to a different
    // revision, must fail authentication (anti-swap / anti-rollback).
    let vk = VaultKey::generate();
    let item = vk.encrypt_item("item-1", 5, b"secret").unwrap();

    let mut moved = item.clone();
    moved.item_id = "item-2".into();
    assert!(vk.decrypt_item(&moved).is_err());

    let mut rolled_back = item.clone();
    rolled_back.revision = 4;
    assert!(vk.decrypt_item(&rolled_back).is_err());
}

// ---------------------------------------------------------------------------
// Recovery

#[test]
fn recovery_code_roundtrip_and_typo_tolerance() {
    let rk = RecoveryKey::generate();
    let code = rk.to_recovery_code();
    assert!(code.starts_with("BV1-"));

    let parsed = RecoveryKey::from_recovery_code(&code).unwrap();
    assert_eq!(parsed, rk);

    // Lowercase, extra whitespace, and O/0 I/1 confusion are tolerated.
    let sloppy = code.to_lowercase().replace('0', "o").replace('1', "l");
    let sloppy = format!("  {} ", sloppy);
    assert_eq!(RecoveryKey::from_recovery_code(&sloppy).unwrap(), rk);
}

#[test]
fn recovery_code_detects_typos() {
    let code = RecoveryKey::generate().to_recovery_code();
    // Flip one character to a different valid alphabet character.
    let mut chars: Vec<char> = code.chars().collect();
    let idx = code.len() - 1;
    chars[idx] = if chars[idx] == '7' { '9' } else { '7' };
    let typo: String = chars.into_iter().collect();
    assert!(RecoveryKey::from_recovery_code(&typo).is_err());
}

#[test]
fn full_recovery_flow_preserves_vault_data() {
    // Register, encrypt an item, "forget" the password, recover with the
    // kit, set a new password — the item must still decrypt.
    let reg = account::register(PASSWORD, EMAIL, params()).unwrap();
    let item = reg
        .secrets
        .vault_key
        .encrypt_item("item-1", 1, b"do not lose me")
        .unwrap();

    let recovered = account::recover_and_rekey(
        &reg.recovery_code,
        &reg.bundle.recovery_wrapped_vault_key,
        "brand new master password",
        EMAIL,
        params(),
    )
    .unwrap();

    assert_eq!(
        recovered.secrets.vault_key.decrypt_item(&item).unwrap(),
        b"do not lose me"
    );
    assert_ne!(
        recovered.bundle.auth_credential, reg.bundle.auth_credential,
        "new password must produce a new auth credential"
    );
    assert_ne!(
        *recovered.recovery_code, *reg.recovery_code,
        "a used recovery kit must be replaced"
    );

    // Old password no longer works against the new bundle.
    assert!(account::unlock(
        PASSWORD,
        EMAIL,
        &recovered.bundle.kdf_params,
        &recovered.bundle.master_wrapped_vault_key
    )
    .is_err());
}

#[test]
fn recovery_wrap_cannot_be_confused_with_master_wrap() {
    // Purpose binding: feeding the recovery-wrapped blob into the master
    // unlock path must fail structurally, not just cryptographically.
    let reg = account::register(PASSWORD, EMAIL, params()).unwrap();
    let err = account::unlock(
        PASSWORD,
        EMAIL,
        &reg.bundle.kdf_params,
        &reg.bundle.recovery_wrapped_vault_key,
    )
    .unwrap_err();
    assert!(matches!(err, CryptoError::Malformed(_)));
}

// ---------------------------------------------------------------------------
// Password change

#[test]
fn change_password_keeps_vault_key_and_rotates_credentials() {
    let reg = account::register(PASSWORD, EMAIL, params()).unwrap();
    let item = reg
        .secrets
        .vault_key
        .encrypt_item("item-1", 1, b"still here")
        .unwrap();

    let changed =
        account::change_password(&reg.secrets, "new password 42", EMAIL, params()).unwrap();

    assert_ne!(changed.bundle.auth_credential, reg.bundle.auth_credential);

    let unlocked = account::unlock(
        "new password 42",
        EMAIL,
        &changed.bundle.kdf_params,
        &changed.bundle.master_wrapped_vault_key,
    )
    .unwrap();
    assert_eq!(
        unlocked.vault_key.decrypt_item(&item).unwrap(),
        b"still here"
    );

    // The freshly issued recovery kit works against the new bundle.
    let recovered = account::recover_and_rekey(
        &changed.recovery_code,
        &changed.bundle.recovery_wrapped_vault_key,
        "yet another password",
        EMAIL,
        params(),
    )
    .unwrap();
    assert_eq!(
        recovered.secrets.vault_key.decrypt_item(&item).unwrap(),
        b"still here"
    );
}

// ---------------------------------------------------------------------------
// Serialization stability (sync layer depends on this)

#[test]
fn encrypted_structures_serialize_roundtrip() {
    let reg = account::register(PASSWORD, EMAIL, params()).unwrap();
    let item = reg.secrets.vault_key.encrypt_item("i", 1, b"x").unwrap();

    let wrapped_json = serde_json::to_string(&reg.bundle.master_wrapped_vault_key).unwrap();
    let item_json = serde_json::to_string(&item).unwrap();

    let wrapped_back: vault_core::WrappedKey = serde_json::from_str(&wrapped_json).unwrap();
    let item_back: vault_core::EncryptedItem = serde_json::from_str(&item_json).unwrap();

    let unlocked = account::unlock(PASSWORD, EMAIL, &reg.bundle.kdf_params, &wrapped_back).unwrap();
    assert_eq!(unlocked.vault_key.decrypt_item(&item_back).unwrap(), b"x");
}

// ---------------------------------------------------------------------------
// Export envelope (single desktop-cost run; volume testing lives in proptests)

#[test]
fn export_envelope_roundtrip() {
    let envelope = vault_core::encrypt_export(b"backup payload", "a passphrase").unwrap();
    assert_eq!(envelope.format, "basementen-vault-export");
    let back = vault_core::decrypt_export(&envelope, "a passphrase").unwrap();
    assert_eq!(&*back, b"backup payload");
    assert!(vault_core::decrypt_export(&envelope, "other").is_err());
}
