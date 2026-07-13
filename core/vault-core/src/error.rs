use thiserror::Error;

/// Errors produced by the crypto core.
///
/// Deliberately coarse-grained: callers must not be able to distinguish
/// *why* a decryption failed (wrong key vs. tampered ciphertext), only that
/// it failed.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// KDF parameters are below the accepted security floor or malformed.
    #[error("KDF parameters rejected: {0}")]
    InvalidKdfParams(String),

    /// Key derivation failed (should not happen with valid params).
    #[error("key derivation failed")]
    KeyDerivation,

    /// Authenticated decryption failed: wrong key, tampered ciphertext,
    /// or mismatched associated data.
    #[error("decryption failed")]
    Decrypt,

    /// Encryption failed.
    #[error("encryption failed")]
    Encrypt,

    /// A serialized structure (wrapped key, recovery code, …) is malformed.
    #[error("malformed input: {0}")]
    Malformed(String),

    /// Version field not understood by this build of the library.
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u16),
}
