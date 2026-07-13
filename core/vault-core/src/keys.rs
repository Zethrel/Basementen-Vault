use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const KEY_LEN: usize = 32;

/// Domain-separation labels for HKDF expansion. Changing any of these is a
/// breaking change to every existing vault; never reuse a label.
const INFO_AUTH: &[u8] = b"basementen-vault/v1/auth-key";
const INFO_WRAP: &[u8] = b"basementen-vault/v1/wrapping-key";

macro_rules! key_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Zeroize, ZeroizeOnDrop)]
        pub struct $name([u8; KEY_LEN]);

        impl $name {
            pub(crate) fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
                Self(bytes)
            }

            pub(crate) fn as_bytes(&self) -> &[u8; KEY_LEN] {
                &self.0
            }
        }

        /// Constant-time equality; never derive `PartialEq` for key material.
        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.0.ct_eq(&other.0).into()
            }
        }
        impl Eq for $name {}

        /// Debug must never print key bytes.
        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
}

key_type! {
    /// Argon2id output of the master password. Root of the hierarchy;
    /// exists only in memory, never transmitted or stored.
    MasterKey
}

key_type! {
    /// Proves identity to the server. The server re-hashes this with its own
    /// Argon2id pass; it can never decrypt anything.
    AuthKey
}

key_type! {
    /// Wraps (encrypts) the Vault Key. Never leaves the client.
    WrappingKey
}

key_type! {
    /// Random data-encryption key for all vault items. Generated once at
    /// registration; stored server-side only in wrapped (encrypted) form.
    VaultKey
}

key_type! {
    /// Random recovery key rendered into the user's Recovery Kit. Wraps a
    /// second copy of the Vault Key so the vault survives a lost master
    /// password.
    RecoveryKey
}

impl MasterKey {
    /// Split the Master Key into the authentication and encryption branches.
    ///
    /// HKDF-SHA-256 with distinct `info` labels guarantees the two outputs
    /// are computationally independent: learning the AuthKey (which the
    /// server sees) reveals nothing about the WrappingKey.
    pub fn derive_subkeys(&self) -> (AuthKey, WrappingKey) {
        let hk = Hkdf::<Sha256>::new(None, self.as_bytes());
        let mut auth = [0u8; KEY_LEN];
        let mut wrap = [0u8; KEY_LEN];
        hk.expand(INFO_AUTH, &mut auth)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        hk.expand(INFO_WRAP, &mut wrap)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        (AuthKey::from_bytes(auth), WrappingKey::from_bytes(wrap))
    }
}

impl VaultKey {
    /// Generate a fresh random Vault Key from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

impl RecoveryKey {
    /// Generate a fresh random Recovery Key from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

impl AuthKey {
    /// Export for transmission to the server during registration/login.
    ///
    /// This is the only key in the hierarchy with a public export method:
    /// sending it to the server is its entire purpose. The server must treat
    /// it like a password (stacked Argon2id, never logged).
    pub fn to_server_credential(&self) -> [u8; KEY_LEN] {
        *self.as_bytes()
    }
}
