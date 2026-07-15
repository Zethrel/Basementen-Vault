#![no_main]
//! Fuzz the encrypted-import decode chain (`desktop_core::import_encrypted`).
//!
//! Exercises, on hostile input: JSON envelope deserialization
//! (`vault_core::ExportEnvelope`), the format-marker gate, KDF-parameter
//! validation, Argon2 key derivation, XChaCha20-Poly1305 decryption, and the
//! inner payload JSON parse. Most random inputs fail fast at the JSON/format
//! gate; the seed corpus carries a structurally valid envelope past it so the
//! deeper stages get coverage. The KDF-parameter *ceiling* (vault-core
//! `kdf.rs`) is what keeps a crafted envelope from turning each iteration into a
//! multi-gigabyte Argon2 allocation.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    // A fixed passphrase: we are fuzzing the parse + decrypt machinery, not the
    // passphrase itself. Authentication will fail for essentially all inputs;
    // what matters is that failure is graceful (no panic / hang / OOM).
    let _ = desktop_core::import_encrypted(&text, "correct horse battery staple");
});
