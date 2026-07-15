#![no_main]
//! Fuzz the decrypted-item JSON parser (`desktop_core::Item::from_plaintext`).
//!
//! This is the `serde_json` → `Item` decode applied to the bytes that come out
//! of a decrypted envelope. A corrupt local replica, a downgrade, or a bug
//! upstream could feed it malformed JSON; it must never panic. Cheap and fast,
//! so it accumulates a lot of iterations per run.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = desktop_core::Item::from_plaintext(data);
});
