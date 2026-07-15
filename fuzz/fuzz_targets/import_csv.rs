#![no_main]
//! Fuzz the CSV import parser (`desktop_core::import_csv`).
//!
//! CSV import is the single largest *untrusted-file* surface in the client: a
//! user points it at an export produced by some other password manager. The
//! property under test is robustness — for any input bytes the parser must
//! return `Ok`/`Err` without panicking, hanging, or exhausting memory. The
//! result value is intentionally ignored.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // `import_csv` takes `&str`; feed arbitrary bytes as lossy UTF-8 so every
    // input is exercised (invalid sequences become U+FFFD rather than being
    // rejected before the parser runs).
    let text = String::from_utf8_lossy(data);
    let _ = desktop_core::import_csv(&text);
});
