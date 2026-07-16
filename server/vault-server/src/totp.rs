//! TOTP (RFC 6238) over HMAC-SHA-1, 6 digits, 30-second steps.
//!
//! SHA-1 here is HMAC-SHA-1 as specified by RFC 4226/6238 — the standard
//! every authenticator app implements — not SHA-1 as a collision-resistant
//! hash; HMAC-SHA-1 remains secure for this use.

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, KeyInit, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha1::Sha1;
use subtle::ConstantTimeEq;

pub const STEP_SECS: i64 = 30;
pub const DIGITS: u32 = 6;
/// Accept the previous/next step to absorb clock drift.
const DRIFT_STEPS: i64 = 1;

/// Generate a new 160-bit shared secret, base32-encoded for QR/manual entry.
pub fn generate_secret() -> String {
    let mut bytes = [0u8; 20];
    OsRng.fill_bytes(&mut bytes);
    BASE32_NOPAD.encode(&bytes)
}

/// The otpauth:// URI encoded into the enrollment QR code.
pub fn otpauth_uri(issuer: &str, account_email: &str, secret_base32: &str) -> String {
    // Percent-encode conservatively: these fields are under our control plus
    // an e-mail address, so escaping the URI-significant characters suffices.
    fn esc(s: &str) -> String {
        s.replace('%', "%25")
            .replace(' ', "%20")
            .replace('&', "%26")
            .replace('?', "%3F")
            .replace('/', "%2F")
            .replace('#', "%23")
    }
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={}&period={}",
        esc(issuer),
        esc(account_email),
        secret_base32,
        esc(issuer),
        DIGITS,
        STEP_SECS
    )
}

fn hotp(secret: &[u8], counter: u64) -> u32 {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let code = ((u32::from(digest[offset]) & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    code % 10u32.pow(DIGITS)
}

/// Compute the code for a given unix time (used by tests and by the client).
pub fn code_at(secret_base32: &str, unix_secs: i64) -> Option<String> {
    let secret = BASE32_NOPAD
        .decode(secret_base32.trim().to_ascii_uppercase().as_bytes())
        .ok()?;
    let counter = (unix_secs / STEP_SECS).max(0) as u64;
    Some(format!("{:06}", hotp(&secret, counter)))
}

/// Verify a submitted code against the secret at the given time, allowing
/// ±1 step of clock drift, and return the matched 30-second time-step
/// (`unix / STEP_SECS`) so callers can enforce one-time use. Returns `None`
/// if no accepted window matched. Comparison is constant-time.
pub fn verify_step(secret_base32: &str, submitted: &str, unix_secs: i64) -> Option<i64> {
    let submitted = submitted.trim();
    if submitted.len() != DIGITS as usize || !submitted.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut matched: Option<i64> = None;
    for drift in -DRIFT_STEPS..=DRIFT_STEPS {
        let t = unix_secs + drift * STEP_SECS;
        // Check every window (no early return) so timing doesn't reveal which
        // one matched. The step number itself is derivable from the clock, so
        // recording the matched window leaks nothing secret.
        if let Some(expected) = code_at(secret_base32, t) {
            if bool::from(expected.as_bytes().ct_eq(submitted.as_bytes())) {
                matched = Some(t / STEP_SECS);
            }
        }
    }
    matched
}

/// Verify a submitted code, allowing ±1 step of clock drift. Constant-time.
/// Use [`verify_step`] where one-time-use enforcement is needed.
pub fn verify(secret_base32: &str, submitted: &str, unix_secs: i64) -> bool {
    verify_step(secret_base32, submitted, unix_secs).is_some()
}
