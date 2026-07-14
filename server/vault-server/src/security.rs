//! Server-side credential hashing, opaque tokens, and the failure delay.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 32 random bytes from the OS CSPRNG (server-side process secrets).
pub fn random_secret() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// A stable, unpredictable 16-byte KDF salt for a *nonexistent* account,
/// so prelogin responses for unknown e-mails are indistinguishable from real
/// ones (which return a stored random salt). Deterministic in `email` under
/// the server's per-process `enumeration_secret`, so repeated queries return
/// the same value, but unpredictable to anyone without the secret.
pub fn dummy_kdf_salt(secret: &[u8; 32], normalized_email: &str) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(normalized_email.as_bytes());
    mac.finalize().into_bytes()[..16].to_vec()
}

/// Server-side Argon2id parameters for hashing the client's AuthKey.
/// The client already did a heavy KDF pass; this second pass exists so a
/// stolen database still can't be used to log in. OWASP-floor parameters
/// keep login latency reasonable on small home hardware.
fn server_argon2() -> Argon2<'static> {
    let params = Params::new(19 * 1024, 2, 1, Some(32)).expect("static Argon2 params are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Hash a client auth credential for storage (PHC string, random salt).
pub fn hash_credential(credential: &[u8]) -> String {
    let salt = SaltString::generate(&mut OsRng);
    server_argon2()
        .hash_password(credential, &salt)
        .expect("hashing cannot fail with valid params")
        .to_string()
}

/// Verify a client auth credential against a stored PHC string.
/// Comparison inside the argon2 crate is constant-time.
pub fn verify_credential(credential: &[u8], phc: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(phc) else {
        return false;
    };
    server_argon2().verify_password(credential, &parsed).is_ok()
}

/// A hash of a random value, used to equalize the work done for unknown
/// accounts: login always performs exactly one Argon2id verification whether
/// or not the e-mail exists, closing the "fast reject = no such user" timing
/// side channel.
pub fn make_dummy_hash() -> String {
    let mut random = [0u8; 32];
    OsRng.fill_bytes(&mut random);
    hash_credential(&random)
}

/// The mini-lockout: sleep a randomized 250–300 ms before answering any
/// failed authentication attempt. The randomization blurs timing analysis;
/// the floor makes online guessing expensive. This is deliberately applied
/// *in addition to* rate limiting and progressive lockout, never instead.
pub const FAILURE_DELAY_MIN_MS: u64 = 250;
pub const FAILURE_DELAY_MAX_MS: u64 = 300;

pub async fn failure_delay() {
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    let span = FAILURE_DELAY_MAX_MS - FAILURE_DELAY_MIN_MS + 1;
    let ms = FAILURE_DELAY_MIN_MS + u64::from_le_bytes(bytes) % span;
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

/// Generate an opaque bearer token: `prefix` + 256 bits of CSPRNG output,
/// base64url. Returns the token (sent to the client, never stored) and the
/// SHA-256 hash (stored; a database leak cannot mint sessions).
pub fn new_token(prefix: &str) -> (String, Vec<u8>) {
    use base64::Engine;
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let token = format!(
        "{prefix}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    );
    let hash = sha256(token.as_bytes());
    (token, hash)
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_secs() as i64
}

/// Progressive lockout: once an account passes `LOCKOUT_THRESHOLD` failures,
/// each further failure doubles the lockout, capped at one hour.
pub const LOCKOUT_THRESHOLD: i64 = 10;
const LOCKOUT_BASE_SECS: i64 = 60;
const LOCKOUT_CAP_SECS: i64 = 3600;

pub fn lockout_duration(failed_attempts: i64) -> Option<i64> {
    if failed_attempts < LOCKOUT_THRESHOLD {
        return None;
    }
    let doublings = (failed_attempts - LOCKOUT_THRESHOLD).min(6) as u32;
    Some((LOCKOUT_BASE_SECS << doublings).min(LOCKOUT_CAP_SECS))
}
