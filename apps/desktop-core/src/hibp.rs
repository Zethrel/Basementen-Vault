//! Breached-password check via the Have I Been Pwned range API, using
//! **k-anonymity** so the password never leaves the device.
//!
//! We SHA-1 the password and send only the **first 5 hex characters** of the
//! digest to `https://api.pwnedpasswords.com/range/{prefix}`. HIBP returns every
//! breached-hash *suffix* sharing that prefix (hundreds of them) with a breach
//! count; we match our own 35-char suffix locally. The server therefore learns
//! only a 5-hex-char prefix — one of ~1 in a million buckets — never the
//! password or its full hash. `Add-Padding: true` further hides which prefix we
//! asked for from response-size analysis; padding rows carry a zero count and
//! are ignored.
//!
//! Best-effort by design: a network failure returns `Err` and the caller
//! proceeds (a self-hosted/offline client must still be able to register). Only
//! a positive match should block a password.

use sha1::{Digest, Sha1};

const RANGE_URL: &str = "https://api.pwnedpasswords.com/range/";
const TIMEOUT_SECS: u64 = 5;

#[derive(Debug, thiserror::Error)]
pub enum HibpError {
    #[error("breached-password check unavailable: {0}")]
    Network(String),
}

fn hex_upper(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02X}");
    }
    s
}

/// SHA-1 the password and split into the 5-char prefix (sent) and 35-char
/// suffix (matched locally), uppercase hex per the range API.
fn prefix_suffix(password: &str) -> (String, String) {
    let hex = hex_upper(&Sha1::digest(password.as_bytes()));
    (hex[..5].to_string(), hex[5..].to_string())
}

/// Scan a range response for our suffix; return its breach count if present
/// with a non-zero count (zero-count rows are `Add-Padding` decoys).
fn find_suffix_count(body: &str, suffix: &str) -> Option<u64> {
    for line in body.lines() {
        let Some((sfx, count)) = line.trim().split_once(':') else {
            continue;
        };
        if sfx.eq_ignore_ascii_case(suffix) {
            let n: u64 = count.trim().parse().ok()?;
            return (n > 0).then_some(n);
        }
    }
    None
}

/// Look up how many known breaches this password appears in. `Ok(Some(n))` =
/// breached n times (reject it); `Ok(None)` = not found; `Err` = the service
/// was unreachable (caller should proceed without blocking).
pub async fn password_breach_count(password: &str) -> Result<Option<u64>, HibpError> {
    let (prefix, suffix) = prefix_suffix(password);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(TIMEOUT_SECS))
        .build()
        .map_err(|e| HibpError::Network(e.to_string()))?;
    let resp = client
        .get(format!("{RANGE_URL}{prefix}"))
        // HIBP requires a User-Agent and honours the padding request.
        .header("User-Agent", "Basementen-Vault")
        .header("Add-Padding", "true")
        .send()
        .await
        .map_err(|e| HibpError::Network(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(HibpError::Network(format!("HTTP {}", resp.status())));
    }
    let body = resp
        .text()
        .await
        .map_err(|e| HibpError::Network(e.to_string()))?;
    Ok(find_suffix_count(&body, &suffix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_is_five_and_suffix_is_thirtyfive() {
        let (p, s) = prefix_suffix("correct horse battery staple");
        assert_eq!(p.len(), 5);
        assert_eq!(s.len(), 35);
        assert!(p.chars().chain(s.chars()).all(|c| c.is_ascii_hexdigit()));
        // Only the prefix would ever be transmitted.
        assert!("0123456789ABCDEF".contains(p.chars().next().unwrap()));
    }

    #[test]
    fn matches_our_suffix_case_insensitively() {
        let (_p, suffix) = prefix_suffix("hunter2");
        // Build a response body containing our suffix (lowercased) + decoys.
        let body = format!(
            "0000000000000000000000000000000000A:3\r\n{}:42\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:9\r\n",
            suffix.to_lowercase()
        );
        assert_eq!(find_suffix_count(&body, &suffix), Some(42));
    }

    #[test]
    fn absent_suffix_returns_none() {
        let (_p, suffix) = prefix_suffix("a-very-unlikely-string-1234567890");
        let body =
            "1111111111111111111111111111111111A:5\r\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:1\r\n";
        assert_eq!(find_suffix_count(body, &suffix), None);
    }

    #[test]
    fn zero_count_padding_rows_are_ignored() {
        let (_p, suffix) = prefix_suffix("padded");
        let body = format!("{suffix}:0\r\n");
        assert_eq!(
            find_suffix_count(&body, &suffix),
            None,
            "a zero-count (padding) row is not a real breach"
        );
    }
}
