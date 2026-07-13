//! Recovery Kit code formatting.
//!
//! The Recovery Key is rendered as a human-transcribable code (printed in the
//! Recovery Kit PDF): Crockford base32, grouped, with a 2-byte SHA-256
//! checksum so typos are caught locally instead of surfacing as a generic
//! decryption failure.
//!
//! Format: `BV1-XXXXX-XXXXX-…` — version prefix plus 55 base32 characters
//! (32 key bytes + 2 checksum bytes) in groups of five.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::keys::{RecoveryKey, KEY_LEN};

const PREFIX: &str = "BV1";
const CHECKSUM_LEN: usize = 2;
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const GROUP: usize = 5;

fn checksum(key: &[u8]) -> [u8; CHECKSUM_LEN] {
    let digest = Sha256::digest(key);
    [digest[0], digest[1]]
}

fn encode_base32(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

fn decode_char(c: char) -> Option<u32> {
    // Crockford: case-insensitive, with common misreads folded in.
    let c = c.to_ascii_uppercase();
    let c = match c {
        'O' => '0',
        'I' | 'L' => '1',
        other => other,
    };
    ALPHABET
        .iter()
        .position(|&a| a as char == c)
        .map(|p| p as u32)
}

fn decode_base32(s: &str, expected_len: usize) -> Result<Vec<u8>, CryptoError> {
    let mut out = Vec::with_capacity(expected_len);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for c in s.chars() {
        let v = decode_char(c)
            .ok_or_else(|| CryptoError::Malformed(format!("invalid character '{c}'")))?;
        buffer = (buffer << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    // Trailing padding bits must be zero, otherwise two different strings
    // could decode to the same bytes.
    if bits > 0 && (buffer & ((1 << bits) - 1)) != 0 {
        return Err(CryptoError::Malformed("non-zero padding bits".into()));
    }
    if out.len() != expected_len {
        return Err(CryptoError::Malformed(format!(
            "expected {expected_len} bytes, got {}",
            out.len()
        )));
    }
    Ok(out)
}

impl RecoveryKey {
    /// Render this key as the human-readable Recovery Kit code.
    pub fn to_recovery_code(&self) -> String {
        let mut payload = Zeroizing::new([0u8; KEY_LEN + CHECKSUM_LEN]);
        payload[..KEY_LEN].copy_from_slice(self.as_bytes());
        payload[KEY_LEN..].copy_from_slice(&checksum(self.as_bytes()));

        let raw = encode_base32(payload.as_ref());
        let mut code = String::with_capacity(PREFIX.len() + raw.len() + raw.len() / GROUP + 1);
        code.push_str(PREFIX);
        for (i, c) in raw.chars().enumerate() {
            if i % GROUP == 0 {
                code.push('-');
            }
            code.push(c);
        }
        code
    }

    /// Parse a Recovery Kit code back into a key. Tolerant of case,
    /// separators, and Crockford's ambiguous characters; rejects any code
    /// whose checksum doesn't match (i.e. a typo).
    pub fn from_recovery_code(code: &str) -> Result<Self, CryptoError> {
        let cleaned: String = code
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .collect();
        // Fold the prefix through the same ambiguity map as the body, so a
        // "bvl…" misreading of "BV1…" still parses.
        let folded_prefix: String = cleaned
            .chars()
            .take(PREFIX.len())
            .map(|c| match c.to_ascii_uppercase() {
                'O' => '0',
                'I' | 'L' => '1',
                other => other,
            })
            .collect();
        if folded_prefix != PREFIX {
            return Err(CryptoError::Malformed(format!("missing {PREFIX} prefix")));
        }
        // Skip PREFIX.len() *characters*, not bytes: pasted input may contain
        // multibyte look-alikes, and a byte slice could panic mid-character.
        let body_start = cleaned
            .char_indices()
            .nth(PREFIX.len())
            .map(|(i, _)| i)
            .unwrap_or(cleaned.len());
        let body = &cleaned[body_start..];

        let payload = Zeroizing::new(decode_base32(body, KEY_LEN + CHECKSUM_LEN)?);
        let key: [u8; KEY_LEN] = payload[..KEY_LEN].try_into().expect("length checked");
        if checksum(&key) != payload[KEY_LEN..] {
            return Err(CryptoError::Malformed(
                "checksum mismatch — the code was mistyped".into(),
            ));
        }
        Ok(RecoveryKey::from_bytes(key))
    }
}
