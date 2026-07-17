//! Password generation from the OS CSPRNG.

use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use rand::seq::SliceRandom;
use rand::RngExt;
use serde::Deserialize;
use zeroize::Zeroizing;

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.<>?";
/// Characters commonly misread across fonts; excluded on request.
const AMBIGUOUS: &str = "Il1O0o";

#[derive(Debug, Clone, Deserialize)]
pub struct GeneratorOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    #[serde(default)]
    pub exclude_ambiguous: bool,
}

impl Default for GeneratorOptions {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GeneratorError {
    #[error("select at least one character class")]
    NoClasses,
    #[error("length must be between 4 and 256")]
    BadLength,
}

/// Generate a password guaranteed to contain at least one character from
/// every selected class (so "with digits" never yields a digit-free result),
/// with the remainder drawn uniformly from the combined pool.
pub fn generate_password(
    opts: &GeneratorOptions,
) -> Result<(Zeroizing<String>, f64), GeneratorError> {
    if !(4..=256).contains(&opts.length) {
        return Err(GeneratorError::BadLength);
    }

    let filter = |set: &'static str| -> Vec<char> {
        set.chars()
            .filter(|c| !opts.exclude_ambiguous || !AMBIGUOUS.contains(*c))
            .collect()
    };

    let mut classes: Vec<Vec<char>> = Vec::new();
    if opts.lowercase {
        classes.push(filter(LOWER));
    }
    if opts.uppercase {
        classes.push(filter(UPPER));
    }
    if opts.digits {
        classes.push(filter(DIGITS));
    }
    if opts.symbols {
        classes.push(filter(SYMBOLS));
    }
    classes.retain(|c| !c.is_empty());
    if classes.is_empty() {
        return Err(GeneratorError::NoClasses);
    }
    if opts.length < classes.len() {
        return Err(GeneratorError::BadLength);
    }

    let pool: Vec<char> = classes.iter().flatten().copied().collect();
    // SysRng is fallible by signature; a failing OS CSPRNG is fatal here, so
    // UnwrapErr converts it to the infallible interface the samplers need.
    let mut rng = UnwrapErr(SysRng);
    let mut chars: Vec<char> = Vec::with_capacity(opts.length);

    // One guaranteed pick per class…
    for class in &classes {
        chars.push(class[rng.random_range(0..class.len())]);
    }
    // …the rest uniform over the pool…
    while chars.len() < opts.length {
        chars.push(pool[rng.random_range(0..pool.len())]);
    }
    // …then shuffle so the guaranteed picks aren't positionally predictable.
    chars.shuffle(&mut rng);

    // Entropy estimate for the UI strength meter (uniform-pool approximation).
    let entropy_bits = (opts.length as f64) * (pool.len() as f64).log2();

    Ok((Zeroizing::new(chars.into_iter().collect()), entropy_bits))
}

/// The EFF Large Wordlist (7776 words, CC BY 3.0 — see the accompanying
/// `data/eff_large_wordlist.LICENSE`). Each word contributes log2(7776) ≈ 12.9
/// bits of entropy when chosen uniformly at random.
const WORDLIST: &str = include_str!("../data/eff_large_wordlist.txt");

#[derive(Debug, Clone, Deserialize)]
pub struct PassphraseOptions {
    pub words: usize,
    /// String placed between words (e.g. "-"). Empty falls back to "-".
    pub separator: String,
    /// Capitalize each word's first letter (readability; adds no entropy since
    /// it is deterministic).
    #[serde(default)]
    pub capitalize: bool,
    /// Append a random two-digit number as a final segment (+log2(100) bits).
    #[serde(default)]
    pub include_number: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self {
            words: 5,
            separator: "-".into(),
            capitalize: false,
            include_number: false,
        }
    }
}

/// Generate a diceware-style passphrase by drawing `words` words uniformly at
/// random from the EFF wordlist. Returns the passphrase and its entropy in bits
/// (word choices only — capitalization is deterministic and contributes none).
pub fn generate_passphrase(
    opts: &PassphraseOptions,
) -> Result<(Zeroizing<String>, f64), GeneratorError> {
    if !(3..=12).contains(&opts.words) {
        return Err(GeneratorError::BadLength);
    }
    let words: Vec<&str> = WORDLIST.lines().filter(|l| !l.is_empty()).collect();
    let n = words.len();
    let mut rng = UnwrapErr(SysRng);

    let mut parts: Vec<String> = Vec::with_capacity(opts.words);
    for _ in 0..opts.words {
        let word = words[rng.random_range(0..n)];
        parts.push(if opts.capitalize {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        } else {
            word.to_string()
        });
    }

    let sep = if opts.separator.is_empty() {
        "-"
    } else {
        &opts.separator
    };
    let mut phrase = parts.join(sep);
    let mut entropy_bits = (opts.words as f64) * (n as f64).log2();
    if opts.include_number {
        phrase.push_str(sep);
        phrase.push_str(&format!("{:02}", rng.random_range(0..100)));
        entropy_bits += 100f64.log2();
    }

    Ok((Zeroizing::new(phrase), entropy_bits))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn wordset() -> HashSet<&'static str> {
        WORDLIST.lines().filter(|l| !l.is_empty()).collect()
    }

    #[test]
    fn wordlist_is_the_full_eff_list() {
        assert_eq!(wordset().len(), 7776);
    }

    #[test]
    fn passphrase_has_requested_word_count_and_valid_words() {
        let words = wordset();
        let opts = PassphraseOptions {
            words: 6,
            separator: ".".into(), // '.' never occurs in a word, so parts == words
            capitalize: false,
            include_number: false,
        };
        for _ in 0..50 {
            let (phrase, entropy) = generate_passphrase(&opts).unwrap();
            let parts: Vec<&str> = phrase.split('.').collect();
            assert_eq!(parts.len(), 6);
            for p in parts {
                assert!(words.contains(p), "generated word not in list: {p}");
            }
            // 6 * log2(7776) ≈ 77.5 bits.
            assert!((entropy - 6.0 * 7776f64.log2()).abs() < 1e-6);
        }
    }

    #[test]
    fn number_option_adds_a_numeric_segment_and_entropy() {
        let opts = PassphraseOptions {
            words: 4,
            separator: ".".into(),
            capitalize: false,
            include_number: true,
        };
        let (phrase, entropy) = generate_passphrase(&opts).unwrap();
        let parts: Vec<&str> = phrase.split('.').collect();
        assert_eq!(parts.len(), 5); // 4 words + number
        assert!(parts[4].chars().all(|c| c.is_ascii_digit()));
        assert_eq!(parts[4].len(), 2);
        let expected = 4.0 * 7776f64.log2() + 100f64.log2();
        assert!((entropy - expected).abs() < 1e-6);
    }

    #[test]
    fn capitalize_uppercases_each_word() {
        let opts = PassphraseOptions {
            words: 5,
            separator: "-".into(),
            capitalize: true,
            include_number: false,
        };
        let (phrase, _) = generate_passphrase(&opts).unwrap();
        for part in phrase.split('-') {
            let first = part.chars().next().unwrap();
            assert!(first.is_uppercase(), "word not capitalized: {part}");
        }
    }

    #[test]
    fn rejects_out_of_range_word_counts() {
        for n in [0usize, 1, 2, 13, 100] {
            let opts = PassphraseOptions {
                words: n,
                ..Default::default()
            };
            assert!(generate_passphrase(&opts).is_err());
        }
    }
}
