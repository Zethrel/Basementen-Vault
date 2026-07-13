//! Password generation from the OS CSPRNG.

use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::Rng;
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
    let mut rng = OsRng;
    let mut chars: Vec<char> = Vec::with_capacity(opts.length);

    // One guaranteed pick per class…
    for class in &classes {
        chars.push(class[rng.gen_range(0..class.len())]);
    }
    // …the rest uniform over the pool…
    while chars.len() < opts.length {
        chars.push(pool[rng.gen_range(0..pool.len())]);
    }
    // …then shuffle so the guaranteed picks aren't positionally predictable.
    chars.shuffle(&mut rng);

    // Entropy estimate for the UI strength meter (uniform-pool approximation).
    let entropy_bits = (opts.length as f64) * (pool.len() as f64).log2();

    Ok((Zeroizing::new(chars.into_iter().collect()), entropy_bits))
}
