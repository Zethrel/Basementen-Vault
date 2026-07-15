//! Master-password strength policy.
//!
//! Enforced entirely client-side: the server is zero-knowledge and never sees
//! the password (only the derived AuthKey), so this is the only place the rule
//! can live. Applied wherever the master password is *set* — registration and
//! recovery — so recovery can't be used to slip a weak password past the check.
//!
//! Policy shape (following NIST SP 800-63B): a generous **length floor** plus a
//! **zxcvbn guessability** bar, and deliberately *no* composition rules
//! (required capital/number/symbol). Composition rules reject strong passphrases
//! like `correct horse battery staple` while doing little to stop weak-but-
//! compliant passwords such as `Password123!` — zxcvbn catches the latter far
//! more reliably, so it does the real work here.

/// Minimum master-password length (characters, Unicode-aware). A high floor is
/// cheap protection: it makes a passphrase the natural way to comply and rules
/// out short strings that zxcvbn might still rate acceptable.
pub const MIN_PASSWORD_LEN: usize = 14;

/// Validate the master password's length floor. On failure returns a single
/// human-readable message. Guessability is checked separately by
/// [`check_password_guessability`]; run both wherever the password is set.
pub fn check_password_strength(password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        Err(format!(
            "Weak master password — it needs at least {MIN_PASSWORD_LEN} characters. \
             A memorable passphrase of a few words is the easiest way to get there."
        ))
    } else {
        Ok(())
    }
}

/// Minimum acceptable zxcvbn score (0–4). 3 = "safely unguessable" under an
/// offline slow-hash attack — the right bar for a master password.
const MIN_ZXCVBN_SCORE: zxcvbn::Score = zxcvbn::Score::Three;

/// Reject a password the length floor accepts but a zxcvbn-style estimator finds
/// too guessable: common passwords, dictionary words, keyboard walks, dates,
/// repeats, or anything resembling `user_inputs` (pass the e-mail so an address-
/// derived password is penalised). Complements [`check_password_strength`]; run
/// it alongside the length check.
///
/// Returns a message that includes zxcvbn's own warning/suggestion when it has
/// one, so the user learns *why* it was rejected.
pub fn check_password_guessability(password: &str, user_inputs: &[&str]) -> Result<(), String> {
    let entropy = zxcvbn::zxcvbn(password, user_inputs);
    if entropy.score() >= MIN_ZXCVBN_SCORE {
        return Ok(());
    }
    let mut msg = String::from("This password is too easy to guess.");
    if let Some(feedback) = entropy.feedback() {
        if let Some(warning) = feedback.warning() {
            msg.push_str(&format!(" {warning}"));
        }
        if let Some(suggestion) = feedback.suggestions().first() {
            msg.push_str(&format!(" {suggestion}"));
        }
    }
    Err(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_a_long_passphrase_without_symbols() {
        // The canonical example that composition rules used to (wrongly) reject.
        assert!(check_password_strength("correct horse battery staple").is_ok());
        // A symbol-heavy password of sufficient length is fine too.
        assert!(check_password_strength("7#kQ9mZ!vB2wLxr").is_ok());
    }

    #[test]
    fn rejects_too_short() {
        let err = check_password_strength("Abc1!def").unwrap_err();
        assert!(err.contains("14 characters"), "{err}");
    }

    #[test]
    fn length_counts_unicode_scalars_not_bytes() {
        // 13 characters (each multi-byte) is still too short despite the byte
        // length being well over the floor.
        assert_eq!("Œufs-du-café!".chars().count(), 13);
        assert!(check_password_strength("Œufs-du-café!").is_err());
    }

    #[test]
    fn guessability_rejects_a_long_but_predictable_password() {
        // Long enough to pass the length floor, yet a textbook weak password —
        // zxcvbn must catch it where composition rules never would.
        assert!(check_password_strength("Password123456").is_ok());
        let err = check_password_guessability("Password123456", &[]).unwrap_err();
        assert!(err.to_lowercase().contains("guess"), "{err}");
    }

    #[test]
    fn guessability_accepts_a_high_entropy_password() {
        assert!(check_password_guessability("7#kQ9mZ!vB2wLxr", &[]).is_ok());
    }

    #[test]
    fn guessability_penalises_user_inputs() {
        // A distinctive string scores well on its own, but reusing it verbatim
        // as the password is caught once it's supplied as context (the e-mail).
        let email = "Zaphod-Beeblebrox-42@example.com";
        assert!(
            check_password_guessability(email, &[email]).is_err(),
            "a password equal to a known user input must be rejected"
        );
    }
}
