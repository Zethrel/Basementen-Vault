//! Master-password strength policy.
//!
//! Enforced entirely client-side: the server is zero-knowledge and never sees
//! the password (only the derived AuthKey), so this is the only place the rule
//! can live. Applied wherever the master password is *set* — registration and
//! recovery — so recovery can't be used to slip a weak password past the check.

/// Minimum master-password length (characters, Unicode-aware).
pub const MIN_PASSWORD_LEN: usize = 12;

/// A "special" character: anything that is not a letter, a digit, or
/// whitespace (so a symbol like `!@#-_`), keeping spaces from counting.
fn is_special(c: char) -> bool {
    !c.is_alphanumeric() && !c.is_whitespace()
}

/// Validate the master password against the strength policy. On failure returns
/// a single human-readable message naming *every* unmet requirement, so the UI
/// can show the user exactly what to fix in one go.
pub fn check_password_strength(password: &str) -> Result<(), String> {
    let mut unmet: Vec<&str> = Vec::new();

    if password.chars().count() < MIN_PASSWORD_LEN {
        unmet.push("at least 12 characters");
    }
    if !password.chars().any(|c| c.is_uppercase()) {
        unmet.push("a capital letter");
    }
    if !password.chars().any(|c| c.is_ascii_digit()) {
        unmet.push("a number");
    }
    if !password.chars().any(is_special) {
        unmet.push("a special character");
    }

    if unmet.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "Weak master password — it needs {}.",
            join_with_and(&unmet)
        ))
    }
}

/// Join clauses as "a, b, and c" (Oxford comma), or "a and b", or "a".
fn join_with_and(items: &[&str]) -> String {
    match items {
        [] => String::new(),
        [only] => only.to_string(),
        [a, b] => format!("{a} and {b}"),
        [rest @ .., last] => format!("{}, and {last}", rest.join(", ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_a_strong_password() {
        assert!(check_password_strength("Abcdef123!xyz").is_ok());
        // Unicode capital + symbol also satisfy the policy.
        assert!(check_password_strength("Œufs-du-matin9").is_ok());
    }

    #[test]
    fn reports_each_missing_requirement() {
        let too_short = check_password_strength("Ab1!").unwrap_err();
        assert!(too_short.contains("12 characters"), "{too_short}");

        assert!(check_password_strength("abcdefghij1!")
            .unwrap_err()
            .contains("a capital letter"));
        assert!(check_password_strength("Abcdefghij!!")
            .unwrap_err()
            .contains("a number"));
        assert!(check_password_strength("Abcdefghij12")
            .unwrap_err()
            .contains("a special character"));
    }

    #[test]
    fn aggregates_multiple_failures() {
        // 12 lowercase letters: missing capital, number, and special.
        let err = check_password_strength("abcdefghijkl").unwrap_err();
        assert!(err.contains("a capital letter"));
        assert!(err.contains("a number"));
        assert!(err.contains("a special character"));
        assert!(err.contains(", and "), "uses an Oxford comma: {err}");
    }

    #[test]
    fn spaces_do_not_count_as_special() {
        // A passphrase with spaces but no symbol still needs a special char.
        assert!(check_password_strength("Abcd 1234 wxyz")
            .unwrap_err()
            .contains("a special character"));
    }
}
