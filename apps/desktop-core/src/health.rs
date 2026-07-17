//! Vault health analysis: find weak and reused login passwords.
//!
//! Runs entirely on decrypted items in memory and returns a report that holds
//! **no passwords** — only per-item strength scores, a reuse flag, ids and
//! names — so the report can be handed to the UI without widening the secret's
//! exposure. Breach checking (HIBP) is a separate, network-bound step layered on
//! top by the caller; this module is deterministic and offline so it stays unit
//! testable.

use serde::Serialize;
use std::collections::HashMap;
use zeroize::Zeroizing;

/// One login item's password, ready for analysis. The password is `Zeroizing`
/// so the caller's transient copy is scrubbed when the input vector drops.
pub struct HealthEntry {
    pub item_id: String,
    pub name: String,
    pub password: Zeroizing<String>,
}

/// One flagged item in the report (weak, reused, or both). No password.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ItemHealth {
    pub item_id: String,
    pub name: String,
    /// zxcvbn strength, 0 (worst) – 4 (best).
    pub score: u8,
    /// The password is shared with at least one other item.
    pub reused: bool,
}

/// Summary + the flagged items, weakest first.
#[derive(Debug, Clone, Serialize, Default, PartialEq, Eq)]
pub struct HealthReport {
    /// Only items with a problem (weak and/or reused), weakest first.
    pub items: Vec<ItemHealth>,
    pub weak_count: usize,
    pub reused_count: usize,
    /// How many login items with a non-empty password were examined.
    pub total_with_password: usize,
}

/// A score at or below this is treated as "weak" and surfaced.
const WEAK_SCORE_MAX: u8 = 2;

fn score_u8(s: zxcvbn::Score) -> u8 {
    match s {
        zxcvbn::Score::Zero => 0,
        zxcvbn::Score::One => 1,
        zxcvbn::Score::Two => 2,
        zxcvbn::Score::Three => 3,
        zxcvbn::Score::Four => 4,
        // zxcvbn::Score is non-exhaustive; treat anything unknown as strongest
        // so we never invent a false "weak" flag.
        _ => 4,
    }
}

/// Analyze the given login passwords for weakness (zxcvbn ≤ 2) and reuse (the
/// same password on more than one item).
pub fn analyze(entries: &[HealthEntry]) -> HealthReport {
    // Group item indices by password to find reuse. The map borrows the
    // passwords and lives only for this call.
    let mut groups: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, e) in entries.iter().enumerate() {
        groups.entry(e.password.as_str()).or_default().push(i);
    }
    let mut reused = vec![false; entries.len()];
    for ids in groups.values() {
        if ids.len() > 1 {
            for &i in ids {
                reused[i] = true;
            }
        }
    }

    let mut items = Vec::new();
    let mut weak_count = 0;
    let mut reused_count = 0;
    for (i, e) in entries.iter().enumerate() {
        let score = score_u8(zxcvbn::zxcvbn(&e.password, &[]).score());
        let is_weak = score <= WEAK_SCORE_MAX;
        let is_reused = reused[i];
        if is_weak {
            weak_count += 1;
        }
        if is_reused {
            reused_count += 1;
        }
        if is_weak || is_reused {
            items.push(ItemHealth {
                item_id: e.item_id.clone(),
                name: e.name.clone(),
                score,
                reused: is_reused,
            });
        }
    }
    // Weakest score first; among equal scores, reused before not-reused.
    items.sort_by(|a, b| a.score.cmp(&b.score).then(b.reused.cmp(&a.reused)));

    HealthReport {
        items,
        weak_count,
        reused_count,
        total_with_password: entries.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, name: &str, pw: &str) -> HealthEntry {
        HealthEntry {
            item_id: id.into(),
            name: name.into(),
            password: Zeroizing::new(pw.into()),
        }
    }

    #[test]
    fn flags_reuse_across_items() {
        let entries = vec![
            entry("1", "Bank", "9xQ!vekf2Rt#mZ7p"),
            entry("2", "Shop", "9xQ!vekf2Rt#mZ7p"), // same strong password, reused
        ];
        let r = analyze(&entries);
        assert_eq!(r.reused_count, 2);
        assert!(r.items.iter().all(|i| i.reused));
        // Strong but reused → still surfaced.
        assert_eq!(r.items.len(), 2);
    }

    #[test]
    fn flags_weak_password() {
        let entries = vec![entry("1", "Email", "password123")];
        let r = analyze(&entries);
        assert_eq!(r.weak_count, 1);
        assert_eq!(r.items.len(), 1);
        assert!(r.items[0].score <= WEAK_SCORE_MAX);
        assert!(!r.items[0].reused);
    }

    #[test]
    fn strong_unique_passwords_are_clean() {
        let entries = vec![
            entry("1", "Bank", "9xQ!vekf2Rt#mZ7p"),
            entry("2", "Shop", "Tz4$Lp0aWn8&qH2u"),
        ];
        let r = analyze(&entries);
        assert_eq!(r.weak_count, 0);
        assert_eq!(r.reused_count, 0);
        assert!(r.items.is_empty());
        assert_eq!(r.total_with_password, 2);
    }

    #[test]
    fn weakest_first_ordering() {
        let entries = vec![
            entry("strong", "Strong", "Tz4$Lp0aWn8&qH2u"),
            entry("weak", "Weak", "123456"),
        ];
        let r = analyze(&entries);
        // Only the weak one is flagged, and it leads.
        assert_eq!(r.items[0].item_id, "weak");
    }
}
