//! Plaintext item schema (what lives *inside* the encrypted envelopes) and
//! search over decrypted items.

use serde::{Deserialize, Serialize};
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// A decrypted vault item. Tagged JSON so new types can be added without
/// breaking old clients (unknown types round-trip as `Other`).
///
/// Holds the most sensitive plaintext in the client (passwords, card numbers,
/// notes), so it is `ZeroizeOnDrop`: the moment an `Item` goes out of scope its
/// string fields are scrubbed. `Debug` is redacted (never print secret fields —
/// invariant I8). Note this only governs the Rust-side lifetime; a copy handed
/// to the web UI for display lives in the JavaScript heap beyond our reach (see
/// `docs/THREAT_MODEL.md` §A6).
#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Item {
    Login {
        name: String,
        #[serde(default)]
        username: String,
        #[serde(default)]
        password: String,
        #[serde(default)]
        url: String,
        #[serde(default)]
        notes: String,
        #[serde(default)]
        tags: Vec<String>,
    },
    Note {
        name: String,
        #[serde(default)]
        notes: String,
        #[serde(default)]
        tags: Vec<String>,
    },
    Card {
        name: String,
        #[serde(default)]
        cardholder: String,
        #[serde(default)]
        number: String,
        #[serde(default)]
        expiry: String,
        #[serde(default)]
        code: String,
        #[serde(default)]
        notes: String,
        #[serde(default)]
        tags: Vec<String>,
    },
}

/// Redacted `Debug`: shows the item kind and nothing else, so an accidental
/// `{:?}` (a log line, a panic message) can never spill a password or note.
impl core::fmt::Debug for Item {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Item::{}(<redacted>)", self.kind())
    }
}

impl Item {
    pub fn name(&self) -> &str {
        match self {
            Item::Login { name, .. } | Item::Note { name, .. } | Item::Card { name, .. } => name,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Item::Login { .. } => "login",
            Item::Note { .. } => "note",
            Item::Card { .. } => "card",
        }
    }

    /// Serialize for encryption. `Zeroizing` so the plaintext buffer is
    /// scrubbed after the envelope is sealed.
    pub fn to_plaintext(&self) -> Result<Zeroizing<Vec<u8>>, serde_json::Error> {
        Ok(Zeroizing::new(serde_json::to_vec(self)?))
    }

    pub fn from_plaintext(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// Case-insensitive substring match over the item's searchable fields.
    /// Passwords and card numbers are deliberately NOT searchable.
    pub fn matches(&self, query: &str) -> bool {
        let q = query.trim().to_lowercase();
        if q.is_empty() {
            return true;
        }
        let haystacks: Vec<&str> = match self {
            Item::Login {
                name,
                username,
                url,
                tags,
                ..
            } => {
                let mut h = vec![name.as_str(), username.as_str(), url.as_str()];
                h.extend(tags.iter().map(|t| t.as_str()));
                h
            }
            Item::Note { name, tags, .. } => {
                let mut h = vec![name.as_str()];
                h.extend(tags.iter().map(|t| t.as_str()));
                h
            }
            Item::Card {
                name,
                cardholder,
                tags,
                ..
            } => {
                let mut h = vec![name.as_str(), cardholder.as_str()];
                h.extend(tags.iter().map(|t| t.as_str()));
                h
            }
        };
        haystacks.iter().any(|h| h.to_lowercase().contains(&q))
    }
}

/// What the list view needs — no secrets.
#[derive(Debug, Clone, Serialize)]
pub struct ItemSummary {
    pub item_id: String,
    pub kind: &'static str,
    pub name: String,
    pub subtitle: String,
}

impl ItemSummary {
    pub fn of(item_id: &str, item: &Item) -> Self {
        let subtitle = match item {
            Item::Login { username, url, .. } => {
                if username.is_empty() {
                    url.clone()
                } else {
                    username.clone()
                }
            }
            Item::Note { .. } => String::new(),
            Item::Card { number, .. } => {
                // Last four digits only.
                let digits: String = number.chars().filter(|c| c.is_ascii_digit()).collect();
                if digits.len() >= 4 {
                    format!("•••• {}", &digits[digits.len() - 4..])
                } else {
                    String::new()
                }
            }
        };
        Self {
            item_id: item_id.to_string(),
            kind: item.kind(),
            name: item.name().to_string(),
            subtitle,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_prints_secret_fields() {
        let item = Item::Login {
            name: "example.com".into(),
            username: "alice".into(),
            password: "hunter2-super-secret".into(),
            url: "https://example.com".into(),
            notes: "private note".into(),
            tags: vec![],
        };
        let rendered = format!("{item:?}");
        assert_eq!(rendered, "Item::login(<redacted>)");
        assert!(!rendered.contains("hunter2"));
        assert!(!rendered.contains("private note"));
    }
}
