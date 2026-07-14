# Cryptographic invariants

The rules every change to Basementen Vault must preserve. This is the
checklist a reviewer (and every future feature) runs against. Each invariant
names **where it is enforced** and **the test that guards it**, so a
regression breaks a build rather than a vault.

Requested by security review (2026-07). Keep it current: adding a feature
that touches keys, ciphertext, or randomness means re-reading this file and,
where relevant, adding a guarding test.

---

## The invariants

### I1 — Encryption keys never leave the client unencrypted
The Master Key, Wrapping Key, and Vault Key exist only in client memory. The
server stores the Vault Key solely as `XChaCha20-Poly1305` ciphertext
(`WrappedKey`), and only ever receives the AuthKey (a one-way branch) and
opaque wrapped/encrypted blobs.
- **Enforced:** `keys.rs` (no byte-export on `MasterKey`/`WrappingKey`/
  `VaultKey`; only `AuthKey::to_server_credential` is public), `account.rs`
  (`RegistrationBundle` carries only the credential + ciphertext).
- **Guarded by:** `crypto_flows::server_known_credential_cannot_decrypt_vault_key`,
  `auth_credential_cannot_unwrap_vault_key`.

### I2 — The AuthKey can never decrypt data
Authentication and encryption are cryptographically independent branches:
`AuthKey = HKDF(MK, "…/auth-key")`, `WrappingKey = HKDF(MK, "…/wrapping-key")`.
Knowing one reveals nothing about the other.
- **Enforced:** `keys.rs::MasterKey::derive_subkeys` (distinct HKDF `info`).
- **Guarded by:** `server_known_credential_cannot_decrypt_vault_key` keys the
  wrap cipher with the AuthKey and asserts decryption fails.

### I3 — Every ciphertext uses a fresh, random nonce
Nonces come from `XChaCha20Poly1305::generate_nonce(&mut OsRng)` at every
encryption; XChaCha20's 192-bit nonce makes random generation collision-safe.
No nonce is ever derived, counted, or reused.
- **Enforced:** `item.rs`, `envelope.rs`, `export.rs`.
- **Guarded by:** `crypto_flows::item_nonces_are_unique_per_encryption`;
  `proptests::item_crypto_roundtrip_and_tamper`.

### I4 — Every ciphertext is authenticated (AEAD), and context is bound
All encryption is AEAD (Poly1305 tag). Item ciphertexts additionally bind
`item_id` + `revision` as associated data (anti-swap, anti-rollback of a
single item); wrapped keys bind their purpose (master vs recovery); exports
bind a format tag.
- **Enforced:** `item.rs::aad_for`, `envelope.rs::WrapPurpose::aad`,
  `export.rs` AAD.
- **Guarded by:** `item_binds_id_and_revision`, `item_rejects_wrong_key_and_tampering`,
  `recovery_wrap_cannot_be_confused_with_master_wrap`,
  `proptests::{item_crypto_roundtrip_and_tamper, export_roundtrip_and_tamper}`.

### I5 — Every key/HKDF label has exactly one purpose; `info` strings are never reused
Each HKDF expansion and each AEAD associated-data context uses a distinct,
versioned, domain-separated constant. Reusing a label across purposes is a
breaking change and forbidden.
- **Enforced:** the `INFO_*` / AAD constants in `keys.rs`, `kdf.rs`,
  `envelope.rs`, `item.rs`, `export.rs` (all `basementen-vault/v1/…`).
- **Review action:** adding a new derivation means adding a new label, never
  reusing one. No two constants may share a string.

### I6 — Randomness comes only from the OS CSPRNG
All salts, nonces, keys, and tokens are drawn from `OsRng` (client) or
`rand::rngs::OsRng` (server). No PRNG is seeded from time, counters, or
user input.
- **Enforced:** `keys.rs` (`VaultKey`/`RecoveryKey::generate`),
  `kdf.rs`, `export.rs`, server `security.rs` (`new_token`, salts, TOTP,
  recovery codes).
- **Review action:** grep for any non-`OsRng` randomness in a diff → reject.

### I7 — Password-derived keys use Argon2id with validated, versioned parameters
Argon2id only; parameters are per-account, versioned, and validated against
the OWASP floor (`MIN_MEMORY_KIB=19456, MIN_ITERATIONS=2, MIN_PARALLELISM=1`)
on **both** client derivation and server-side registration.
- **Enforced:** `kdf.rs::{KdfParams::validate, derive_master_key}`,
  server `routes/accounts.rs` (rejects sub-floor `kdf_params`).
- **Guarded by:** `crypto_flows::kdf_rejects_parameters_below_floor`;
  `proptests::kdf_params_validation_total` (total over the `u32` space).

### I8 — Secret material is zeroized and never `Debug`-printed
Key types are `#[derive(Zeroize, ZeroizeOnDrop)]`; transient plaintext buffers
use `Zeroizing`; every secret's `Debug` prints `<redacted>`; key equality is
constant-time.
- **Enforced:** `keys.rs` (`key_type!` macro), `account.rs`
  (`AccountSecrets` Debug), `kdf.rs`/`export.rs`/`item.rs` (`Zeroizing`).
- **Guarded by:** compile-time (`Debug` impls) + `unsafe_code = "forbid"`
  workspace-wide. See `THREAT_MODEL.md` §A6 for the honest limits (no page
  locking / core-dump suppression yet).

### I9 — No plaintext secret is written to logs
Server logging never includes passwords, credentials, keys, tokens, or vault
plaintext. (The dev-only `console` mailer prints e-mail bodies, which contain
recovery/verification *tokens* — acceptable only because it is a local
development backend, never a production one.)
- **Enforced:** audited in `server/vault-server/src`; the API returns opaque
  error codes, not secret values.
- **Review action:** `grep -rE 'tracing::(info|debug|warn|error)!'` over a
  diff must show no secret in the fields. CI-greppable.

### I10 — The server verifies identity without ever being able to impersonate or decrypt
The server stores `Argon2id(AuthKey, random per-account salt)` — a second
stacked derivation — plus only hashes of session/recovery tokens. A database
leak yields nothing that logs in or decrypts.
- **Enforced:** `security.rs::{hash_credential, new_token}`, schema stores
  `*_hash` columns only.
- **Guarded by:** `api_flows::refresh_rotates_and_detects_reuse`,
  `recovery_flows::without_kit_requires_explicit_wipe_and_destroys_items`.

### I11 — Recovery preserves zero-knowledge
A data-preserving recovery requires proof of Recovery-Kit possession (the
`recovery_verifier`, an HKDF branch of the Vault Key stored only as SHA-256).
E-mail access alone can only trigger an explicit, destructive wipe after the
cooling-off period.
- **Enforced:** `keys.rs::VaultKey::recovery_verifier`, server
  `routes/recovery.rs`.
- **Guarded by:** the six `recovery_flows` tests.

---

## Salt (design note)

The client KDF salt is a **random 128-bit per-account value**
(`kdf::generate_salt`), created once at registration, stored server-side, and
returned by `prelogin`. The account **e-mail does not enter key derivation**;
it is an identifier only.

Rationale (this replaced an earlier e-mail-derived salt after a security
review — see `docs/REVIEW_RESPONSE.md`):

- **Robustness:** an e-mail-derived salt required byte-identical e-mail
  normalization on every platform (Windows/macOS/Linux/Android/iOS/extension)
  or a user could derive a different key and be locked out. A random salt is
  independent of identity and removes that entire failure class.
- **E-mail can change** without touching keys or rewrapping the vault.
- **No lost benefit:** the only advantage of a deterministic e-mail salt was
  deriving before contacting the server; our flows already call `prelogin`
  (which now returns the salt) before every derivation, and offline unlock
  reads the cached salt from `AccountMeta`.
- **Standard + auditable:** random-salt-in-DB is what most password managers
  do and is simpler to reason about.

**Anti-enumeration:** `prelogin` for an unknown e-mail must not reveal that
the account doesn't exist. It returns a *stable, unpredictable* dummy salt =
`HMAC-SHA256(server_enumeration_secret, normalized_email)[..16]`. Stable so
repeated queries match (a real account has a fixed stored salt); unpredictable
so an attacker without the server secret cannot compute the "expected" dummy
and diff it against the response. Enforced in `routes/accounts::prelogin` +
`security::dummy_kdf_salt`; guarded by
`api_flows::unknown_email_fails_indistinguishably`.

The server additionally applies its own **random** per-account salt to the
Argon2id pass over the AuthKey (I10), independent of this client salt.

---

## How to use this file

1. Writing a feature that touches keys, ciphertext, randomness, or logging?
   Re-read I1–I11 first.
2. Adding a derivation or AEAD context? Add a new versioned label (I5), never
   reuse one.
3. Prefer to make an invariant a *test*, not a comment. The `crypto_flows`
   and `proptests` suites are where guards live.
