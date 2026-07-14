# Cryptographic invariants

The rules every change to Basementen Vault must preserve. This is the
checklist a reviewer (and every future feature) runs against. Each invariant
names **where it is enforced** and **the test that guards it**, so a
regression breaks a build rather than a vault.

Requested by security review (2026-07). Keep it current: adding a feature
that touches keys, ciphertext, or randomness means re-reading this file and,
where relevant, adding a guarding test.

---

## The rules, at a glance

1. The server never possesses enough information to derive or decrypt the
   Vault Key. *(I1, I10)*
2. Every encryption operation uses authenticated encryption (AEAD). *(I4)*
3. Every key has exactly one purpose; HKDF/AAD labels are never reused. *(I5)*
4. The AuthKey never decrypts data. *(I2)*
5. The WrappingKey never authenticates and never leaves the client. *(I1, I2)*
6. Every nonce is unique (fresh from the CSPRNG). *(I3, I6)*
7. Every ciphertext carries authenticated associated data binding its
   context, purpose, and version. *(I4, I12)*
8. Every client validates the crypto version before use. *(I12)*
9. Password-derived keys use Argon2id with validated, versioned parameters. *(I7)*
10. Secret material is zeroized and never logged or `Debug`-printed. *(I8, I9)*
11. Recovery never becomes "prove control of e-mail → receive vault". *(I11)*
12. The KDF salt is account-lifetime (never rotated). *(I13)*
13. The sync sequence is authenticated against whole-vault rollback. *(I14)*

The numbered invariants below give the enforcement point and guarding test
for each. (Rules 1–8 map to the reviewer's proposed checklist.)

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

### I12 — Every persisted crypto record binds its version/algorithm into AAD
The format version is authenticated, not just present, so a record of one
version can never be confused for another (crypto-agility safety). Item AAD
binds `version + item_id + revision`; wrapped-key AAD binds `purpose +
version`; export AAD binds `version` (and the KDF parameters implicitly, since
they key the derivation). Clients also validate the version with an explicit
equality check before use.
- **Enforced:** `item.rs::aad_for`, `envelope.rs::wrap_aad`,
  `export.rs::export_aad`; version checks in `decrypt_item`/`unwrap`/
  `decrypt_export`.
- **Guarded by:** `crypto_flows::item_binds_version_in_aad`,
  `recovery_wrap_cannot_be_confused_with_master_wrap`, and the export
  round-trip/tamper proptests.

### I14 — Sync sequence is authenticated against rollback
The global sync sequence is defended two ways: every client keeps a durable
monotonic `last_seq` and refuses a pull that regresses below it; and clients
publish a vault-key-MAC'd checkpoint `HKDF(VaultKey, "sync-checkpoint" ‖ seq)`
that any device verifies and the server can neither forge nor raise. A server
serving data below a checkpoint it presents is caught as withholding.
- **Enforced:** `vault-sync::engine` (monotonic guard),
  `keys.rs::VaultKey::{sync_checkpoint_tag, verify_sync_checkpoint}`,
  `desktop-core::rollback::synchronize`, server `routes/items` checkpoint.
- **Guarded by:** `sync_flows::server_rollback_is_detected`,
  `crypto_flows::sync_checkpoint_tag_is_deterministic_key_and_seq_bound`,
  `desktop_core::{checkpoint_published_and_verified, forged_checkpoint_is_rejected,
  withholding_committed_data_is_detected}`.

### I13 — The KDF salt is account-lifetime
A random salt is generated once at registration and **never rotated** — not
on password change, not on recovery. It is not secret, and the derived key
already changes when the password changes, so rotating it would only add
state that must stay synchronized. `recover_and_rekey` / `change_password`
take the existing salt; `recovery/data` returns it.
- **Enforced:** `account.rs` (only `register` calls `generate_salt`); server
  `recovery/complete` stores the client-supplied (unchanged) salt.
- **Guarded by:** `crypto_flows::{full_recovery_flow_preserves_vault_data,
  change_password_keeps_vault_key_and_rotates_credentials}` assert the salt
  is preserved; `recovery_flows` asserts `recovery/data` returns the original.

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
