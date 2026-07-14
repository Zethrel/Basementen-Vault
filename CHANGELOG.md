# Changelog

All notable changes to Basementen Vault are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it
reaches 1.0.

> **Status:** everything below is pre-release development toward 1.0. **No
> version has been published, and the project has not had an independent
> security audit** (a hard prerequisite before real-world use — see
> `SECURITY.md` and `docs/RUNBOOK.md`). On-disk/on-the-wire formats are
> versioned but may still change before 1.0.

## [Unreleased]

### Added

- **Zero-knowledge crypto core** (`vault-core`): Argon2id key derivation, an
  HKDF key hierarchy (Master Key → independent Auth / Wrapping keys),
  XChaCha20-Poly1305 envelope encryption, and per-item authenticated
  encryption. The server can never derive or decrypt the Vault Key.
- **Self-hostable server** (`vault-server`, axum + SQLite): registration with
  e-mail verification, login, opaque bearer tokens stored only as SHA-256 with
  single-use refresh rotation, TOTP MFA with single-use recovery codes,
  progressive per-account lockout, per-IP rate limiting, anti-enumeration, and
  baseline security headers.
- **Encrypted item storage + revision-based delta sync** API, and an
  offline-first, transport-agnostic sync engine (`vault-sync`).
- **Desktop app** (Tauri 2 — Windows / macOS / Linux) over a shared client core
  (`desktop-core`): encrypted local replica, session auto-lock, password
  generator, item editor, and client-side search.
- **Mobile-ready**: the same codebase builds for Android and iOS; responsive UI.
- **Account recovery**: a printable Recovery Kit (verifier-gated,
  data-preserving) plus an optional verified trusted backup e-mail with a
  cooling-off period; the only e-mail-only path is an explicit, loud wipe.
- **Encrypted export + import** (including Bitwarden CSV).
- **Two-factor (TOTP) enrollment in the app**: scannable QR + manual key,
  activation, one-time recovery codes, regenerate, and disable.
- **Change master password in the app**: re-wraps the (unchanged) Vault Key so
  items stay readable, issues a fresh Recovery Kit, and signs out other devices.
- **Device/session management UI**: list active devices and revoke one or all
  others; absolute 90-day session lifetime cap.
- **Master-password strength enforcement** (client-side, at registration *and*
  recovery): composition rules (≥12 chars + capital + number + special), a Have
  I Been Pwned breached-password check via k-anonymity (only a 5-char SHA-1
  prefix leaves the device), and zxcvbn guessability scoring.
- Brand identity: logo, color theme, and application icons.

### Security

- **Random per-account KDF salt**, account-lifetime (never rotated, including
  through recovery and password change).
- **Crypto record versions bound into AEAD associated data** (items, wrapped
  keys, exports) so a record of one version can't be passed off as another.
- **Session/auth hardening**: absolute session cap, refresh-token-reuse
  detection that revokes the whole session family, activity tracking, and
  dead-session cleanup.
- **Sync rollback protection**: a per-device monotonic sequence guard, a
  vault-key-MAC'd cross-device checkpoint (the server can neither forge nor
  lower it), and withholding detection — surfaced to the user, never silent.
- **TOTP one-time use** (a code can't be replayed within its window),
  **new-device sign-in e-mail alerts**, and device-name sanitization.
- **Item-size padding** (`EncryptedItem` v2, 256-byte buckets) so stored
  ciphertext length no longer approximates content length; v1 items still
  decrypt and migrate on next write.
- **Key pages locked out of swap** (`mlock` / `VirtualLock`) and **core dumps
  suppressed** at startup, so key material isn't written to disk. The `unsafe`
  syscalls live in dependencies; first-party crates remain `forbid(unsafe)`.
- **Decrypted plaintext scrubbed** on drop (`Zeroizing` / `ZeroizeOnDrop`), with
  a documented in-memory-plaintext map and honest residuals (`THREAT_MODEL` §A6).
- **Enumeration secret persisted** across server restarts, closing a weak
  cross-restart account-enumeration signal.

### Changed

- Migrated the client KDF salt from **e-mail-derived to random per-account**
  (and then to account-lifetime). This changed `vault-core` public signatures —
  the e-mail no longer participates in key derivation and can change freely.
- Shipped the server on **SQLite with opaque hashed bearer tokens** (the initial
  plan proposed PostgreSQL + PASETO/JWT); documented the rationale.

### Documentation

- Design and operations docs: `IMPLEMENTATION_PLAN`, `THREAT_MODEL`,
  `CRYPTOGRAPHIC_INVARIANTS`, `METADATA`, `SELF_HOSTING`, `RUNBOOK`, `MOBILE`,
  `REVIEW_RESPONSE`, and `RELEASE_CHECKLIST`.
- Added `LICENSE` (GNU AGPL-3.0-only) and `SECURITY.md` (vulnerability
  disclosure policy, scope, and safe harbor).
- Responded to three rounds of external architecture review plus follow-on
  hardening passes; reconciled documentation inconsistencies.

### Known limitations (not yet addressed)

- **No independent security audit yet** — the blocker before production use.
- Deferred by design and tracked in `THREAT_MODEL` §Known gaps:
  sender-constrained (DPoP/mTLS) tokens, WebAuthn/passkeys, mobile Argon2
  parameter benchmarking, and the WebView / JavaScript-heap plaintext residual.

[Unreleased]: https://github.com/Zethrel/Basementen-Vault/commits/main
