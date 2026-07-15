# Changelog

All notable changes to Basementen Vault are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it
reaches 1.0.

> **Status:** the current tagged release is **1.0.0-beta.3**. It is an
> **unaudited beta** — the project has **not** had an independent security audit
> (a hard prerequisite before real-world use; see `SECURITY.md` and
> `docs/RUNBOOK.md`). Do not store irreplaceable secrets in it yet. On-disk /
> on-the-wire formats are versioned but may still change before a final 1.0.0.

## [Unreleased]

Documentation and supply-chain follow-ups from a third review pass, plus a CI
trigger fix. No code paths in the app or server changed.

- **Breaking changes:** None.
- **Migration required:** No.

### Supply chain

- **`cargo deny` in CI** (`deny.toml`): security advisories (same RustSec
  database as `cargo audit`), banned/duplicate crates, and a source-registry
  allow-list, on every push. Replaces the separate `rustsec/audit-check` job,
  which was a redundant second advisory copy that couldn't honour ignores. The
  license gate is configured but not yet enforced (allow-list pending a
  full-tree review — noted in `deny.toml`).
- **Fixed the CI trigger.** `ci.yml` fired only on push to `main`, but the
  working branch is the default branch and takes direct commits — so fmt,
  clippy, tests, and advisory scanning had **not** been running automatically.
  CI now runs on every push and pull request. The first real run surfaced the
  items below.
- **Triaged the advisories the first CI run found**, all transitive and
  unreachable, ignored with written justifications in `deny.toml` and
  `THREAT_MODEL` §A7: `rsa` Marvin (RUSTSEC-2023-0071 — not compiled into any
  binary), `quick-xml` DoS (RUSTSEC-2026-0194/-0195 — build-time parse of
  trusted Wayland XML), and the archived gtk-rs GTK3 stack incl. `glib`
  unsoundness (Tauri's Linux backend).

### Fixed

- **Clippy lint** (`unnecessary_sort_by`) in the desktop search command,
  surfaced by the now-working CI. Behaviour unchanged.

### Documentation

- Documented `secure_delete`'s **limits** (no reach into WAL/SHM history,
  filesystem/volume snapshots, backups, or SSD wear-levelled blocks) and its
  minor write-amplification cost — so "secure delete" is not mistaken for
  unrecoverable erasure (`THREAT_MODEL` §A6).
- Documented that **client-side search touches no plaintext on disk**: it runs
  in memory over decrypted items, keeps no persistent search index, and
  excludes passwords and card numbers from the searchable fields (§A6).
- Stated the **no-telemetry** posture explicitly: no analytics, crash
  reporting, or phone-home; panic messages aren't built from secrets and core
  dumps are suppressed (§A7).

## [1.0.0-beta.3] - 2026-07-15

Follow-up hardening from a second external review pass.

- **Breaking changes:** None.
- **Migration required:** No — on-disk and on-the-wire formats are unchanged;
  existing vaults are unaffected.

### Changed

- **Master-password policy follows NIST SP 800-63B.** Dropped the composition
  requirements (a capital, a number, a special character) in favour of a higher
  length floor (**14 characters**) plus the existing zxcvbn guessability bar
  (score ≥ 3). Composition rules rejected strong passphrases like
  `correct horse battery staple` while doing little against weak-but-compliant
  passwords such as `Password123!`; zxcvbn handles the latter far better.

### Security

- **Local replica `secure_delete`.** The desktop SQLite replica now sets
  `PRAGMA secure_delete = ON`, so freed pages (deleted item ciphertext, rotated
  wrapped keys) are overwritten rather than left in the file's free list.
- **Replica file permissions.** On unix the replica database is created `0600`
  before its WAL sidecars exist (SQLite gives `-wal`/`-shm` the same mode), so
  other local users can't read it. Defense-in-depth — the file is ciphertext +
  public metadata regardless.
- **Console-mailer warning.** The (default) console mailer writes verification
  and recovery links to the server log; it now logs a loud warning at startup
  so self-hosters know to switch to `BV_MAILER=smtp` where logs are shared.

## [1.0.0-beta.2] - 2026-07-15

Packaging fixes only — no changes to crypto, storage, or on-the-wire formats.
The `beta.1` desktop bundles failed to build on Windows and macOS; this release
makes the release workflow produce artifacts on all three platforms.

### Fixed

- **Windows bundle failed on the prerelease version.** The WiX **MSI** target
  rejects a non-numeric prerelease identifier (`-beta.2`), aborting the Windows
  build. Dropped `msi` from the Tauri bundle targets; Windows now ships the
  **NSIS** installer only, which accepts the version string.
- **macOS bundle failed at code-signing.** Defined-but-empty `APPLE_*` secrets
  made `tauri-action` attempt a keychain certificate import and fail. Removed
  the `APPLE_*` env entirely so macOS builds **unsigned** (still gated as
  unsigned in `docs/RELEASE_CHECKLIST.md`); re-add the secrets to sign.

## [1.0.0-beta.1] - 2026-07-14

First tagged release. Everything below is the initial feature set and hardening.

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

### Build & release tooling

- **GitHub Actions release workflow** (`.github/workflows/release.yml`): on a
  version tag, builds desktop bundles (macOS/Linux/Windows) via `tauri-action`,
  pushes a **multi-arch** (`amd64`/`arm64`) server image to GHCR, generates
  `SHA256SUMS`, and opens a draft release (unsigned unless signing secrets are
  set; `:latest` not auto-moved).
- Enabled Tauri bundling (`bundle.active`) with generated Windows/macOS icons
  (`.ico` / `.icns`).
- **Fixed the server `Dockerfile`** to build against the current workspace (it
  predated the `apps/*` crates and no longer loaded the workspace); added a
  `.dockerignore`.

### Known limitations (not yet addressed)

- **No independent security audit yet** — the blocker before production use.
- Deferred by design and tracked in `THREAT_MODEL` §Known gaps:
  sender-constrained (DPoP/mTLS) tokens, WebAuthn/passkeys, mobile Argon2
  parameter benchmarking, and the WebView / JavaScript-heap plaintext residual.

[Unreleased]: https://github.com/Zethrel/Basementen-Vault/compare/v1.0.0-beta.3...HEAD
[1.0.0-beta.3]: https://github.com/Zethrel/Basementen-Vault/compare/v1.0.0-beta.2...v1.0.0-beta.3
[1.0.0-beta.2]: https://github.com/Zethrel/Basementen-Vault/compare/v1.0.0-beta.1...v1.0.0-beta.2
[1.0.0-beta.1]: https://github.com/Zethrel/Basementen-Vault/releases/tag/v1.0.0-beta.1
