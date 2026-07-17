# Changelog

All notable changes to Basementen Vault are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it
reaches 1.0.

> **Status:** the current tagged release is **1.0.0-beta.5**. It is an
> **unaudited beta** — the project has **not** had an independent security audit
> (a hard prerequisite before real-world use; see `SECURITY.md` and
> `docs/RUNBOOK.md`). Do not store irreplaceable secrets in it yet. On-disk /
> on-the-wire formats are versioned but may still change before a final 1.0.0.

## [Unreleased]

### Added

- **Tag filter facet**: the vault list gains a row of tag chips built from the
  tags currently in use ("All" + one per tag, with counts). Clicking one filters
  the list to that tag, and search narrows further within it. The chips are
  derived live from your items (new `list_tags` command) — a tag appears the
  moment you first use it and disappears when its last item is deleted, with no
  separate list to maintain. Tags also now show as small labels on each list
  row. Because tags live inside the end-to-end-encrypted item and the facet is
  computed on-device, the server never sees them. Enables e.g. grouping stored
  credentials per client and filtering to one at a time.
- **Tag autocomplete** in the item editor: typing in the Tags field suggests
  existing tags (keyboard-navigable, click or Enter to accept), so reusing a tag
  like "Shop A" doesn't accidentally spawn near-duplicates ("shop a", "ShopA")
  that would fragment the filter.
- **Password health dashboard** (🛡 in the toolbar): scans every login's password
  and flags **weak** ones (zxcvbn ≤ 2) and **reused** ones (shared across items),
  weakest first, with a click-through to fix each. The analysis runs on-device
  and the report carries no passwords — only per-item scores, a reuse flag, and
  names. New `vault-core` `health` module (unit-tested) + `vault_health` command.
- **Tag management**: with a tag selected in the filter bar, **Rename** (updates
  it across every item, de-duplicating) and **Delete** (strips it from all items,
  keeping the items). New `Item::retag` helper (unit-tested) +
  `rename_tag`/`delete_tag` commands; changed items are re-encrypted and synced.

### Security

- **Resend-verification throttle**: repeated resend requests for the same
  account within a 60-second cooldown are silently coalesced — no extra e-mail
  or token — limiting inbox spam and token churn. Implemented as a silent skip
  (not a 429) so it never reveals whether the address has a pending account.

## [1.0.0-beta.5] - 2026-07-16

Refreshes the entire crypto dependency stack to its current upstream generation,
plus the first round of self-hosting UX fixes found in real testing. **No format
changes and no server migrations** — existing vaults, exports, Recovery Kits, and
server databases are untouched, and upgrading requires no user action.

### Added

- **Resend verification e-mail**: a new `POST /api/v1/accounts/resend-verification`
  endpoint (and a "Didn't get the verification e-mail? Resend it…" link on the
  login screen, shown when a login is blocked as unverified) issues a fresh link
  for an account that exists but hasn't been verified. Previously the 15-minute
  link could lapse with no way to get a new one — registering again didn't mint
  one — stranding the account. Anti-enumeration: the response is identical for
  unknown, already-verified, and genuinely-pending addresses, and only a real
  pending account triggers an e-mail.

### Fixed

- **Desktop: scheme-less server URL** no longer fails with "network error:
  builder error". The client now adds `http://` for loopback/LAN hosts and
  `https://` for public hosts when no scheme is typed (explicit scheme
  respected).
- **Desktop: editor no longer overwrites the item just saved.** After a save the
  form stayed bound to that item, so adding another (e.g. after switching Type)
  overwrote it and dropped the previous type's fields. Every save now resets to
  a fresh new-item form, with a brief "Saved" confirmation.
- **Console mailer readability**: e-mail bodies now print with real line breaks
  instead of escaped `\n`, so a verification/recovery link lands on its own line
  and copies cleanly out of the server log.

### Changed

- **Coordinated RustCrypto generation migration** (the change the closed
  Dependabot PRs #8/#9/#11/#15 attempted one-by-one): `sha2` 0.10→0.11, `sha1`
  0.10→0.11, `hmac` 0.12→0.13, `hkdf` 0.12→0.13, `chacha20poly1305` 0.10→0.11
  (`digest` 0.11 / `crypto-common` 0.2 / `hybrid-array` base), migrated together
  because the shared traits make individual bumps uncompilable. Code changes are
  API-shape only (nonce generation via the new `Generate` trait, cipher
  construction via `new_from_slice`, OS randomness via `getrandom` directly);
  **algorithms, key derivation, and all on-disk / on-the-wire formats are
  unchanged** — v1/v2 ciphertext round-trip and AAD version-binding tests prove
  existing vaults decrypt as before.
- **`rand` 0.8→0.10** (completes Dependabot PR #18, same ecosystem generation
  as the RustCrypto migration): the password generator in `desktop-core` moves
  to the renamed API (`SysRng` + `UnwrapErr`, `random_range`); `vault-server`
  drops `rand` entirely — TOTP/MFA secrets, recovery codes, tokens, and the
  Argon2 storage salt now draw from `getrandom` directly, matching `vault-core`.
  Output semantics are unchanged (same OS CSPRNG, same uniform sampling, same
  16-byte PHC salt format); `rand` 0.9 remains in the lockfile only as
  `proptest`'s dev-dependency.
- **`argon2` deliberately stays at 0.5**: the new-generation `argon2` is still a
  release candidate (`0.6.0-rc.x`), and the KDF of a password vault does not
  ride on RCs. Its internal `digest` 0.10 coexists as a duplicate-version
  (tolerated by `deny.toml`); revisit when 0.6.0 finalizes.

### Build & release tooling

- **Dependabot** (`.github/dependabot.yml`): weekly dependency-update PRs for
  Cargo, GitHub Actions, and the server Docker base, vetted by the existing CI
  supply-chain gates.
- **Standalone server binaries in releases**: `release.yml` now also builds and
  attaches bare `vault-server` binaries (Windows x86-64, Linux x86-64/ARM64,
  macOS ARM64) so self-hosters don't need Docker; `docs/SELF_HOSTING.md` gained
  a "Without Docker" section including Windows LAN setup.
- **Release-review lockfile hygiene**: bumped the yanked `spin` 0.9.8 to 0.9.9
  (clearing the last yanked-crate warning) and removed two stale `deny.toml`
  advisory ignores that no longer match the tree — `RUSTSEC-2023-0071` (`rsa`,
  gone with `sqlx` 0.9) and `RUSTSEC-2024-0429` (`glib`, advisory no longer
  applies to the in-tree version).

### Documentation

- Recorded the **Dependabot-alert disposition** for the accepted transitive
  advisories (e.g. `glib` `RUSTSEC-2024-0429`): dismissed as "risk is tolerable",
  cross-referenced to the `deny.toml` ignore list as the single source of truth
  (`THREAT_MODEL` §A7 + `deny.toml` header). Surfaced once the repo went public.

## [1.0.0-beta.4] - 2026-07-15

Third review pass: supply-chain gating, a CI-trigger fix, coverage-guided
fuzzing of the untrusted-input parsers, and one denial-of-service hardening that
fuzzing motivated.

- **Breaking changes:** None.
- **Migration required:** No — on-disk / on-the-wire formats unchanged. (The new
  KDF-parameter ceiling only rejects values far above any real configuration; no
  existing vault uses them.)

### Security

- **KDF-parameter ceiling (untrusted-input DoS).** `KdfParams::validate()` now
  enforces an upper bound (≤ 1 GiB memory, ≤ 64 iterations, ≤ 64 lanes) in
  addition to the OWASP floor. KDF parameters arrive inside untrusted data — an
  export file's envelope and the server's prelogin/login response — and gate an
  Argon2 derivation, so an unbounded block could force a multi-gigabyte
  allocation or multi-minute hash (memory/CPU DoS on import or unlock, including
  from a malicious server). Surfaced while building the import fuzz target.

### Build & release tooling

- **Build-provenance attestations** (SLSA, `actions/attest-build-provenance`):
  the release workflow attaches signed provenance to every desktop bundle and
  the server image, binding each to its source commit and workflow, verifiable
  with `gh attestation verify`. Gated on repo visibility — GitHub's attestation
  API is unavailable for user-owned *private* repos, so it activates once the
  repo is public; until then `SHA256SUMS` (always published) is the verification
  path. See `docs/REPRODUCIBLE_BUILDS.md`.
- **Pinned Rust toolchain** (`rust-toolchain.toml` → the exact `rustc`/`cargo`
  version), used by CI, the release workflow, and the server `Dockerfile` (now
  an exact patch base image). A prerequisite for reproducible builds — a
  floating `stable` silently changes codegen between builds.
- **`docs/REPRODUCIBLE_BUILDS.md`**: verification instructions and an honest
  reproducibility status matrix (library crates: yes; server image: targeted;
  desktop GUI bundles: not yet — provenance is their verification path).

### Testing

- **Coverage-guided fuzzing** (`fuzz/`, cargo-fuzz / libFuzzer) of the
  untrusted-input parsers — `import_csv`, `import_encrypted` (envelope → KDF →
  AEAD → payload), and `Item::from_plaintext` — with a committed seed corpus and
  a short CI smoke on every push (`.github/workflows/fuzz.yml`). Complements the
  existing `proptest` coverage.

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

[Unreleased]: https://github.com/Zethrel/Basementen-Vault/compare/v1.0.0-beta.5...HEAD
[1.0.0-beta.5]: https://github.com/Zethrel/Basementen-Vault/compare/v1.0.0-beta.4...v1.0.0-beta.5
[1.0.0-beta.4]: https://github.com/Zethrel/Basementen-Vault/compare/v1.0.0-beta.3...v1.0.0-beta.4
[1.0.0-beta.3]: https://github.com/Zethrel/Basementen-Vault/compare/v1.0.0-beta.2...v1.0.0-beta.3
[1.0.0-beta.2]: https://github.com/Zethrel/Basementen-Vault/compare/v1.0.0-beta.1...v1.0.0-beta.2
[1.0.0-beta.1]: https://github.com/Zethrel/Basementen-Vault/releases/tag/v1.0.0-beta.1
