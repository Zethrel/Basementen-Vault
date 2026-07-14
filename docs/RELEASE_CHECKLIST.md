# Release checklist

The steps to cut a Basementen Vault release, in order. This is a password
manager, so the bar is high: **a release that isn't reproducibly built, signed,
and end-to-end verified on real devices should not ship.** Copy this list into
the release tracking issue and check items off there.

Legend: 🚧 = hard gate (do not proceed until met).

---

## 0. Hard gates before *any* 1.0 release

- [ ] 🚧 **Independent security audit + cryptographic review complete**, and its
  findings triaged/fixed or explicitly accepted. This is the standing blocker in
  `docs/RUNBOOK.md` and `SECURITY.md`. Pre-1.0 (beta) releases may skip this
  **only if** the release notes and download page say "beta, unaudited" in plain
  language.
- [ ] 🚧 No unresolved High/Critical items in `docs/THREAT_MODEL.md` §Known gaps
  beyond those explicitly marked *Accepted* for this version.
- [ ] 🚧 `main` CI is green: `cargo fmt --all --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace`, and the RustSec audit
  job all pass.

## 1. Code freeze & pre-flight

- [ ] Cut a release branch (`release/vX.Y.Z`) from a green `main`.
- [ ] `cargo test --workspace` locally on a clean checkout (not just CI).
- [ ] `cargo audit` (or `cargo deny check advisories bans sources`) — no
  unpatched advisories; review any allow-listed exceptions.
- [ ] `cargo update --dry-run` reviewed; `Cargo.lock` committed and intentional.
- [ ] Secret-scan the tree (e.g. `gitleaks detect`) — no keys, tokens, or real
  e-mail addresses committed.
- [ ] Grep for debug leftovers: `dbg!`, `println!`/`eprintln!` of secrets,
  `TODO`/`FIXME` that block release, and any `MailConfig::Console` default that
  must not reach production.

## 2. Crypto & data-format review (project-specific — do not skip)

The on-disk and on-the-wire formats are versioned; a silent format change is a
data-loss/interop bug.

- [ ] No change to a persisted crypto format without a **version bump + AAD
  binding** (invariant I12): `EncryptedItem.version`, `WrappedKey` purpose/
  version, `ExportEnvelope.version`. If bumped, confirm old-version records
  still decrypt (backward-compat path + test).
- [ ] Server DB **migrations are forward-only** and apply cleanly on top of a
  *populated* previous-version database (not just an empty one). Test the
  upgrade, not just a fresh install.
- [ ] KDF parameter defaults reviewed (`KdfParams::desktop`, `mobile_floor`) and
  still at/above the OWASP floor (invariant I7). Note the mobile-benchmarking
  deferral if params are unchanged.
- [ ] Recovery Kit code format (`BV1-…`) unchanged, or migration documented.
- [ ] Re-read `docs/CRYPTOGRAPHIC_INVARIANTS.md`; every invariant still has a
  passing guard test.

## 3. Versioning & changelog

- [ ] Bump `[workspace.package] version` in the root `Cargo.toml` (and confirm
  member crates inherit it); commit the resulting `Cargo.lock`.
- [ ] Update `CHANGELOG.md` (create it if absent): user-facing changes, security
  fixes with severity, and any migration/breaking notes.
- [ ] Update `SECURITY.md` "Supported versions" if the support window changes.
- [ ] Update the `README.md` status line if the maturity level changed
  (e.g. "beta" → "1.0").

## 4. Build, sign & notarize artifacts

Build every artifact from the **exact tagged commit**, in a clean environment.

### Desktop (Tauri)
- [ ] **Windows:** `.msi`/`.exe` built and **Authenticode-signed** (ideally an
  EV/OV cert so SmartScreen doesn't warn); verify the signature.
- [ ] **macOS:** `.dmg`/`.app` **signed with a Developer ID**, **notarized**
  (`notarytool`), and **stapled**; verify with `spctl -a -vv` and
  `stapler validate`.
- [ ] **Linux:** `.AppImage` and/or `.deb`/`.rpm`; sign the checksums (below).
  Verify it launches on a stock distro (not just the build box).

### Mobile
- [ ] **Android:** release **AAB + APK signed** with the release keystore
  (keystore backed up offline; never in the repo). `bundletool`/install check on
  a device.
- [ ] **iOS:** `.ipa` signed with the distribution profile; TestFlight build
  submitted and installable.

### Server
- [ ] Docker image built for the tag, **multi-arch** (`linux/amd64` **and**
  `linux/arm64` — many self-hosters run ARM SBCs) via `docker buildx`.
- [ ] Image tagged `:X.Y.Z` **and** `:latest` (only move `:latest` after
  verification); pushed to the registry.
- [ ] Image runs migrations cleanly on start and passes a container smoke test.

### Provenance
- [ ] Generate `SHA256SUMS` for every artifact and **sign it** (minisign/GPG or
  Sigstore); publish the public key / verification instructions.
- [ ] Attach an **SBOM** (e.g. `cargo auditable` build + `syft`) for the server
  image and desktop binaries.

## 5. End-to-end verification on real platforms 🚧

Headless integration tests are green, but a release must be exercised as a user.
Run this smoke test **from the signed artifacts** on each platform you ship:

- [ ] Fresh install → **register** (weak passwords rejected: composition + HIBP
  + zxcvbn) → verify e-mail → **log in** → **add** a login/note/card → **copy**
  a password (clipboard auto-clears) → **lock** → **unlock**.
- [ ] **Second device**: log in, confirm the item **syncs** both ways; make a
  conflicting edit and confirm the **conflict copy** appears (no data loss).
- [ ] **Offline**: airplane-mode unlock works; edits queue and sync on
  reconnect.
- [ ] **MFA**: enroll TOTP (QR scans in a real authenticator), activate, log in
  with a code, use a recovery code once, regenerate codes, disable.
- [ ] **Change master password**: succeeds, other devices are signed out, items
  still open, a **new Recovery Kit** is shown.
- [ ] **Recovery**: with the Recovery Kit, restore on a clean install; without
  it, confirm only the explicit wipe path exists (after cooling-off).
- [ ] **Backup e-mail** add/verify/remove; **export** an encrypted backup and
  **re-import** it (and a Bitwarden CSV) on a clean install.
- [ ] **Upgrade path**: install the *previous* release, create data, then
  upgrade in place — data intact, migrations applied, no re-login loop.
- [ ] Self-hosted server per `docs/SELF_HOSTING.md` behind TLS/VPN; confirm
  security headers and that the HIBP call is skippable offline.

## 6. Docs & operator readiness

- [ ] `README.md`, `docs/SELF_HOSTING.md`, `docs/RUNBOOK.md`, `docs/MOBILE.md`
  reference the new version/tags and any changed steps.
- [ ] Backup/restore drill in `RUNBOOK.md` re-verified against this build.
- [ ] Download page / release notes state the audit status honestly.

## 7. Publish

- [ ] Tag the commit `vX.Y.Z` (annotated, **signed**) and push.
- [ ] Create the GitHub Release: notes, artifacts, `SHA256SUMS` + signature,
  SBOM, verification instructions.
- [ ] Push the server image tags; move `:latest` only now.
- [ ] Announce with the honest maturity/audit caveat.

## 8. Post-release

- [ ] Confirm `SECURITY.md` reporting channel (GitHub private advisories) is
  enabled and watched.
- [ ] Watch for install/upgrade breakage reports for the first days; keep a
  hotfix branch ready.
- [ ] Open the next milestone; move any deferred `THREAT_MODEL` gaps forward
  (DPoP tokens, WebAuthn, mobile Argon2 benchmarking).
- [ ] Rotate/secure signing keys and keystores; confirm offline backups exist.

---

### Minimal beta (pre-audit) release

If publishing a **beta** before the audit, the irreducible subset is: §0 CI
gate, §1 pre-flight, §2 crypto/format review, §3 version+changelog, §5 the
smoke test on at least one desktop platform, signed checksums, and release notes
that say **"unaudited beta — do not store irreplaceable secrets."**
