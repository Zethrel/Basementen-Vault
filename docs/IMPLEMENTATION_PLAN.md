# Basementen Vault — Implementation Plan

A self-built, cross-platform password vault manager designed around established
industry best practices (OWASP ASVS / Password Storage Cheat Sheet, NIST SP 800-63B,
and the architecture patterns used by Bitwarden and 1Password).

**Core requirements (from product owner):**

- Argon2id for all password-based key derivation
- A small fixed lockout delay (250–300 ms) on every failed password attempt
- Account registration and login with e-mail + password
- Multi-factor authentication (MFA)
- Optional trusted backup e-mail for account recovery
- Cross-platform sync: Windows / macOS / Linux desktop + mobile (iOS / Android)

---

## 1. Guiding security principles

These are non-negotiable design rules; every feature below must comply.

1. **Zero-knowledge / end-to-end encryption.** The server never sees the master
   password, any key derived from it, or any plaintext vault data. All
   encryption and decryption happens on the client. A full server compromise
   must yield only ciphertext and Argon2id hashes.
2. **Separate keys for authentication and encryption.** The value sent to the
   server to log in must be cryptographically independent from the key that
   decrypts the vault, so the server can verify identity without ever being
   able to decrypt data.
3. **Random data keys, wrapped by derived keys (envelope encryption).** The
   vault is encrypted with a random 256-bit *vault key*, not directly with the
   password-derived key. Changing the master password then only re-wraps one
   key instead of re-encrypting the whole vault, and enables recovery keys.
4. **Modern, misuse-resistant primitives only.** Argon2id, XChaCha20-Poly1305
   (or AES-256-GCM where hardware acceleration matters), HKDF-SHA-256, HMAC,
   CSPRNG from the OS. No home-rolled crypto, no ECB/CBC, no MD5/SHA-1.
5. **Fail closed and be boring.** Constant-time comparisons, authenticated
   encryption everywhere, explicit versioning of all crypto parameters so we
   can migrate later without breaking old vaults.

---

## 2. Cryptographic design

### 2.1 Key hierarchy

```
master password + email (salt input)
        │
        ▼  Argon2id (client-side)
   Master Key (MK, 256-bit)
        │
        ├── HKDF(MK, info="auth")    → Auth Key      → sent to server for login
        │                              (server stores Argon2id(AuthKey, server salt))
        │
        └── HKDF(MK, info="enc")     → Wrapping Key  → wraps (encrypts) the Vault Key
                                                        │
                                       Vault Key (VK, random 256-bit, generated at registration)
                                                        │
                                                        ▼
                                       encrypts every vault item (XChaCha20-Poly1305)
```

- **Client-side KDF: Argon2id.** Starting parameters: `memory = 64 MiB`,
  `iterations = 3`, `parallelism = 4` on desktop; mobile may negotiate down to
  the OWASP floor (`m = 19 MiB, t = 2, p = 1`) but never below it. Parameters
  are stored per-account and versioned so they can be raised over time.
- **Salt** for the client KDF is derived from the normalized e-mail
  (`HKDF(email)`) so the client can derive keys before talking to the server;
  a per-account random salt is additionally mixed in after first contact.
- **Server-side hashing.** The server never stores the Auth Key directly — it
  runs it through Argon2id again with a random per-user salt. A leaked
  database therefore requires attacking two stacked Argon2id computations.
- **Vault Key (VK)** is generated from the OS CSPRNG at registration and never
  leaves the client unencrypted. It is stored server-side only as
  `XChaCha20-Poly1305(WrappingKey, VK)`.
- **Per-item encryption.** Each vault item is encrypted independently
  (`XChaCha20-Poly1305`, random 192-bit nonce, AAD = item ID + record version)
  so sync can move individual items and a nonce reuse bug is structurally hard.

### 2.2 What each party knows

| Data                          | Client | Server |
|-------------------------------|--------|--------|
| Master password               | ✅ (never persisted) | ❌ |
| Master Key / Wrapping Key     | ✅ (memory only)     | ❌ |
| Auth Key                      | ✅                   | only its Argon2id hash |
| Vault Key                     | ✅ (memory only)     | only wrapped ciphertext |
| Vault items                   | ✅ plaintext in memory | ciphertext only |

---

## 3. Authentication flows

### 3.1 Registration

1. User enters e-mail + master password (client enforces: ≥ 12 chars, checked
   against a compromised-password list — local `zxcvbn` scoring + k-anonymity
   query to Have I Been Pwned; never send the password itself).
2. Client derives MK → AuthKey + WrappingKey, generates VK, wraps VK.
3. Client sends: e-mail, AuthKey, wrapped VK, KDF parameters.
4. Server Argon2id-hashes the AuthKey, stores the record, and sends a
   **verification e-mail** (signed, single-use, 15-minute expiry token).
   Accounts are unusable until the e-mail is verified.
5. Client generates and shows a **Recovery Kit** (see §5) exactly once.

### 3.2 Login

1. Client fetches the account's KDF parameters by e-mail (return dummy-but-
   deterministic parameters for unknown e-mails to prevent user enumeration).
2. Client derives AuthKey, sends it over TLS.
3. Server verifies against the stored hash **in constant time**, then:
   - **On every failure: sleep 250–300 ms (randomized within that window)
     before responding.** The randomization avoids giving a perfectly clean
     timing oracle while satisfying the fixed-mini-lockout requirement.
   - Failures are also counted per-account *and* per-IP:
     - 5 failures → CAPTCHA / proof-of-work challenge
     - 10 failures → exponential backoff (1 min, 2 min, 4 min… capped at 1 h)
     - notification e-mail to the account owner after 10 failures.
   - The 250–300 ms delay is the *floor*, not the whole defense: online
     guessing is stopped by rate limiting; offline guessing is stopped by
     Argon2id. Failed attempts must cost the same server work as successes
     (no early exits) to avoid timing side channels.
4. On success + MFA (§4): server issues a short-lived access token (JWT or
   PASETO, 15 min) + rotating refresh token (30 days, revocable, one per
   device, stored hashed).
5. Client downloads the wrapped VK, unwraps it locally, and holds keys in
   memory only (locked/zeroized on vault lock, screen lock, or timeout).

### 3.3 Session & device management

- Each device registers a device ID + public key on first login; users can
  list and revoke devices from settings.
- Vault auto-locks after configurable idle time (default 15 min) and on OS
  sleep. Unlock re-runs the KDF locally (or uses OS biometrics via
  Keychain / TPM / StrongBox-wrapped cached key — the *cached key* path never
  weakens the crypto, it only re-wraps MK with hardware-backed keys).

---

## 4. Multi-factor authentication

MFA gates the *server's* willingness to hand over the wrapped Vault Key and
encrypted vault — it complements, not replaces, the master password.

| Factor | Priority | Notes |
|--------|----------|-------|
| TOTP (RFC 6238) | v1 (required option) | 30 s window ±1 step, rate-limited, secret shown as QR + text |
| WebAuthn / passkeys (FIDO2) | v1.1 | Preferred factor; phishing-resistant; platform + roaming authenticators |
| Recovery codes | v1 (required) | 10 single-use codes generated with MFA enrollment, stored hashed server-side |

Rules:

- Enrolling or removing a factor requires a fresh master-password confirmation.
- MFA failures share the same 250–300 ms delay + rate-limit machinery as
  password failures.
- New-device logins always require MFA even if "remember this device" is set
  elsewhere.

---

## 5. Account recovery (trusted backup e-mail)

**The honest zero-knowledge constraint:** an e-mail reset alone can restore
*access to the account*, but it cannot decrypt the vault — the server doesn't
have the keys. Pretending otherwise would require the server to hold
decryption capability, which breaks the entire model. So recovery is layered:

1. **Recovery Kit (primary, offline).** At registration the client generates a
   random 256-bit **Recovery Key**, uses it to create a second wrapped copy of
   the VK stored on the server, and renders the Recovery Key as a printable
   PDF/code (formatted like 1Password's Secret Key). Whoever has e-mail access
   + the Recovery Key can fully restore the vault and set a new master
   password.
2. **Trusted backup e-mail (optional, user-configured).** A secondary verified
   e-mail address that can be used to *initiate* recovery:
   - Recovery links are sent to **both** primary and backup addresses; the
     primary address gets a "recovery was initiated — cancel here" message
     with a 72-hour cooling-off delay before the reset proceeds.
   - Combined with the Recovery Key → full vault restoration.
   - Without the Recovery Key → the user may reset authentication and keep the
     account/e-mail identity, but the vault contents are unrecoverable and the
     UI must say so in plain language before the user confirms.
3. Changing the backup e-mail requires master password + MFA, and triggers
   notification to all addresses on file.

---

## 6. Sync architecture

### 6.1 Model

- **Server is a dumb encrypted-blob store with per-item granularity.** Sync
  exchanges encrypted vault items, never plaintext, so the sync protocol needs
  no trust in the server beyond availability.
- Every item carries: `item_id (UUIDv7)`, `revision (monotonic int)`,
  `modified_at`, `deleted (tombstone flag)`, `ciphertext`, `nonce`,
  `key_version`.
- **Protocol: revision-based delta sync.** Client sends its last-seen global
  revision; server returns all items changed since. Writes are optimistic:
  a write with a stale `revision` is rejected and the client merges.
- **Conflict resolution:** last-writer-wins per item *field-group*, with the
  losing version preserved in the item's history (encrypted, N latest
  revisions kept) so nothing is silently destroyed. Deletes are tombstones,
  purged after 30 days.
- **Offline-first.** Every client keeps a full encrypted local replica
  (SQLite via SQLCipher, or plain SQLite storing only ciphertext) and works
  fully offline; sync is opportunistic.
- Real-time nudge via WebSocket/SSE ("something changed, pull now") — the
  nudge carries no data.

### 6.2 Transport & server hardening

- TLS 1.3 only, HSTS, certificate pinning in the mobile/desktop clients.
- All request/response bodies with key material are additionally
  application-layer encrypted (defense in depth against TLS interception
  middleboxes on corporate networks).
- Standard API protections: strict input validation, request size caps,
  per-token and per-IP rate limits, audit log of auth events (never vault
  content), security headers, dependency scanning in CI.

---

## 7. Technology stack (recommendation)

**One shared core, thin native shells** — this is how every serious vault
avoids re-implementing crypto five times.

| Layer | Choice | Rationale |
|-------|--------|-----------|
| **Core library** (crypto, vault model, sync engine) | **Rust** (`argon2`, `chacha20poly1305`, `hkdf`, `zeroize` crates — all RustCrypto, widely audited) | Memory safety for key handling, `zeroize` for scrubbing secrets, compiles to every target incl. iOS/Android (via UniFFI) and WASM |
| Desktop apps (Win/macOS/Linux) | **Tauri** (Rust backend = the core lib, web UI) | Single codebase, small binaries, direct in-process use of the core |
| Mobile apps (iOS/Android) | **Tauri 2 mobile** — the same app as desktop (revised from Flutter/KMP) | One codebase for all five platforms; the Rust core runs in-process; see `docs/MOBILE.md` |
| Server | **Rust (axum)** or **Go** | Stateless API + PostgreSQL; the server does little, so pick team familiarity |
| Database | **PostgreSQL** | Row-level per-user isolation, proven operational story |
| Client local store | SQLite (ciphertext-only rows) | Offline-first replica |
| Tokens | PASETO v4 (or JWT with strict alg allowlist) | Avoids JWT's foot-guns |

If team familiarity makes Rust too slow to start with, the acceptable fallback
is a TypeScript core using `libsodium.js` — but the Rust core is the
recommendation and the rest of this plan assumes it.

---

## 8. Milestones

### M0 — Foundations (week 1–2)
- Repo layout (monorepo: `core/`, `server/`, `apps/desktop/`, `apps/mobile/`, `docs/`)
- CI: build, tests, `cargo audit`/dependency scanning, lint, secret scanning
- Threat model document (STRIDE pass over the design above)

### M1 — Crypto core (week 2–5) ✅ *exit: audited-pattern crypto with test vectors*
- Rust core: Argon2id KDF with versioned parameters, key hierarchy (§2.1),
  envelope wrap/unwrap, per-item encrypt/decrypt, zeroization
- Golden test vectors committed; property tests (round-trip, tamper detection)
- Vault data model: items (logins, notes, cards), folders, item history

### M2 — Server: accounts & auth (week 4–8)
- Registration + e-mail verification, login with stacked Argon2id (§3),
  **250–300 ms randomized failure delay**, rate limiting & progressive lockout,
  user-enumeration-safe responses
- Token issuance/refresh/revocation, device registry
- TOTP enrollment/verification + recovery codes

### M3 — Vault storage & sync (week 7–11)
- Encrypted item CRUD API, revision-based delta sync, tombstones,
  conflict handling, WebSocket change nudge
- Local SQLite replica + offline queue in the core library

### M4 — Desktop client (week 10–15)
- Tauri app: onboarding (register, Recovery Kit), unlock/lock, item CRUD,
  search, password generator (CSPRNG, configurable charset/length/diceware)
- OS keychain/biometric quick-unlock, auto-lock, clipboard auto-clear (30 s)

### M5 — Mobile client (week 14–20)
- Flutter/KMP app over the same core; biometric unlock; iOS AutoFill
  credential provider + Android Autofill service

### M6 — Recovery & backup e-mail (week 18–21)
- Recovery Kit generation + recovery flow (§5), trusted backup e-mail with
  cooling-off period and cancellation, explicit data-loss warnings

### M7 — Hardening & release (week 20–24)
- WebAuthn as MFA factor
- Full security review: this repo's threat model revisited, fuzzing the sync
  protocol, dependency audit, **external penetration test / crypto review
  before any real users** (non-negotiable for a credential product)
- Export/import (encrypted export + standard CSV import from other managers)
- Operational runbook: backups, key-parameter migration plan, incident response

---

## 9. Testing & verification strategy

- **Unit + property tests** on all crypto paths (round-trip, wrong-key fails,
  tampered ciphertext fails, nonce uniqueness under concurrency).
- **Known-answer tests** against reference Argon2id/XChaCha20 vectors.
- **Integration tests**: full register → login → MFA → sync → recover flows
  against a real server in CI.
- **Timing tests**: assert failed-login responses land in the 250–300 ms
  window and success/failure server work is comparable.
- **Abuse tests**: brute-force simulation must hit CAPTCHA/backoff thresholds;
  user-enumeration probes must be indistinguishable.
- **Fuzzing**: sync payload parser and any format decoders.

---

## 10. Explicitly out of scope for v1

- Sharing vaults / organizations / emergency access contacts
- Browser extension (planned v2 — it has its own large attack surface)
- SSO login, hardware-key-only accounts

**In scope (revised):** self-hosting is the primary deployment model — the
server ships as a single binary / Docker container with SQLite by default
(see `docs/SELF_HOSTING.md`); PostgreSQL support can come later if needed.
Sessions use opaque rotating bearer tokens stored hashed server-side instead
of JWT/PASETO: fully revocable and one less signing key to manage.
- Secrets other than logins/notes/cards (SSH keys, TOTP-storage-in-vault)

---

## 11. Key risks & mitigations

| Risk | Mitigation |
|------|------------|
| Users lose master password *and* Recovery Kit | Unavoidable in zero-knowledge; mitigate with aggressive UX at onboarding (forced Kit download, periodic "verify your recovery" prompts) |
| Crypto implementation bugs | Use audited libraries only, golden vectors, external review at M7, no custom primitives |
| Mobile KDF too slow → users pick weak params | Parameter floor enforced server-side; cache hardware-wrapped MK for biometric unlock |
| Sync conflicts corrupt data | Per-item versioned history, tombstones, never hard-delete on conflict |
| E-mail account takeover → recovery abuse | 72 h cooling-off, cancel link to primary e-mail, Recovery Key still required for data access |
