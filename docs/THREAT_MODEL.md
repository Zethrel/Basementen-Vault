# Threat model

What Basementen Vault protects, against whom, and how. Read together with
`IMPLEMENTATION_PLAN.md` (design) and `RUNBOOK.md` (operations).

## Assets

1. **Vault item plaintext** (passwords, notes, cards) — the crown jewels.
2. **The master password** and every key derived from it.
3. **The Recovery Kit code** (equivalent power to the master password).
4. **Account availability** (a destroyed account is also a loss).
5. **Metadata**: which e-mail addresses have accounts, item counts, timing.

## Adversaries and outcomes

### A1 — Thief with the server database (or backups)

Sees: e-mails, Argon2id hashes of client AuthKeys (themselves Argon2id
outputs — two stacked derivations from the password), wrapped vault keys
(XChaCha20-Poly1305 ciphertext), item ciphertexts, hashed session tokens,
hashed recovery verifiers/codes.

Can do: offline guessing against the stacked KDFs, at ~full password-cracking
cost per account per guess. Cannot: decrypt anything, mint sessions (tokens
are stored hashed), or forge recovery (verifier stored hashed).

**Residual risk:** weak master passwords. Mitigated at every point the master
password is set (registration and recovery) by two client-side checks:
(1) a composition policy — ≥12 characters plus at least one capital letter, one
number, and one special character (`desktop_core::check_password_strength`); and
(2) a **breached-password check** against Have I Been Pwned using k-anonymity
(`desktop_core::password_breach_count`) — only a 5-hex-char SHA-1 prefix leaves
the device, and a match is rejected. The breach check is best-effort: if HIBP is
unreachable (offline / blocked), registration still proceeds on the other two
checks. (3) **`zxcvbn` guessability scoring**
(`desktop_core::check_password_guessability`) rejects anything scoring below
"safely unguessable" (3/4) — common passwords, dictionary words, keyboard walks,
dates, or anything resembling the account e-mail — catching `Password123!`-shaped
inputs that pass composition and aren't (yet) in a breach corpus. Together these
close the weak-master-password gap for v1.

### A2 — Malicious or compromised server (active)

Everything in A1, plus it can refuse service or lie in any protocol
response. What the client validates independently means most such lies are
**fail-safe (denial of service at worst), never key disclosure**:

| Malicious server action | Outcome for the client |
|---|---|
| Substitute / downgrade KDF parameters (prelogin, login) | The client rejects any params below the OWASP floor before deriving (I7). Params above the floor but *different* from registration derive a different Master Key → the Wrapping Key differs → unwrapping the Vault Key **fails**. DoS, never disclosure or a genuine cost downgrade — the vault was wrapped under the real-param key. |
| Substitute the KDF salt | Same as above: different salt → different key → unwrap fails. DoS. |
| Replay an old `master_wrapped_vault_key` | Harmless: password changes re-wrap the *same* Vault Key, so any historical wrap decrypts to the same VK. |
| Replay / inject a foreign wrapped key | AEAD + purpose+version AAD binding (I4, I12) → decryption fails. |
| Swap item ciphertexts between items, or roll one item back | Item AAD binds `item_id + revision` (I4) → decryption fails. |
| Inject malformed / truncated ciphertext | AEAD tag check fails → `Decrypt` error, never a parse-level exploit (Rust, `forbid(unsafe)`). |
| Alter an item's `version`/metadata field | Version is bound in AAD and explicitly checked (I12) → rejected. |
| Learn the Wrapping Key from login traffic | Impossible: auth and encryption are HKDF-independent branches (I2), verified by test. |
| Serve a **complete old vault snapshot** (whole-vault rollback) | **Detected** in the common cases (see below); one narrow residual remains. |

**Whole-vault rollback — now mitigated.** The server could present an
internally-consistent older state (all items at older revisions); per-item
AAD can't catch this because each old item is individually valid. Three
layered defenses now apply (implemented this pass):

1. **Per-device monotonic guard.** Each client stores a durable high-water
   `last_seq`. The sync engine refuses any pull whose global `latest_seq`
   regressed below it (`RollbackDetected`), leaving the local replica
   untouched. This catches *any* rollback below a state this device has
   already seen — including the realistic accidental case of a self-hoster
   restoring the server from an old backup. (`vault-sync`;
   `server_rollback_is_detected`.)
2. **Vault-key-MAC'd checkpoint (cross-device).** After each sync a client
   publishes `checkpoint = (seq, HKDF(VaultKey, "sync-checkpoint" ‖ seq))` to
   the server, which keeps the highest. Any device verifies the tag under the
   Vault Key — the server can neither forge a checkpoint nor raise it. If the
   server serves data *below* a checkpoint it presents, that is caught as
   **withholding committed writes**. (`desktop-core::synchronize`;
   `checkpoint_published_and_verified`, `forged_checkpoint_is_rejected`,
   `withholding_committed_data_is_detected`.)
3. **Alarm, never silent.** A detected rollback/withholding/forgery stops the
   sync and surfaces a prominent error in the app instead of applying the
   stale state; the local replica is preserved.

**How the checkpoint and the monotonic guard interact (order within one sync).**
`desktop-core::rollback::synchronize` sequences the two so a forgery or
rollback is caught *before* any local state is mutated:

1. Fetch the server's checkpoint and **verify its MAC** under the Vault Key.
   A bad tag → `CheckpointForged`, abort (nothing touched).
2. If the authentic checkpoint's `seq` is **below** this device's durable
   `last_seq`, that is a rollback → abort before pulling.
3. Run the engine sync; the engine's **own** monotonic guard independently
   refuses a pull whose `latest_seq` regressed below `last_seq`. (Two guards,
   different anchors: step 2 compares against the cross-device *checkpoint*,
   the engine compares against this device's *own high-water mark*. Either
   firing aborts.)
4. After applying, check the served `latest_seq` against the verified
   checkpoint: served < checkpoint → **withholding**, abort.
5. Only if all checks pass, publish an updated checkpoint at the new
   high-water mark (the server keeps the max, so it can never lower it).

The layering is deliberate: the engine guard needs no key and protects even a
key-less transport test, while the checkpoint adds the cross-device / fresh-
reinstall dimension the per-device guard alone can't see.

**Residual risk (narrow):** a *fully consistent* rollback presented to a
device with **no local history and no newer checkpoint to compare against** —
i.e. a brand-new install syncing for the first time while the server
simultaneously rewinds both the data and the checkpoint to an earlier real
state. This is the well-known limit of untrusted storage without a trusted
monotonic anchor; closing it entirely needs an out-of-band anchor (a second
device, or persisting the last checkpoint into the Recovery Kit). Every device
that has synced even once, and every case where any device published a newer
checkpoint, is protected. Tracked for a future enhancement.

### A3 — Network attacker (on-path)

TLS 1.3 (Caddy) or VPN-only deployment is mandatory outside localhost; the
apps refuse plain HTTP by OS policy on mobile. Bearer tokens are
password-equivalent for their lifetime (15 min access / 30 d refresh,
rotated, revocable, reuse-detected with family revocation).

### A4 — Online guesser (credential stuffing / brute force)

Every failed password or MFA attempt costs a randomized 250–300 ms delay,
counts toward per-account progressive lockout (doubling to 1 h at 10
failures, owner notified) and a per-IP budget (20/15 min). Unknown accounts
burn the same Argon2id work as real ones (dummy-hash equalization), and
registration/recovery/prelogin responses are enumeration-safe.

### A4b — Attacker with a stolen session token

Bearer tokens are password-equivalent for their lifetime, so the design
minimizes that lifetime and makes every token revocable:

- **Access token:** opaque 256-bit random, stored server-side only as its
  SHA-256, 15-minute TTL. A leaked access token works for at most 15 minutes
  and can be killed instantly by revoking its session.
- **Refresh token:** opaque, hashed, 30-day sliding TTL, **single-use**. Each
  use rotates both tokens; presenting an already-rotated refresh token is
  treated as theft and **revokes the whole session family** (all descendants
  of that login). So a stolen refresh token is either caught (if the victim
  refreshes and the thief replays → family killed) or the thief's own use
  invalidates the victim's copy (victim's next refresh → family killed).
- **Absolute lifetime cap:** 90 days from login, carried unchanged through
  rotations, so sliding refresh cannot keep a compromised session alive
  indefinitely — re-login (and thus the master password + MFA) is forced.
- **Revocation:** the user can list active devices (`GET /sessions`) and
  revoke any one (`DELETE /sessions/{family}`) or all others
  (`POST /sessions/revoke-others`) from the app; recovery revokes every
  session, and a **master-password change** (`POST /account/change-password`)
  revokes every *other* session while keeping the device that made the change
  signed in.
- Tokens are server-generated random values, never client-supplied, so there
  is no session fixation. The API authenticates via the `Authorization`
  header, not cookies, so CSRF does not apply.

**Residual risk:** within a stolen access token's ≤15-minute window, before
detection/revocation, the thief can read the encrypted vault blobs (still
useless without the master password) and metadata. True proof-of-possession
binding (DPoP / mTLS) would close the bearer-replay window entirely but is a
large feature; for a self-hosted vault behind TLS/VPN the short TTL +
rotation + revocation is the accepted v1 posture. Tracked as a possible
enhancement.

### A4c — Second factor and device enrollment

A new device is enrolled by an ordinary login (e-mail + master password →
AuthKey, plus TOTP when enrolled) — there is no separate device-approval step,
so the second factor and the detection controls below carry the weight:

- **TOTP is one-time-use.** The server records the last consumed 30-second
  time-step and rejects any code whose step is not strictly newer (RFC 6238
  §5.2). A code phished or sniffed once cannot be replayed within its validity
  window, nor reused across a login and a follow-up sensitive action.
  (`routes/mfa::consume_totp`; `api_flows::totp_code_cannot_be_replayed`.)
- **New-device sign-in alert.** A login that opens a session for a device
  label not already active e-mails the account owner, so an attacker who has
  the password *and* a second factor still can't sign in silently. (Primary
  address only; concurrent same-named devices don't re-alarm.
  `api_flows::new_device_login_notifies_owner_once_per_device`.)
- **Recovery codes are single-use and replenishable.** Ten one-time codes are
  issued on TOTP activation; each works exactly once. `GET /mfa/status` reports
  how many remain and `POST /mfa/recovery-codes/regenerate` (fresh password +
  current TOTP) mints a fresh set, so exhaustion doesn't force the heavier
  account-recovery path. (`api_flows::recovery_codes_status_and_regeneration`.)
- **Sensitive settings re-authenticate.** Enrolling/disabling TOTP,
  regenerating recovery codes, and changing the backup e-mail each require a
  fresh master-password confirmation (and a current TOTP when enrolled) — a
  stolen session token alone cannot weaken MFA.
- **Device labels are untrusted input.** `device_name` is client-supplied;
  the server strips control characters and caps it at 64 chars before storing,
  and the app renders it as text (never HTML), so it can neither bloat the
  table nor inject into the device list.

**Residual risk:** a phisher who relays the password *and* a live TOTP code in
real time can complete one login — but it triggers the new-device alert, and
the one-time-use rule denies any second use of that code. Closing the relay
vector entirely needs origin-bound WebAuthn (deferred; see gaps).

### A5 — Attacker with the victim's e-mail inbox

Can start recovery. Cannot complete a data-preserving recovery (needs the
Recovery Kit's verifier preimage); the only available path destroys all
items, after a 72 h cooling-off during which the owner is notified at every
address and can cancel with one click. Backup-address changes require a
fresh master password + TOTP.

**Residual risk:** inbox attacker + 72 h of owner inattention = account
denial/wipe (not disclosure). Deliberate trade-off, documented to users.

### A6 — Thief with the client device

The local replica stores only ciphertext; the refresh token is encrypted
under the vault key. Unlocking requires the master password (Argon2id at
desktop parameters). Auto-lock (15 min idle) zeroizes keys in memory;
clipboard auto-clears 30 s after copying a secret.

**Memory-protection posture (as built, with honest limits).** What we do:
key types are zeroize-on-drop *and* **page-locked** (`mlock`/`VirtualLock`),
transient plaintext uses `Zeroizing`, dropping the session on lock/auto-lock
scrubs the keys, `unsafe_code = "forbid"` rules out whole classes of memory
bugs, and the clipboard clear only fires if the clipboard still holds the
copied secret (never clobbers newer content). Status of each vector:

| Vector | Status | Note |
|---|---|---|
| Compiler reordering defeating zeroization | Mitigated | `zeroize` uses volatile writes + compiler fences by design |
| Locking key pages out of swap (`mlock`) | **Done (best-effort)** | Every key type is backed by `secmem::SecretBytes`, a page-locked heap allocation (`mlock`/`VirtualLock` via the `region` crate). Keys are pinned in RAM, not written to swap/hibernation. Best-effort: if the OS refuses (e.g. `RLIMIT_MEMLOCK`), the key still works, just unpinned. The syscall's `unsafe` is inside `region`, so `forbid(unsafe)` stands. |
| Suppressing core dumps / crash dumps | **Done (best-effort)** | Both the client and server call `harden::suppress_core_dumps()` at startup: Linux sets `RLIMIT_CORE = 0` **and** `PR_SET_DUMPABLE = 0` (the latter also covers the `core_pattern`-pipe case that the rlimit alone doesn't, e.g. systemd-coredump); other unix sets `RLIMIT_CORE = 0`. **Windows:** not suppressed in-app — Windows Error Reporting may still capture a dump; disable via policy (RUNBOOK). |
| Panic-path scrubbing | Partial | Drop-based scrub runs during unwinding; a hard abort does not unwind (but produces no core dump either, per the row above). |
| Clipboard history managers / OS sync | Out of app control | The app clears its own write; third-party clipboard managers may retain it. Documented for users. |

These are the standard limits of a userspace password manager and match the
posture of mainstream products; they are listed here so an auditor sees them
stated, not hidden. The remaining userspace-unclosable item is Windows crash
dumps (operator-disabled) and the live-attacker case below.

**In-memory-plaintext map (audit, 2026-07).** Every place a plaintext secret
lives in the *Rust* process, how long, and whether it is scrubbed:

| Secret | Where | Lifetime | Scrubbed? |
|--------|-------|----------|-----------|
| Master password / export passphrase | `String` arg into a Tauri command | one command call | **Yes** — wrapped in `Zeroizing` at entry |
| Master Key, Auth/Wrapping/Vault/Recovery keys | `keys.rs` key types (page-locked `SecretBytes`) | unlock → lock | **Yes** — zeroize-on-drop *and* `mlock`'d out of swap; subkey scratch is `Zeroizing` |
| KDF Argon2id output buffer | `derive_master_key` | derivation only | **Yes** — `Zeroizing` |
| Decrypted item bytes | `decrypt_item` result | until caller drops | **Yes** — returns `Zeroizing<Vec<u8>>` |
| Decrypted `Item` (password, card #, notes) | `Item` model | while displayed/edited server-side | **Yes** — `ZeroizeOnDrop`; `Debug` redacted |
| Serialized item plaintext (pre-encrypt) | `Item::to_plaintext` | until sealed | **Yes** — `Zeroizing` |
| Generated password | `generate_password` result | until dropped/copied | **Yes** — `Zeroizing<String>` (the transient `Vec<char>` is not `Zeroize`-able and is a brief exception) |
| Recovery Kit code | `Registration.recovery_code`; Tauri result | until shown once | Core copy `Zeroizing`; the `String` handed to the UI is **not** (see below) |
| Session refresh/access tokens | `ApiClient`, reqwest headers | session | **No** — plain `String` (a bearer credential, not a vault secret) |

**Residuals this audit deliberately leaves open (not fixable in Rust):**

- **The web-UI / JavaScript heap is the dominant residual.** Any secret shown
  or edited — an item password, the generated password, the Recovery Kit code
  — is serialized across the Tauri bridge into the WebView, where it lives in
  the **JS heap** as strings that Rust cannot reach and the JS GC will not
  scrub on any schedule. This is inherent to a web-UI password manager
  (Bitwarden, 1Password's Electron app, etc. share it). Auto-lock drops the
  Rust session but cannot evict JS strings; only closing the WebView does.
  A native-widget UI (or a WebAssembly core owning its own scrubbed buffers)
  would be required to close it — a large architectural change, tracked, not
  planned for v1.
- **Session tokens** sit in the API client and in reqwest's header buffers as
  plain UTF-8. They are session credentials (revocable, short-TTL — §A4b), not
  vault secrets, and TLS/reqwest would copy them regardless, so they are left
  unscrubbed by design.
- **The transient `Vec<char>`** inside the password generator holds the
  password briefly before it is collected into a `Zeroizing<String>`; `char`
  is not zeroizable in place. Negligible and noted for completeness.

**Residual risk:** malware on an *unlocked* device reads process memory —
out of scope for any password manager. Zeroization on lock narrows the
window; it does not close it against a live attacker on the device.

### A7 — Supply chain

Crypto is confined to audited RustCrypto crates; `unsafe_code = "forbid"`
workspace-wide; RustSec `cargo audit` in CI; `Cargo.lock` committed; no
frontend package dependencies at all (plain JS, CSP `default-src 'self'`).

Our own code contains no `unsafe`. The one operation that inherently needs a
raw syscall — locking key pages out of swap (`mlock`/`VirtualLock`) — is
delegated to the small, widely-used `region` crate, which encapsulates that
`unsafe` behind a safe API. This keeps `forbid(unsafe)` intact for every
first-party crate while still getting the syscall; `region` is in scope for
`cargo audit` like any other dependency.

## Metadata integrity — what is authenticated

Distinct from disclosure (below): which fields are covered by AEAD associated
data, so tampering is detected. As of the version-binding change (invariant
I12):

| Record | Authenticated (AEAD tag + AAD) | Not in AAD but safe because… |
|---|---|---|
| **Item** | ciphertext, nonce (it *is* the AEAD nonce), `item_id`, `revision`, `version` | — everything relevant is bound |
| **Wrapped key** | ciphertext, nonce, `purpose` (master/recovery), `version` | — |
| **Export** | ciphertext, nonce, `version`; KDF params implicitly (they key derivation) | — |

`nonce` is not "in the AAD" for any record, but it is the AEAD nonce itself,
so altering it changes the keystream and fails the tag. No field is both
attacker-controllable **and** trusted-without-authentication. Tests:
`item_binds_id_and_revision`, `item_binds_version_in_aad`,
`recovery_wrap_cannot_be_confused_with_master_wrap`, export tamper proptests.

*Server-managed* sync fields (`seq`, `updated_at`, tombstone flag) are **not**
end-to-end authenticated — they are the server's bookkeeping. The global `seq`
in particular is what a rollback manipulates; that is now defended by the
per-device monotonic guard and the vault-key-MAC'd checkpoint (§A2), which
authenticate the *sequence* under the Vault Key even though individual
server fields are not signed.

## Metadata disclosure

Zero-knowledge protects contents, not all metadata. Exactly what a
compromised server can observe (item count, ciphertext sizes, timing, device
names, …) — and what it cannot — is enumerated in **`docs/METADATA.md`**.
The largest remaining channel is item-ciphertext length; padding to fixed
buckets is the tracked mitigation below.

## Known gaps / accepted risks (v1)

Ordered roughly by priority for post-v1 work.

| Gap | Priority | Status |
|---|---|---|
| Whole-vault rollback by malicious server | **Mitigated** | Implemented: per-device monotonic guard + vault-key-MAC'd cross-device checkpoint + withholding detection (§A2). Only the first-sync-of-a-fresh-install-with-no-anchor case remains (narrow residual, §A2). |
| Item-size metadata leak | **Mitigated** | Implemented as `EncryptedItem` v2: plaintext is length-prefixed and zero-padded to 256-byte buckets before encryption, so ciphertext length reveals only a bucket. v1 records migrate on next write. Residual: long notes still leak size to 256-byte granularity (a future larger floor / exponential bucketing could tighten it). §Item record format in CRYPTOGRAPHIC_INVARIANTS. |
| No WebAuthn second factor | Medium | Deferred: WebKit webviews (Tauri) lack usable `navigator.credentials` platform-authenticator support; revisit with the browser extension or native FFI. TOTP + single-use recovery codes cover v1. |
| Master-password strength at registration | **Closed** | Three client-side checks now run at registration *and* recovery: composition rules (≥12 + capital + number + special), a HIBP breached-password check (SHA-1 k-anonymity; only a 5-char prefix leaves the device), and `zxcvbn` guessability scoring (rejects < 3/4 — common/dictionary/keyboard-walk/date passwords and e-mail-derived ones). Enforced client-side by necessity (zero-knowledge server). |
| Windows crash dumps (WER) not suppressed in-app | Low | On unix, core dumps are suppressed at startup (§A6, done). On Windows, Windows Error Reporting can still capture a crash dump; the app can't fully disable WER from userspace, so operators disable it via policy/registry (RUNBOOK). Keys are still `mlock`'d, limiting what lands in a dump. |
| Plaintext secrets in the WebView / JS heap | Medium | Inherent to a web-UI password manager: secrets shown/edited live in the JS heap until the view closes, beyond Rust's zeroization. Closing it needs a native-widget or WASM-core UI. Rust-side lifetime is now fully scrubbed (§A6 in-memory map). |
| `prelogin` enumeration secret is per-process | **Closed** | The enumeration secret is now persisted in the database (`server_secrets` table, `db::load_or_create_secret`) and reloaded on boot, so an unregistered address's dummy KDF salt is identical before and after a restart — the cross-restart signal analysed below no longer exists. (`dummy_hash` stays per-process by design: its value never leaves the server, so it carries no such signal.) Guarded by `enumeration_secret_persists_across_restarts`. |
| Bearer access tokens are replayable for ≤15 min | Low | Sender-constrained tokens (DPoP proof-of-possession or mTLS) would eliminate the replay window (§A4b). Deferred; short TTL + rotation + revocation is the v1 posture. |
| Mobile Argon2 parameters possibly conservative | Low | Floor is `m=19 MiB, t=2, p=1`; desktop `m=64 MiB, t=3, p=4`. Benchmark real unlock times per device class and raise toward `m=64–128 MiB` where UX allows — reviewer note. Parameters are per-account and versioned, so raising them later is a normal password-change (`RUNBOOK.md` §KDF migration). |
| E-mail inbox compromise enables wipe-after-72h | Accepted | By design (§A5): disclosure is worse than denial. |
| External security audit | **Blocker** | **Required before real-world use** — see RUNBOOK. |

### The `enumeration_secret` restart signal (now closed)

`prelogin` returns, for an unknown e-mail, a dummy salt
`HMAC(enumeration_secret, email)` that is stable within a server run and
indistinguishable from a real account's stored salt. Previously the secret was
per-process, so a restart regenerated it: an *unknown* e-mail's dummy salt would
change while a *real* account's salt (in the DB) stayed fixed, giving an
attacker who recorded salts across a restart a weak "salt changed ⇒ probably
unregistered" signal.

**Fixed.** The secret is now persisted (`server_secrets` table, loaded on boot),
so it is identical across restarts and the dummy salt for an unknown address no
longer changes — the diff the signal depended on is gone. It was always a
narrow oracle (required observing an infrequent, non-attacker-triggerable
restart; leaked only *existence*, never a secret or credential; and existence is
independently anti-enumerated and rate-limited across register/recover/login),
but it is now closed outright rather than merely bounded. `dummy_hash` remains
per-process deliberately: its value never leaves the server, so — unlike the
enumeration secret — it produces no client-observable cross-restart signal.
