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

**Residual risk:** weak master passwords. Mitigated by the 12-char client
minimum; strengthen with a wordlist check (backlog).

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
| Serve a **complete old vault snapshot** (whole-vault rollback) | **Not yet prevented** — see residual risk. |

**Residual risk:** whole-vault rollback. The server could present an
internally-consistent older state (all items at older revisions). Per-item
AAD doesn't catch this because each old item is individually valid. Clients
detect a *decrease* in the global `seq` they've seen, but a fresh client has
no baseline. Full mitigation — a signed monotonic checkpoint the client
verifies is not older than its last-seen — is the top post-v1 item (§Known
gaps).

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
key types are `Zeroize`/`ZeroizeOnDrop`, transient plaintext uses
`Zeroizing`, dropping the session on lock/auto-lock scrubs the keys,
`unsafe_code = "forbid"` rules out whole classes of memory bugs, and the
clipboard clear only fires if the clipboard still holds the copied secret
(never clobbers newer content). What we do **not** yet do, and the resulting
exposure:

| Vector | Status | Note |
|---|---|---|
| Compiler reordering defeating zeroization | Mitigated | `zeroize` uses volatile writes + compiler fences by design |
| Locking key pages out of swap (`mlock`) | **Not done** | Keys can be paged to disk under memory pressure. Mitigation: encrypted swap at the OS level (operator responsibility; note in RUNBOOK). |
| Suppressing core dumps / crash dumps | **Not done** | A crash could write key-bearing memory to a dump file. |
| Panic-path scrubbing | Partial | `ZeroizeOnDrop` runs during unwinding; a hard abort does not unwind. |
| Clipboard history managers / OS sync | Out of app control | The app clears its own write; third-party clipboard managers may retain it. Documented for users. |

These are the standard limits of a userspace password manager and match the
posture of mainstream products; they are listed here so an auditor sees them
stated, not hidden. Page-locking and core-dump suppression are tracked
below.

**Residual risk:** malware on an *unlocked* device reads process memory —
out of scope for any password manager. Zeroization on lock narrows the
window; it does not close it against a live attacker on the device.

### A7 — Supply chain

Crypto is confined to audited RustCrypto crates; `unsafe_code = "forbid"`
workspace-wide; RustSec `cargo audit` in CI; `Cargo.lock` committed; no
frontend package dependencies at all (plain JS, CSP `default-src 'self'`).

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
end-to-end authenticated — they are the server's bookkeeping. Trusting them is
exactly the whole-vault rollback gap (§A2), addressed by signed checkpoints
post-v1.

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
| **Whole-vault rollback by malicious server** | **High** | Accepted for v1. Signed/authenticated monotonic checkpoints (server presents a client-signed `(max_seq, timestamp)` the client verifies is not older than its last-seen) is the intended fix — promoted to the top of the post-v1 list on reviewer recommendation. |
| **Item-size metadata leak** | High | Ciphertext length ≈ plaintext length. Fix: pad item plaintext to fixed buckets as a versioned `EncryptedItem` v2 (`docs/METADATA.md` rec. 1). |
| No WebAuthn second factor | Medium | Deferred: WebKit webviews (Tauri) lack usable `navigator.credentials` platform-authenticator support; revisit with the browser extension or native FFI. TOTP + single-use recovery codes cover v1. |
| No compromised-password (HIBP) check + `zxcvbn` strength scoring at registration | Medium | Backlog. Only the ≥12-char minimum is enforced today. HIBP via SHA-1 k-anonymity (prefix query; password never leaves the device). |
| Key pages not `mlock`ed; core dumps not suppressed | Medium | See §A6 memory table. |
| `prelogin` enumeration secret is per-process | Low | Dummy KDF salts for unknown accounts are stable within a server run but reshuffle on restart (a weak cross-restart enumeration signal). Persisting the secret closes it; deferred, consistent with the existing per-process `dummy_hash`. |
| Mobile Argon2 parameters possibly conservative | Low | Floor is `m=19 MiB, t=2, p=1`; desktop `m=64 MiB, t=3, p=4`. Benchmark real unlock times per device class and raise toward `m=64–128 MiB` where UX allows — reviewer note. Parameters are per-account and versioned, so raising them later is a normal password-change (`RUNBOOK.md` §KDF migration). |
| E-mail inbox compromise enables wipe-after-72h | Accepted | By design (§A5): disclosure is worse than denial. |
| External security audit | **Blocker** | **Required before real-world use** — see RUNBOOK. |
