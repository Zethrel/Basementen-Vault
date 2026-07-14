# Response to security architecture review (2026-07)

A reviewer assessed the design documentation (README, IMPLEMENTATION_PLAN,
THREAT_MODEL) and rated the *documented architecture* 9.3/10 while flagging
areas to examine as implementation proceeds. This document records our
response to each point. It also corrects a few places where the reviewer,
working from docs alone, could not see what the code actually does.

## Corrections the reviewer couldn't see from docs

While addressing the review we re-read the code against the docs and fixed
two places where the **plan over-promised** relative to the as-built system.
Honesty about this matters more than looking finished:

- **Salt derivation.** The plan said the client salt was email-derived *and*
  "a per-account random salt is additionally mixed in after first contact."
  The code never did the hybrid — it uses a single, deterministic
  `HKDF-SHA256(email)` salt (`kdf::email_salt`). We removed the misleading
  sentence and documented the deliberate single-scheme choice with rationale
  (IMPLEMENTATION_PLAN §2.1, CRYPTOGRAPHIC_INVARIANTS §Salt). This directly
  answers the reviewer's concern #1.
- **Registration password checks.** The plan implied `zxcvbn` + HIBP were
  implemented; at the time only the ≥12-char minimum was. Reworded to "as
  built" vs "backlog." (Composition rules, the HIBP breach check, and `zxcvbn`
  scoring were all added later — see the 1.0 hardening notes below; the gap is
  now closed.)
- **Verification token.** Described as "signed"; it is actually a random
  token stored as SHA-256. Corrected.

## Point-by-point

| # | Reviewer point | Our response |
|---|---|---|
| 1 | Salt derivation — wants to verify the email→random transition can't be abused | **Resolved by removing the transition.** There is no hybrid; salt is a single deterministic `HKDF(email)`. Rationale (Argon2id is memory-hard → per-target precomputation is worthless; e-mails are unique → no cross-account amortization; server adds its own random salt on the AuthKey): CRYPTOGRAPHIC_INVARIANTS §Salt, PLAN §2.1. |
| 2 | Whole-vault rollback → make signed checkpoints high-priority post-v1 | **Agreed and promoted** to the top of the post-v1 gap list (THREAT_MODEL). Intended design sketched: server presents a client-signed `(max_seq, timestamp)` checkpoint the client verifies is not stale. |
| 3 | Metadata — enumerate exactly what the server learns | **New doc `docs/METADATA.md`** enumerates every server-visible field from the schema, flags the item-count and ciphertext-length leaks, and lists mitigations. Item-size padding is now a tracked High-priority gap. |
| 4 | Memory protection — zeroization, panics, crash dumps, clipboard, swap | **THREAT_MODEL §A6 expanded** into an explicit posture table: what we do (zeroize/Zeroizing, drop-on-lock, `forbid(unsafe)`, safe clipboard clear) and what we don't yet (mlock, core-dump suppression, hard-abort scrubbing) with the exposure each implies. Operator guidance (encrypted swap, FDE) added to RUNBOOK. |
| 5 | Mobile Argon2 parameters — benchmark; maybe 128 MiB is fine | **Tracked** (THREAT_MODEL gaps). Parameters are already per-account + versioned, so raising them is a normal password-change (RUNBOOK §KDF migration). Concrete per-device benchmarking is the next step before bumping the floor. |
| 6 | Add `docs/CRYPTOGRAPHIC_INVARIANTS.md` | **Done.** Eleven invariants, each mapped to its enforcement point *and* the test that guards it, plus the salt design note. Intended as the checklist every new feature is reviewed against. |

## What we did NOT change, and why

- **We did not switch to a random client salt.** For a memory-hard KDF it
  provides negligible real security over the email-derived salt while adding
  a mandatory server round-trip before any derivation and a migration story.
  We documented the reasoning instead of churning the core derivation. The
  door is left open (prelogin could carry an extra salt) if a future audit
  disagrees.
- **We did not implement item-size padding or signed checkpoints yet.** Both
  touch versioned on-the-wire formats and are scheduled as deliberate,
  tested post-v1 changes rather than rushed in — consistent with the
  "crypto versioning from day one" the reviewer praised.

## Second review — salt design (2026-07)

The reviewer pressed on the e-mail-derived KDF salt: not insecure, but they
asked us to either justify it or simplify to a random per-account salt, and
noted the downsides (cross-client e-mail-normalization becomes
security-critical; changing e-mail becomes awkward).

**We changed it.** On re-examining our own flows, the one benefit that would
justify an e-mail-derived salt — deriving keys *before* contacting the server
— we don't use: every online derivation already calls `prelogin` first, and
offline unlock reads cached account metadata. So we were paying the downsides
(a real cross-platform lockout risk for a 5-client product, plus e-mail-change
friction) for a benefit we never spent. The previous doc's "we deliberately
keep it" stance was, honestly, rationalizing a design that didn't serve us.

What shipped (this commit):

- Client KDF salt is now a **random 128-bit per-account value**
  (`kdf::generate_salt`); the e-mail no longer enters derivation at all.
- The salt is stored server-side (`accounts.kdf_salt`), returned by
  `prelogin`/`login`, and cached in `AccountMeta` for offline unlock. (The
  third review then made it account-lifetime — never rotated; see below.)
- **Anti-enumeration preserved:** `prelogin` returns a stable, unpredictable
  dummy salt (`HMAC(server_secret, email)`) for unknown accounts, so the
  response is indistinguishable from a real one. New test:
  `unknown_email_fails_indistinguishably` now also asserts salt stability.
- `vault-core` signatures dropped the `email` argument
  (`register`/`login_credential`/`unlock`/`recover_and_rekey`/
  `change_password`); e-mail is purely an identifier and can now change
  without touching keys.

Docs updated to match: PLAN §2.1, CRYPTOGRAPHIC_INVARIANTS §Salt. Full suite
(61 tests) green, including the two-device sync and recovery end-to-end paths
that would catch any salt-threading inconsistency.

One residual was tracked here: the `enumeration_secret` was per-process, so it
reshuffled on restart. **Now closed** — it is persisted in the database and
reloaded on boot (see the 1.0 hardening note below). `dummy_hash` stays
per-process by design (its value never leaves the server).

## Third review — salt lifetime, and the "edges" (2026-07)

The reviewer endorsed the random-salt change and raised one concrete item
plus a list of areas to scrutinize next.

**Concrete change — don't rotate the salt on password change (done).** They
were right: rotating adds synchronized state and a half-failed-operation path
for zero cryptographic benefit (the password already changed the key). We
made the salt **account-lifetime**: generated once at registration, never
rotated — including through recovery. `recover_and_rekey`/`change_password`
now take the existing salt; `recovery/data` returns it; invariant I13 and
tests assert preservation.

**Metadata integrity (their #5) — hardened + documented.** We bound the
record/format `version` into the AEAD associated data for items, wrapped
keys, and exports (invariant I12), so *all* persisted metadata is now
authenticated, not just the ciphertext. THREAT_MODEL now has a precise
"what is authenticated" table.

**Server-compromise model (their #4) — documented as a matrix.** THREAT_MODEL
§A2 now enumerates each malicious-server action (param/salt substitution,
wrapped-key replay, item swap/rollback, malformed ciphertext, metadata
alteration) and shows the client-side check that makes it fail-safe (DoS, not
disclosure) — with the one genuine exception, whole-vault rollback, called
out as the top post-v1 item.

**Recovery (their #3) — the answer is "no".** Recovery can *never* become
"prove control of e-mail → receive vault": data-preserving recovery requires
the Recovery-Kit verifier (I11); e-mail alone yields only an explicit,
cooling-off-gated wipe. Unchanged, restated here for the record.

**CRYPTOGRAPHIC_INVARIANTS.md** now opens with a 12-rule at-a-glance list; the
reviewer's proposed 8 map to rules 1–8.

**Areas deferred to dedicated review (agreed milestone order):** session
layer, sync protocol + rollback/replay, device enrollment, and a full
in-memory-plaintext audit. These match the reviewer's proposed pre-audit
milestones; the browser extension is intentionally not designed yet (it
would change the threat model and we'd rather model it when it's real). No
code exists for these beyond what's already documented; we'll take them one
at a time.

## Session/auth layer — the reviewer's #1 next milestone (2026-07)

The reviewer named the session layer highest priority ("often more dangerous
than the encryption itself"). We reviewed it against their checklist and
hardened the gaps.

Already solid (documented in THREAT_MODEL §A4b): opaque 256-bit access +
refresh tokens stored only as SHA-256; 15-min access TTL; single-use refresh
with rotation; refresh-reuse detection that revokes the whole session family;
no session fixation (server-generated tokens); no CSRF (header auth, not
cookies).

New in this pass:

- **Absolute session lifetime cap** (90 days). Previously sliding refresh
  could keep a session alive forever; now a hard ceiling is set at login,
  carried unchanged through every rotation, and enforced at refresh *and* in
  the auth extractor. Test: `absolute_lifetime_cap_stops_sliding_refresh`.
- **Device (session) management API + UI.** `GET /sessions` lists active
  devices (device name, login time, last-active, current flag — no secrets);
  `DELETE /sessions/{family}` revokes one; `POST /sessions/revoke-others`
  logs out everywhere else. Wired into the app's ⚙ dialog as an "Active
  devices" list with per-device Revoke and "Log out all other devices".
  Previously the only way to revoke a device was raw SQL (runbook). Tests:
  `sessions_list_shows_devices_and_current`,
  `revoke_one_device_kills_only_that_session`,
  `revoke_others_logs_out_everyone_else`,
  `cannot_revoke_another_accounts_session` (revocation is account-scoped),
  plus a client-side end-to-end `api_client_session_management`.
- **Activity tracking.** `last_used_at` updates on each refresh; `created_at`
  is carried forward as the original login time (a bug the tests caught: it
  was resetting on every rotation). Powers the device list and makes stale
  sessions visible.
- **Dead-session cleanup** on login (rows past the refresh window, beyond any
  reuse-detection value) so the table can't grow unbounded.

Deferred (documented): sender-constrained tokens (DPoP/mTLS) to close the
≤15-min bearer-replay window — a large feature, not warranted for a
self-hosted vault behind TLS/VPN at v1.

Next from the reviewer's list: the **sync protocol** (rollback/replay/
conflict), then recovery/device-enrollment and the in-memory-plaintext audit.

## Sync protocol — the reviewer's #2 next milestone (2026-07)

The reviewer asked us to model the sync engine against a malicious or buggy
server and against concurrent devices, with five concrete questions. We took
the pass and answer each below.

Already solid (documented, now tested end-to-end): the engine is
**crypto-agnostic** — it moves opaque ciphertext and never sees a key — so a
compromised server learns nothing new by observing sync. Deltas are
revision-based off a per-account monotonic `seq`; tombstones propagate deletes
and are purged after 30 days; writes use **optimistic concurrency** (a stale
base revision gets a `409`, never a silent clobber); the resolution rule is
**server-wins with a conflict-copy** so a losing edit is preserved, never
destroyed.

New in this pass — **whole-vault rollback is now detected**, closing the one
malicious-server gap the previous reviews left open (was THREAT_MODEL §A2's
top post-v1 item). Three layered defenses:

- **Per-device monotonic guard (engine).** The engine records a durable
  `last_seq` high-water mark and refuses any pull whose `latest_seq` regressed
  below it (`SyncEngineError::RollbackDetected`), *before* mutating the
  replica. This also catches the honest-mistake case — restoring an old
  server backup — not just malice. Test: `server_rollback_is_detected`.
- **Vault-key-MAC'd cross-device checkpoint.** A device publishes
  `checkpoint = (seq, HKDF(VaultKey, "sync-checkpoint" ‖ seq))` to the server
  (invariant I14). Any other device — including a fresh reinstall with no
  local `last_seq` — fetches it and verifies the tag under the Vault Key. The
  server cannot forge a checkpoint (no key) and the endpoint only accepts a
  *higher* `seq`, so it cannot lower an existing anchor either. A tag that
  fails to verify is treated as server compromise (`CheckpointForged`). Tests:
  `checkpoint_published_and_verified`, `forged_checkpoint_is_rejected`,
  `sync_checkpoint_tag_is_deterministic_key_and_seq_bound`.
- **Alarm-never-silent.** All three conditions surface to the user as a hard
  "Sync stopped" alert, never a quiet degrade; the replica is left untouched.

The reviewer's five questions, answered:

1. *Can two devices overwrite each other's writes?* No — optimistic
   concurrency rejects a stale base with `409`; the client re-pulls and
   re-applies. A true concurrent edit to the same item yields a preserved
   conflict-copy, not a lost write. Test:
   `stale_delete_cannot_destroy_a_concurrent_edit`.
2. *Offline edits then reconnect?* The engine replays local pending ops on top
   of the pulled server state; each carries its base revision so a conflict is
   detected rather than silently merged.
3. *Can the server replay an older vault state?* No — see the three-layer
   rollback defense above; a regressed `latest_seq` or a checkpoint below the
   device floor aborts the sync.
4. *Conflict resolution?* Deterministic server-wins with conflict-copy
   preservation; the user sees both records and never loses data silently.
5. *Malicious ordering / silent data loss?* Withholding is caught: an
   authentic checkpoint for `seq` higher than the data the server actually
   served triggers `SyncError::Withholding`. Reordering below the floor is a
   rollback and aborts. Test: `withholding_committed_data_is_detected`.

Layering is deliberate: the checkpoint lives in `desktop-core::rollback::
synchronize` (it needs the Vault Key) while the engine stays key-free, so the
transport-agnostic core is unchanged and independently testable.

One narrow residual, tracked (THREAT_MODEL §A2): a *fresh install* that has
**never** seen this account and whose **first** contact is with a server
already serving a consistently-rolled-back state has no anchor to compare
against. Every device that has synced even once is protected. Closing the
residual fully needs an out-of-band signed checkpoint (e.g. printed with the
Recovery Kit) — deferred, not rushed into the wire format.

Next from the reviewer's list: recovery/device-enrollment, then the
in-memory-plaintext audit.

## Recovery / device-enrollment — the reviewer's #3 milestone (2026-07)

We reviewed the recovery and device-enrollment surface. The core crypto was
already solid (the six `recovery_flows` tests: Recovery-Kit-preserves-data,
cooling-off, cancel, verifier enforcement, wipe-reset, backup-email lifecycle;
verifier is an HKDF branch of the Vault Key stored only as SHA-256, so e-mail
alone can never data-preservingly recover). The gaps were in the *enrollment
and second-factor* edges, which we hardened:

- **TOTP one-time use (RFC 6238 §5.2).** Codes were previously replayable
  within their ±1-step window. The server now records the last consumed
  time-step and refuses any non-newer code, across login and every sensitive-
  action confirmation. Enforcement starts at first login (not enrollment) so
  the "activate then sign in" flow stays natural.
- **New-device sign-in notification.** Enrollment is just a login, so we added
  the missing detection control: a session opened for a not-already-active
  device label alerts the owner. This is the answer to "attacker has my
  password and a second factor" — they can't sign in silently.
- **`device_name` hardening.** It was unbounded client input echoed into the
  device list; now sanitized (control chars stripped, capped at 64 chars).
- **Recovery-code replenishment.** Ten single-use codes could be exhausted
  with no path back except full account recovery. Added `GET /mfa/status`
  (remaining count) and `POST /mfa/recovery-codes/regenerate` (fresh password
  + current TOTP).

Four new tests; full suite green. Documented in THREAT_MODEL §A4c (these are
auth-layer controls — recorded with the session/second-factor threats rather
than as crypto invariants).

## Documentation review — reconciliation pass (2026-07)

A documentation reviewer read all eight docs and flagged inconsistencies and
ambiguities. Every point is now fixed or answered in-place:

- **SQLite vs PostgreSQL.** The as-built server uses **SQLite**; the plan's
  tech-choice table still listed PostgreSQL (and PASETO/JWT) as the target.
  Corrected to the shipped choices with the rationale, noting Postgres as an
  optional future backend (IMPLEMENTATION_PLAN §7).
- **`device_name` default contradiction.** METADATA said both "defaults to
  empty" and "app sends the OS hostname." Reconciled: the app sends the
  hostname (fallback `"desktop"`); the field is optional *at the protocol
  level* (a client may send empty); the server sanitizes but never invents one
  (METADATA). MOBILE.md doesn't actually assert a default — no change needed
  there.
- **Recovery Kit timing.** Clarified that a fresh kit is issued on **both**
  password change and full recovery (both rebuild the bundle); the verifier
  value itself is stable because the Vault Key is (CRYPTOGRAPHIC_INVARIANTS
  I11).
- **Two (three) distinct salts.** Added a table separating the client KDF
  salt, the server auth-hash salt, and the export salt — where each lives and
  what it defends (CRYPTOGRAPHIC_INVARIANTS §Salt).
- **Export envelope spec.** Added the full v1 field-by-field format
  (CRYPTOGRAPHIC_INVARIANTS §Export file format).
- **Prelogin / cache lifecycle.** Documented what the `AccountMeta` cache
  holds, when it refreshes, and why an account-lifetime salt means a stale
  cache is never wrong (CRYPTOGRAPHIC_INVARIANTS §Salt).
- **Operator SQL vs "no admin override."** Reconciled in RUNBOOK: raw SQL is a
  self-host operator's break-glass tool that touches only *availability*; it
  can never reach plaintext, because the server holds no keys. "No admin
  override" means no path to plaintext, not no operational control.
- **Conflict-copy granularity (Q).** Corrected: resolution is **whole-item**
  server-wins-with-conflict-copy, not field-group — the zero-knowledge engine
  sees only opaque ciphertext, so field-level merge is impossible by
  construction (IMPLEMENTATION_PLAN §6).
- **Checkpoint ↔ monotonic-guard order (Q).** Documented the exact five-step
  sequence within one sync cycle and why there are two guards against
  different anchors (THREAT_MODEL §A2).
- **`enumeration_secret` restart signal (Q).** Added an exploitability
  analysis: it is a probabilistic *existence* hint gated on observing a server
  restart and re-querying across it, never a disclosure or auth path;
  persisting the secret closes even that (THREAT_MODEL gaps).

## In-memory-plaintext audit — the reviewer's #4 milestone (2026-07)

The last item on the agreed pre-audit list: trace every plaintext secret in
client memory, scrub what we control, and document the rest honestly.

Already good: all key types were `Zeroize`/`ZeroizeOnDrop`, the KDF output and
pre-encryption item buffer used `Zeroizing`, and auto-lock dropped the session
to scrub keys. The audit found and fixed the gaps where *decrypted* plaintext
lingered:

- **`decrypt_item` now returns `Zeroizing<Vec<u8>>`** (matching
  `decrypt_export`), so every decrypted item buffer is scrubbed on drop.
- **The `Item` model is now `ZeroizeOnDrop`** — it holds the most sensitive
  plaintext (passwords, card numbers, notes) — and its `Debug` is **redacted**;
  it previously derived `Debug`, which would have printed secret fields (an I8
  violation). New test: `debug_never_prints_secret_fields`.
- **Tauri command password/passphrase/recovery-code args are wrapped in
  `Zeroizing`**, so the master password isn't left in the deserialized request
  buffer after the call.
- **`derive_subkeys` uses `Zeroizing` scratch**, scrubbing the transient
  subkey copies otherwise left on the stack.

Documented residuals we deliberately don't chase (they can't be fixed in Rust):
the **JavaScript heap** is the dominant one — any secret shown or edited is
serialized into the WebView and lives there beyond Rust's reach until the view
closes; **session tokens** stay plain in the API client / reqwest headers (a
revocable session credential, not a vault secret, and TLS copies them anyway).
Both, plus a full secret-by-secret lifetime table, are now in THREAT_MODEL §A6.

This completes the reviewer's proposed pre-audit milestones (session, sync,
recovery/enrollment, in-memory audit). The external penetration test / crypto
review remains the hard blocker before real-world use.

## Post-milestone hardening — item-size padding (2026-07)

Closed the top-priority metadata gap (reviewer point #3, THREAT_MODEL's former
"High" item). Vault items now encrypt as `EncryptedItem` **v2**: plaintext is
length-prefixed and zero-padded to 256-byte buckets before AEAD, so the stored
ciphertext length reveals only which bucket an item falls in — every ordinary
login and card share one length. The record version is authenticated in the AAD
(I12); v1 (unpadded) items still decrypt and migrate to v2 on their next write,
so no forced migration is needed. Residual: long notes still leak their size to
256-byte granularity (a larger floor or exponential bucketing is a future v3
option). Spec in CRYPTOGRAPHIC_INVARIANTS §Item record format; guarded by four
new tests.

## Post-milestone hardening — key-page locking (2026-07)

Closed the `mlock` gap (THREAT_MODEL §A6, was "Not done / Medium"). Every key
type now stores its bytes in `secmem::SecretBytes` — a heap allocation whose
backing page is locked out of swap (`mlock`/`VirtualLock`) and zeroized on
drop — so key material is pinned in RAM and never written to a swap file or
hibernation image. Notes:

- **No new first-party `unsafe`.** The syscall lives in the small, widely-used
  `region` crate behind a safe API, so `forbid(unsafe)` still holds for every
  crate we write (called out in THREAT_MODEL §A7).
- **Neighbour-safe locking.** `SecretBytes` allocates two pages and locks the
  one page fully contained inside them, so locking/unlocking never touches
  another allocation's memory (which could otherwise unlock a neighbour's key
  when one drops). Guarded by `secmem::tests`.
- **Best-effort.** If the OS refuses (e.g. `RLIMIT_MEMLOCK`, or a container
  ulimit), the key still works — just unpinned. RUNBOOK now tells operators how
  to raise the locked-memory budget and how to disable core dumps (the one
  remaining §A6 item).

## Post-milestone hardening — core-dump suppression (2026-07)

Closed the last §A6 memory item. Both binaries call
`vault_core::harden::suppress_core_dumps()` at startup (before any secret
exists), so a later crash can't spill key-bearing memory to a core/crash dump:

- **Linux:** `RLIMIT_CORE = 0` **and** `PR_SET_DUMPABLE = 0`. The rlimit alone
  is insufficient — the kernel ignores it when `core_pattern` pipes to a
  handler (systemd-coredump/apport), the common desktop case — so
  `PR_SET_DUMPABLE = 0` is what actually suppresses the dump (and blocks
  same-user `ptrace` as a bonus).
- **Other unix (macOS/BSD):** `RLIMIT_CORE = 0`.
- **Windows:** not suppressible from userspace; operators disable WER dumps by
  policy (RUNBOOK). Keys are `mlock`'d regardless, limiting exposure.

Same `forbid(unsafe)` discipline as `mlock`: the syscalls live in the target-
gated `rlimit` / `prctl` dependencies (no-op on non-unix), never in our code.
Guarded by `harden::tests`. This leaves the client memory posture with only the
two inherent residuals — the JS heap and a live attacker on an unlocked device.

## Post-milestone hardening — persist the enumeration secret (2026-07)

Closed the last low-severity anti-enumeration residual. The `enumeration_secret`
(which derives the stable dummy prelogin salt for unknown accounts) is now
stored in the database (`server_secrets` table, `db::load_or_create_secret`,
minted on first boot) and reloaded on startup, so an unregistered address's
dummy salt is identical before and after a restart — the cross-restart
"salt changed ⇒ probably unregistered" signal no longer exists. If the DB read
ever fails the server falls back to a per-process secret rather than refusing to
boot. `dummy_hash` intentionally stays per-process (its value never leaves the
server). Guarded by `enumeration_secret_persists_across_restarts`.

## Post-milestone hardening — master-password strength policy (2026-07)

Added a composition policy for the master password, enforced client-side (the
only place possible — the server never sees the password): **≥12 characters,
plus at least one capital letter, one number, and one special character.**
Applied at **both** registration and recovery, so recovery can't be used to set
a weaker password. Lives in `desktop_core::check_password_strength`, which
returns a single message naming every unmet requirement; the setup and recovery
screens show the rule up front. Guarded by `password::tests`.

Scope note at the time: composition rules stop trivially weak inputs but not a
long-but-breached passphrase. The stronger complements — a Have I Been Pwned
k-anonymity check and `zxcvbn` entropy scoring — were then added in the two
hardening passes below, closing the gap.

## Post-milestone hardening — breached-password check (2026-07)

Added the Have I Been Pwned breached-password check that had been backlog,
complementing the composition policy. When a master password is set
(registration or recovery), `desktop_core::password_breach_count` looks it up
via **k-anonymity**: the client SHA-1s the password and sends only the first
5 hex characters to the HIBP range API, then matches the returned 35-char
suffixes locally. The password and its full hash never leave the device; the
service sees only a ~1-in-a-million-buckets prefix. `Add-Padding: true` hides
which prefix was requested from response-size analysis; zero-count padding rows
are ignored. A match is rejected with a count; a network failure is **ignored**
so an offline/air-gapped deployment can still register (the composition policy
still gates). The one outbound call is documented in SELF_HOSTING for operator
transparency. Guarded by `hibp::tests` (pure prefix/suffix + response parsing).

This leaves only `zxcvbn`-style entropy scoring on the password-strength gap
(Low) — structurally weak but unbreached inputs.

## Post-milestone hardening — zxcvbn guessability scoring (2026-07)

Added the final password-strength check: `desktop_core::check_password_
guessability` runs a zxcvbn-style estimator and rejects any master password
scoring below "safely unguessable" (3 of 4). This catches the class that
composition rules and the breach corpus both miss — `Password123!`, keyboard
walks, dictionary words, dates, and passwords derived from the account e-mail
(passed as a user-input so they're penalised). The rejection message includes
zxcvbn's own warning/suggestion so the user learns why. Runs at registration
*and* recovery, after the composition check. Guarded by `password::tests`
(rejects a composition-passing-but-common password, accepts a high-entropy one,
and rejects a password equal to a supplied user input).

With composition rules + HIBP breach check + zxcvbn scoring all in place, the
master-password-strength gap is **closed** for v1 (THREAT_MODEL gaps table).

## v1-readiness — MFA enrollment in the app (2026-07)

A pre-1.0 review found that TOTP was fully implemented server-side and in the
client library but **not reachable from the app UI** — an advertised security
feature users couldn't actually turn on. Now wired end to end:

- ApiClient gains `totp_enroll` / `totp_activate` / `totp_disable` (joining the
  existing `mfa_status` / `regenerate_recovery_codes`).
- New Tauri commands `mfa_status`, `totp_enroll`, `totp_activate`,
  `totp_disable`, `regenerate_recovery_codes`; enroll/disable/regenerate are
  gated on a fresh master-password confirmation (derived to the AuthKey
  client-side), matching the server's requirement.
- The Settings dialog gains a **Two-factor authentication** section: shows
  on/off + recovery codes remaining; enrolling renders the `otpauth://` secret
  as a scannable **QR** (generated on-device with the `qrcode` crate, inline SVG
  — no external fetch, CSP-safe) plus the manual key; confirming with a live
  code activates it and displays the one-time recovery codes; when on, offers
  regenerate-codes and turn-off.

Guarded by `mfa::tests` (QR render) and an end-to-end
`api_client_mfa_enrollment_lifecycle` (enroll → activate → status → disable
against a real server). No server changes — the endpoints already existed and
were tested.

## v1-readiness — change master password in the app (2026-07)

The other advertised-but-unreachable feature: `vault_core::account::
change_password` existed but had no server endpoint or UI. Now wired end to end:

- **Server:** `POST /api/v1/account/change-password` — gated on a fresh
  confirmation of the *current* password (and TOTP when enrolled, via the
  shared `confirm_sensitive`). It stores the new auth hash, re-wrapped Vault
  Key, and fresh recovery kit; **keeps the account-lifetime salt** (I13); and
  revokes every *other* session (the current device stays signed in).
- **Client:** `ApiClient::change_password`, a Tauri `change_password` command
  that validates the new password with the full policy (composition +
  guessability keyed on the e-mail + breach check), re-wraps the unchanged
  Vault Key locally, updates the cached `AccountMeta` so offline unlock uses the
  new password, and returns the **new Recovery Kit code** to show once.
- **UI:** a "Change master password" section in Settings (current + new
  password, 2FA code, requirement hint) that surfaces the new Recovery Kit and
  warns the old one is spent.

Crucially, the **Vault Key is unchanged**, so all items stay readable and no
re-encryption of the vault is needed — only the password-derived wrapping and
the recovery kit rotate. Guarded by
`change_password_rewraps_preserves_data_and_revokes_others` (data survives,
salt unchanged, other devices signed out, old password rejected, new one works).

## Standing invitation

We welcome continuous review. The most useful next artifacts for a reviewer
are now in place: `CRYPTOGRAPHIC_INVARIANTS.md` (the rules), `METADATA.md`
(the disclosure surface), and `THREAT_MODEL.md` (adversaries + honestly
prioritized gaps). The external penetration test / crypto review remains a
hard blocker before real-world use (`RUNBOOK.md`).
