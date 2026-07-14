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
  implemented; only the ≥12-char minimum is. Reworded to "as built" vs
  "backlog," and tracked in the threat model gaps table.
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

## Standing invitation

We welcome continuous review. The most useful next artifacts for a reviewer
are now in place: `CRYPTOGRAPHIC_INVARIANTS.md` (the rules), `METADATA.md`
(the disclosure surface), and `THREAT_MODEL.md` (adversaries + honestly
prioritized gaps). The external penetration test / crypto review remains a
hard blocker before real-world use (`RUNBOOK.md`).
