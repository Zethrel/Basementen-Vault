# Security Policy

Basementen Vault is a password manager: the confidentiality and integrity of
user secrets is the entire point of the project. We take security reports
seriously and are grateful for responsible disclosure.

> **Pre-1.0 status — read this first.** Basementen Vault has **not yet
> undergone an independent security audit or cryptographic review.** That review
> is tracked as a hard blocker before real-world use (`docs/RUNBOOK.md`). Until
> it is done, treat this as beta software and do not rely on it as the sole
> protection for high-value secrets.

## Reporting a vulnerability

**Please do not open a public issue, pull request, or discussion for a security
problem** — that discloses it before a fix exists.

Report it privately using GitHub's **"Report a vulnerability"** button on the
repository's **Security** tab:

> https://github.com/Zethrel/Basementen-Vault/security/advisories/new

This opens a private advisory visible only to you and the maintainers. If you
are unable to use GitHub private reporting, open a minimal public issue titled
"security contact request" (with **no** technical details) asking a maintainer
to reach out, or use the contact in the repository owner's GitHub profile.

Please include, as far as you can:

- a description of the issue and the impact you believe it has;
- the affected component and the version or commit hash;
- reproduction steps or a proof of concept;
- any suggested remediation.

If you have found a way to break the zero-knowledge property (the server, or
anyone with the database, learning plaintext, keys, or the master password),
say so prominently — that is the most serious class of bug for this project.

## What to expect

- **Acknowledgement** of your report within **3 business days**.
- An **initial assessment** (severity + rough plan) within about **10 days**.
- **Coordinated disclosure:** we will agree a timeline with you, develop and
  ship a fix, and publish an advisory. Please allow a reasonable window
  (typically up to **90 days**) before any public disclosure. We are usually
  much faster for clear, high-severity issues.
- **Credit:** we will credit you in the advisory and changelog unless you ask
  to remain anonymous.

## Scope

**In scope** — anything that undermines the documented security model:

- Breaking **zero-knowledge**: the server (or a database thief) recovering
  plaintext, key material, or the master password.
- **Cryptographic** weaknesses: the key hierarchy, KDF usage, AEAD/envelope
  encryption, item/version binding, the recovery verifier, or the sync
  rollback-protection checkpoints.
- **Authentication / session** flaws: token handling, MFA bypass, recovery
  abuse, account takeover, or account enumeration.
- **Client** issues that expose vault contents: injection into the web UI,
  insecure local storage of secrets, or memory disclosure beyond the limits
  already documented in `docs/THREAT_MODEL.md` §A6.

`docs/THREAT_MODEL.md` and `docs/CRYPTOGRAPHIC_INVARIANTS.md` describe what the
system is designed to resist. A report that demonstrably **violates a stated
invariant** is especially valuable.

**Known / accepted limitations** (documented, and *not* considered
vulnerabilities):

- The items marked "Deferred" or "Accepted" in `docs/THREAT_MODEL.md`
  §Known gaps — e.g. sender-constrained (DPoP/mTLS) tokens, WebAuthn, and the
  WebView / JavaScript-heap plaintext residual.
- Denial of service against a server you self-host and control.
- Attacks that require an already-compromised device, a malicious OS, or an
  attacker with access to an already-unlocked session.
- Social engineering of a user or of their e-mail provider.
- Missing hardening on a deployment that ignores `docs/SELF_HOSTING.md` /
  `docs/RUNBOOK.md` (e.g. no TLS, exposed to the public internet without a
  reverse proxy).

## Supported versions

Basementen Vault is pre-1.0 and self-hosted. Only the latest commit on the
default branch is supported; please reproduce against `main` before reporting.

## Safe harbor

We consider good-faith security research that follows this policy to be
authorized, and we will not pursue or support legal action against researchers
who:

- make a good-faith effort to avoid privacy violations, data destruction, and
  service disruption;
- only interact with accounts and servers they own or have explicit permission
  to test;
- give us a reasonable time to remediate before disclosing publicly.

Thank you for helping keep Basementen Vault and its users safe.
