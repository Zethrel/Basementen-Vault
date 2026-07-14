# Basementen Vault

A cross-platform, zero-knowledge password vault manager (Windows / macOS /
Linux / iOS / Android) built on industry-standard cryptography: Argon2id key
derivation, end-to-end encrypted sync, MFA, and offline-capable recovery.

## Status

Milestones M0–M7 implemented: crypto core, self-hostable server (MFA,
rate-limiting, recovery), offline-first sync, desktop app (also builds for
Android/iOS from the same codebase), export/import, and hardening. **Not yet
production-ready:** an external security review is a hard prerequisite before
real-world use (see the runbook), and several post-v1 hardening items are
tracked in the threat model.

## Documentation

| Doc | What it covers |
|---|---|
| [IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md) | Architecture, cryptographic design, milestones |
| [CRYPTOGRAPHIC_INVARIANTS.md](docs/CRYPTOGRAPHIC_INVARIANTS.md) | The crypto rules every change must preserve, each tied to a guarding test |
| [THREAT_MODEL.md](docs/THREAT_MODEL.md) | Assets, adversaries, and honestly-prioritized accepted risks |
| [METADATA.md](docs/METADATA.md) | Exactly what a compromised server can and cannot observe |
| [SELF_HOSTING.md](docs/SELF_HOSTING.md) | Running it at home (SQLite, SMTP, TLS/VPN, backups) |
| [RUNBOOK.md](docs/RUNBOOK.md) | Backups, upgrades, KDF migration, incident response |
| [MOBILE.md](docs/MOBILE.md) | Android / iOS build steps |
| [REVIEW_RESPONSE.md](docs/REVIEW_RESPONSE.md) | Response to the security architecture review |

## Security pillars (summary)

- **Zero-knowledge:** the server only ever stores ciphertext and password
  hashes — it can never decrypt your vault.
- **Argon2id** everywhere a password is stretched, on both client and server.
- **Envelope encryption:** a random vault key encrypts your data; your master
  password only wraps that key.
- **MFA:** TOTP + recovery codes at launch, WebAuthn/passkeys next.
- **Recovery:** printable Recovery Kit, plus an optional trusted backup
  e-mail with a cooling-off period.
- **Failed logins** cost a randomized 250–300 ms delay plus progressive
  rate limiting.
