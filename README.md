# Basementen Vault

A cross-platform, zero-knowledge password vault manager (Windows / macOS /
Linux / iOS / Android) built on industry-standard cryptography: Argon2id key
derivation, end-to-end encrypted sync, MFA, and offline-capable recovery.

## Status

First tagged release: **1.0.0-beta.1** — feature-complete (crypto core,
self-hostable server with MFA/rate-limiting/recovery, offline-first sync,
desktop app that also builds for Android/iOS, export/import) and hardened across
three review rounds plus follow-on passes. **It is an unaudited beta:** an
independent security review is a hard prerequisite before real-world use (see
the runbook), so don't store irreplaceable secrets in it yet. Post-v1 items are
tracked in the threat model; see [CHANGELOG.md](CHANGELOG.md) for the history.

## Documentation

| Doc | What it covers |
|---|---|
| [IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md) | Architecture, cryptographic design, milestones |
| [CRYPTOGRAPHIC_INVARIANTS.md](docs/CRYPTOGRAPHIC_INVARIANTS.md) | The crypto rules every change must preserve, each tied to a guarding test |
| [THREAT_MODEL.md](docs/THREAT_MODEL.md) | Assets, adversaries, and honestly-prioritized accepted risks |
| [METADATA.md](docs/METADATA.md) | Exactly what a compromised server can and cannot observe |
| [SELF_HOSTING.md](docs/SELF_HOSTING.md) | Running it at home (SQLite, SMTP, TLS/VPN, backups) |
| [RUNBOOK.md](docs/RUNBOOK.md) | Backups, upgrades, KDF migration, incident response |
| [RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md) | Step-by-step gate for cutting a signed, verified release |
| [MOBILE.md](docs/MOBILE.md) | Android / iOS build steps |
| [REVIEW_RESPONSE.md](docs/REVIEW_RESPONSE.md) | Response to the security architecture review |
| [SECURITY.md](SECURITY.md) | How to report a vulnerability, scope, and safe harbor |

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

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the dev
setup, the checks CI enforces, and the non-negotiables (zero-knowledge,
`forbid(unsafe)`, and the cryptographic invariants). For anything non-trivial,
open an issue to discuss first.

## Reporting security issues

Please **do not** file public issues for vulnerabilities. See
[SECURITY.md](SECURITY.md) for private reporting via GitHub, scope, and our
safe-harbor policy. (Reminder: this project has not yet had an independent
security audit — treat it as beta.)

## License

Copyright (C) 2026 The Basementen Vault authors.

Basementen Vault is free software licensed under the **GNU Affero General Public
License v3.0 only** (`AGPL-3.0-only`); see [LICENSE](LICENSE) for the full text.
The AGPL's network-use clause (§13) means that if you run a modified server for
others over a network, you must offer them the corresponding source. This is
deliberate: it keeps self-hosted forks open for the people who depend on them.
