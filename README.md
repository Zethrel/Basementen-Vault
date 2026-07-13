# Basementen Vault

A cross-platform, zero-knowledge password vault manager (Windows / macOS /
Linux / iOS / Android) built on industry-standard cryptography: Argon2id key
derivation, end-to-end encrypted sync, MFA, and offline-capable recovery.

## Status

Planning. See **[docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md)**
for the full architecture, cryptographic design, milestones, and testing
strategy.

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
