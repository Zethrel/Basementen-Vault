# Contributing to Basementen Vault

Thanks for your interest! Basementen Vault is a **password manager**, so the
confidentiality and integrity of user secrets is the whole point. Contributions
are very welcome, but the bar for anything touching crypto, auth, or storage is
deliberately high. This guide explains how to work with the project.

## Before anything else

- **Found a security vulnerability? Do NOT open a public issue or PR.** Follow
  the private reporting process in [SECURITY.md](SECURITY.md).
- **Read the design docs** so a change lands with the model, not against it:
  - [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — what we defend against, and the honestly-accepted gaps.
  - [`docs/CRYPTOGRAPHIC_INVARIANTS.md`](docs/CRYPTOGRAPHIC_INVARIANTS.md) — the rules every change must preserve.
  - [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md) — architecture and rationale.
- For anything non-trivial, **open an issue to discuss first.** A change that
  weakens the threat model or breaks an invariant will be declined no matter how
  clean the code is; talking early saves everyone time.

## Non-negotiables

These are the project's invariants. A PR that violates one won't be merged.

1. **Zero-knowledge stays zero-knowledge.** The server must never be able to
   derive or decrypt the Vault Key, see the master password, or read item
   plaintext. If a change makes the server learn something new, it needs an
   explicit threat-model update and discussion.
2. **`unsafe` is forbidden in first-party crates** (`unsafe_code = "forbid"`,
   workspace-wide). If a task genuinely needs a raw syscall (e.g. `mlock`), wrap
   a vetted dependency that encapsulates the `unsafe` — don't add it to our code.
3. **Preserve the cryptographic invariants.** Any change touching keys,
   ciphertext, randomness, KDF usage, or serialization of the above must keep
   every rule in `CRYPTOGRAPHIC_INVARIANTS.md` true **and add/extend a guarding
   test.** New AEAD context or HKDF label? Add a new versioned constant — never
   reuse one.
4. **Persisted formats are versioned.** Don't change an on-disk / on-the-wire
   crypto format without bumping its version, binding that version into the AEAD
   associated data, and keeping a backward-compatible decrypt path (see
   `EncryptedItem` v1→v2 for the pattern).
5. **Secrets are scrubbed and never logged.** Key material and decrypted
   plaintext use `Zeroizing` / `ZeroizeOnDrop`; `Debug` on secret types is
   redacted; nothing secret goes to `tracing`/`println!`.

## Development setup

You need a recent stable **Rust** toolchain (`rustup` recommended); `rustfmt`
and `clippy` components; and, for the desktop app, the
[Tauri v2 prerequisites](https://v2.tauri.app/start/prerequisites/) for your OS
(on Linux, the WebKitGTK / build-essential packages).

```sh
# Build and test everything
cargo build --workspace
cargo test --workspace

# Run the server (see docs/SELF_HOSTING.md for BV_* configuration)
cargo run -p vault-server

# Run the desktop app against a local server
cargo tauri dev   # from apps/desktop/src-tauri, or `cargo run -p basementen-vault-desktop`
```

Mobile builds (Android/iOS) are described in [`docs/MOBILE.md`](docs/MOBILE.md).

### Repository layout

| Path | What it is |
|------|------------|
| `core/vault-core` | Zero-knowledge crypto: key hierarchy, envelope + item encryption, KDF, recovery, page-locked secret memory. **`forbid(unsafe)`.** |
| `core/vault-sync` | Offline-first, transport-agnostic sync engine (moves opaque ciphertext). |
| `server/vault-server` | axum + SQLite API: accounts, auth/sessions, MFA, recovery, item storage, sync. |
| `apps/desktop-core` | Client core the apps share: API client, local replica, session, generator, password checks. |
| `apps/desktop/src-tauri` + `apps/desktop/ui` | Tauri shell (thin command layer) + plain-JS/CSS UI (no frontend build step; CSP `default-src 'self'`). |
| `docs/` | Design, threat model, invariants, self-hosting, runbook, release checklist. |

## Checks your PR must pass (this is CI)

Run these locally before pushing; CI runs the same and will block on failure:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo audit          # or: cargo deny check
```

- **New behavior needs tests.** Prefer making an invariant a *test* over a
  comment — the `crypto_flows` / `proptests` suites and the server/client
  integration tests are where guards live.
- **Match the surrounding style** — naming, module layout, and comment density.
  Comments explain *why*, not *what*.
- **Keep the UI dependency-free and CSP-safe:** plain JS, no external scripts or
  fonts, no `innerHTML` of untrusted data, secrets rendered as text.

## Submitting changes

- Branch from `main`; keep each PR to **one logical change**.
- Write a clear PR description: what changed, why, and how it preserves the
  threat model / invariants. Link the issue it addresses.
- **Update the docs and `CHANGELOG.md`** (under `[Unreleased]`) in the same PR
  when behavior, formats, or the security posture change.
- **Sign off your commits** (Developer Certificate of Origin): commit with
  `git commit -s`, which adds a `Signed-off-by:` line certifying you have the
  right to submit the work under the project license (see
  <https://developercertificate.org/>).

## Licensing of contributions

Basementen Vault is licensed under the **GNU AGPL-3.0-only** (see
[LICENSE](LICENSE)). By submitting a contribution you agree it is licensed under
those same terms. Don't paste code you don't have the right to relicense under
the AGPL.

## Getting help

Open a discussion or a (non-security) issue. Reviews focus first on the security
model, then correctness, then style — expect questions on the first, and thanks
in advance for your patience with them.
