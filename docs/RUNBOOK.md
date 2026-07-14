# Operations runbook

Day-2 operations for a self-hosted Basementen Vault. Assumes the setup from
`SELF_HOSTING.md`.

## Backups

- **What:** the SQLite file at `BV_DB_PATH` (all ciphertext — safe anywhere).
- **How (live):** `sqlite3 vault.db "VACUUM INTO '/backups/vault-$(date +%F).db'"`
  nightly via cron; keep 30 days; copy off-machine.
- **Client-side:** each user should periodically run *Export encrypted
  backup* from the app (⚙ dialog). That file restores even without the
  server and has its own passphrase.
- **Restore drill (do this once):** stop server → swap in backup file →
  start → log in → verify an item decrypts. Clients that were ahead of the
  backup will re-push queued changes on next sync; items written only
  between backup and restore on *no* device are gone — hence nightly.

## Upgrading the server

1. Read the release notes for migration entries (`server/vault-server/migrations/`).
2. Back up the database (above).
3. `docker compose pull && docker compose up -d` (or rebuild the binary).
   Migrations run automatically at startup; they are append-only.
4. `curl -fsS localhost:8080/api/v1/health` and a test login.

Rollback = stop server, restore the pre-upgrade backup, start the old image.
Never run an old binary against a newer schema.

## Raising KDF parameters over time

Hardware improves; parameters should follow. The design supports per-account
versioned parameters:

1. Bump the defaults in `vault_core::kdf::KdfParams::desktop()`.
2. Existing accounts keep their stored parameters (login unaffected).
3. A client-side "upgrade" is a normal password change (`change_password`
   re-derives under the new parameters and re-wraps the vault key — cheap).
   Prompting users to rotate after a floor bump is a UI backlog item.

Never lower `MIN_*` floors; the server rejects sub-floor registrations.

## Incident response

**Suspected server compromise**

1. Take the server offline; preserve the database and logs for analysis.
2. Rebuild the host from scratch; restore the database (it is ciphertext;
   integrity matters more than confidentiality here — prefer a pre-incident
   backup if tampering is possible).
3. Revoke all sessions: `sqlite3 vault.db "UPDATE sessions SET revoked_at = strftime('%s','now') WHERE revoked_at IS NULL;"`
4. Tell users: vault contents remain encrypted; they should still rotate
   their master passwords (defense in depth) and watch for phishing.

**Lost/stolen user device**

1. From any other logged-in device: nothing to do server-side yet (device
   revocation UI is backlog); revoke that device's sessions via SQL as above,
   filtered by `device_name`.
2. The local replica on the stolen device is ciphertext; the master password
   still gates it. If the master password may be known, change it — that
   re-wraps the vault key and invalidates the old wrapped copy everywhere.

**User locked out (forgot password)**

Normal path: app → "Recover your vault" (needs e-mail + Recovery Kit).
Admin shortcut does not exist by design — the server cannot decrypt or
bypass. Without kit: wipe-reset only.

**Recovery abuse suspected** (user reports unexpected recovery mail)

The mail's cancel link kills the request. Check
`SELECT * FROM recovery_requests ORDER BY created_at DESC` for patterns;
consider raising `BV_RECOVERY_COOLOFF_HOURS`.

## Monitoring

- Watch the log for `refresh token reuse detected` (session theft signal)
  and repeated `lockout` warnings (targeted guessing).
- `GET /api/v1/health` for liveness.
- Disk: SQLite WAL grows under write bursts; `PRAGMA wal_checkpoint` runs
  automatically, just alert on disk >80 %.

## Host hardening for client devices

The app zeroizes keys in memory on lock, but userspace cannot fully prevent
key-bearing memory from reaching disk. Recommend to users:

- **Enable full-disk or encrypted swap.** Under memory pressure the OS may
  page process memory (including keys) to swap; encrypted swap neutralizes
  that. macOS encrypts swap by default; Linux users should use an encrypted
  swap partition or `zram`; Windows users should enable BitLocker.
- **Rely on OS full-disk encryption** (FileVault / LUKS / BitLocker) so the
  local ciphertext replica and any crash dumps are protected at rest.

See `THREAT_MODEL.md` §A6 for the exact memory-protection posture and limits.

## Before real-world use

- [ ] External security review / penetration test (non-negotiable for a
      credential product; scope: crypto design review + API pentest)
- [ ] TLS or VPN in front of every deployment (never plain HTTP)
- [ ] `BV_REGISTRATION_OPEN=false` after onboarding
- [ ] Nightly backups verified by a restore drill
- [ ] Every user: MFA enrolled, Recovery Kit printed, backup e-mail set
