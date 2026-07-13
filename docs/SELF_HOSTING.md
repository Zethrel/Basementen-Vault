# Self-hosting Basementen Vault at home

The server is a single binary with a single SQLite file. It stores only
ciphertext and password hashes — a full compromise of the machine yields
nothing decryptable — so hosting it on a Raspberry Pi in the basement is a
perfectly sound deployment.

## Quick start (Docker)

```sh
cp .env.example .env      # edit BV_BASE_URL and (optionally) SMTP settings
docker compose up -d
curl http://127.0.0.1:8080/api/v1/health   # → ok
```

Or without Docker:

```sh
cargo build --release -p vault-server
BV_DB_PATH=/var/lib/vault/vault.db BV_LISTEN_ADDR=127.0.0.1:8080 \
  ./target/release/vault-server
```

## Configuration reference

| Variable | Default | Meaning |
|---|---|---|
| `BV_LISTEN_ADDR` | `127.0.0.1:8080` | Bind address |
| `BV_DB_PATH` | `vault.db` | SQLite database file |
| `BV_BASE_URL` | `http://127.0.0.1:8080` | Public URL used in e-mail links |
| `BV_REGISTRATION_OPEN` | `true` | Accept new registrations |
| `BV_TRUST_PROXY` | `false` | Trust `X-Forwarded-For` (only behind your own proxy) |
| `BV_RECOVERY_COOLOFF_HOURS` | `72` | Delay before a recovery request becomes usable (the owner's window to cancel) |
| `BV_MAILER` | `console` | `console` (log mails) or `smtp` |
| `BV_SMTP_HOST/PORT/USERNAME/PASSWORD/FROM` | — | SMTP relay settings |
| `BV_SMTP_IMPLICIT_TLS` | `false` | `true` for port 465, `false` for STARTTLS on 587 |

## E-mail delivery

Verification mails, lockout warnings, and (later) recovery links need
outbound e-mail. Residential ISPs block direct sending, so either:

- **SMTP relay** (recommended): a Gmail app password, or the free tier of
  Brevo / Mailgun / Postmark. Fill in the `BV_SMTP_*` variables.
- **Console mailer**: `BV_MAILER=console` writes mails to the server log.
  Workable for a VPN-only family server — read the verification link out of
  `docker compose logs vault`.

## Reaching the server from your devices

Two good options, in order of preference:

### 1. VPN-only (smallest attack surface)

Install Tailscale (or WireGuard) on the server and your devices. Nothing is
exposed to the internet; clients use `http://<tailscale-name>:8080` (or put
Caddy in front for TLS inside the tailnet). Set `BV_BASE_URL` accordingly.

### 2. Public HTTPS behind Caddy

```
# /etc/caddy/Caddyfile
vault.your-domain.com {
    reverse_proxy 127.0.0.1:8080
}
```

Caddy provisions Let's Encrypt certificates automatically. Point a DNS name
(dynamic DNS is fine) at your public IP, forward port 443 on your router,
set `BV_TRUST_PROXY=true` and `BV_BASE_URL=https://vault.your-domain.com`.

Never expose the server on plain HTTP: the auth credential in transit is a
password-equivalent secret. TLS is mandatory outside a VPN.

## Backups

Everything lives in one SQLite file (`BV_DB_PATH`, plus its `-wal`/`-shm`
journal files). Because the database contains only ciphertext:

- Copies are safe to store anywhere, including cloud storage.
- Snapshot while the server is stopped, or use
  `sqlite3 vault.db "VACUUM INTO '/backups/vault-$(date +%F).db'"` live.

Test a restore once: stop the server, swap in the backup file, start, log in.

**What a backup does NOT protect against:** losing your master password and
Recovery Kit. The server (and its backups) never has your keys — that is the
point — so keep the printed Recovery Kit somewhere safe.

## Account recovery, in practice

- Every account gets a printable **Recovery Kit** code at registration (and a
  fresh one after every password change or recovery — old kits are spent).
- "Forgot password" in the app starts recovery: instruction mails go to the
  account address **and** its verified backup address; the request only
  becomes usable after the cooling-off period, and the mail contains a
  one-click cancel link.
- With the Recovery Kit code: the vault is fully restored under a new master
  password. Without it: the only path is an explicit reset that permanently
  destroys all stored items — the server refuses anything in between, and
  proves kit possession cryptographically (a verifier derived from the vault
  key, stored only as a hash).
- Every completed recovery revokes all sessions and notifies all addresses.

## Hardening checklist

- [ ] Server bound to localhost/VPN only, or behind Caddy with TLS
- [ ] `BV_REGISTRATION_OPEN=false` once your household is on board
- [ ] `BV_TRUST_PROXY` enabled **only** if a proxy is actually in front
- [ ] Automatic OS updates on the host (`unattended-upgrades`)
- [ ] Nightly database backup to a second machine or cloud bucket
- [ ] Every account has MFA enrolled and its Recovery Kit printed
