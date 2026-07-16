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

## Without Docker (standalone binary)

Every release ships standalone `vault-server` binaries for Windows, Linux
(x86-64 and ARM64 — Raspberry Pi), and macOS: download the one for your OS
from the GitHub release, verify it against `SHA256SUMS`, and run it. There is
no installer and nothing else to set up — configuration is environment
variables (same table below; the `.env` file is a Docker convenience, the
bare binary reads the process environment).

**Windows** — put the binary in a folder of its own and start it with a
`run.bat` next to it:

```bat
@echo off
set BV_LISTEN_ADDR=0.0.0.0:8080
set BV_DB_PATH=%ProgramData%\BasementenVault\vault.db
set BV_BASE_URL=http://192.168.1.20:8080
set BV_MAILER=console
vault-server-v1.0.0-beta.5-x86_64-windows.exe
```

Replace `192.168.1.20` with the machine's LAN IP (`ipconfig`). Create the
`%ProgramData%\BasementenVault` folder first. With the console mailer,
verification links appear in this terminal window. To let other devices on
your network reach it, allow the port through Windows Firewall once, from an
administrator prompt:

```
netsh advfirewall firewall add rule name="Basementen Vault" dir=in action=allow protocol=TCP localport=8080
```

Note `BV_LISTEN_ADDR=0.0.0.0:8080`: the default (`127.0.0.1`) is
localhost-only, which other devices — including your phone — cannot reach.
Binding to the LAN without TLS is acceptable only for testing on a network
you trust; for real use, front it with a VPN (Tailscale) or Caddy TLS as
described below.

**Linux/macOS** — same idea:

```sh
BV_DB_PATH=/var/lib/vault/vault.db BV_LISTEN_ADDR=127.0.0.1:8080 \
  ./vault-server-v1.0.0-beta.5-x86_64-linux
```

Building from source works too: `cargo build --release -p vault-server`.

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

## Outbound calls from the app

The desktop/mobile app itself makes one third-party call you should know about:
when a **new master password is set** (registration or recovery), it checks that
password against Have I Been Pwned. This uses **k-anonymity** — only the first
5 hex characters of the password's SHA-1 are sent to `api.pwnedpasswords.com`,
and the match happens locally — so the password (and its full hash) never leave
the device. The check is **best-effort**: if that host is unreachable (a fully
offline/air-gapped deployment, or a firewall rule), the app silently skips it
and relies on the composition policy. There is no other automatic third-party
traffic; all vault sync goes only to your own server.

## Hardening checklist

- [ ] Server bound to localhost/VPN only, or behind Caddy with TLS
- [ ] `BV_REGISTRATION_OPEN=false` once your household is on board
- [ ] `BV_TRUST_PROXY` enabled **only** if a proxy is actually in front
- [ ] Automatic OS updates on the host (`unattended-upgrades`)
- [ ] Nightly database backup to a second machine or cloud bucket
- [ ] Every account has MFA enrolled and its Recovery Kit printed
