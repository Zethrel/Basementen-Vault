# What the server learns (metadata disclosure)

Zero-knowledge protects vault *contents*, not all *metadata*. This document
states precisely what a fully compromised server (or its database) can
observe, so the trade-offs are explicit rather than surprising. Derived from
the actual schema (`server/vault-server/migrations/`).

## Visible to the server

| Metadata | Source | Notes / mitigation |
|---|---|---|
| Account e-mail address | `accounts.email` | Required for login and mail. Also the KDF salt input (public by design). |
| Trusted backup e-mail | `accounts.backup_email` | Only if the user sets one. |
| Account + verification timestamps | `accounts.created_at`, `email_verified_at` | Coarse activity signal. |
| KDF parameters | `accounts.kdf_params` | Public tuning values, not secret. |
| **Number of vault items** | row count in `vault_items` | A genuine leak — see below. |
| Size *bucket* of each item | `vault_items.content` ciphertext length | **Mitigated:** v2 items pad plaintext to 256-byte buckets before encryption, so the length reveals only which bucket an item falls in, not its exact size. Every ordinary login/card shares one length; a long note still leaks its size to 256-byte granularity. (v1 items predating this remain unpadded until their next write; see below.) |
| Per-item modification cadence | `vault_items.updated_at`, `seq`, `revision` | Reveals *when* and *how often* items change, not what. |
| Item identifiers | `vault_items.item_id` (UUIDv7) | Random v7 UUIDs; the embedded timestamp reveals item *creation* time. |
| Deletions | `vault_items.deleted` tombstones | Reveals that an item existed and was deleted. |
| Device names | `sessions.device_name` | **Client-supplied.** The desktop/mobile app sends the device hostname (falling back to `"desktop"`) so the device list is readable; the field is *optional at the protocol level* — a client may send an empty string, which is stored as-is. The server sanitizes it (strips control characters, caps at 64 chars) but never invents one. Opt-out today means a client that sends `""`; an in-app toggle is the tracked follow-up below. |
| Login / session activity | `sessions.created_at`, refresh cadence | When and how often the user logs in, per device. |
| MFA status | presence of a `totp` row | Whether TOTP is enabled (not the secret's use). |
| Client IP addresses | rate limiter (in-memory) + reverse-proxy logs | **Not persisted** by the app; the in-memory limiter forgets on restart. Your reverse proxy (Caddy/nginx) may log IPs — configure it per your privacy needs. |

## NOT visible to the server

- Any vault item plaintext (names, usernames, passwords, notes, card numbers).
- The master password or any key derived from it.
- The Vault Key (stored only wrapped) or the Recovery Kit.
- Folder/tag names or item *titles* — these live **inside** the encrypted
  item payload, not in server columns. (The server sees only opaque
  `content` ciphertext and the random `item_id`.)
- Search queries (search runs entirely client-side over decrypted items).

## Recommendations (tracked, not yet implemented)

1. **Pad item plaintext before encryption** — **DONE.** Shipped as
   `EncryptedItem` **v2**: plaintext is length-prefixed and zero-padded to the
   next 256-byte bucket before encryption, so ciphertext length no longer
   approximates content length. The version is authenticated in the AEAD AAD
   (I12), and v1 (unpadded) records still decrypt, migrating to v2 on their
   next write. Format spec in `CRYPTOGRAPHIC_INVARIANTS.md` §Item record
   format; guards in `item::tests` + `crypto_flows::item_ciphertext_length_is_bucketed`.
   A larger fixed floor or exponential bucketing could hide big notes better —
   a future v3 option, not needed for v1.
2. **Make `device_name` opt-in** in the app UI rather than defaulting to the
   hostname, for users who prefer not to record it.
3. **Document proxy log hygiene** in `SELF_HOSTING.md` for IP-privacy-
   conscious operators (VPN-only deployment already avoids exposing IPs to
   the wider internet).

## Why this is acceptable for v1

For a self-hosted, single-household vault the server is *your own machine*,
so this metadata is disclosed only to yourself. The disclosure matters most
under the A2 "malicious/compromised server" threat (see `THREAT_MODEL.md`);
even there, the leak is item count, sizes, and timing — never content — and
item-size padding (recommendation 1) closes the largest remaining channel.
