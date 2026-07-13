-- Basementen Vault server schema.
-- The server stores only: e-mail addresses, Argon2id hashes of client-derived
-- auth credentials, opaque encrypted key blobs, and session bookkeeping.
-- Nothing in this database can decrypt a vault.

CREATE TABLE accounts (
    id                        INTEGER PRIMARY KEY,
    email                     TEXT NOT NULL UNIQUE,
    email_verified_at         INTEGER,             -- unix seconds, NULL = unverified
    -- PHC string: Argon2id(client AuthKey, random server salt)
    server_auth_hash          TEXT NOT NULL,
    -- Client KDF parameters (JSON KdfParams), returned by prelogin
    kdf_params                TEXT NOT NULL,
    -- Opaque ciphertext blobs (JSON WrappedKey); server never inspects them
    master_wrapped_vault_key   TEXT NOT NULL,
    recovery_wrapped_vault_key TEXT NOT NULL,
    failed_attempts           INTEGER NOT NULL DEFAULT 0,
    lockout_until             INTEGER,             -- unix seconds
    created_at                INTEGER NOT NULL
);

-- Single-use e-mail tokens (verification, recovery initiation).
CREATE TABLE email_tokens (
    id          INTEGER PRIMARY KEY,
    account_id  INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    purpose     TEXT NOT NULL,        -- 'verify_email'
    token_hash  BLOB NOT NULL,        -- SHA-256 of the token; token itself is never stored
    expires_at  INTEGER NOT NULL,
    used_at     INTEGER
);
CREATE INDEX idx_email_tokens_account ON email_tokens(account_id, purpose);

-- Opaque bearer-token sessions. Tokens are random 256-bit values; only their
-- SHA-256 hashes are stored, so a database leak cannot mint valid sessions.
CREATE TABLE sessions (
    id                  INTEGER PRIMARY KEY,
    account_id          INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    -- All rotations of one login share a family; reusing a rotated-out
    -- refresh token revokes the entire family (theft response).
    family_id           TEXT NOT NULL,
    access_token_hash   BLOB NOT NULL,
    refresh_token_hash  BLOB NOT NULL,
    access_expires_at   INTEGER NOT NULL,
    refresh_expires_at  INTEGER NOT NULL,
    device_name         TEXT NOT NULL DEFAULT '',
    created_at          INTEGER NOT NULL,
    revoked_at          INTEGER
);
CREATE INDEX idx_sessions_access ON sessions(access_token_hash);
CREATE INDEX idx_sessions_refresh ON sessions(refresh_token_hash);
CREATE INDEX idx_sessions_account ON sessions(account_id);

-- TOTP enrollment (RFC 6238). The shared secret must be stored recoverable
-- (the server needs it to verify codes); activated_at NULL = enrollment
-- started but not yet confirmed with a valid code.
CREATE TABLE totp (
    account_id    INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    secret_base32 TEXT NOT NULL,
    activated_at  INTEGER,
    created_at    INTEGER NOT NULL
);

-- Single-use MFA recovery codes, stored hashed.
CREATE TABLE recovery_codes (
    id          INTEGER PRIMARY KEY,
    account_id  INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    code_hash   BLOB NOT NULL,
    used_at     INTEGER
);
CREATE INDEX idx_recovery_codes_account ON recovery_codes(account_id);
