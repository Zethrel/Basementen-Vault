-- Account recovery and trusted backup e-mail.

-- SHA-256 of the client's recovery verifier (an HKDF branch of the Vault
-- Key). Required to complete a data-preserving recovery. NULL only for
-- accounts created before this migration; those can only do a wipe-reset.
ALTER TABLE accounts ADD COLUMN recovery_verifier_hash BLOB;

ALTER TABLE accounts ADD COLUMN backup_email TEXT;
ALTER TABLE accounts ADD COLUMN backup_email_verified_at INTEGER;

-- One recovery attempt lifecycle. Starting a new request supersedes any
-- pending one (restarting the cooling-off clock).
CREATE TABLE recovery_requests (
    id                 INTEGER PRIMARY KEY,
    account_id         INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    completion_token_hash BLOB NOT NULL,
    cancel_token_hash  BLOB NOT NULL,
    created_at         INTEGER NOT NULL,
    -- Cooling-off: the completion token is inert until this moment.
    usable_at          INTEGER NOT NULL,
    expires_at         INTEGER NOT NULL,
    cancelled_at       INTEGER,
    completed_at       INTEGER
);
CREATE INDEX idx_recovery_account ON recovery_requests(account_id);
