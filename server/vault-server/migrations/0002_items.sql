-- Encrypted vault items and sync bookkeeping.
--
-- `seq` is a per-account monotonic counter bumped on every write; clients
-- sync by asking for "everything with seq > my last seen". Deletes are
-- tombstones so they propagate to offline devices; tombstones are purged
-- after 30 days, and clients further behind than the purge horizon are told
-- to do a full resync.

CREATE TABLE vault_items (
    account_id  INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    item_id     TEXT NOT NULL,
    revision    INTEGER NOT NULL,
    seq         INTEGER NOT NULL,
    deleted     INTEGER NOT NULL DEFAULT 0,
    -- EncryptedItem JSON (opaque ciphertext envelope); NULL for tombstones.
    content     TEXT,
    updated_at  INTEGER NOT NULL,
    PRIMARY KEY (account_id, item_id)
);
CREATE INDEX idx_vault_items_seq ON vault_items(account_id, seq);

ALTER TABLE accounts ADD COLUMN sync_seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE accounts ADD COLUMN purged_before_seq INTEGER NOT NULL DEFAULT 0;
