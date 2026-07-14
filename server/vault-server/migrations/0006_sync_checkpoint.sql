-- Vault-key-MAC'd sync checkpoint (whole-vault rollback detection).
--
-- The client stores an authenticated high-water mark: checkpoint_seq is a
-- global sequence a device confirmed it synced to, and checkpoint_tag is
-- HKDF(VaultKey, "sync-checkpoint" || seq) proving a real device (holder of
-- the Vault Key) reached it. The server keeps only the highest and returns it
-- on pull; it cannot forge or raise it. NULL until the first sync.
ALTER TABLE accounts ADD COLUMN checkpoint_seq INTEGER;
ALTER TABLE accounts ADD COLUMN checkpoint_tag BLOB;
