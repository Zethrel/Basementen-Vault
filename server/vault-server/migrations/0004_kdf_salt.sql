-- Random per-account KDF salt (replaces the earlier email-derived salt).
-- Not secret: returned by prelogin so any client can derive. NULL only for
-- rows created before this migration (there are none in a fresh install).
ALTER TABLE accounts ADD COLUMN kdf_salt BLOB;
