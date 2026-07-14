-- One-time-use enforcement for TOTP (RFC 6238 §5.2): remember the last
-- 30-second time-step consumed so a sniffed code cannot be replayed while it
-- is still inside its validity window.
ALTER TABLE totp ADD COLUMN last_used_step INTEGER;
