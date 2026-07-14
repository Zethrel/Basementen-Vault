-- Session activity tracking and an absolute lifetime cap.
--
-- last_used_at: updated on each token refresh, so the device list can show
--   activity and stale sessions are visible.
-- absolute_expires_at: a hard ceiling set at login and carried unchanged
--   through every rotation, so sliding refresh cannot keep a session alive
--   forever — after this moment the user must log in again.
ALTER TABLE sessions ADD COLUMN last_used_at INTEGER;
ALTER TABLE sessions ADD COLUMN absolute_expires_at INTEGER;
