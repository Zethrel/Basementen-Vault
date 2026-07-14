-- Server-side long-lived secrets that must survive restarts. Currently holds
-- the enumeration secret used to derive stable dummy KDF salts for unknown
-- accounts in prelogin; persisting it means an unregistered address looks the
-- same before and after a restart, closing a weak cross-restart enumeration
-- signal (see docs/THREAT_MODEL.md).
CREATE TABLE server_secrets (
    name  TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
