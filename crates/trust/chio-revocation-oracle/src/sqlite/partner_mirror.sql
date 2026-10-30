CREATE TABLE IF NOT EXISTS chio_partner_revocation_mirror (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    partner_id TEXT NOT NULL CHECK (length(partner_id) BETWEEN 1 AND 64),
    signed_root TEXT
) STRICT;
CREATE TABLE IF NOT EXISTS chio_partner_revocation_conflicts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    observed_at_unix_ms INTEGER NOT NULL,
    reason TEXT NOT NULL,
    accepted_root TEXT,
    offered_root TEXT NOT NULL,
    offered_root_sha256 TEXT NOT NULL UNIQUE CHECK (length(offered_root_sha256) = 64)
) STRICT;
