CREATE TABLE IF NOT EXISTS tool_outcome_security_releases (
    operation_id TEXT NOT NULL PRIMARY KEY,
    canonical_record BLOB NOT NULL CHECK (length(canonical_record) BETWEEN 1 AND 8192),
    participant_digest TEXT NOT NULL CHECK (
        length(participant_digest) = 64 AND participant_digest NOT GLOB '*[^0-9a-f]*'
    ),
    acknowledged_at_unix_ms INTEGER NOT NULL CHECK (acknowledged_at_unix_ms > 0),
    store_uuid TEXT NOT NULL CHECK (store_uuid <> ''),
    store_lease_id TEXT NOT NULL CHECK (store_lease_id <> ''),
    store_owner_epoch INTEGER NOT NULL CHECK (store_owner_epoch > 0),
    FOREIGN KEY (operation_id) REFERENCES tool_outcomes(operation_id),
    FOREIGN KEY (store_uuid, store_owner_epoch) REFERENCES chio_serving_leases(store_uuid, owner_epoch)
);

CREATE TRIGGER IF NOT EXISTS tool_outcome_security_releases_exact_owner
BEFORE INSERT ON tool_outcome_security_releases
WHEN NOT EXISTS (
    SELECT 1 FROM chio_serving_leases
    WHERE store_uuid = NEW.store_uuid AND owner_epoch = NEW.store_owner_epoch
      AND lease_id = NEW.store_lease_id AND end_head_index IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'security release requires the exact serving owner');
END;

CREATE TRIGGER IF NOT EXISTS tool_outcome_security_releases_no_replace
BEFORE INSERT ON tool_outcome_security_releases
WHEN EXISTS (SELECT 1 FROM tool_outcome_security_releases WHERE operation_id = NEW.operation_id)
BEGIN
    SELECT RAISE(ABORT, 'security release cannot be replaced');
END;

CREATE TRIGGER IF NOT EXISTS tool_outcome_security_releases_no_update
BEFORE UPDATE ON tool_outcome_security_releases
BEGIN
    SELECT RAISE(ABORT, 'security release is immutable');
END;

CREATE TRIGGER IF NOT EXISTS tool_outcome_security_releases_no_delete
BEFORE DELETE ON tool_outcome_security_releases
BEGIN
    SELECT RAISE(ABORT, 'security release must be retained');
END;
