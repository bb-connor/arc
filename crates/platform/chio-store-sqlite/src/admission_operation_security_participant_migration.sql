-- Inactive source inventory is immutable migration history, never invocation authority.
CREATE TABLE IF NOT EXISTS security_participant_migration_expectations (
    security_authority_id TEXT NOT NULL PRIMARY KEY CHECK (typeof(security_authority_id) = 'text' AND length(CAST(security_authority_id AS BLOB)) BETWEEN 1 AND 512),
    source_id TEXT NOT NULL UNIQUE CHECK (typeof(source_id) = 'text' AND length(CAST(source_id AS BLOB)) BETWEEN 1 AND 512),
    expectation_id TEXT NOT NULL UNIQUE CHECK (length(expectation_id) = 64 AND expectation_id NOT GLOB '*[^0-9a-f]*'),
    destination_store_uuid TEXT NOT NULL CHECK (typeof(destination_store_uuid) = 'text' AND length(CAST(destination_store_uuid AS BLOB)) BETWEEN 1 AND 512),
    source_device TEXT NOT NULL CHECK (typeof(source_device) = 'text' AND length(source_device) BETWEEN 1 AND 20),
    source_inode TEXT NOT NULL CHECK (typeof(source_inode) = 'text' AND length(source_inode) BETWEEN 1 AND 20),
    canonical_source BLOB NOT NULL CHECK (typeof(canonical_source) = 'blob' AND length(canonical_source) BETWEEN 1 AND 65536),
    fingerprint_digest TEXT NOT NULL CHECK (length(fingerprint_digest) = 64 AND fingerprint_digest NOT GLOB '*[^0-9a-f]*'),
    UNIQUE (source_device, source_inode)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS security_participant_migration_events (
    security_authority_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (typeof(sequence) = 'integer' AND sequence BETWEEN 1 AND 2),
    mutation_kind TEXT NOT NULL CHECK (mutation_kind IN ('expect_security_participant_source', 'import_security_participant_source')),
    event_digest TEXT NOT NULL CHECK (length(event_digest) = 64 AND event_digest NOT GLOB '*[^0-9a-f]*'),
    observed_at_unix_ms INTEGER NOT NULL CHECK (typeof(observed_at_unix_ms) = 'integer' AND observed_at_unix_ms BETWEEN 1 AND 9007199254740991),
    store_uuid TEXT NOT NULL,
    store_lease_id TEXT NOT NULL,
    store_owner_epoch INTEGER NOT NULL CHECK (typeof(store_owner_epoch) = 'integer' AND store_owner_epoch > 0),
    CHECK ((sequence = 1 AND mutation_kind = 'expect_security_participant_source')
        OR (sequence = 2 AND mutation_kind = 'import_security_participant_source')),
    PRIMARY KEY (security_authority_id, sequence),
    FOREIGN KEY (security_authority_id) REFERENCES security_participant_migration_expectations(security_authority_id),
    FOREIGN KEY (store_uuid, store_owner_epoch) REFERENCES chio_serving_leases(store_uuid, owner_epoch)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS security_participant_migration_rows (
    security_authority_id TEXT NOT NULL,
    table_name TEXT NOT NULL CHECK (typeof(table_name) = 'text' AND length(CAST(table_name AS BLOB)) BETWEEN 1 AND 128),
    row_index INTEGER NOT NULL CHECK (typeof(row_index) = 'integer' AND row_index BETWEEN 0 AND 16383),
    canonical_row BLOB NOT NULL CHECK (typeof(canonical_row) = 'blob' AND length(canonical_row) BETWEEN 1 AND 16777216),
    PRIMARY KEY (security_authority_id, table_name, row_index),
    FOREIGN KEY (security_authority_id) REFERENCES security_participant_migration_expectations(security_authority_id)
) WITHOUT ROWID;

CREATE TRIGGER IF NOT EXISTS security_participant_migration_expectations_immutable
BEFORE UPDATE ON security_participant_migration_expectations
BEGIN SELECT RAISE(ABORT, 'security participant migration history is immutable'); END;

CREATE TRIGGER IF NOT EXISTS security_participant_migration_expectations_no_delete
BEFORE DELETE ON security_participant_migration_expectations
BEGIN SELECT RAISE(ABORT, 'security participant migration history is immutable'); END;

CREATE TRIGGER IF NOT EXISTS security_participant_migration_expectations_no_replace
BEFORE INSERT ON security_participant_migration_expectations WHEN EXISTS (SELECT 1 FROM security_participant_migration_expectations WHERE security_authority_id = NEW.security_authority_id
    OR source_id = NEW.source_id OR expectation_id = NEW.expectation_id
    OR (source_device = NEW.source_device AND source_inode = NEW.source_inode))
BEGIN SELECT RAISE(ABORT, 'security participant migration history is immutable'); END;

CREATE TRIGGER IF NOT EXISTS security_participant_migration_events_immutable
BEFORE UPDATE ON security_participant_migration_events
BEGIN SELECT RAISE(ABORT, 'security participant migration history is immutable'); END;

CREATE TRIGGER IF NOT EXISTS security_participant_migration_events_no_delete
BEFORE DELETE ON security_participant_migration_events
BEGIN SELECT RAISE(ABORT, 'security participant migration history is immutable'); END;

CREATE TRIGGER IF NOT EXISTS security_participant_migration_events_no_replace
BEFORE INSERT ON security_participant_migration_events WHEN EXISTS (SELECT 1 FROM security_participant_migration_events WHERE security_authority_id = NEW.security_authority_id AND sequence = NEW.sequence)
BEGIN SELECT RAISE(ABORT, 'security participant migration history is immutable'); END;

CREATE TRIGGER IF NOT EXISTS security_participant_migration_rows_immutable
BEFORE UPDATE ON security_participant_migration_rows
BEGIN SELECT RAISE(ABORT, 'security participant migration history is immutable'); END;

CREATE TRIGGER IF NOT EXISTS security_participant_migration_rows_no_delete
BEFORE DELETE ON security_participant_migration_rows
BEGIN SELECT RAISE(ABORT, 'security participant migration history is immutable'); END;

CREATE TRIGGER IF NOT EXISTS security_participant_migration_rows_no_replace
BEFORE INSERT ON security_participant_migration_rows WHEN EXISTS (SELECT 1 FROM security_participant_migration_rows WHERE security_authority_id = NEW.security_authority_id AND table_name = NEW.table_name AND row_index = NEW.row_index)
    OR EXISTS (SELECT 1 FROM security_participant_migration_events WHERE security_authority_id = NEW.security_authority_id AND sequence = 2)
BEGIN SELECT RAISE(ABORT, 'security participant migration history is immutable'); END;
