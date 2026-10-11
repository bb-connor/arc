-- Governed approval replay migration is authority-wide, not an invocation.
-- Historical reservations remain unresolved inventory, never operation owners.
CREATE TABLE IF NOT EXISTS governed_approval_replay_migration_expectations (
    approval_authority_id TEXT NOT NULL PRIMARY KEY CHECK (
        typeof(approval_authority_id) = 'text'
        AND length(CAST(approval_authority_id AS BLOB)) BETWEEN 1 AND 512
    ),
    source_id TEXT NOT NULL UNIQUE CHECK (
        typeof(source_id) = 'text'
        AND length(CAST(source_id AS BLOB)) BETWEEN 1 AND 512
    ),
    expectation_id TEXT NOT NULL UNIQUE CHECK (
        typeof(expectation_id) = 'text'
        AND length(CAST(expectation_id AS BLOB)) BETWEEN 1 AND 512
    ),
    destination_store_uuid TEXT NOT NULL CHECK (destination_store_uuid <> ''),
    canonical_source BLOB NOT NULL CHECK (
        typeof(canonical_source) = 'blob'
        AND length(canonical_source) BETWEEN 1 AND 8388608
    ),
    inventory_sha256 TEXT NOT NULL CHECK (
        length(inventory_sha256) = 64 AND inventory_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    expectation_digest TEXT NOT NULL CHECK (
        length(expectation_digest) = 64 AND expectation_digest NOT GLOB '*[^0-9a-f]*'
    )
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS governed_approval_replay_migration_events (
    approval_authority_id TEXT NOT NULL CHECK (
        typeof(approval_authority_id) = 'text'
        AND length(CAST(approval_authority_id AS BLOB)) BETWEEN 1 AND 512
    ),
    sequence INTEGER NOT NULL CHECK (typeof(sequence) = 'integer' AND sequence BETWEEN 1 AND 3),
    mutation_kind TEXT NOT NULL CHECK (mutation_kind IN (
        'expect_governed_approval_replay_source', 'import_governed_approval_replay_source', 'activate_governed_approval_replay_source'
    )),
    expectation_digest TEXT NOT NULL CHECK (
        length(expectation_digest) = 64 AND expectation_digest NOT GLOB '*[^0-9a-f]*'
    ),
    inventory_sha256 TEXT NOT NULL CHECK (
        length(inventory_sha256) = 64 AND inventory_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    event_digest TEXT NOT NULL CHECK (
        length(event_digest) = 64 AND event_digest NOT GLOB '*[^0-9a-f]*'
    ),
    observed_at_unix_ms INTEGER NOT NULL CHECK (
        typeof(observed_at_unix_ms) = 'integer'
        AND observed_at_unix_ms BETWEEN 0 AND 9007199254740991
    ),
    store_uuid TEXT NOT NULL CHECK (store_uuid <> ''),
    store_lease_id TEXT NOT NULL CHECK (store_lease_id <> ''),
    store_owner_epoch INTEGER NOT NULL CHECK (
        typeof(store_owner_epoch) = 'integer' AND store_owner_epoch > 0
    ),
    CHECK (
        (sequence = 1 AND mutation_kind = 'expect_governed_approval_replay_source')
        OR (sequence = 2 AND mutation_kind = 'import_governed_approval_replay_source')
        OR (sequence = 3 AND mutation_kind = 'activate_governed_approval_replay_source')
    ),
    PRIMARY KEY (approval_authority_id, sequence),
    FOREIGN KEY (approval_authority_id)
        REFERENCES governed_approval_replay_migration_expectations(approval_authority_id),
    FOREIGN KEY (store_uuid, store_owner_epoch)
        REFERENCES chio_serving_leases(store_uuid, owner_epoch)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS governed_approval_replay_legacy_tombstones (
    approval_authority_id TEXT NOT NULL CHECK (
        typeof(approval_authority_id) = 'text'
        AND length(CAST(approval_authority_id AS BLOB)) BETWEEN 1 AND 512
    ),
    subject_id TEXT NOT NULL CHECK (
        typeof(subject_id) = 'text'
        AND length(CAST(subject_id AS BLOB)) BETWEEN 1 AND 512
    ),
    request_id TEXT NOT NULL CHECK (
        typeof(request_id) = 'text'
        AND length(CAST(request_id AS BLOB)) BETWEEN 1 AND 512
    ),
    intent_hash TEXT NOT NULL CHECK (
        typeof(intent_hash) = 'text'
        AND length(CAST(intent_hash AS BLOB)) BETWEEN 1 AND 512
    ),
    source_id TEXT NOT NULL CHECK (
        typeof(source_id) = 'text'
        AND length(CAST(source_id AS BLOB)) BETWEEN 1 AND 512
    ),
    expectation_id TEXT NOT NULL CHECK (
        typeof(expectation_id) = 'text'
        AND length(CAST(expectation_id AS BLOB)) BETWEEN 1 AND 512
    ),
    expires_at INTEGER NOT NULL CHECK (typeof(expires_at) = 'integer' AND expires_at >= 0),
    historical_reservation_id TEXT CHECK (
        historical_reservation_id IS NULL OR (
            typeof(historical_reservation_id) = 'text'
            AND length(CAST(historical_reservation_id AS BLOB)) BETWEEN 1 AND 512
        )
    ),
    PRIMARY KEY (approval_authority_id, subject_id, request_id, intent_hash),
    FOREIGN KEY (approval_authority_id)
        REFERENCES governed_approval_replay_migration_expectations(approval_authority_id)
) WITHOUT ROWID;

-- REPLACE may otherwise bypass DELETE triggers when recursive_triggers is
-- disabled. WITHOUT ROWID excludes hidden-key collisions, and these guards
-- cover every declared key. Retries read immutable rows, never replace them.
CREATE TRIGGER IF NOT EXISTS governed_approval_replay_migration_expectations_no_replace
BEFORE INSERT ON governed_approval_replay_migration_expectations
WHEN EXISTS (
    SELECT 1 FROM governed_approval_replay_migration_expectations
    WHERE approval_authority_id = NEW.approval_authority_id
       OR source_id = NEW.source_id
       OR expectation_id = NEW.expectation_id
)
BEGIN
    SELECT RAISE(ABORT, 'governed approval replay migration expectation is immutable');
END;

CREATE TRIGGER IF NOT EXISTS governed_approval_replay_migration_events_no_replace
BEFORE INSERT ON governed_approval_replay_migration_events
WHEN EXISTS (
    SELECT 1 FROM governed_approval_replay_migration_events
    WHERE approval_authority_id = NEW.approval_authority_id AND sequence = NEW.sequence
)
BEGIN
    SELECT RAISE(ABORT, 'governed approval replay migration event is immutable');
END;

CREATE TRIGGER IF NOT EXISTS governed_approval_replay_legacy_tombstones_no_replace
BEFORE INSERT ON governed_approval_replay_legacy_tombstones
WHEN EXISTS (
    SELECT 1 FROM governed_approval_replay_legacy_tombstones
    WHERE approval_authority_id = NEW.approval_authority_id
      AND subject_id = NEW.subject_id
      AND request_id = NEW.request_id
      AND intent_hash = NEW.intent_hash
)
BEGIN
    SELECT RAISE(ABORT, 'governed approval replay legacy tombstone is immutable');
END;

CREATE TRIGGER IF NOT EXISTS governed_approval_replay_migration_expectations_immutable
BEFORE UPDATE ON governed_approval_replay_migration_expectations
BEGIN
    SELECT RAISE(ABORT, 'governed approval replay migration expectation is immutable');
END;

CREATE TRIGGER IF NOT EXISTS governed_approval_replay_migration_expectations_no_delete
BEFORE DELETE ON governed_approval_replay_migration_expectations
BEGIN
    SELECT RAISE(ABORT, 'governed approval replay migration expectation is permanent');
END;

CREATE TRIGGER IF NOT EXISTS governed_approval_replay_migration_events_immutable
BEFORE UPDATE ON governed_approval_replay_migration_events
BEGIN
    SELECT RAISE(ABORT, 'governed approval replay migration event is immutable');
END;

CREATE TRIGGER IF NOT EXISTS governed_approval_replay_migration_events_no_delete
BEFORE DELETE ON governed_approval_replay_migration_events
BEGIN
    SELECT RAISE(ABORT, 'governed approval replay migration event is permanent');
END;

CREATE TRIGGER IF NOT EXISTS governed_approval_replay_legacy_tombstones_immutable
BEFORE UPDATE ON governed_approval_replay_legacy_tombstones
BEGIN
    SELECT RAISE(ABORT, 'governed approval replay legacy tombstone is immutable');
END;

CREATE TRIGGER IF NOT EXISTS governed_approval_replay_legacy_tombstones_no_delete
BEFORE DELETE ON governed_approval_replay_legacy_tombstones
BEGIN
    SELECT RAISE(ABORT, 'governed approval replay legacy tombstone is permanent');
END;
