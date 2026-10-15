-- DPoP replay migration is authority-wide, not an invocation.
-- Historical reservations remain unresolved inventory, never operation owners.
CREATE TABLE IF NOT EXISTS dpop_replay_migration_expectations (
    dpop_authority_id TEXT NOT NULL PRIMARY KEY CHECK (
        typeof(dpop_authority_id) = 'text'
        AND typeof(dpop_authority_id) = 'text' AND length(dpop_authority_id) BETWEEN 1 AND 512 AND octet_length(dpop_authority_id) <= 2048 AND instr(dpop_authority_id, char(0)) = 0
    ),
    source_instance_id TEXT NOT NULL UNIQUE CHECK (
        typeof(source_instance_id) = 'text'
        AND typeof(source_instance_id) = 'text' AND length(source_instance_id) BETWEEN 1 AND 512 AND octet_length(source_instance_id) <= 2048 AND instr(source_instance_id, char(0)) = 0
    ),
    expectation_id TEXT NOT NULL UNIQUE CHECK (
        typeof(expectation_id) = 'text'
        AND typeof(expectation_id) = 'text' AND length(expectation_id) BETWEEN 1 AND 512 AND octet_length(expectation_id) <= 2048 AND instr(expectation_id, char(0)) = 0
    ),
    destination_store_uuid TEXT NOT NULL CHECK (destination_store_uuid <> ''),
    canonical_source BLOB NOT NULL CHECK (
        typeof(canonical_source) = 'blob'
        AND typeof(canonical_source) = 'blob' AND length(canonical_source) BETWEEN 1 AND 16777216
    ),
    inventory_sha256 TEXT NOT NULL CHECK (
        typeof(inventory_sha256) = 'text' AND length(inventory_sha256) = 64 AND instr(inventory_sha256, char(0)) = 0 AND inventory_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    expectation_digest TEXT NOT NULL CHECK (
        typeof(expectation_digest) = 'text' AND length(expectation_digest) = 64 AND instr(expectation_digest, char(0)) = 0 AND expectation_digest NOT GLOB '*[^0-9a-f]*'
    )
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS dpop_replay_migration_events (
    dpop_authority_id TEXT NOT NULL CHECK (
        typeof(dpop_authority_id) = 'text'
        AND typeof(dpop_authority_id) = 'text' AND length(dpop_authority_id) BETWEEN 1 AND 512 AND octet_length(dpop_authority_id) <= 2048 AND instr(dpop_authority_id, char(0)) = 0
    ),
    sequence INTEGER NOT NULL CHECK (typeof(sequence) = 'integer' AND sequence BETWEEN 1 AND 3),
    mutation_kind TEXT NOT NULL CHECK (mutation_kind IN (
        'expect_dpop_replay_source', 'import_dpop_replay_source', 'activate_dpop_replay_source'
    )),
    expectation_digest TEXT NOT NULL CHECK (
        typeof(expectation_digest) = 'text' AND length(expectation_digest) = 64 AND instr(expectation_digest, char(0)) = 0 AND expectation_digest NOT GLOB '*[^0-9a-f]*'
    ),
    inventory_sha256 TEXT NOT NULL CHECK (
        typeof(inventory_sha256) = 'text' AND length(inventory_sha256) = 64 AND instr(inventory_sha256, char(0)) = 0 AND inventory_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    event_digest TEXT NOT NULL CHECK (
        typeof(event_digest) = 'text' AND length(event_digest) = 64 AND instr(event_digest, char(0)) = 0 AND event_digest NOT GLOB '*[^0-9a-f]*'
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
        (sequence = 1 AND mutation_kind = 'expect_dpop_replay_source')
        OR (sequence = 2 AND mutation_kind = 'import_dpop_replay_source')
        OR (sequence = 3 AND mutation_kind = 'activate_dpop_replay_source')
    ),
    PRIMARY KEY (dpop_authority_id, sequence),
    FOREIGN KEY (dpop_authority_id)
        REFERENCES dpop_replay_migration_expectations(dpop_authority_id),
    FOREIGN KEY (store_uuid, store_owner_epoch)
        REFERENCES chio_serving_leases(store_uuid, owner_epoch)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS dpop_replay_legacy_tombstones (
    dpop_authority_id TEXT NOT NULL CHECK (
        typeof(dpop_authority_id) = 'text' AND typeof(dpop_authority_id) = 'text' AND length(dpop_authority_id) BETWEEN 1 AND 512 AND octet_length(dpop_authority_id) <= 2048 AND instr(dpop_authority_id, char(0)) = 0
    ),
    capability_id TEXT NOT NULL CHECK (
        typeof(capability_id) = 'text' AND typeof(capability_id) = 'text' AND length(capability_id) BETWEEN 0 AND 4096 AND octet_length(capability_id) <= 16384 AND instr(capability_id, char(0)) = 0
    ),
    nonce TEXT NOT NULL CHECK (
        typeof(nonce) = 'text' AND typeof(nonce) = 'text' AND length(nonce) BETWEEN 0 AND 4096 AND octet_length(nonce) <= 16384 AND instr(nonce, char(0)) = 0
    ),
    source_instance_id TEXT NOT NULL CHECK (
        typeof(source_instance_id) = 'text' AND typeof(source_instance_id) = 'text' AND length(source_instance_id) BETWEEN 1 AND 512 AND octet_length(source_instance_id) <= 2048 AND instr(source_instance_id, char(0)) = 0
    ),
    expectation_id TEXT NOT NULL CHECK (
        typeof(expectation_id) = 'text' AND typeof(expectation_id) = 'text' AND length(expectation_id) BETWEEN 1 AND 512 AND octet_length(expectation_id) <= 2048 AND instr(expectation_id, char(0)) = 0
    ),
    canonical_marker BLOB NOT NULL CHECK (
        typeof(canonical_marker) = 'blob' AND typeof(canonical_marker) = 'blob' AND length(canonical_marker) BETWEEN 1 AND 131072
    ),
    PRIMARY KEY (dpop_authority_id, capability_id, nonce),
    FOREIGN KEY (dpop_authority_id) REFERENCES dpop_replay_migration_expectations(dpop_authority_id)
) WITHOUT ROWID;

-- REPLACE may otherwise bypass DELETE triggers when recursive_triggers is
-- disabled. WITHOUT ROWID excludes hidden-key collisions, and these guards
-- cover every declared key. Retries read immutable rows, never replace them.
CREATE TRIGGER IF NOT EXISTS dpop_replay_migration_expectations_no_replace
BEFORE INSERT ON dpop_replay_migration_expectations
WHEN EXISTS (
    SELECT 1 FROM dpop_replay_migration_expectations
    WHERE dpop_authority_id = NEW.dpop_authority_id
       OR source_instance_id = NEW.source_instance_id
       OR expectation_id = NEW.expectation_id
)
BEGIN
    SELECT RAISE(ABORT, 'DPoP replay migration expectation is immutable');
END;

CREATE TRIGGER IF NOT EXISTS dpop_replay_migration_events_no_replace
BEFORE INSERT ON dpop_replay_migration_events
WHEN EXISTS (
    SELECT 1 FROM dpop_replay_migration_events
    WHERE dpop_authority_id = NEW.dpop_authority_id AND sequence = NEW.sequence
)
BEGIN
    SELECT RAISE(ABORT, 'DPoP replay migration event is immutable');
END;

CREATE TRIGGER IF NOT EXISTS dpop_replay_legacy_tombstones_no_replace
BEFORE INSERT ON dpop_replay_legacy_tombstones
WHEN EXISTS (
    SELECT 1 FROM dpop_replay_legacy_tombstones
    WHERE dpop_authority_id = NEW.dpop_authority_id
      AND capability_id = NEW.capability_id
      AND nonce = NEW.nonce
)
BEGIN
    SELECT RAISE(ABORT, 'DPoP replay legacy tombstone is immutable');
END;

CREATE TRIGGER IF NOT EXISTS dpop_replay_migration_expectations_immutable
BEFORE UPDATE ON dpop_replay_migration_expectations
BEGIN
    SELECT RAISE(ABORT, 'DPoP replay migration expectation is immutable');
END;

CREATE TRIGGER IF NOT EXISTS dpop_replay_migration_expectations_no_delete
BEFORE DELETE ON dpop_replay_migration_expectations
BEGIN
    SELECT RAISE(ABORT, 'DPoP replay migration expectation is permanent');
END;

CREATE TRIGGER IF NOT EXISTS dpop_replay_migration_events_immutable
BEFORE UPDATE ON dpop_replay_migration_events
BEGIN
    SELECT RAISE(ABORT, 'DPoP replay migration event is immutable');
END;

CREATE TRIGGER IF NOT EXISTS dpop_replay_migration_events_no_delete
BEFORE DELETE ON dpop_replay_migration_events
BEGIN
    SELECT RAISE(ABORT, 'DPoP replay migration event is permanent');
END;

CREATE TRIGGER IF NOT EXISTS dpop_replay_legacy_tombstones_immutable
BEFORE UPDATE ON dpop_replay_legacy_tombstones
BEGIN
    SELECT RAISE(ABORT, 'DPoP replay legacy tombstone is immutable');
END;

CREATE TRIGGER IF NOT EXISTS dpop_replay_legacy_tombstones_no_delete
BEFORE DELETE ON dpop_replay_legacy_tombstones
BEGIN
    SELECT RAISE(ABORT, 'DPoP replay legacy tombstone is permanent');
END;
