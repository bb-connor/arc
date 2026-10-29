CREATE TABLE IF NOT EXISTS runtime_source_qualifications (
    runtime_authority_id TEXT NOT NULL PRIMARY KEY CHECK (
        typeof(runtime_authority_id) = 'text' AND length(runtime_authority_id) BETWEEN 1 AND 512
        AND octet_length(runtime_authority_id) <= 2048 AND instr(runtime_authority_id, char(0)) = 0
    ),
    source_id TEXT NOT NULL UNIQUE CHECK (
        typeof(source_id) = 'text' AND length(source_id) BETWEEN 1 AND 512
        AND octet_length(source_id) <= 2048 AND instr(source_id, char(0)) = 0
    ),
    qualification_id TEXT NOT NULL UNIQUE CHECK (
        typeof(qualification_id) = 'text' AND length(qualification_id) = 64
        AND octet_length(qualification_id) <= 128 AND instr(qualification_id, char(0)) = 0
        AND qualification_id NOT GLOB '*[^0-9a-f]*'
    ),
    destination_store_uuid TEXT NOT NULL CHECK (
        typeof(destination_store_uuid) = 'text' AND octet_length(destination_store_uuid) BETWEEN 1 AND 512
        AND instr(destination_store_uuid, char(0)) = 0
    ),
    canonical_source BLOB NOT NULL CHECK (
        typeof(canonical_source) = 'blob' AND length(canonical_source) BETWEEN 1 AND 4096
    ),
    observed_at_unix_ms INTEGER NOT NULL CHECK (
        typeof(observed_at_unix_ms) = 'integer' AND observed_at_unix_ms BETWEEN 0 AND 9007199254740991
    ),
    store_lease_id TEXT NOT NULL CHECK (
        typeof(store_lease_id) = 'text' AND octet_length(store_lease_id) BETWEEN 1 AND 512
        AND instr(store_lease_id, char(0)) = 0
    ),
    store_owner_epoch INTEGER NOT NULL CHECK (typeof(store_owner_epoch) = 'integer' AND store_owner_epoch > 0),
    record_digest TEXT NOT NULL CHECK (
        typeof(record_digest) = 'text' AND length(record_digest) = 64 AND record_digest NOT GLOB '*[^0-9a-f]*'
        AND octet_length(record_digest) <= 128 AND instr(record_digest, char(0)) = 0
    ),
    FOREIGN KEY (destination_store_uuid, store_owner_epoch) REFERENCES chio_serving_leases(store_uuid, owner_epoch)
) WITHOUT ROWID;

CREATE TRIGGER IF NOT EXISTS runtime_source_qualifications_no_replace
BEFORE INSERT ON runtime_source_qualifications
WHEN EXISTS (SELECT 1 FROM runtime_source_qualifications
    WHERE runtime_authority_id = NEW.runtime_authority_id OR source_id = NEW.source_id
       OR qualification_id = NEW.qualification_id)
BEGIN SELECT RAISE(ABORT, 'runtime source qualification is immutable'); END;

CREATE TRIGGER IF NOT EXISTS runtime_source_qualifications_no_update
BEFORE UPDATE ON runtime_source_qualifications
BEGIN SELECT RAISE(ABORT, 'runtime source qualification is immutable'); END;

CREATE TRIGGER IF NOT EXISTS runtime_source_qualifications_no_delete
BEFORE DELETE ON runtime_source_qualifications
BEGIN SELECT RAISE(ABORT, 'runtime source qualification is immutable'); END;
