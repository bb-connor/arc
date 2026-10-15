-- Mutable recovery projections are bound to immutable events and global commits.
CREATE TABLE admission_operation_recovery_records (
    record_key TEXT PRIMARY KEY NOT NULL CHECK (length(record_key) BETWEEN 1 AND 512),
    scope_key TEXT NOT NULL CHECK (length(scope_key) = 64),
    kind TEXT NOT NULL CHECK (kind IN ('deployment', 'workflow', 'command')),
    version INTEGER NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991),
    payload BLOB NOT NULL CHECK (length(payload) BETWEEN 1 AND 262144),
    native_namespace TEXT CHECK (
        native_namespace IS NULL OR length(native_namespace) = 64
    ),
    native_request TEXT CHECK (
        native_request IS NULL OR length(native_request) BETWEEN 1 AND 256
    ),
    CHECK ((native_namespace IS NULL) = (native_request IS NULL)),
    CHECK (kind = 'workflow' OR native_request IS NULL),
    CONSTRAINT recovery_record_storage CHECK (
        typeof(record_key) = 'text' AND typeof(scope_key) = 'text'
        AND typeof(kind) = 'text' AND typeof(version) = 'integer'
        AND typeof(payload) = 'blob'
        AND (native_namespace IS NULL OR typeof(native_namespace) = 'text')
        AND (native_request IS NULL OR typeof(native_request) = 'text')
    ),
    CONSTRAINT recovery_record_text CHECK (
        instr(record_key, char(0)) = 0
        AND instr(scope_key, char(0)) = 0
        AND instr(kind, char(0)) = 0
        AND (native_namespace IS NULL OR instr(native_namespace, char(0)) = 0)
        AND (native_request IS NULL OR instr(native_request, char(0)) = 0)
    ),
    CONSTRAINT recovery_record_bytes CHECK (
        length(CAST(record_key AS BLOB)) <= 2048
        AND length(CAST(scope_key AS BLOB)) <= 256
        AND (native_namespace IS NULL OR length(CAST(native_namespace AS BLOB)) <= 256)
        AND (native_request IS NULL OR length(CAST(native_request AS BLOB)) <= 1024)
    )
) WITHOUT ROWID;
CREATE UNIQUE INDEX admission_operation_recovery_native_identity
    ON admission_operation_recovery_records(native_namespace, native_request)
    WHERE native_request IS NOT NULL;
CREATE INDEX admission_operation_recovery_scope
    ON admission_operation_recovery_records(scope_key, kind);
CREATE TRIGGER admission_operation_recovery_records_no_replace
BEFORE INSERT ON admission_operation_recovery_records
WHEN EXISTS (
    SELECT 1 FROM main.admission_operation_recovery_records
    WHERE record_key = NEW.record_key
       OR (
           native_namespace = NEW.native_namespace
           AND native_request = NEW.native_request
       )
)
BEGIN
    SELECT RAISE(ABORT, 'recovery ownership cannot be replaced');
END;
CREATE TRIGGER admission_operation_recovery_native_owner
BEFORE UPDATE ON admission_operation_recovery_records
WHEN EXISTS (
    SELECT 1 FROM main.admission_operation_recovery_records
    WHERE native_namespace = NEW.native_namespace
      AND native_request = NEW.native_request
      AND record_key <> OLD.record_key
)
BEGIN
    SELECT RAISE(ABORT, 'recovery native identity already has an owner');
END;
CREATE TRIGGER admission_operation_recovery_identity
BEFORE UPDATE ON admission_operation_recovery_records
WHEN NEW.record_key <> OLD.record_key
    OR NEW.scope_key <> OLD.scope_key
    OR NEW.kind <> OLD.kind
    OR NEW.version <> OLD.version + 1
    OR (
        OLD.native_request IS NOT NULL
        AND (
            NEW.native_request IS NOT OLD.native_request
            OR NEW.native_namespace IS NOT OLD.native_namespace
        )
    )
BEGIN
    SELECT RAISE(ABORT, 'recovery identity is immutable');
END;
CREATE TRIGGER admission_operation_recovery_records_no_delete
BEFORE DELETE ON admission_operation_recovery_records
BEGIN
    SELECT RAISE(ABORT, 'recovery ownership cannot be deleted');
END;
CREATE TABLE admission_operation_recovery_events (
    sequence INTEGER PRIMARY KEY CHECK (sequence BETWEEN 1 AND 9007199254740991),
    record_key TEXT NOT NULL REFERENCES admission_operation_recovery_records(record_key)
        CHECK (length(record_key) BETWEEN 1 AND 512),
    record_version INTEGER NOT NULL CHECK (
        record_version BETWEEN 1 AND 9007199254740991
    ),
    record_digest TEXT NOT NULL CHECK (length(record_digest) = 64),
    previous_digest TEXT NOT NULL CHECK (length(previous_digest) = 64),
    event_digest TEXT NOT NULL CHECK (length(event_digest) = 64),
    observed_at INTEGER NOT NULL CHECK (
        observed_at BETWEEN 1 AND 9007199254740991
    ),
    UNIQUE(record_key, record_version),
    CONSTRAINT recovery_event_storage CHECK (
        typeof(record_key) = 'text' AND typeof(record_version) = 'integer'
        AND typeof(record_digest) = 'text' AND typeof(previous_digest) = 'text'
        AND typeof(event_digest) = 'text' AND typeof(observed_at) = 'integer'
    ),
    CONSTRAINT recovery_event_text CHECK (
        instr(record_key, char(0)) = 0
        AND instr(record_digest, char(0)) = 0
        AND instr(previous_digest, char(0)) = 0
        AND instr(event_digest, char(0)) = 0
    ),
    CONSTRAINT recovery_event_bytes CHECK (
        length(CAST(record_key AS BLOB)) <= 2048
        AND length(CAST(record_digest AS BLOB)) <= 256
        AND length(CAST(previous_digest AS BLOB)) <= 256
        AND length(CAST(event_digest AS BLOB)) <= 256
    )
);
CREATE TRIGGER admission_operation_recovery_event_no_replace
BEFORE INSERT ON admission_operation_recovery_events
WHEN EXISTS (
    SELECT 1 FROM main.admission_operation_recovery_events
    WHERE sequence = NEW.sequence
       OR (
           record_key = NEW.record_key
           AND record_version = NEW.record_version
       )
)
BEGIN
    SELECT RAISE(ABORT, 'recovery history cannot be replaced');
END;
CREATE TRIGGER admission_operation_recovery_event_no_update
BEFORE UPDATE ON admission_operation_recovery_events
BEGIN
    SELECT RAISE(ABORT, 'recovery history is immutable');
END;
CREATE TRIGGER admission_operation_recovery_event_no_delete
BEFORE DELETE ON admission_operation_recovery_events
BEGIN
    SELECT RAISE(ABORT, 'recovery history cannot be deleted');
END;
