-- Recovery shares the protected native authority inventory. Mutable projections
-- are checked against immutable events and authority-wide commit references.
CREATE TABLE IF NOT EXISTS admission_operation_recovery_records (
    record_key TEXT PRIMARY KEY CHECK(length(record_key) BETWEEN 1 AND 512),
    scope_key TEXT NOT NULL CHECK(length(scope_key)=64),
    kind TEXT NOT NULL CHECK(kind IN ('deployment','workflow','command')),
    version INTEGER NOT NULL CHECK(version BETWEEN 1 AND 9007199254740991),
    payload BLOB NOT NULL CHECK(length(payload) BETWEEN 1 AND 262144),
    native_namespace TEXT CHECK(native_namespace IS NULL OR length(native_namespace)=64),
    native_request TEXT CHECK(native_request IS NULL OR length(native_request) BETWEEN 1 AND 256),
    CHECK ((native_namespace IS NULL) = (native_request IS NULL)),
    CHECK (kind='workflow' OR native_request IS NULL)
);
CREATE UNIQUE INDEX IF NOT EXISTS admission_operation_recovery_native_identity
    ON admission_operation_recovery_records(native_namespace,native_request)
    WHERE native_request IS NOT NULL;
CREATE INDEX IF NOT EXISTS admission_operation_recovery_scope
    ON admission_operation_recovery_records(scope_key,kind);
CREATE TRIGGER IF NOT EXISTS admission_operation_recovery_identity
BEFORE UPDATE ON admission_operation_recovery_records
WHEN NEW.record_key<>OLD.record_key OR NEW.scope_key<>OLD.scope_key OR NEW.kind<>OLD.kind
 OR NEW.version<>OLD.version+1
 OR (OLD.native_request IS NOT NULL AND (NEW.native_request IS NOT OLD.native_request
       OR NEW.native_namespace IS NOT OLD.native_namespace))
BEGIN SELECT RAISE(ABORT,'recovery identity is immutable'); END;
CREATE TRIGGER IF NOT EXISTS admission_operation_recovery_no_delete
BEFORE DELETE ON admission_operation_recovery_records
BEGIN SELECT RAISE(ABORT,'recovery ownership cannot be deleted'); END;
CREATE TABLE IF NOT EXISTS admission_operation_recovery_events (
    sequence INTEGER PRIMARY KEY CHECK(sequence BETWEEN 1 AND 9007199254740991),
    record_key TEXT NOT NULL REFERENCES admission_operation_recovery_records(record_key),
    record_version INTEGER NOT NULL CHECK(record_version BETWEEN 1 AND 9007199254740991),
    record_digest TEXT NOT NULL CHECK(length(record_digest)=64),
    previous_digest TEXT NOT NULL CHECK(length(previous_digest)=64),
    event_digest TEXT NOT NULL CHECK(length(event_digest)=64),
    observed_at INTEGER NOT NULL CHECK(observed_at BETWEEN 1 AND 9007199254740991),
    UNIQUE(record_key,record_version)
);
CREATE TRIGGER IF NOT EXISTS admission_operation_recovery_event_no_update
BEFORE UPDATE ON admission_operation_recovery_events
BEGIN SELECT RAISE(ABORT,'recovery history is immutable'); END;
CREATE TRIGGER IF NOT EXISTS admission_operation_recovery_event_no_delete
BEFORE DELETE ON admission_operation_recovery_events
BEGIN SELECT RAISE(ABORT,'recovery history cannot be deleted'); END;
