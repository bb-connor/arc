CREATE TABLE IF NOT EXISTS admission_operation_recovery_deferrals (
    operation_id TEXT PRIMARY KEY,
    canonical_status BLOB NOT NULL CHECK (length(canonical_status) BETWEEN 1 AND 4096),
    status_digest TEXT NOT NULL CHECK (
        length(status_digest) = 64 AND status_digest NOT GLOB '*[^0-9a-f]*'
    ),
    quarantined INTEGER NOT NULL CHECK (quarantined IN (0, 1)),
    retry_not_before_unix_ms INTEGER NOT NULL CHECK (
        retry_not_before_unix_ms BETWEEN 1 AND 9007199254740991
    ),
    FOREIGN KEY (operation_id) REFERENCES admission_operations(operation_id)
);
CREATE INDEX IF NOT EXISTS admission_operation_recovery_due
    ON admission_operation_recovery_deferrals(quarantined, retry_not_before_unix_ms, operation_id);
CREATE TRIGGER IF NOT EXISTS admission_operation_recovery_identity_immutable
BEFORE UPDATE OF operation_id ON admission_operation_recovery_deferrals
BEGIN
    SELECT RAISE(ABORT, 'recovery operation identity is immutable');
END;
CREATE TRIGGER IF NOT EXISTS admission_operation_recovery_no_delete
BEFORE DELETE ON admission_operation_recovery_deferrals
BEGIN
    SELECT RAISE(ABORT, 'recovery history must be retained');
END;
