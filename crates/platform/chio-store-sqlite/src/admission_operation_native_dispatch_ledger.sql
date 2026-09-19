CREATE TABLE IF NOT EXISTS admission_operation_native_dispatch_ledger (
    operation_id TEXT PRIMARY KEY NOT NULL
        REFERENCES admission_operations(operation_id)
        CHECK (length(operation_id) = 64 AND operation_id NOT GLOB '*[^0-9a-f]*'),
    record_digest TEXT NOT NULL
        CHECK (length(record_digest) = 64 AND record_digest NOT GLOB '*[^0-9a-f]*'),
    canonical_record BLOB NOT NULL
        CHECK (typeof(canonical_record) = 'blob' AND length(canonical_record) BETWEEN 1 AND 1048576)
);

CREATE TRIGGER IF NOT EXISTS admission_operation_native_dispatch_ledger_immutable
BEFORE UPDATE ON admission_operation_native_dispatch_ledger
BEGIN
    SELECT RAISE(ABORT, 'native dispatch ledger is immutable');
END;

CREATE TRIGGER IF NOT EXISTS admission_operation_native_dispatch_ledger_no_delete
BEFORE DELETE ON admission_operation_native_dispatch_ledger
BEGIN
    SELECT RAISE(ABORT, 'native dispatch ledger is immutable');
END;
