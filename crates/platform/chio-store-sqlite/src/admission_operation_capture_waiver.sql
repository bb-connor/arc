-- Waivers preserve original positive capture intent, outcome and budget.
CREATE TABLE IF NOT EXISTS capture_waiver_records (
    operation_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence IN (1, 2)),
    request_digest TEXT NOT NULL CHECK (
        length(request_digest) = 64 AND request_digest NOT GLOB '*[^0-9a-f]*'
    ),
    record_json BLOB NOT NULL CHECK (length(record_json) BETWEEN 1 AND 1048576),
    record_digest TEXT NOT NULL CHECK (
        length(record_digest) = 64 AND record_digest NOT GLOB '*[^0-9a-f]*'
    ),
    PRIMARY KEY (operation_id, sequence),
    FOREIGN KEY (operation_id) REFERENCES admission_operations(operation_id)
);
CREATE TRIGGER IF NOT EXISTS capture_waiver_records_immutable
BEFORE UPDATE ON capture_waiver_records
BEGIN
    SELECT RAISE(ABORT, 'capture waiver history is immutable');
END;
CREATE TRIGGER IF NOT EXISTS capture_waiver_records_no_delete
BEFORE DELETE ON capture_waiver_records
BEGIN
    SELECT RAISE(ABORT, 'capture waiver history is immutable');
END;
