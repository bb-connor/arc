-- Monetary successors preserve the original unknown terminal and authorization.
CREATE TABLE IF NOT EXISTS unknown_payment_release_records (
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
CREATE TRIGGER IF NOT EXISTS unknown_payment_release_records_immutable
BEFORE UPDATE ON unknown_payment_release_records
BEGIN
    SELECT RAISE(ABORT, 'unknown payment release history is immutable');
END;
CREATE TRIGGER IF NOT EXISTS unknown_payment_release_records_no_delete
BEFORE DELETE ON unknown_payment_release_records
BEGIN
    SELECT RAISE(ABORT, 'unknown payment release history is immutable');
END;
