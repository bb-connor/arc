CREATE TABLE IF NOT EXISTS finding_recovery_issuances (
    recovery_id TEXT NOT NULL PRIMARY KEY
        CHECK (typeof(recovery_id) = 'text' AND length(recovery_id) = 64 AND instr(recovery_id, char(0)) = 0 AND octet_length(recovery_id) <= 256 AND recovery_id NOT GLOB '*[^0-9a-f]*'),
    finding_id TEXT NOT NULL
        CHECK (typeof(finding_id) = 'text' AND length(finding_id) = 64 AND instr(finding_id, char(0)) = 0 AND octet_length(finding_id) <= 256 AND finding_id NOT GLOB '*[^0-9a-f]*'),
    listing_id TEXT NOT NULL CHECK (typeof(listing_id) = 'text' AND length(listing_id) BETWEEN 1 AND 512 AND instr(listing_id, char(0)) = 0 AND octet_length(listing_id) <= 2048),
    original_capability_id TEXT NOT NULL
        CHECK (typeof(original_capability_id) = 'text' AND length(original_capability_id) BETWEEN 1 AND 512 AND instr(original_capability_id, char(0)) = 0 AND octet_length(original_capability_id) <= 2048),
    original_delivery_receipt_id TEXT NOT NULL
        CHECK (typeof(original_delivery_receipt_id) = 'text' AND length(original_delivery_receipt_id) BETWEEN 1 AND 512 AND instr(original_delivery_receipt_id, char(0)) = 0 AND octet_length(original_delivery_receipt_id) <= 2048),
    purchase_key TEXT NOT NULL REFERENCES purchase_records(purchase_key),
    original_subject_key_hex TEXT NOT NULL CHECK (
        typeof(original_subject_key_hex) = 'text'
        AND length(original_subject_key_hex) = 64
        AND instr(original_subject_key_hex, char(0)) = 0
        AND octet_length(original_subject_key_hex) <= 256
        AND original_subject_key_hex NOT GLOB '*[^0-9a-f]*'
    ),
    max_recoveries INTEGER NOT NULL CHECK (max_recoveries BETWEEN 1 AND 8),
    issued_at INTEGER NOT NULL CHECK (issued_at > 0)
);

CREATE TRIGGER IF NOT EXISTS finding_recovery_issuances_immutable
BEFORE UPDATE ON finding_recovery_issuances
BEGIN
    SELECT RAISE(ABORT, 'finding recovery issuance is immutable');
END;

CREATE TRIGGER IF NOT EXISTS finding_recovery_issuances_no_delete
BEFORE DELETE ON finding_recovery_issuances
BEGIN
    SELECT RAISE(ABORT, 'finding recovery issuance must be retained');
END;

CREATE TABLE IF NOT EXISTS finding_recovery_attempts (
    recovery_id TEXT NOT NULL REFERENCES finding_recovery_issuances(recovery_id),
    request_id TEXT NOT NULL CHECK (typeof(request_id) = 'text' AND length(request_id) BETWEEN 1 AND 512 AND instr(request_id, char(0)) = 0 AND octet_length(request_id) <= 2048),
    attempt_ordinal INTEGER NOT NULL CHECK (attempt_ordinal > 0),
    reserved_at INTEGER NOT NULL CHECK (reserved_at > 0),
    PRIMARY KEY (recovery_id, request_id),
    UNIQUE (recovery_id, attempt_ordinal)
);

CREATE TRIGGER IF NOT EXISTS finding_recovery_attempts_immutable
BEFORE UPDATE ON finding_recovery_attempts
BEGIN
    SELECT RAISE(ABORT, 'finding recovery attempt is immutable');
END;

CREATE TRIGGER IF NOT EXISTS finding_recovery_attempts_no_delete
BEFORE DELETE ON finding_recovery_attempts
BEGIN
    SELECT RAISE(ABORT, 'finding recovery attempt must be retained');
END;

CREATE TABLE IF NOT EXISTS finding_recovery_receipt_lineage (
    recovery_receipt_id TEXT NOT NULL PRIMARY KEY
        CHECK (typeof(recovery_receipt_id) = 'text' AND length(recovery_receipt_id) BETWEEN 1 AND 512 AND instr(recovery_receipt_id, char(0)) = 0 AND octet_length(recovery_receipt_id) <= 2048),
    recovery_id TEXT NOT NULL REFERENCES finding_recovery_issuances(recovery_id),
    original_delivery_receipt_id TEXT NOT NULL
        CHECK (typeof(original_delivery_receipt_id) = 'text' AND length(original_delivery_receipt_id) BETWEEN 1 AND 512 AND instr(original_delivery_receipt_id, char(0)) = 0 AND octet_length(original_delivery_receipt_id) <= 2048),
    purchase_key TEXT NOT NULL
        CHECK (typeof(purchase_key) = 'text' AND length(purchase_key) = 64 AND instr(purchase_key, char(0)) = 0 AND octet_length(purchase_key) <= 256 AND purchase_key NOT GLOB '*[^0-9a-f]*'),
    recorded_at INTEGER NOT NULL CHECK (recorded_at > 0)
);

CREATE INDEX IF NOT EXISTS finding_recovery_lineage_by_origin
    ON finding_recovery_receipt_lineage(original_delivery_receipt_id, recovery_receipt_id);

CREATE TRIGGER IF NOT EXISTS finding_recovery_receipt_lineage_immutable
BEFORE UPDATE ON finding_recovery_receipt_lineage
BEGIN
    SELECT RAISE(ABORT, 'finding recovery receipt lineage is immutable');
END;

CREATE TRIGGER IF NOT EXISTS finding_recovery_receipt_lineage_no_delete
BEFORE DELETE ON finding_recovery_receipt_lineage
BEGIN
    SELECT RAISE(ABORT, 'finding recovery receipt lineage must be retained');
END;
