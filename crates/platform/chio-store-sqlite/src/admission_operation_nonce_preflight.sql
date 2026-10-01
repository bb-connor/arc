-- One internal preflight participant per admission, separate from its executable
-- budget operation. Neither identity nor the physical hold may be recycled.
CREATE TABLE IF NOT EXISTS admission_nonce_preflight_holds (
    operation_id TEXT PRIMARY KEY REFERENCES admission_operations(operation_id),
    budget_operation_id TEXT NOT NULL UNIQUE CHECK(length(budget_operation_id) BETWEEN 1 AND 512),
    hold_id TEXT NOT NULL UNIQUE REFERENCES budget_authorization_holds(hold_id),
    ownership_json BLOB NOT NULL CHECK(length(ownership_json) BETWEEN 1 AND 4096),
    operation_json BLOB NOT NULL CHECK(length(operation_json) BETWEEN 1 AND 262144),
    recorded_at_unix_ms INTEGER NOT NULL CHECK(recorded_at_unix_ms BETWEEN 0 AND 9007199254740991)
);

CREATE TRIGGER IF NOT EXISTS admission_nonce_preflight_holds_immutable
BEFORE UPDATE ON admission_nonce_preflight_holds
BEGIN
    SELECT RAISE(ABORT, 'admission nonce preflight ownership is immutable');
END;

CREATE TRIGGER IF NOT EXISTS admission_nonce_preflight_holds_no_delete
BEFORE DELETE ON admission_nonce_preflight_holds
BEGIN
    SELECT RAISE(ABORT, 'admission nonce preflight ownership is permanent');
END;
