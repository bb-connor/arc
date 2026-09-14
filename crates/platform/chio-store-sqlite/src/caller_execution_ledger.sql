CREATE TABLE caller_executor_configuration (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    identity BLOB NOT NULL CHECK (length(identity) BETWEEN 1 AND 4096),
    device TEXT NOT NULL CHECK (length(device) BETWEEN 1 AND 20),
    inode TEXT NOT NULL CHECK (length(inode) BETWEEN 1 AND 20),
    max_operations INTEGER NOT NULL CHECK (max_operations BETWEEN 1 AND 64)
);
CREATE TABLE caller_executor_clock (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    high_water_unix_ms INTEGER NOT NULL CHECK (high_water_unix_ms BETWEEN 1 AND 9007199254740991)
);
CREATE TABLE caller_executor_claims (
    kernel_key TEXT NOT NULL CHECK (length(kernel_key) = 64),
    operation_id TEXT PRIMARY KEY NOT NULL CHECK (length(operation_id) = 64),
    authorization_digest TEXT NOT NULL UNIQUE CHECK (length(authorization_digest) = 64),
    authorization BLOB NOT NULL CHECK (length(authorization) BETWEEN 1 AND 32768),
    claim_id TEXT NOT NULL UNIQUE CHECK (length(claim_id) = 36),
    claimed_at_unix_ms INTEGER NOT NULL CHECK (claimed_at_unix_ms BETWEEN 1 AND 9007199254740991),
    UNIQUE (kernel_key, operation_id)
);
CREATE TABLE caller_executor_reports (
    kernel_key TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    report BLOB NOT NULL CHECK (length(report) BETWEEN 1 AND 1048576),
    PRIMARY KEY (kernel_key, operation_id),
    FOREIGN KEY (kernel_key, operation_id)
        REFERENCES caller_executor_claims(kernel_key, operation_id)
);
CREATE TRIGGER caller_executor_configuration_no_insert BEFORE INSERT ON caller_executor_configuration
WHEN EXISTS (SELECT 1 FROM caller_executor_configuration)
BEGIN SELECT RAISE(ABORT, 'executor configuration is immutable'); END;
CREATE TRIGGER caller_executor_configuration_no_update BEFORE UPDATE ON caller_executor_configuration
BEGIN SELECT RAISE(ABORT, 'executor configuration is immutable'); END;
CREATE TRIGGER caller_executor_configuration_no_delete BEFORE DELETE ON caller_executor_configuration
BEGIN SELECT RAISE(ABORT, 'executor configuration is immutable'); END;
CREATE TRIGGER caller_executor_clock_no_insert BEFORE INSERT ON caller_executor_clock
WHEN EXISTS (SELECT 1 FROM caller_executor_clock)
BEGIN SELECT RAISE(ABORT, 'executor clock cannot be replaced'); END;
CREATE TRIGGER caller_executor_clock_monotonic BEFORE UPDATE ON caller_executor_clock
WHEN NEW.singleton != OLD.singleton OR NEW.high_water_unix_ms < OLD.high_water_unix_ms
BEGIN SELECT RAISE(ABORT, 'executor clock cannot regress'); END;
CREATE TRIGGER caller_executor_clock_no_delete BEFORE DELETE ON caller_executor_clock
BEGIN SELECT RAISE(ABORT, 'executor clock is permanent'); END;
CREATE TRIGGER caller_executor_claims_no_insert BEFORE INSERT ON caller_executor_claims
WHEN EXISTS (SELECT 1 FROM caller_executor_claims WHERE
    operation_id = NEW.operation_id
    OR authorization_digest = NEW.authorization_digest OR claim_id = NEW.claim_id)
BEGIN SELECT RAISE(ABORT, 'executor claim cannot be replaced'); END;
CREATE TRIGGER caller_executor_claims_no_update BEFORE UPDATE ON caller_executor_claims
BEGIN SELECT RAISE(ABORT, 'executor claim is immutable'); END;
CREATE TRIGGER caller_executor_claims_no_delete BEFORE DELETE ON caller_executor_claims
BEGIN SELECT RAISE(ABORT, 'executor claim is permanent'); END;
CREATE TRIGGER caller_executor_reports_no_insert BEFORE INSERT ON caller_executor_reports
WHEN EXISTS (SELECT 1 FROM caller_executor_reports WHERE kernel_key = NEW.kernel_key AND operation_id = NEW.operation_id)
BEGIN SELECT RAISE(ABORT, 'executor report cannot be replaced'); END;
CREATE TRIGGER caller_executor_reports_no_update BEFORE UPDATE ON caller_executor_reports
BEGIN SELECT RAISE(ABORT, 'executor report is immutable'); END;
CREATE TRIGGER caller_executor_reports_no_delete BEFORE DELETE ON caller_executor_reports
BEGIN SELECT RAISE(ABORT, 'executor report is permanent'); END;
