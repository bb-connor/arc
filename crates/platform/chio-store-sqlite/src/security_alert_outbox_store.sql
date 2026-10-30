CREATE TABLE chio_security_alert_outbox (
    idempotency_key TEXT PRIMARY KEY NOT NULL,
    command_json BLOB NOT NULL CHECK (length(command_json) BETWEEN 1 AND 16384),
    command_hash BLOB NOT NULL CHECK (typeof(command_hash) = 'blob' AND length(command_hash) = 32),
    status TEXT NOT NULL CHECK (status IN ('pending', 'delivered', 'parked')),
    attempts INTEGER NOT NULL CHECK (attempts >= 0),
    next_attempt_at_unix_ms INTEGER NOT NULL CHECK (next_attempt_at_unix_ms >= 0),
    delivered_at_unix_ms INTEGER CHECK (delivered_at_unix_ms >= 0),
    CHECK ((status IN ('pending', 'parked') AND delivered_at_unix_ms IS NULL)
        OR (status = 'delivered' AND delivered_at_unix_ms IS NOT NULL))
) STRICT;
CREATE INDEX idx_chio_security_alert_outbox_due
ON chio_security_alert_outbox (status, next_attempt_at_unix_ms, idempotency_key);
CREATE TABLE chio_security_alert_outbox_backend (
    idempotency_key TEXT NOT NULL REFERENCES chio_security_alert_outbox (idempotency_key),
    backend_name TEXT NOT NULL CHECK (typeof(backend_name) = 'text' AND length(backend_name) > 0 AND instr(backend_name, char(0)) = 0),
    command_hash BLOB NOT NULL CHECK (typeof(command_hash) = 'blob' AND length(command_hash) = 32),
    status TEXT NOT NULL CHECK (status IN ('pending', 'delivered')),
    attempts INTEGER NOT NULL CHECK (attempts > 0),
    delivered_at_unix_ms INTEGER CHECK (delivered_at_unix_ms >= 0),
    PRIMARY KEY (idempotency_key, backend_name),
    CHECK ((status = 'pending' AND delivered_at_unix_ms IS NULL)
        OR (status = 'delivered' AND delivered_at_unix_ms IS NOT NULL))
) STRICT;
