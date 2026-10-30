pub(super) const SELECT_STATUS: &str = "SELECT command_json, command_hash, status, attempts,
        next_attempt_at_unix_ms, delivered_at_unix_ms
    FROM chio_security_alert_outbox WHERE idempotency_key = ?1";
pub(super) const INSERT_PENDING: &str = "INSERT INTO chio_security_alert_outbox
    (idempotency_key, command_json, command_hash, status, attempts,
     next_attempt_at_unix_ms, delivered_at_unix_ms)
    VALUES (?1, ?2, ?3, 'pending', 0, ?4, NULL)";
pub(super) const SELECT_BACKLOG: &str = "SELECT
        COALESCE(SUM(status = 'pending'), 0),
        COALESCE(SUM(status = 'parked'), 0)
    FROM chio_security_alert_outbox
    WHERE status IN ('pending', 'parked')";
pub(super) const SELECT_DUE: &str = "SELECT command_json, command_hash, attempts
    FROM chio_security_alert_outbox
    WHERE status = 'pending' AND next_attempt_at_unix_ms <= ?1
    ORDER BY next_attempt_at_unix_ms, idempotency_key
    LIMIT ?2";
pub(super) const SELECT_PENDING_ATTEMPTS: &str = "SELECT attempts FROM chio_security_alert_outbox
    WHERE idempotency_key = ?1 AND command_hash = ?2 AND status = 'pending'";
pub(super) const RECORD_FAILURE: &str = "UPDATE chio_security_alert_outbox
    SET attempts = ?1, next_attempt_at_unix_ms = ?2
    WHERE idempotency_key = ?3 AND command_hash = ?4 AND status = 'pending' AND attempts = ?5";
pub(super) const RECORD_DELIVERY: &str = "UPDATE chio_security_alert_outbox
    SET status = 'delivered', attempts = ?1, delivered_at_unix_ms = ?2
    WHERE idempotency_key = ?3 AND command_hash = ?4 AND status = 'pending' AND attempts = ?5";
pub(super) const RECORD_PARKED: &str = "UPDATE chio_security_alert_outbox
    SET status = 'parked', attempts = ?1
    WHERE idempotency_key = ?2 AND command_hash = ?3 AND status = 'pending' AND attempts = ?4";
pub(super) const SELECT_BACKEND_RECORDS: &str =
    "SELECT backend_name, command_hash, status, attempts,
        delivered_at_unix_ms
    FROM chio_security_alert_outbox_backend WHERE idempotency_key = ?1";
pub(super) const INSERT_BACKEND_OUTCOME: &str = "INSERT INTO chio_security_alert_outbox_backend
    (idempotency_key, backend_name, command_hash, status, attempts, delivered_at_unix_ms)
    VALUES (?1, ?2, ?3, ?4, 1, ?5)";
pub(super) const UPDATE_BACKEND_OUTCOME: &str = "UPDATE chio_security_alert_outbox_backend
    SET status = ?1, attempts = ?2, delivered_at_unix_ms = ?3
    WHERE idempotency_key = ?4 AND backend_name = ?5 AND command_hash = ?6
      AND status = 'pending' AND attempts = ?7";
