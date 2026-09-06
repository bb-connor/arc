-- Permanent reservation identity. Lifecycle transitions must append evidence;
-- this row is never pruned or recycled, including after the signed nonce expires.
CREATE TABLE IF NOT EXISTS admission_execution_nonce_reservations (
    operation_id TEXT PRIMARY KEY REFERENCES admission_operations(operation_id),
    nonce_id TEXT NOT NULL UNIQUE CHECK(length(nonce_id) BETWEEN 1 AND 512),
    issuer TEXT NOT NULL CHECK(length(issuer) = 64),
    reservation_json BLOB NOT NULL CHECK(length(reservation_json) BETWEEN 1 AND 16384),
    ready_operation_json BLOB NOT NULL CHECK(length(ready_operation_json) BETWEEN 1 AND 262144),
    reserved_at_unix_ms INTEGER NOT NULL CHECK(reserved_at_unix_ms BETWEEN 0 AND 9007199254740991)
);

CREATE TRIGGER IF NOT EXISTS admission_execution_nonce_reservations_immutable
BEFORE UPDATE ON admission_execution_nonce_reservations
BEGIN
    SELECT RAISE(ABORT, 'admission execution nonce reservation is immutable');
END;

-- Each phase is append-only and authenticated by its exact admission commit.
-- CapturePending is preparation only; committed is atomic with budget capture
-- and DispatchCommitted. Cancellation is possible only before that transaction.
CREATE TABLE IF NOT EXISTS admission_execution_nonce_transitions (
    operation_id TEXT NOT NULL REFERENCES admission_execution_nonce_reservations(operation_id),
    kind TEXT NOT NULL CHECK(kind IN ('capture_pending', 'committed', 'cancelled')),
    operation_json BLOB NOT NULL CHECK(length(operation_json) BETWEEN 1 AND 262144),
    recorded_at_unix_ms INTEGER NOT NULL CHECK(recorded_at_unix_ms BETWEEN 0 AND 9007199254740991),
    participant_digest TEXT CHECK(participant_digest IS NULL OR (
        length(participant_digest) = 64 AND participant_digest NOT GLOB '*[^0-9a-f]*'
    )),
    CHECK((kind = 'cancelled') = (participant_digest IS NULL)),
    PRIMARY KEY(operation_id, kind)
);

CREATE TRIGGER IF NOT EXISTS admission_execution_nonce_transitions_immutable
BEFORE UPDATE ON admission_execution_nonce_transitions
BEGIN
    SELECT RAISE(ABORT, 'admission execution nonce transition is immutable');
END;

CREATE TRIGGER IF NOT EXISTS admission_execution_nonce_transitions_no_delete
BEFORE DELETE ON admission_execution_nonce_transitions
BEGIN
    SELECT RAISE(ABORT, 'admission execution nonce transition is permanent');
END;

CREATE TRIGGER IF NOT EXISTS admission_execution_nonce_reservations_no_delete
BEFORE DELETE ON admission_execution_nonce_reservations
BEGIN
    SELECT RAISE(ABORT, 'admission execution nonce reservation is permanent');
END;
