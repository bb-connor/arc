CREATE TABLE IF NOT EXISTS process_unused_recovery_reservations (
    process_id TEXT NOT NULL,
    operation_key TEXT NOT NULL,
    continuation_id TEXT NOT NULL,
    closure BLOB NOT NULL CHECK(typeof(closure)='blob' AND length(closure) BETWEEN 1 AND 16384),
    PRIMARY KEY(process_id,operation_key),
    UNIQUE(process_id,continuation_id),
    FOREIGN KEY(process_id,operation_key) REFERENCES process_recovery_calls(process_id,operation_key)
);
CREATE TRIGGER IF NOT EXISTS process_unused_recovery_closure_no_update
BEFORE UPDATE ON process_unused_recovery_reservations
BEGIN SELECT RAISE(ABORT,'unused recovery closure is immutable'); END;
CREATE TRIGGER IF NOT EXISTS process_unused_recovery_closure_no_delete
BEFORE DELETE ON process_unused_recovery_reservations
BEGIN SELECT RAISE(ABORT,'unused recovery closure is retained'); END;
CREATE TRIGGER IF NOT EXISTS process_unused_recovery_no_call_insert
BEFORE INSERT ON process_calls
WHEN EXISTS(SELECT 1 FROM process_unused_recovery_reservations WHERE process_id=NEW.process_id AND operation_key=NEW.operation_key)
BEGIN SELECT RAISE(ABORT,'unused recovery reservation is permanently closed'); END;
CREATE TRIGGER IF NOT EXISTS process_unused_recovery_no_call_update
BEFORE UPDATE ON process_calls
WHEN EXISTS(SELECT 1 FROM process_unused_recovery_reservations WHERE
    (process_id=OLD.process_id AND operation_key=OLD.operation_key) OR
    (process_id=NEW.process_id AND operation_key=NEW.operation_key))
BEGIN SELECT RAISE(ABORT,'unused recovery reservation is permanently closed'); END;
CREATE TRIGGER IF NOT EXISTS process_unused_recovery_no_reservation_update
BEFORE UPDATE ON process_recovery_calls
WHEN EXISTS(SELECT 1 FROM process_unused_recovery_reservations WHERE process_id=OLD.process_id AND operation_key=OLD.operation_key)
BEGIN SELECT RAISE(ABORT,'unused recovery reservation is permanently closed'); END;
CREATE TRIGGER IF NOT EXISTS process_unused_recovery_no_reservation_reinsert
BEFORE INSERT ON process_recovery_calls
WHEN EXISTS(SELECT 1 FROM process_recovery_calls WHERE process_id=NEW.process_id AND
    (operation_key=NEW.operation_key OR continuation_id=NEW.continuation_id))
BEGIN SELECT RAISE(ABORT,'original recovery reservation is retained'); END;
CREATE TRIGGER IF NOT EXISTS process_unused_recovery_version_requires_closure
BEFORE UPDATE OF version ON process_runtime
WHEN NEW.version=6 AND NOT EXISTS(SELECT 1 FROM process_unused_recovery_reservations)
BEGIN SELECT RAISE(ABORT,'unused recovery journal requires actual closed custody'); END;
CREATE TRIGGER IF NOT EXISTS process_unused_recovery_version_no_downgrade
BEFORE UPDATE OF version ON process_runtime
WHEN OLD.version>=6 AND NEW.version<OLD.version
BEGIN SELECT RAISE(ABORT,'unused recovery closure cannot downgrade'); END;
