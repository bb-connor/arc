CREATE TABLE IF NOT EXISTS process_confined_delivery_markers (
    child_id TEXT PRIMARY KEY REFERENCES process_confined_return_slots(child_id),
    parent_id TEXT NOT NULL REFERENCES processes(id),
    boundary_id TEXT NOT NULL UNIQUE,
    release_id TEXT NOT NULL UNIQUE,
    receipt BLOB NOT NULL CHECK(typeof(receipt)='blob' AND length(receipt) BETWEEN 1 AND 262144)
);
CREATE TRIGGER IF NOT EXISTS process_confined_delivery_no_update
BEFORE UPDATE ON process_confined_delivery_markers
BEGIN SELECT RAISE(ABORT,'ordered confined delivery is immutable'); END;
CREATE TRIGGER IF NOT EXISTS process_confined_delivery_no_delete
BEFORE DELETE ON process_confined_delivery_markers
BEGIN SELECT RAISE(ABORT,'ordered confined delivery is retained'); END;
CREATE TRIGGER IF NOT EXISTS process_confined_delivery_version_requires_marker
BEFORE UPDATE OF version ON process_runtime
WHEN NEW.version=7 AND NOT EXISTS(SELECT 1 FROM process_confined_delivery_markers)
BEGIN SELECT RAISE(ABORT,'confined delivery requires actual ordered custody'); END;
CREATE TRIGGER IF NOT EXISTS process_confined_delivery_version_no_downgrade
BEFORE UPDATE OF version ON process_runtime
WHEN OLD.version>=7 AND NEW.version<OLD.version
BEGIN SELECT RAISE(ABORT,'confined delivery cannot downgrade'); END;
