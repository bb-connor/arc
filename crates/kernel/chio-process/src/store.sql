CREATE TABLE IF NOT EXISTS process_runtime (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    version INTEGER NOT NULL,
    namespace TEXT NOT NULL,
    authority TEXT NOT NULL,
    kernel_key TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS processes (
    id TEXT PRIMARY KEY,
    parent_id TEXT REFERENCES processes(id),
    root_id TEXT NOT NULL REFERENCES processes(id),
    depth INTEGER NOT NULL CHECK (depth BETWEEN 0 AND 64),
    capability TEXT NOT NULL,
    limits TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'running' CHECK (state IN ('running', 'cancelled')),
    revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    checkpoint TEXT NOT NULL DEFAULT 'null',
    tree_calls INTEGER NOT NULL DEFAULT 0 CHECK (tree_calls >= 0)
);
CREATE INDEX IF NOT EXISTS processes_parent ON processes(parent_id);
CREATE INDEX IF NOT EXISTS processes_root ON processes(root_id);
CREATE TABLE IF NOT EXISTS process_calls (
    process_id TEXT NOT NULL REFERENCES processes(id),
    operation_key TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 1 CHECK (attempts >= 1),
    PRIMARY KEY (process_id, operation_key)
);
CREATE TABLE IF NOT EXISTS process_call_nonces (
    process_id TEXT NOT NULL,
    operation_key TEXT NOT NULL,
    attempt INTEGER NOT NULL CHECK (attempt >= 1),
    nonce_json BLOB NOT NULL CHECK (typeof(nonce_json) = 'blob' AND length(nonce_json) BETWEEN 1 AND 16384),
    PRIMARY KEY (process_id, operation_key, attempt),
    FOREIGN KEY (process_id, operation_key) REFERENCES process_calls(process_id, operation_key)
);
CREATE TABLE IF NOT EXISTS process_recovery_calls (
    process_id TEXT NOT NULL REFERENCES processes(id),
    operation_key TEXT NOT NULL,
    continuation_id TEXT NOT NULL,
    reservation BLOB NOT NULL CHECK (typeof(reservation)='blob' AND length(reservation) BETWEEN 1 AND 4096),
    final_binding TEXT CHECK (final_binding IS NULL OR (length(final_binding)=64 AND final_binding NOT GLOB '*[^0-9a-f]*')),
    PRIMARY KEY (process_id, operation_key),
    UNIQUE (process_id, continuation_id)
);
CREATE TRIGGER IF NOT EXISTS process_recovery_identity_immutable
BEFORE UPDATE ON process_recovery_calls
WHEN OLD.process_id!=NEW.process_id OR OLD.operation_key!=NEW.operation_key
    OR OLD.continuation_id!=NEW.continuation_id OR OLD.reservation!=NEW.reservation
    OR OLD.final_binding IS NOT NULL
BEGIN SELECT RAISE(ABORT,'recovery reservation is immutable'); END;
CREATE TRIGGER IF NOT EXISTS process_recovery_no_delete BEFORE DELETE ON process_recovery_calls
BEGIN SELECT RAISE(ABORT,'recovery reservation is immutable'); END;
CREATE TRIGGER IF NOT EXISTS process_recovery_version_monotone BEFORE UPDATE OF version ON process_runtime
WHEN NEW.version < OLD.version OR NEW.version NOT BETWEEN 1 AND 5
BEGIN SELECT RAISE(ABORT,'recovery journal cannot downgrade'); END;
CREATE TABLE IF NOT EXISTS worker_credentials (
    credential_hash TEXT PRIMARY KEY,
    process_id TEXT NOT NULL REFERENCES processes(id),
    expires_at INTEGER NOT NULL CHECK (expires_at > 0)
);
CREATE INDEX IF NOT EXISTS worker_credentials_process ON worker_credentials(process_id);
CREATE TABLE IF NOT EXISTS process_delegation_keys (
    process_id TEXT PRIMARY KEY REFERENCES processes(id),
    seed_hex TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS process_child_work (
    sequence INTEGER PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE,
    request_hash TEXT NOT NULL,
    process_id TEXT NOT NULL UNIQUE REFERENCES processes(id),
    parent_id TEXT NOT NULL REFERENCES processes(id),
    template TEXT NOT NULL,
    input TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS process_worker_waits (
    process_id TEXT PRIMARY KEY REFERENCES processes(id),
    children TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS process_settled_waits (
    process_id TEXT PRIMARY KEY REFERENCES process_worker_waits(process_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS process_state_blobs (
    process_id TEXT NOT NULL REFERENCES processes(id),
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
    data BLOB NOT NULL CHECK (typeof(data) = 'blob' AND length(data) <= 1048576),
    knowledge_generation TEXT NOT NULL DEFAULT 'legacy' CHECK(length(knowledge_generation) BETWEEN 1 AND 64),
    legacy_quarantined INTEGER NOT NULL DEFAULT 1 CHECK (legacy_quarantined IN (0,1)),
    PRIMARY KEY (process_id, sha256)
);
CREATE TABLE IF NOT EXISTS process_artifact_objects (
    process_id TEXT NOT NULL REFERENCES processes(id),
    object_id TEXT NOT NULL CHECK(length(object_id) BETWEEN 1 AND 256),
    generation TEXT NOT NULL UNIQUE CHECK(length(generation)=36),
    sha256 TEXT NOT NULL CHECK(length(sha256)=64 AND sha256 NOT GLOB '*[^0-9a-f]*'),
    size_bytes INTEGER NOT NULL CHECK(size_bytes BETWEEN 0 AND 1048576),
    data BLOB CHECK(data IS NULL OR (typeof(data)='blob' AND length(data)=size_bytes)),
    PRIMARY KEY(process_id, object_id)
);
CREATE TRIGGER IF NOT EXISTS process_artifact_object_identity_immutable
BEFORE UPDATE ON process_artifact_objects
WHEN OLD.process_id!=NEW.process_id OR OLD.object_id!=NEW.object_id
    OR OLD.generation!=NEW.generation OR OLD.sha256!=NEW.sha256
    OR OLD.size_bytes!=NEW.size_bytes
    OR (OLD.data IS NOT NEW.data AND NEW.data IS NOT NULL)
BEGIN SELECT RAISE(ABORT,'artifact object identity is immutable'); END;
CREATE TRIGGER IF NOT EXISTS process_artifact_object_no_delete
BEFORE DELETE ON process_artifact_objects
BEGIN SELECT RAISE(ABORT,'artifact object retirement is retained'); END;
CREATE TABLE IF NOT EXISTS process_confined_return_slots (
    child_id TEXT PRIMARY KEY REFERENCES processes(id),
    parent_id TEXT NOT NULL REFERENCES processes(id),
    boundary_id TEXT NOT NULL UNIQUE,
    boundary_digest TEXT NOT NULL CHECK(length(boundary_digest)=64 AND boundary_digest NOT GLOB '*[^0-9a-f]*'),
    generation TEXT NOT NULL UNIQUE CHECK(length(generation)=36),
    sha256 TEXT CHECK(sha256 IS NULL OR (length(sha256)=64 AND sha256 NOT GLOB '*[^0-9a-f]*')),
    data BLOB CHECK(data IS NULL OR (typeof(data)='blob' AND length(data) IN(4,5))),
    CHECK((sha256 IS NULL)=(data IS NULL))
);
CREATE TRIGGER IF NOT EXISTS process_confined_return_slot_identity_immutable
BEFORE UPDATE ON process_confined_return_slots
WHEN OLD.child_id!=NEW.child_id OR OLD.parent_id!=NEW.parent_id
    OR OLD.boundary_id!=NEW.boundary_id OR OLD.boundary_digest!=NEW.boundary_digest
    OR OLD.generation!=NEW.generation
    OR (OLD.data IS NOT NULL AND (OLD.data IS NOT NEW.data OR OLD.sha256 IS NOT NEW.sha256))
BEGIN SELECT RAISE(ABORT,'confined return slot is immutable'); END;
CREATE TRIGGER IF NOT EXISTS process_confined_return_slot_no_delete
BEFORE DELETE ON process_confined_return_slots
BEGIN SELECT RAISE(ABORT,'confined return capacity is retained'); END;
