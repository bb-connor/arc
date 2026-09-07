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
CREATE TABLE IF NOT EXISTS process_state_blobs (
    process_id TEXT NOT NULL REFERENCES processes(id),
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
    data BLOB NOT NULL CHECK (typeof(data) = 'blob' AND length(data) <= 1048576),
    PRIMARY KEY (process_id, sha256)
);
