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
    PRIMARY KEY (process_id, operation_key)
);
