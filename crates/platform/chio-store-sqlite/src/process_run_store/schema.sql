CREATE TABLE run_binding(
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    binding TEXT NOT NULL
) STRICT;
CREATE TABLE run_workers(
    process TEXT PRIMARY KEY,
    state TEXT NOT NULL CHECK(state IN ('pending','running','completed','failed')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
    suspensions INTEGER NOT NULL DEFAULT 0 CHECK(suspensions BETWEEN 0 AND attempts),
    outcome TEXT,
    peak_resident_bytes INTEGER NOT NULL DEFAULT 0,
    cpu_ms INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE TABLE run_containers(
    owner TEXT PRIMARY KEY,
    process TEXT NOT NULL,
    attempt INTEGER NOT NULL,
    engine TEXT NOT NULL,
    container_id TEXT,
    create_rejected INTEGER NOT NULL DEFAULT 0 CHECK(create_rejected IN (0,1)),
    UNIQUE(process,attempt)
) STRICT;
CREATE TABLE run_container_launches(
    process TEXT NOT NULL,
    attempt INTEGER NOT NULL,
    record TEXT NOT NULL,
    PRIMARY KEY(process,attempt)
) STRICT;
CREATE TABLE run_child_settlements(
    parent TEXT NOT NULL,
    child TEXT NOT NULL,
    request_id TEXT NOT NULL,
    PRIMARY KEY(parent,child)
) STRICT;
CREATE TABLE run_socket_leases(
    singleton INTEGER PRIMARY KEY CHECK(singleton >= 1),
    name TEXT NOT NULL UNIQUE,
    directory_device TEXT,
    directory_inode TEXT,
    socket_device TEXT,
    socket_inode TEXT,
    CHECK((directory_device IS NULL)=(directory_inode IS NULL)),
    CHECK((socket_device IS NULL)=(socket_inode IS NULL))
) STRICT;
