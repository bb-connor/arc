CREATE TABLE work_graph_heads (
    graph_id TEXT PRIMARY KEY CHECK (
        typeof(graph_id) = 'text' AND length(graph_id) BETWEEN 1 AND 256
        AND octet_length(graph_id) <= 1024 AND instr(graph_id, char(0)) = 0
    ),
    bundle_sha256 TEXT NOT NULL CHECK (
        typeof(bundle_sha256) = 'text' AND length(bundle_sha256) = 64
        AND instr(bundle_sha256, char(0)) = 0 AND octet_length(bundle_sha256) <= 256 AND bundle_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    bundle TEXT NOT NULL CHECK (
        typeof(bundle) = 'text' AND octet_length(bundle) BETWEEN 1 AND 67108864
        AND instr(bundle, char(0)) = 0
    ),
    revision INTEGER NOT NULL CHECK (
        typeof(revision) = 'integer' AND revision BETWEEN 1 AND 9007199254740991
    )
);

CREATE TRIGGER work_graph_heads_no_delete
BEFORE DELETE ON work_graph_heads
BEGIN
    SELECT RAISE(ABORT, 'graph issuer head is never deleted');
END;

CREATE TABLE work_graph_versions (
    graph_id TEXT NOT NULL REFERENCES work_graph_heads(graph_id),
    graph_sha256 TEXT NOT NULL CHECK (
        typeof(graph_sha256) = 'text' AND length(graph_sha256) = 64
        AND instr(graph_sha256, char(0)) = 0 AND octet_length(graph_sha256) <= 256 AND graph_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    bundle_sha256 TEXT NOT NULL CHECK (
        typeof(bundle_sha256) = 'text' AND length(bundle_sha256) = 64
        AND instr(bundle_sha256, char(0)) = 0 AND octet_length(bundle_sha256) <= 256 AND bundle_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    bundle TEXT NOT NULL CHECK (
        typeof(bundle) = 'text' AND octet_length(bundle) BETWEEN 1 AND 67108864
        AND instr(bundle, char(0)) = 0
    ),
    successor_bundle_sha256 TEXT NOT NULL CHECK (
        typeof(successor_bundle_sha256) = 'text' AND length(successor_bundle_sha256) = 64
        AND instr(successor_bundle_sha256, char(0)) = 0 AND octet_length(successor_bundle_sha256) <= 256
        AND successor_bundle_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    PRIMARY KEY (graph_id, graph_sha256)
);

CREATE TRIGGER work_graph_versions_immutable
BEFORE UPDATE ON work_graph_versions
BEGIN
    SELECT RAISE(ABORT, 'archived graph version is immutable');
END;

CREATE TRIGGER work_graph_versions_no_delete
BEFORE DELETE ON work_graph_versions
BEGIN
    SELECT RAISE(ABORT, 'archived graph version is immutable');
END;

CREATE TABLE work_graph_issuances (
    bundle_sha256 TEXT PRIMARY KEY CHECK (
        typeof(bundle_sha256) = 'text' AND length(bundle_sha256) = 64
        AND instr(bundle_sha256, char(0)) = 0 AND octet_length(bundle_sha256) <= 256 AND bundle_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    graph_id TEXT NOT NULL REFERENCES work_graph_heads(graph_id),
    parent_bundle_sha256 TEXT CHECK (
        parent_bundle_sha256 IS NULL OR (
            typeof(parent_bundle_sha256) = 'text' AND length(parent_bundle_sha256) = 64
            AND instr(parent_bundle_sha256, char(0)) = 0 AND octet_length(parent_bundle_sha256) <= 256
            AND parent_bundle_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    revision INTEGER NOT NULL CHECK (
        typeof(revision) = 'integer' AND revision BETWEEN 1 AND 9007199254740991
    ),
    UNIQUE (graph_id, revision)
);

CREATE TRIGGER work_graph_issuances_immutable
BEFORE UPDATE ON work_graph_issuances
BEGIN
    SELECT RAISE(ABORT, 'graph issuance is immutable');
END;

CREATE TRIGGER work_graph_issuances_no_delete
BEFORE DELETE ON work_graph_issuances
BEGIN
    SELECT RAISE(ABORT, 'graph issuance is immutable');
END;

CREATE TABLE work_graph_events (
    sequence INTEGER PRIMARY KEY CHECK (
        typeof(sequence) = 'integer' AND sequence BETWEEN 1 AND 9007199254740991
    ),
    bundle_sha256 TEXT NOT NULL UNIQUE REFERENCES work_graph_issuances(bundle_sha256)
);

CREATE TRIGGER work_graph_events_immutable
BEFORE UPDATE ON work_graph_events
BEGIN
    SELECT RAISE(ABORT, 'graph event is immutable');
END;

CREATE TRIGGER work_graph_events_no_delete
BEFORE DELETE ON work_graph_events
BEGIN
    SELECT RAISE(ABORT, 'graph event is immutable');
END;
