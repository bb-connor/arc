CREATE TABLE work_delegation_namespace (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    namespace TEXT NOT NULL CHECK (
        typeof(namespace) = 'text' AND length(namespace) = 64
        AND instr(namespace, char(0)) = 0 AND octet_length(namespace) <= 256 AND namespace NOT GLOB '*[^0-9a-f]*'
    )
);

CREATE TRIGGER work_delegation_namespace_immutable
BEFORE UPDATE ON work_delegation_namespace
BEGIN
    SELECT RAISE(ABORT, 'delegation namespace is immutable');
END;

CREATE TRIGGER work_delegation_namespace_no_delete
BEFORE DELETE ON work_delegation_namespace
BEGIN
    SELECT RAISE(ABORT, 'delegation namespace is immutable');
END;

CREATE TABLE work_delegation_slots (
    slot_id TEXT PRIMARY KEY CHECK (
        typeof(slot_id) = 'text' AND length(slot_id) BETWEEN 1 AND 256
        AND octet_length(slot_id) <= 1024 AND instr(slot_id, char(0)) = 0
    ),
    parent_id TEXT REFERENCES work_delegation_slots(slot_id) CHECK (
        parent_id IS NULL OR (
            typeof(parent_id) = 'text' AND length(parent_id) BETWEEN 1 AND 256
            AND octet_length(parent_id) <= 1024 AND instr(parent_id, char(0)) = 0
        )
    ),
    root_id TEXT NOT NULL CHECK (
        typeof(root_id) = 'text' AND length(root_id) BETWEEN 1 AND 256
        AND octet_length(root_id) <= 1024 AND instr(root_id, char(0)) = 0
    ),
    slot TEXT NOT NULL CHECK (
        typeof(slot) = 'text' AND octet_length(slot) BETWEEN 1 AND 65536
        AND instr(slot, char(0)) = 0
    ),
    allocated INTEGER NOT NULL CHECK (
        typeof(allocated) = 'integer' AND allocated BETWEEN 0 AND 9007199254740991
    ),
    selection TEXT CHECK (
        selection IS NULL OR (
            typeof(selection) = 'text' AND octet_length(selection) BETWEEN 1 AND 65536
            AND instr(selection, char(0)) = 0
        )
    ),
    revision INTEGER NOT NULL CHECK (
        typeof(revision) = 'integer' AND revision BETWEEN 0 AND 9007199254740991
    ),
    dispatched INTEGER NOT NULL CHECK (dispatched IN (0, 1)),
    CHECK ((parent_id IS NULL) = (root_id = slot_id))
);

CREATE INDEX work_delegation_slots_parent ON work_delegation_slots(parent_id);
CREATE INDEX work_delegation_slots_root ON work_delegation_slots(root_id);

CREATE TRIGGER work_delegation_slots_no_delete
BEFORE DELETE ON work_delegation_slots
BEGIN
    SELECT RAISE(ABORT, 'delegated allocation is never released');
END;

CREATE TABLE work_delegation_permits (
    slot_id TEXT PRIMARY KEY REFERENCES work_delegation_slots(slot_id),
    permit TEXT NOT NULL CHECK (
        typeof(permit) = 'text' AND octet_length(permit) BETWEEN 1 AND 65536
        AND instr(permit, char(0)) = 0
    )
);

CREATE TRIGGER work_delegation_permits_immutable
BEFORE UPDATE ON work_delegation_permits
BEGIN
    SELECT RAISE(ABORT, 'sealed permit is immutable');
END;

CREATE TRIGGER work_delegation_permits_no_delete
BEFORE DELETE ON work_delegation_permits
BEGIN
    SELECT RAISE(ABORT, 'sealed permit is immutable');
END;

CREATE TABLE work_delegation_commands (
    command_id TEXT PRIMARY KEY CHECK (
        typeof(command_id) = 'text' AND length(command_id) BETWEEN 1 AND 256
        AND octet_length(command_id) <= 1024 AND instr(command_id, char(0)) = 0
    ),
    action TEXT NOT NULL CHECK (
        action IN ('create_root', 'subdivide', 'select', 'claim', 'seal')
    ),
    request_digest TEXT NOT NULL CHECK (
        typeof(request_digest) = 'text' AND length(request_digest) = 64
        AND instr(request_digest, char(0)) = 0 AND octet_length(request_digest) <= 256 AND request_digest NOT GLOB '*[^0-9a-f]*'
    ),
    slot_id TEXT NOT NULL REFERENCES work_delegation_slots(slot_id)
);

CREATE TRIGGER work_delegation_commands_immutable
BEFORE UPDATE ON work_delegation_commands
BEGIN
    SELECT RAISE(ABORT, 'delegation command binding is immutable');
END;

CREATE TRIGGER work_delegation_commands_no_delete
BEFORE DELETE ON work_delegation_commands
BEGIN
    SELECT RAISE(ABORT, 'delegation command binding is immutable');
END;

CREATE TABLE work_delegation_events (
    sequence INTEGER PRIMARY KEY CHECK (
        typeof(sequence) = 'integer' AND sequence BETWEEN 1 AND 9007199254740991
    ),
    command_id TEXT NOT NULL REFERENCES work_delegation_commands(command_id),
    slot_id TEXT NOT NULL REFERENCES work_delegation_slots(slot_id),
    state_digest TEXT NOT NULL CHECK (
        typeof(state_digest) = 'text' AND length(state_digest) = 64
        AND instr(state_digest, char(0)) = 0 AND octet_length(state_digest) <= 256 AND state_digest NOT GLOB '*[^0-9a-f]*'
    )
);

CREATE INDEX work_delegation_events_slot ON work_delegation_events(slot_id, sequence);

CREATE TRIGGER work_delegation_events_immutable
BEFORE UPDATE ON work_delegation_events
BEGIN
    SELECT RAISE(ABORT, 'delegation event is immutable');
END;

CREATE TRIGGER work_delegation_events_no_delete
BEFORE DELETE ON work_delegation_events
BEGIN
    SELECT RAISE(ABORT, 'delegation event is immutable');
END;
