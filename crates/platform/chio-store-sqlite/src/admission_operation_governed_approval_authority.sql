-- One operator-installed approval authority per row. Claims reference it and
-- its install is a single fenced global commit; rows are never replaced.
CREATE TABLE IF NOT EXISTS governed_approval_replay_authorities (
    approval_authority_id TEXT NOT NULL PRIMARY KEY CHECK (
        typeof(approval_authority_id) = 'text'
        AND length(approval_authority_id) BETWEEN 1 AND 512 AND octet_length(approval_authority_id) <= 2048 AND instr(approval_authority_id, char(0)) = 0
    ),
    expectation_id TEXT NOT NULL UNIQUE CHECK (
        typeof(expectation_id) = 'text'
        AND length(expectation_id) BETWEEN 1 AND 512 AND octet_length(expectation_id) <= 2048 AND instr(expectation_id, char(0)) = 0
    ),
    destination_store_uuid TEXT NOT NULL CHECK (
        typeof(destination_store_uuid) = 'text' AND length(destination_store_uuid) BETWEEN 1 AND 512
    ),
    capacity INTEGER NOT NULL CHECK (typeof(capacity) = 'integer' AND capacity BETWEEN 1 AND 65536),
    installed_at_unix_ms INTEGER NOT NULL CHECK (
        typeof(installed_at_unix_ms) = 'integer'
        AND installed_at_unix_ms BETWEEN 0 AND 9007199254740991
    ),
    install_digest TEXT NOT NULL CHECK (
        typeof(install_digest) = 'text' AND length(install_digest) = 64 AND instr(install_digest, char(0)) = 0 AND install_digest NOT GLOB '*[^0-9a-f]*'
    ),
    store_uuid TEXT NOT NULL CHECK (typeof(store_uuid) = 'text' AND store_uuid <> ''),
    store_lease_id TEXT NOT NULL CHECK (typeof(store_lease_id) = 'text' AND store_lease_id <> ''),
    store_owner_epoch INTEGER NOT NULL CHECK (
        typeof(store_owner_epoch) = 'integer' AND store_owner_epoch > 0
    ),
    CHECK (store_uuid = destination_store_uuid),
    FOREIGN KEY (store_uuid, store_owner_epoch)
        REFERENCES chio_serving_leases(store_uuid, owner_epoch)
) WITHOUT ROWID;

-- REPLACE may otherwise bypass DELETE triggers when recursive_triggers is
-- disabled. This guard covers every declared key.
CREATE TRIGGER IF NOT EXISTS governed_approval_replay_authorities_no_replace
BEFORE INSERT ON governed_approval_replay_authorities
WHEN EXISTS (
    SELECT 1 FROM governed_approval_replay_authorities
    WHERE approval_authority_id = NEW.approval_authority_id
       OR expectation_id = NEW.expectation_id
)
BEGIN
    SELECT RAISE(ABORT, 'governed approval authority install is immutable');
END;

CREATE TRIGGER IF NOT EXISTS governed_approval_replay_authorities_immutable
BEFORE UPDATE ON governed_approval_replay_authorities
BEGIN
    SELECT RAISE(ABORT, 'governed approval authority install is immutable');
END;

CREATE TRIGGER IF NOT EXISTS governed_approval_replay_authorities_no_delete
BEFORE DELETE ON governed_approval_replay_authorities
BEGIN
    SELECT RAISE(ABORT, 'governed approval authority install is permanent');
END;
