-- Runtime claims share the admission authority and its participant commit chain.
-- Historical source markers remain in the separate, permanent migration import.
CREATE TABLE IF NOT EXISTS runtime_replay_claim_episodes (
    operation_id TEXT NOT NULL CHECK (
        typeof(operation_id) = 'text'
        AND length(CAST(operation_id AS BLOB)) BETWEEN 1 AND 512
    ),
    episode_id TEXT NOT NULL CHECK (
        typeof(episode_id) = 'text'
        AND length(CAST(episode_id AS BLOB)) BETWEEN 1 AND 512
    ),
    runtime_authority_id TEXT NOT NULL CHECK (
        typeof(runtime_authority_id) = 'text'
        AND length(CAST(runtime_authority_id AS BLOB)) BETWEEN 1 AND 512
    ),
    ledger_digest TEXT NOT NULL CHECK (
        typeof(ledger_digest) = 'text'
        AND length(CAST(ledger_digest AS BLOB)) = 64 AND ledger_digest NOT GLOB '*[^0-9a-f]*'
    ),
    claim_digest TEXT NOT NULL CHECK (
        typeof(claim_digest) = 'text'
        AND length(CAST(claim_digest AS BLOB)) = 64 AND claim_digest NOT GLOB '*[^0-9a-f]*'
    ),
    claim_json BLOB NOT NULL CHECK (
        typeof(claim_json) = 'blob' AND length(claim_json) BETWEEN 1 AND 16384
    ),
    operation_json BLOB NOT NULL CHECK (
        typeof(operation_json) = 'blob' AND length(operation_json) BETWEEN 1 AND 262144
    ),
    PRIMARY KEY (operation_id, episode_id),
    FOREIGN KEY (operation_id) REFERENCES admission_operations(operation_id),
    FOREIGN KEY (runtime_authority_id)
        REFERENCES runtime_replay_migration_expectations(runtime_authority_id)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS runtime_replay_claim_resources (
    operation_id TEXT NOT NULL CHECK (
        typeof(operation_id) = 'text'
        AND length(CAST(operation_id AS BLOB)) BETWEEN 1 AND 512
    ),
    episode_id TEXT NOT NULL CHECK (
        typeof(episode_id) = 'text'
        AND length(CAST(episode_id AS BLOB)) BETWEEN 1 AND 512
    ),
    runtime_authority_id TEXT NOT NULL CHECK (
        typeof(runtime_authority_id) = 'text'
        AND length(CAST(runtime_authority_id AS BLOB)) BETWEEN 1 AND 512
    ),
    participant_kind TEXT NOT NULL CHECK (participant_kind IN (
        'destructive_lease', 'treaty_continuation', 'swarm_continuation'
    )),
    resource_id TEXT NOT NULL CHECK (
        typeof(resource_id) = 'text'
        AND length(CAST(resource_id AS BLOB)) BETWEEN 1 AND 512
    ),
    artifact_digest TEXT NOT NULL CHECK (
        typeof(artifact_digest) = 'text'
        AND length(CAST(artifact_digest AS BLOB)) = 64 AND artifact_digest NOT GLOB '*[^0-9a-f]*'
    ),
    PRIMARY KEY (operation_id, episode_id, participant_kind),
    FOREIGN KEY (operation_id, episode_id)
        REFERENCES runtime_replay_claim_episodes(operation_id, episode_id)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS runtime_replay_claim_resource_identity
ON runtime_replay_claim_resources(runtime_authority_id, participant_kind, resource_id);

CREATE TABLE IF NOT EXISTS runtime_replay_claim_releases (
    operation_id TEXT NOT NULL CHECK (
        typeof(operation_id) = 'text'
        AND length(CAST(operation_id AS BLOB)) BETWEEN 1 AND 512
    ),
    episode_id TEXT NOT NULL CHECK (
        typeof(episode_id) = 'text'
        AND length(CAST(episode_id AS BLOB)) BETWEEN 1 AND 512
    ),
    release_digest TEXT NOT NULL CHECK (
        typeof(release_digest) = 'text'
        AND length(CAST(release_digest AS BLOB)) = 64 AND release_digest NOT GLOB '*[^0-9a-f]*'
    ),
    release_json BLOB NOT NULL CHECK (
        typeof(release_json) = 'blob' AND length(release_json) BETWEEN 1 AND 16384
    ),
    operation_json BLOB NOT NULL CHECK (
        typeof(operation_json) = 'blob' AND length(operation_json) BETWEEN 1 AND 262144
    ),
    PRIMARY KEY (operation_id, episode_id),
    FOREIGN KEY (operation_id, episode_id)
        REFERENCES runtime_replay_claim_episodes(operation_id, episode_id)
) WITHOUT ROWID;

CREATE TRIGGER IF NOT EXISTS runtime_replay_claim_episodes_no_replace
BEFORE INSERT ON runtime_replay_claim_episodes
WHEN EXISTS (SELECT 1 FROM runtime_replay_claim_episodes
    WHERE operation_id = NEW.operation_id AND episode_id = NEW.episode_id)
BEGIN SELECT RAISE(ABORT, 'runtime claim episode is immutable'); END;

CREATE TRIGGER IF NOT EXISTS runtime_replay_claim_episodes_no_update
BEFORE UPDATE ON runtime_replay_claim_episodes
BEGIN SELECT RAISE(ABORT, 'runtime claim episode is immutable'); END;

CREATE TRIGGER IF NOT EXISTS runtime_replay_claim_episodes_no_delete
BEFORE DELETE ON runtime_replay_claim_episodes
BEGIN SELECT RAISE(ABORT, 'runtime claim episode is permanent'); END;

CREATE TRIGGER IF NOT EXISTS runtime_replay_claim_resources_no_replace
BEFORE INSERT ON runtime_replay_claim_resources
WHEN EXISTS (SELECT 1 FROM runtime_replay_claim_resources
    WHERE operation_id = NEW.operation_id AND episode_id = NEW.episode_id
      AND participant_kind = NEW.participant_kind)
BEGIN SELECT RAISE(ABORT, 'runtime claim resource is immutable'); END;

CREATE TRIGGER IF NOT EXISTS runtime_replay_claim_resources_no_update
BEFORE UPDATE ON runtime_replay_claim_resources
BEGIN SELECT RAISE(ABORT, 'runtime claim resource is immutable'); END;

CREATE TRIGGER IF NOT EXISTS runtime_replay_claim_resources_no_delete
BEFORE DELETE ON runtime_replay_claim_resources
BEGIN SELECT RAISE(ABORT, 'runtime claim resource is permanent'); END;

CREATE TRIGGER IF NOT EXISTS runtime_replay_claim_releases_no_replace
BEFORE INSERT ON runtime_replay_claim_releases
WHEN EXISTS (SELECT 1 FROM runtime_replay_claim_releases
    WHERE operation_id = NEW.operation_id AND episode_id = NEW.episode_id)
BEGIN SELECT RAISE(ABORT, 'runtime claim release is immutable'); END;

CREATE TRIGGER IF NOT EXISTS runtime_replay_claim_releases_no_update
BEFORE UPDATE ON runtime_replay_claim_releases
BEGIN SELECT RAISE(ABORT, 'runtime claim release is immutable'); END;

CREATE TRIGGER IF NOT EXISTS runtime_replay_claim_releases_no_delete
BEFORE DELETE ON runtime_replay_claim_releases
BEGIN SELECT RAISE(ABORT, 'runtime claim release is permanent'); END;
