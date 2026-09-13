-- Approval claims share the admission authority and its participant commit chain.
-- Historical source markers remain in the separate, permanent migration import.
CREATE TABLE IF NOT EXISTS governed_approval_replay_claim_episodes (
    operation_id TEXT NOT NULL CHECK (
        typeof(operation_id) = 'text'
        AND length(CAST(operation_id AS BLOB)) BETWEEN 1 AND 512
    ),
    episode_id TEXT NOT NULL CHECK (
        typeof(episode_id) = 'text'
        AND length(CAST(episode_id AS BLOB)) BETWEEN 1 AND 512
    ),
    approval_authority_id TEXT NOT NULL CHECK (
        typeof(approval_authority_id) = 'text'
        AND length(CAST(approval_authority_id AS BLOB)) BETWEEN 1 AND 512
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
    FOREIGN KEY (approval_authority_id)
        REFERENCES governed_approval_replay_migration_expectations(approval_authority_id)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS governed_approval_replay_claim_resources (
    operation_id TEXT NOT NULL CHECK (
        typeof(operation_id) = 'text'
        AND length(CAST(operation_id AS BLOB)) BETWEEN 1 AND 512
    ),
    episode_id TEXT NOT NULL CHECK (
        typeof(episode_id) = 'text'
        AND length(CAST(episode_id AS BLOB)) BETWEEN 1 AND 512
    ),
    approval_authority_id TEXT NOT NULL CHECK (
        typeof(approval_authority_id) = 'text'
        AND length(CAST(approval_authority_id AS BLOB)) BETWEEN 1 AND 512
    ),
    subject_id TEXT NOT NULL CHECK (typeof(subject_id) = 'text' AND length(CAST(subject_id AS BLOB)) BETWEEN 1 AND 512),
    request_id TEXT NOT NULL CHECK (typeof(request_id) = 'text' AND length(CAST(request_id AS BLOB)) BETWEEN 1 AND 512),
    intent_hash TEXT NOT NULL CHECK (typeof(intent_hash) = 'text' AND length(intent_hash) = 64 AND intent_hash NOT GLOB '*[^0-9a-f]*'),
    token_digest TEXT NOT NULL CHECK (typeof(token_digest) = 'text' AND length(token_digest) = 64 AND token_digest NOT GLOB '*[^0-9a-f]*'),
    expires_at INTEGER NOT NULL CHECK (typeof(expires_at) = 'integer' AND expires_at BETWEEN 1 AND 9007199254740),
    PRIMARY KEY (operation_id, episode_id),
    FOREIGN KEY (operation_id, episode_id)
        REFERENCES governed_approval_replay_claim_episodes(operation_id, episode_id)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS governed_approval_replay_claim_resource_identity
ON governed_approval_replay_claim_resources(approval_authority_id, subject_id, request_id, intent_hash);

CREATE TABLE IF NOT EXISTS governed_approval_replay_claim_releases (
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
        REFERENCES governed_approval_replay_claim_episodes(operation_id, episode_id)
) WITHOUT ROWID;

CREATE TRIGGER IF NOT EXISTS governed_approval_replay_claim_episodes_no_replace
BEFORE INSERT ON governed_approval_replay_claim_episodes
WHEN EXISTS (SELECT 1 FROM governed_approval_replay_claim_episodes
    WHERE operation_id = NEW.operation_id AND episode_id = NEW.episode_id)
BEGIN SELECT RAISE(ABORT, 'approval claim episode is immutable'); END;

CREATE TRIGGER IF NOT EXISTS governed_approval_replay_claim_episodes_no_update
BEFORE UPDATE ON governed_approval_replay_claim_episodes
BEGIN SELECT RAISE(ABORT, 'approval claim episode is immutable'); END;

CREATE TRIGGER IF NOT EXISTS governed_approval_replay_claim_episodes_no_delete
BEFORE DELETE ON governed_approval_replay_claim_episodes
BEGIN SELECT RAISE(ABORT, 'approval claim episode is permanent'); END;

CREATE TRIGGER IF NOT EXISTS governed_approval_replay_claim_resources_no_replace
BEFORE INSERT ON governed_approval_replay_claim_resources
WHEN EXISTS (SELECT 1 FROM governed_approval_replay_claim_resources
    WHERE operation_id = NEW.operation_id AND episode_id = NEW.episode_id)
BEGIN SELECT RAISE(ABORT, 'approval claim resource is immutable'); END;

CREATE TRIGGER IF NOT EXISTS governed_approval_replay_claim_resources_no_update
BEFORE UPDATE ON governed_approval_replay_claim_resources
BEGIN SELECT RAISE(ABORT, 'approval claim resource is immutable'); END;

CREATE TRIGGER IF NOT EXISTS governed_approval_replay_claim_resources_no_delete
BEFORE DELETE ON governed_approval_replay_claim_resources
BEGIN SELECT RAISE(ABORT, 'approval claim resource is permanent'); END;

CREATE TRIGGER IF NOT EXISTS governed_approval_replay_claim_releases_no_replace
BEFORE INSERT ON governed_approval_replay_claim_releases
WHEN EXISTS (SELECT 1 FROM governed_approval_replay_claim_releases
    WHERE operation_id = NEW.operation_id AND episode_id = NEW.episode_id)
BEGIN SELECT RAISE(ABORT, 'approval claim release is immutable'); END;

CREATE TRIGGER IF NOT EXISTS governed_approval_replay_claim_releases_no_update
BEFORE UPDATE ON governed_approval_replay_claim_releases
BEGIN SELECT RAISE(ABORT, 'approval claim release is immutable'); END;

CREATE TRIGGER IF NOT EXISTS governed_approval_replay_claim_releases_no_delete
BEFORE DELETE ON governed_approval_replay_claim_releases
BEGIN SELECT RAISE(ABORT, 'approval claim release is permanent'); END;
