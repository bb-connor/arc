-- Only the explicitly signed v2 domain may use this activation. Legacy proofs
-- remain rejected, and their complete imported history is never erased.
CREATE TABLE IF NOT EXISTS dpop_replay_authority_activations (
    dpop_authority_id TEXT NOT NULL PRIMARY KEY CHECK (
        typeof(dpop_authority_id) = 'text'
        AND length(CAST(dpop_authority_id AS BLOB)) BETWEEN 1 AND 512
    ),
    canonical_authority BLOB NOT NULL CHECK (
        typeof(canonical_authority) = 'blob'
        AND length(canonical_authority) BETWEEN 1 AND 4096
    ),
    FOREIGN KEY (dpop_authority_id)
        REFERENCES dpop_replay_migration_expectations(dpop_authority_id)
) WITHOUT ROWID;

CREATE TRIGGER IF NOT EXISTS dpop_replay_authority_activations_no_replace
BEFORE INSERT ON dpop_replay_authority_activations
WHEN EXISTS (SELECT 1 FROM dpop_replay_authority_activations
    WHERE dpop_authority_id = NEW.dpop_authority_id)
BEGIN
    SELECT RAISE(ABORT, 'DPoP authority activation is immutable');
END;

CREATE TRIGGER IF NOT EXISTS dpop_replay_authority_activations_immutable
BEFORE UPDATE ON dpop_replay_authority_activations
BEGIN
    SELECT RAISE(ABORT, 'DPoP authority activation is immutable');
END;

CREATE TRIGGER IF NOT EXISTS dpop_replay_authority_activations_no_delete
BEFORE DELETE ON dpop_replay_authority_activations
BEGIN
    SELECT RAISE(ABORT, 'DPoP authority activation is permanent');
END;
