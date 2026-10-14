-- Immutable Merkle leaves over one initialized authority's sealed imported
-- source scopes; the protected imported influence record authenticates their
-- root. The retained inventory holds at most 65536 source rows and each row
-- joins at most two scopes, so an authority holds at most 131072 leaves, a
-- scope holds at most 65536 members and a proof carries at most 17 hashes.
CREATE TABLE IF NOT EXISTS security_participant_state_imported_scope_index (
    security_authority_id TEXT NOT NULL CHECK (length(CAST(security_authority_id AS BLOB)) BETWEEN 1 AND 512),
    scope_key TEXT NOT NULL CHECK (length(scope_key) = 64 AND scope_key NOT GLOB '*[^0-9a-f]*'),
    leaf_index INTEGER NOT NULL CHECK (leaf_index BETWEEN 0 AND 131071),
    member_count INTEGER NOT NULL CHECK (member_count BETWEEN 1 AND 65536),
    member_digest TEXT NOT NULL CHECK (length(member_digest) = 64 AND member_digest NOT GLOB '*[^0-9a-f]*'),
    inclusion_proof BLOB NOT NULL CHECK (length(inclusion_proof) BETWEEN 1 AND 2048),
    members BLOB NOT NULL CHECK (length(members) BETWEEN 2 AND 655362),
    PRIMARY KEY (security_authority_id, scope_key),
    UNIQUE (security_authority_id, leaf_index),
    FOREIGN KEY (security_authority_id) REFERENCES security_participant_state_initializations(security_authority_id)
) STRICT, WITHOUT ROWID;

CREATE TRIGGER IF NOT EXISTS security_participant_state_imported_scope_index_immutable
BEFORE UPDATE ON security_participant_state_imported_scope_index
BEGIN SELECT RAISE(ABORT, 'native imported scope index is immutable'); END;

CREATE TRIGGER IF NOT EXISTS security_participant_state_imported_scope_index_no_delete
BEFORE DELETE ON security_participant_state_imported_scope_index
BEGIN SELECT RAISE(ABORT, 'native imported scope index is immutable'); END;

CREATE TRIGGER IF NOT EXISTS security_participant_state_imported_scope_index_no_replace
BEFORE INSERT ON security_participant_state_imported_scope_index WHEN EXISTS (SELECT 1 FROM security_participant_state_imported_scope_index WHERE security_authority_id = NEW.security_authority_id AND (scope_key = NEW.scope_key OR leaf_index = NEW.leaf_index))
BEGIN SELECT RAISE(ABORT, 'native imported scope index is immutable'); END;
