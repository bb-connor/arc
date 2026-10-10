-- tenant-read-contract: security_participant_checkpoint_events; class=administrative; principal=kernel-admission
-- tenant-read-contract: security_participant_checkpoint_rows; class=administrative; principal=kernel-admission
-- Contracts: docs/security/trust-boundary-inventory.json

CREATE TABLE IF NOT EXISTS security_participant_checkpoint_events (
    security_authority_id TEXT NOT NULL CHECK (length(CAST(security_authority_id AS BLOB)) BETWEEN 1 AND 512),
    sequence INTEGER NOT NULL CHECK (sequence BETWEEN 1 AND 9007199254740991),
    canonical_record BLOB NOT NULL CHECK (length(canonical_record) BETWEEN 1 AND 65536),
    checkpoint_digest TEXT NOT NULL CHECK (length(checkpoint_digest) = 64 AND checkpoint_digest NOT GLOB '*[^0-9a-f]*'),
    observed_at INTEGER NOT NULL CHECK (observed_at BETWEEN 1 AND 9007199254740991),
    PRIMARY KEY (security_authority_id, sequence),
    FOREIGN KEY (security_authority_id) REFERENCES security_participant_state_initializations(security_authority_id)
) STRICT;

CREATE TABLE IF NOT EXISTS security_participant_checkpoint_rows (
    security_authority_id TEXT NOT NULL CHECK (length(CAST(security_authority_id AS BLOB)) BETWEEN 1 AND 512),
    checkpoint_sequence INTEGER NOT NULL CHECK (checkpoint_sequence BETWEEN 1 AND 9007199254740991),
    table_name TEXT NOT NULL CHECK (length(CAST(table_name AS BLOB)) BETWEEN 1 AND 128),
    row_index INTEGER NOT NULL CHECK (row_index BETWEEN 0 AND 65535),
    canonical_row BLOB NOT NULL CHECK (length(canonical_row) BETWEEN 1 AND 16777216),
    PRIMARY KEY (security_authority_id, checkpoint_sequence, table_name, row_index),
    FOREIGN KEY (security_authority_id, checkpoint_sequence)
        REFERENCES security_participant_checkpoint_events(security_authority_id, sequence)
        DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE TRIGGER IF NOT EXISTS security_participant_checkpoint_events_no_update
BEFORE UPDATE ON security_participant_checkpoint_events
BEGIN SELECT RAISE(ABORT, 'native checkpoint history is immutable'); END;
CREATE TRIGGER IF NOT EXISTS security_participant_checkpoint_events_no_delete
BEFORE DELETE ON security_participant_checkpoint_events
BEGIN SELECT RAISE(ABORT, 'native checkpoint history is immutable'); END;
CREATE TRIGGER IF NOT EXISTS security_participant_checkpoint_events_no_replace
BEFORE INSERT ON security_participant_checkpoint_events
WHEN EXISTS (SELECT 1 FROM security_participant_checkpoint_events
    WHERE security_authority_id = NEW.security_authority_id AND sequence = NEW.sequence)
BEGIN SELECT RAISE(ABORT, 'native checkpoint history is immutable'); END;

CREATE TRIGGER IF NOT EXISTS security_participant_checkpoint_rows_no_update
BEFORE UPDATE ON security_participant_checkpoint_rows
BEGIN SELECT RAISE(ABORT, 'native checkpoint snapshot is immutable'); END;
CREATE TRIGGER IF NOT EXISTS security_participant_checkpoint_rows_no_delete
BEFORE DELETE ON security_participant_checkpoint_rows
BEGIN SELECT RAISE(ABORT, 'native checkpoint snapshot is immutable'); END;
CREATE TRIGGER IF NOT EXISTS security_participant_checkpoint_rows_no_replace
BEFORE INSERT ON security_participant_checkpoint_rows
WHEN EXISTS (SELECT 1 FROM security_participant_checkpoint_rows
    WHERE security_authority_id = NEW.security_authority_id
      AND checkpoint_sequence = NEW.checkpoint_sequence
      AND table_name = NEW.table_name AND row_index = NEW.row_index)
BEGIN SELECT RAISE(ABORT, 'native checkpoint snapshot is immutable'); END;
