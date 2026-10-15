-- tenant-read-contract: security_participant_state_mutations; class=administrative; principal=kernel-admission
-- Contracts: docs/security/trust-boundary-inventory.json

CREATE TABLE IF NOT EXISTS security_participant_state_mutations (
    security_authority_id TEXT NOT NULL CHECK (length(security_authority_id) BETWEEN 1 AND 512 AND octet_length(security_authority_id) <= 2048 AND instr(security_authority_id, char(0)) = 0),
    sequence INTEGER NOT NULL CHECK (sequence BETWEEN 2 AND 9007199254740991),
    operation_id TEXT NOT NULL UNIQUE CHECK (length(operation_id) BETWEEN 1 AND 512 AND octet_length(operation_id) <= 2048 AND instr(operation_id, char(0)) = 0),
    tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 512 AND octet_length(tenant_id) <= 2048 AND instr(tenant_id, char(0)) = 0),
    transition_id TEXT NOT NULL CHECK (length(transition_id) BETWEEN 1 AND 512 AND octet_length(transition_id) <= 2048 AND instr(transition_id, char(0)) = 0),
    observed_at INTEGER NOT NULL CHECK (observed_at BETWEEN 1 AND 9007199254740991),
    canonical_record BLOB NOT NULL CHECK (length(canonical_record) BETWEEN 1 AND 16777216),
    mutation_digest TEXT NOT NULL CHECK (length(mutation_digest) = 64 AND instr(mutation_digest, char(0)) = 0 AND mutation_digest NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (security_authority_id, sequence),
    UNIQUE (security_authority_id, tenant_id, transition_id),
    FOREIGN KEY (security_authority_id) REFERENCES security_participant_state_initializations(security_authority_id),
    FOREIGN KEY (operation_id) REFERENCES admission_operations(operation_id)
) STRICT;

CREATE TRIGGER IF NOT EXISTS security_participant_state_mutations_no_update
BEFORE UPDATE ON security_participant_state_mutations
BEGIN SELECT RAISE(ABORT, 'native mutation history is immutable'); END;

CREATE TRIGGER IF NOT EXISTS security_participant_state_mutations_no_delete
BEFORE DELETE ON security_participant_state_mutations
BEGIN SELECT RAISE(ABORT, 'native mutation history is immutable'); END;

CREATE TRIGGER IF NOT EXISTS security_participant_state_mutations_no_replace
BEFORE INSERT ON security_participant_state_mutations
WHEN EXISTS (SELECT 1 FROM security_participant_state_mutations
    WHERE (security_authority_id = NEW.security_authority_id AND sequence = NEW.sequence)
       OR operation_id = NEW.operation_id
       OR (security_authority_id = NEW.security_authority_id
           AND tenant_id = NEW.tenant_id AND transition_id = NEW.transition_id))
BEGIN SELECT RAISE(ABORT, 'native mutation history is immutable'); END;
