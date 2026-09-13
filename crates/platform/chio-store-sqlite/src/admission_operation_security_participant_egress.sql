-- Native egress is independent of the immutable join-v1 journal vocabulary.
CREATE TABLE IF NOT EXISTS security_participant_egress_events (
    security_authority_id TEXT NOT NULL REFERENCES security_participant_state_initializations(security_authority_id),
    sequence INTEGER NOT NULL CHECK (sequence BETWEEN 1 AND 9007199254740991),
    operation_id TEXT NOT NULL REFERENCES admission_operations(operation_id),
    phase TEXT NOT NULL CHECK (phase IN ('acquired', 'committed')),
    tenant_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    fence_id TEXT NOT NULL,
    canonical_record BLOB NOT NULL CHECK (length(canonical_record) BETWEEN 1 AND 16777216),
    event_digest TEXT NOT NULL CHECK (length(event_digest) = 64 AND event_digest NOT GLOB '*[^0-9a-f]*'),
    observed_at INTEGER NOT NULL CHECK (observed_at BETWEEN 1 AND 9007199254740991),
    PRIMARY KEY (security_authority_id, sequence),
    UNIQUE (operation_id, phase),
    UNIQUE (security_authority_id, tenant_id, request_id, phase),
    UNIQUE (security_authority_id, fence_id, phase)
);
CREATE TRIGGER IF NOT EXISTS security_participant_egress_events_no_update
BEFORE UPDATE ON security_participant_egress_events
BEGIN SELECT RAISE(ABORT, 'native egress history is immutable'); END;
CREATE TRIGGER IF NOT EXISTS security_participant_egress_events_no_delete
BEFORE DELETE ON security_participant_egress_events
BEGIN SELECT RAISE(ABORT, 'native egress history is immutable'); END;
CREATE TRIGGER IF NOT EXISTS security_participant_egress_events_no_replace
BEFORE INSERT ON security_participant_egress_events
WHEN EXISTS (SELECT 1 FROM security_participant_egress_events
 WHERE (security_authority_id = NEW.security_authority_id AND sequence = NEW.sequence)
    OR (operation_id = NEW.operation_id AND phase = NEW.phase)
    OR (security_authority_id = NEW.security_authority_id AND tenant_id = NEW.tenant_id AND request_id = NEW.request_id AND phase = NEW.phase)
    OR (security_authority_id = NEW.security_authority_id AND fence_id = NEW.fence_id AND phase = NEW.phase))
BEGIN SELECT RAISE(ABORT, 'native egress history is immutable'); END;
