-- Authority-scoped native rows. Hydration is not serving activation.
CREATE TABLE IF NOT EXISTS security_participant_state_initializations (
    security_authority_id TEXT NOT NULL PRIMARY KEY,
    expectation_id TEXT NOT NULL CHECK (length(expectation_id) = 64 AND expectation_id NOT GLOB '*[^0-9a-f]*'),
    fingerprint_digest TEXT NOT NULL CHECK (length(fingerprint_digest) = 64 AND fingerprint_digest NOT GLOB '*[^0-9a-f]*'),
    schema_digest TEXT NOT NULL CHECK (length(schema_digest) = 64 AND schema_digest NOT GLOB '*[^0-9a-f]*'),
    initialized_at INTEGER NOT NULL CHECK (initialized_at BETWEEN 1 AND 9007199254740991),
    store_uuid TEXT NOT NULL,
    store_lease_id TEXT NOT NULL,
    store_owner_epoch INTEGER NOT NULL CHECK (store_owner_epoch > 0),
    initialization_digest TEXT NOT NULL CHECK (length(initialization_digest) = 64 AND initialization_digest NOT GLOB '*[^0-9a-f]*'),
    FOREIGN KEY (security_authority_id) REFERENCES security_participant_migration_expectations(security_authority_id),
    FOREIGN KEY (store_uuid, store_owner_epoch) REFERENCES chio_serving_leases(store_uuid, owner_epoch)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS security_participant_state_declassification_evidence_identity (
    security_authority_id TEXT NOT NULL REFERENCES security_participant_migration_expectations(security_authority_id),
    evidence_id TEXT NOT NULL,
    transition_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('consumption', 'outcome')),
    body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
    PRIMARY KEY (security_authority_id, tenant_id, evidence_id),
    UNIQUE (security_authority_id, tenant_id, transition_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS security_participant_state_declassification_lifecycle (
    security_authority_id TEXT NOT NULL REFERENCES security_participant_migration_expectations(security_authority_id),
    singleton INTEGER NOT NULL CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version = 2),
    readiness_cursor TEXT NOT NULL,
    reconciliation_active INTEGER NOT NULL DEFAULT 0
        CHECK (reconciliation_active IN (0, 1)),
    live_dispatch_sealed INTEGER NOT NULL DEFAULT 0
        CHECK (live_dispatch_sealed IN (0, 1)),
    compaction_active INTEGER NOT NULL DEFAULT 0
        CHECK (compaction_active IN (0, 1)),
    CHECK (reconciliation_active = 0 OR live_dispatch_sealed = 0),
    PRIMARY KEY (security_authority_id, singleton)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS security_participant_state_declassification_receipt_outbox (
    security_authority_id TEXT NOT NULL REFERENCES security_participant_migration_expectations(security_authority_id),
    tenant_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('consumption', 'outcome')),
    phase_ordinal INTEGER NOT NULL CHECK (phase_ordinal IN (0, 1)),
    request_hash BLOB NOT NULL CHECK (length(request_hash) = 32),
    state TEXT NOT NULL CHECK (
        state IN (
            'consumed_pending_dispatch', 'released', 'dispatch_failed',
            'outcome_unknown'
        )
    ),
    transition_binding BLOB NOT NULL CHECK (length(transition_binding) <= 4096),
    evidence_type TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    canonical_body BLOB NOT NULL CHECK (length(canonical_body) <= 1048576),
    body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
    transition_id TEXT NOT NULL,
    occurred_at INTEGER NOT NULL,
    predecessor_evidence_id TEXT,
    acknowledged INTEGER NOT NULL DEFAULT 0 CHECK (acknowledged IN (0, 1)),
    acknowledged_at INTEGER,
    durable_sink_record_hash BLOB CHECK (length(durable_sink_record_hash) = 32),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at INTEGER NOT NULL,
    last_error_code TEXT,
    CHECK (
        (acknowledged = 0 AND acknowledged_at IS NULL
            AND durable_sink_record_hash IS NULL)
        OR (acknowledged = 1 AND acknowledged_at IS NOT NULL
            AND durable_sink_record_hash IS NOT NULL)
    ),
    CHECK (
        (phase = 'consumption' AND phase_ordinal = 0
            AND state = 'consumed_pending_dispatch'
            AND predecessor_evidence_id IS NULL)
        OR
        (phase = 'outcome' AND phase_ordinal = 1
            AND state IN ('released', 'dispatch_failed', 'outcome_unknown')
            AND predecessor_evidence_id IS NOT NULL)
    ),
    PRIMARY KEY (security_authority_id, tenant_id, grant_id, phase_ordinal),
    FOREIGN KEY (security_authority_id, tenant_id, evidence_id)
        REFERENCES security_participant_state_declassification_evidence_identity (
        security_authority_id, tenant_id, evidence_id
        ),
    FOREIGN KEY (security_authority_id, tenant_id, grant_id)
        REFERENCES security_participant_state_declassification_uses (
        security_authority_id, tenant_id, grant_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS security_participant_state_declassification_tombstones (
    security_authority_id TEXT NOT NULL REFERENCES security_participant_migration_expectations(security_authority_id),
    tenant_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    request_hash BLOB NOT NULL CHECK (length(request_hash) = 32),
    terminal_state TEXT NOT NULL CHECK (
        terminal_state IN ('released', 'dispatch_failed')
    ),
    consumption_evidence_id TEXT NOT NULL,
    consumption_body_hash BLOB NOT NULL CHECK (length(consumption_body_hash) = 32),
    consumption_transition_id TEXT NOT NULL,
    consumption_occurred_at INTEGER NOT NULL,
    consumption_sink_record_hash BLOB NOT NULL
        CHECK (length(consumption_sink_record_hash) = 32),
    outcome_evidence_id TEXT NOT NULL,
    outcome_body_hash BLOB NOT NULL CHECK (length(outcome_body_hash) = 32),
    outcome_transition_id TEXT NOT NULL,
    outcome_occurred_at INTEGER NOT NULL,
    outcome_sink_record_hash BLOB NOT NULL
        CHECK (length(outcome_sink_record_hash) = 32),
    policy_hash BLOB NOT NULL CHECK (length(policy_hash) = 32),
    compacted_at INTEGER NOT NULL,
    PRIMARY KEY (security_authority_id, tenant_id, grant_id),
    FOREIGN KEY (security_authority_id, tenant_id, consumption_evidence_id)
        REFERENCES security_participant_state_declassification_evidence_identity (
        security_authority_id, tenant_id, evidence_id
        ),
    FOREIGN KEY (security_authority_id, tenant_id, outcome_evidence_id)
        REFERENCES security_participant_state_declassification_evidence_identity (
        security_authority_id, tenant_id, evidence_id
        )
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS security_participant_state_declassification_uses (
    security_authority_id TEXT NOT NULL REFERENCES security_participant_migration_expectations(security_authority_id),
    grant_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    request_hash BLOB NOT NULL CHECK (length(request_hash) = 32),
    state TEXT NOT NULL CHECK (
        state IN (
            'consumed_pending_dispatch', 'released', 'dispatch_failed',
            'outcome_unknown'
        )
    ),
    consumed_at INTEGER NOT NULL,
    grant_expires_at INTEGER NOT NULL,
    retain_until INTEGER NOT NULL,
    consumption_binding BLOB NOT NULL CHECK (length(consumption_binding) <= 4096),
    outcome_binding BLOB CHECK (length(outcome_binding) <= 4096),
    transition_id TEXT,
    CHECK (
        grant_expires_at > consumed_at AND retain_until >= grant_expires_at
    ),
    CHECK (
        (state = 'consumed_pending_dispatch' AND transition_id IS NULL
            AND outcome_binding IS NULL)
        OR
        (state IN ('released', 'dispatch_failed', 'outcome_unknown')
            AND transition_id IS NOT NULL AND outcome_binding IS NOT NULL)
    ),
    PRIMARY KEY (security_authority_id, tenant_id, grant_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS security_participant_state_egress_fences (
    security_authority_id TEXT NOT NULL REFERENCES security_participant_migration_expectations(security_authority_id),
    fence_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    lineage_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    isolation_epoch_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    request_hash BLOB NOT NULL CHECK (length(request_hash) = 32),
    context_generation INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    dispatch_commitment_id TEXT,
    committed_at INTEGER,
    PRIMARY KEY (security_authority_id, tenant_id, fence_id),
    UNIQUE (security_authority_id, tenant_id, request_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS security_participant_state_flow_contexts (
    security_authority_id TEXT NOT NULL REFERENCES security_participant_migration_expectations(security_authority_id),
    tenant_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    lineage_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    isolation_epoch_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    PRIMARY KEY (security_authority_id,
        tenant_id, principal_id, lineage_id, session_id, isolation_epoch_id
    )
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS security_participant_state_flow_sequences (
    security_authority_id TEXT NOT NULL REFERENCES security_participant_migration_expectations(security_authority_id),
    tenant_id TEXT NOT NULL,
    last_generation INTEGER NOT NULL,
    PRIMARY KEY (security_authority_id, tenant_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS security_participant_state_isolation_epochs (
    security_authority_id TEXT NOT NULL REFERENCES security_participant_migration_expectations(security_authority_id),
    tenant_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    lineage_id TEXT NOT NULL,
    isolation_epoch_id TEXT NOT NULL,
    previous_isolation_epoch_id TEXT,
    evidence_hash BLOB NOT NULL CHECK (length(evidence_hash) = 32),
    evidence_verifier_id TEXT,
    evidence_receipt_ref TEXT,
    transition_id TEXT NOT NULL,
    effective_at INTEGER NOT NULL,
    CHECK (
        (evidence_verifier_id IS NULL AND evidence_receipt_ref IS NULL)
        OR (evidence_verifier_id IS NOT NULL AND evidence_receipt_ref IS NOT NULL)
    ),
    PRIMARY KEY (security_authority_id, tenant_id, principal_id, lineage_id, isolation_epoch_id),
    UNIQUE (security_authority_id, tenant_id, transition_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS security_participant_state_lineage_flow_state (
    security_authority_id TEXT NOT NULL REFERENCES security_participant_migration_expectations(security_authority_id),
    tenant_id TEXT NOT NULL,
    lineage_id TEXT NOT NULL,
    label_json BLOB NOT NULL CHECK (length(label_json) <= 1048576),
    label_hash BLOB NOT NULL CHECK (length(label_hash) = 32),
    generation INTEGER NOT NULL,
    PRIMARY KEY (security_authority_id, tenant_id, lineage_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS security_participant_state_principal_flow_state (
    security_authority_id TEXT NOT NULL REFERENCES security_participant_migration_expectations(security_authority_id),
    tenant_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    isolation_epoch_id TEXT NOT NULL,
    label_json BLOB NOT NULL CHECK (length(label_json) <= 1048576),
    label_hash BLOB NOT NULL CHECK (length(label_hash) = 32),
    generation INTEGER NOT NULL,
    PRIMARY KEY (security_authority_id, tenant_id, principal_id, isolation_epoch_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS security_participant_state_session_flow_state (
    security_authority_id TEXT NOT NULL REFERENCES security_participant_migration_expectations(security_authority_id),
    tenant_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    isolation_epoch_id TEXT NOT NULL,
    label_json BLOB NOT NULL CHECK (length(label_json) <= 1048576),
    label_hash BLOB NOT NULL CHECK (length(label_hash) = 32),
    generation INTEGER NOT NULL,
    PRIMARY KEY (security_authority_id, tenant_id, principal_id, session_id, isolation_epoch_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS security_participant_state_session_memberships (
    security_authority_id TEXT NOT NULL REFERENCES security_participant_migration_expectations(security_authority_id),
    tenant_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    isolation_epoch_id TEXT NOT NULL,
    PRIMARY KEY (security_authority_id, tenant_id, principal_id, session_id, isolation_epoch_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS security_participant_state_transitions (
    security_authority_id TEXT NOT NULL REFERENCES security_participant_migration_expectations(security_authority_id),
    transition_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    transition_kind TEXT NOT NULL,
    request_hash BLOB NOT NULL CHECK (length(request_hash) = 32),
    PRIMARY KEY (security_authority_id, tenant_id, transition_id)
) STRICT, WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS security_participant_state_pending_evidence
ON security_participant_state_declassification_receipt_outbox (
    security_authority_id, acknowledged, next_attempt_at, tenant_id, grant_id, phase_ordinal
);

CREATE TRIGGER IF NOT EXISTS security_participant_state_outbox_use_binding
BEFORE INSERT ON security_participant_state_declassification_receipt_outbox
WHEN NOT EXISTS (
    SELECT 1 FROM security_participant_state_declassification_uses AS used
    WHERE used.security_authority_id = NEW.security_authority_id
      AND used.tenant_id = NEW.tenant_id AND used.grant_id = NEW.grant_id
      AND used.request_hash = NEW.request_hash AND used.state = NEW.state
)
BEGIN SELECT RAISE(ABORT, 'native evidence use binding is invalid'); END;

CREATE TRIGGER IF NOT EXISTS security_participant_state_outcome_predecessor
BEFORE INSERT ON security_participant_state_declassification_receipt_outbox
WHEN NEW.phase = 'outcome' AND NOT EXISTS (
    SELECT 1 FROM security_participant_state_declassification_receipt_outbox AS prior
    WHERE prior.security_authority_id = NEW.security_authority_id
      AND prior.tenant_id = NEW.tenant_id AND prior.grant_id = NEW.grant_id
      AND prior.phase = 'consumption' AND prior.phase_ordinal = 0
      AND prior.evidence_id = NEW.predecessor_evidence_id
)
BEGIN SELECT RAISE(ABORT, 'native evidence predecessor is absent'); END;

CREATE TRIGGER IF NOT EXISTS security_participant_state_spent_grant
BEFORE INSERT ON security_participant_state_declassification_uses
WHEN EXISTS (
    SELECT 1 FROM security_participant_state_declassification_tombstones AS spent
    WHERE spent.security_authority_id = NEW.security_authority_id
      AND spent.tenant_id = NEW.tenant_id AND spent.grant_id = NEW.grant_id
)
BEGIN SELECT RAISE(ABORT, 'native grant is permanently spent'); END;
