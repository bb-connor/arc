CREATE TABLE capability_grant_budgets (
    capability_id TEXT NOT NULL,
    grant_index INTEGER NOT NULL,
    invocation_count INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    seq INTEGER NOT NULL DEFAULT 0,
    total_cost_exposed INTEGER NOT NULL DEFAULT 0,
    total_cost_realized_spend INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (capability_id, grant_index)
);

CREATE INDEX idx_capability_grant_budgets_updated_at
    ON capability_grant_budgets(updated_at);

CREATE TABLE budget_replication_meta (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    next_seq INTEGER NOT NULL
);

CREATE TABLE budget_authorization_holds (
    hold_id TEXT PRIMARY KEY,
    capability_id TEXT NOT NULL,
    grant_index INTEGER NOT NULL,
    authorized_exposure_units INTEGER NOT NULL,
    remaining_exposure_units INTEGER NOT NULL,
    invocation_count_debited INTEGER NOT NULL,
    invocation_captured INTEGER NOT NULL DEFAULT 0,
    disposition TEXT NOT NULL,
    authority_id TEXT,
    lease_id TEXT,
    lease_epoch INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    reserved_until INTEGER,
    reserved_currency TEXT,
    reserved_payment_reference TEXT,
    reserved_budget_total INTEGER,
    reserved_delegation_depth INTEGER,
    reserved_root_budget_holder TEXT,
    operation_id TEXT,
    projection_kind TEXT NOT NULL DEFAULT 'standalone' CHECK (projection_kind IN ('standalone', 'composite_v1')),
    revocation_set_digest TEXT CHECK (revocation_set_digest IS NULL OR (length(revocation_set_digest) = 64 AND revocation_set_digest NOT GLOB '*[^0-9a-f]*')),
    expected_quota_count INTEGER CHECK (expected_quota_count IS NULL OR expected_quota_count BETWEEN 0 AND 8),
    expected_revocation_count INTEGER CHECK (expected_revocation_count IS NULL OR expected_revocation_count BETWEEN 1 AND 256),
    expected_artifact_count INTEGER CHECK (expected_artifact_count IS NULL OR expected_artifact_count BETWEEN 0 AND 8),
    has_cumulative_approval INTEGER CHECK (has_cumulative_approval IS NULL OR has_cumulative_approval IN (0, 1)),
    has_revocation_commit INTEGER CHECK (has_revocation_commit IS NULL OR has_revocation_commit IN (0, 1)),
    authorization_outcome TEXT,
    invocation_state TEXT,
    monetary_state TEXT,
    supplemental_verifier_id TEXT,
    supplemental_verifier_config_digest TEXT,
    supplemental_artifact_digest TEXT,
    supplemental_expires_at INTEGER,
    trusted_capture_time INTEGER CHECK (trusted_capture_time IS NULL OR trusted_capture_time >= 0)
);

CREATE INDEX idx_budget_authorization_holds_capability
    ON budget_authorization_holds(capability_id, grant_index);

CREATE TABLE budget_mutation_events (
    event_id TEXT PRIMARY KEY,
    hold_id TEXT,
    capability_id TEXT NOT NULL,
    grant_index INTEGER NOT NULL,
    kind TEXT NOT NULL,
    allowed INTEGER,
    recorded_at INTEGER NOT NULL,
    event_seq INTEGER,
    usage_seq INTEGER,
    exposure_units INTEGER NOT NULL DEFAULT 0,
    realized_spend_units INTEGER NOT NULL DEFAULT 0,
    max_invocations INTEGER,
    max_exposure_per_invocation INTEGER,
    max_total_exposure_units INTEGER,
    invocation_count_after INTEGER NOT NULL,
    total_cost_exposed_after INTEGER NOT NULL,
    total_cost_realized_spend_after INTEGER NOT NULL,
    authority_id TEXT,
    lease_id TEXT,
    lease_epoch INTEGER,
    operation_id TEXT,
    projection_kind TEXT NOT NULL DEFAULT 'standalone' CHECK (projection_kind IN ('standalone', 'composite_v1')),
    revocation_set_digest TEXT CHECK (revocation_set_digest IS NULL OR (length(revocation_set_digest) = 64 AND revocation_set_digest NOT GLOB '*[^0-9a-f]*')),
    expected_quota_count INTEGER CHECK (expected_quota_count IS NULL OR expected_quota_count BETWEEN 0 AND 8),
    expected_revocation_count INTEGER CHECK (expected_revocation_count IS NULL OR expected_revocation_count BETWEEN 1 AND 256),
    expected_artifact_count INTEGER CHECK (expected_artifact_count IS NULL OR expected_artifact_count BETWEEN 0 AND 8),
    has_cumulative_approval INTEGER CHECK (has_cumulative_approval IS NULL OR has_cumulative_approval IN (0, 1)),
    has_revocation_commit INTEGER CHECK (has_revocation_commit IS NULL OR has_revocation_commit IN (0, 1)),
    authorization_outcome TEXT,
    invocation_state_before TEXT,
    invocation_state_after TEXT,
    monetary_state_before TEXT,
    monetary_state_after TEXT,
    cumulative_approval_set_digest TEXT CHECK (
    cumulative_approval_set_digest IS NULL
    OR (
        length(cumulative_approval_set_digest) = 64
        AND cumulative_approval_set_digest NOT GLOB '*[^0-9a-f]*'
    )
),
    supplemental_verifier_id TEXT,
    supplemental_verifier_config_digest TEXT,
    supplemental_artifact_digest TEXT,
    supplemental_expires_at INTEGER,
    invocation_quotas_explicit INTEGER,
    trusted_time INTEGER,
    expected_cumulative_state TEXT
);

CREATE INDEX idx_budget_mutation_events_capability
    ON budget_mutation_events(capability_id, grant_index, recorded_at);

CREATE UNIQUE INDEX idx_budget_mutation_events_event_seq
    ON budget_mutation_events(event_seq);

CREATE TABLE budget_import_floors (
    authority_id TEXT PRIMARY KEY,
    floor_seq    INTEGER NOT NULL DEFAULT 0,
    CHECK (floor_seq >= 0)
);

CREATE TABLE budget_ack_head_watermark (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    head_seq  INTEGER NOT NULL DEFAULT 0,
    CHECK (head_seq >= 0)
);
CREATE TABLE budget_origin_ack_heads (
    authority_id TEXT PRIMARY KEY,
    head_seq     INTEGER NOT NULL,
    CHECK (head_seq >= 0)
);
CREATE TABLE budget_abandoned_event_seqs (
    seq INTEGER PRIMARY KEY,
    CHECK (seq > 0)
);

CREATE UNIQUE INDEX idx_budget_holds_operation
    ON budget_authorization_holds(operation_id)
    WHERE operation_id IS NOT NULL;
CREATE UNIQUE INDEX idx_budget_holds_operation_hold
    ON budget_authorization_holds(operation_id, hold_id);
CREATE INDEX idx_budget_holds_supplemental_artifact ON budget_authorization_holds(supplemental_artifact_digest, operation_id) WHERE supplemental_artifact_digest IS NOT NULL;

CREATE TABLE payment_release_evidence (
    operation_id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL UNIQUE CHECK (
        evidence_id <> '' AND length(evidence_id) <= 512
    ),
    evidence_kind TEXT NOT NULL CHECK (evidence_kind IN (
        'pre_dispatch_no_effect',
        'transport_not_accepted',
        'contractual_zero_charge'
    )),
    operation_version INTEGER NOT NULL CHECK (
        operation_version BETWEEN 1 AND 9007199254740991
    ),
    canonical_bundle BLOB NOT NULL CHECK (
        length(canonical_bundle) BETWEEN 1 AND 1048576
    ),
    bundle_digest TEXT NOT NULL CHECK (
        length(bundle_digest) = 64
        AND bundle_digest NOT GLOB '*[^0-9a-f]*'
    ),
    created_at_unix_ms INTEGER NOT NULL CHECK (
        created_at_unix_ms BETWEEN 1 AND 9007199254740991
    ),
    FOREIGN KEY (operation_id) REFERENCES payment_journal(operation_id)
);

CREATE TRIGGER payment_release_evidence_immutable
BEFORE UPDATE ON payment_release_evidence
BEGIN
    SELECT RAISE(ABORT, 'payment release evidence is immutable');
END;

CREATE TRIGGER payment_release_evidence_no_delete
BEFORE DELETE ON payment_release_evidence
BEGIN
    SELECT RAISE(ABORT, 'payment release evidence is immutable');
END;

CREATE TABLE budget_invocation_quotas (
    profile TEXT NOT NULL,
    owner_id TEXT NOT NULL CHECK (owner_id <> ''),
    grant_index INTEGER NOT NULL,
    max_invocations INTEGER NOT NULL CHECK (max_invocations > 0),
    reserved_invocations INTEGER NOT NULL DEFAULT 0
        CHECK (reserved_invocations >= 0 AND reserved_invocations <= max_invocations),
    captured_invocations INTEGER NOT NULL DEFAULT 0
        CHECK (captured_invocations >= 0
               AND captured_invocations <= max_invocations - reserved_invocations),
    version INTEGER NOT NULL DEFAULT 0 CHECK (version >= 0),
    PRIMARY KEY (profile, owner_id, grant_index),
    UNIQUE (profile, owner_id, grant_index, max_invocations),
    CHECK (
        (profile = 'chio.grant-invocation.v1' AND grant_index >= 0)
        OR
        (profile IN (
            'chio.aggregate-capability-invocation.v1',
            'chio.aggregate-family-invocation.v1',
            'chio.broker-capability-execution.v1'
        ) AND grant_index = -1)
    )
);

CREATE TABLE budget_hold_quota_members (
    hold_id TEXT NOT NULL,
    profile TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    grant_index INTEGER NOT NULL,
    max_invocations INTEGER NOT NULL,
    PRIMARY KEY (hold_id, profile, owner_id, grant_index),
    FOREIGN KEY (hold_id)
        REFERENCES budget_authorization_holds(hold_id),
    FOREIGN KEY (profile, owner_id, grant_index, max_invocations)
        REFERENCES budget_invocation_quotas(
            profile, owner_id, grant_index, max_invocations
        )
);

CREATE TABLE budget_event_quota_members (
    event_id TEXT NOT NULL,
    profile TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    grant_index INTEGER NOT NULL,
    max_invocations INTEGER NOT NULL CHECK (max_invocations >= 0),
    reserved_before INTEGER NOT NULL CHECK (reserved_before >= 0),
    captured_before INTEGER NOT NULL CHECK (
        captured_before >= 0 AND reserved_before <= max_invocations
        AND captured_before <= max_invocations - reserved_before
    ),
    reserved_after INTEGER NOT NULL CHECK (reserved_after >= 0),
    captured_after INTEGER NOT NULL CHECK (
        captured_after >= 0 AND reserved_after <= max_invocations
        AND captured_after <= max_invocations - reserved_after
    ),
    PRIMARY KEY (event_id, profile, owner_id, grant_index),
    FOREIGN KEY (event_id) REFERENCES budget_mutation_events(event_id),
    CHECK (owner_id <> ''),
    CHECK (
        (profile = 'chio.grant-invocation.v1' AND grant_index >= 0)
        OR
        (profile IN (
            'chio.aggregate-capability-invocation.v1',
            'chio.aggregate-family-invocation.v1',
            'chio.broker-capability-execution.v1'
        ) AND grant_index = -1)
    )
);

CREATE TABLE budget_hold_revocation_members (
    hold_id TEXT NOT NULL,
    member_index INTEGER NOT NULL CHECK (
        member_index >= 0 AND member_index < 256
    ),
    capability_id TEXT NOT NULL CHECK (
        length(CAST(capability_id AS BLOB)) BETWEEN 1 AND 512
    ),
    PRIMARY KEY (hold_id, member_index),
    UNIQUE (hold_id, capability_id),
    FOREIGN KEY (hold_id)
        REFERENCES budget_authorization_holds(hold_id)
);

CREATE TABLE budget_event_revocation_members (
    event_id TEXT NOT NULL,
    member_index INTEGER NOT NULL CHECK (
        member_index >= 0 AND member_index < 256
    ),
    capability_id TEXT NOT NULL CHECK (
        length(CAST(capability_id AS BLOB)) BETWEEN 1 AND 512
    ),
    PRIMARY KEY (event_id, member_index),
    UNIQUE (event_id, capability_id),
    FOREIGN KEY (event_id) REFERENCES budget_mutation_events(event_id)
);

CREATE TABLE budget_hold_revocation_commits (
    hold_id TEXT PRIMARY KEY,
    authority_id TEXT NOT NULL CHECK (authority_id <> ''),
    lease_id TEXT NOT NULL CHECK (lease_id <> ''),
    lease_epoch INTEGER NOT NULL CHECK (lease_epoch > 0),
    guarantee_level TEXT NOT NULL CHECK (guarantee_level IN (
        'single_node_atomic', 'ha_linearizable'
    )),
    commit_index INTEGER NOT NULL CHECK (commit_index > 0),
    FOREIGN KEY (hold_id)
        REFERENCES budget_authorization_holds(hold_id)
);

CREATE TABLE budget_event_revocation_commits (
    event_id TEXT PRIMARY KEY,
    authority_id TEXT NOT NULL CHECK (authority_id <> ''),
    lease_id TEXT NOT NULL CHECK (lease_id <> ''),
    lease_epoch INTEGER NOT NULL CHECK (lease_epoch > 0),
    guarantee_level TEXT NOT NULL CHECK (guarantee_level IN (
        'single_node_atomic', 'ha_linearizable'
    )),
    commit_index INTEGER NOT NULL CHECK (commit_index > 0),
    FOREIGN KEY (event_id) REFERENCES budget_mutation_events(event_id)
);

CREATE TABLE budget_hold_authorization_artifacts (
    hold_id TEXT NOT NULL,
    artifact_index INTEGER NOT NULL CHECK (
        artifact_index >= 0 AND artifact_index < 8
    ),
    artifact_digest TEXT NOT NULL CHECK (
        length(artifact_digest) = 64
        AND artifact_digest NOT GLOB '*[^0-9a-f]*'
    ),
    PRIMARY KEY (hold_id, artifact_index),
    UNIQUE (hold_id, artifact_digest),
    FOREIGN KEY (hold_id)
        REFERENCES budget_authorization_holds(hold_id)
);

CREATE TABLE budget_event_authorization_artifacts (
    event_id TEXT NOT NULL,
    artifact_index INTEGER NOT NULL CHECK (
        artifact_index >= 0 AND artifact_index < 8
    ),
    artifact_digest TEXT NOT NULL CHECK (
        length(artifact_digest) = 64
        AND artifact_digest NOT GLOB '*[^0-9a-f]*'
    ),
    PRIMARY KEY (event_id, artifact_index),
    UNIQUE (event_id, artifact_digest),
    FOREIGN KEY (event_id) REFERENCES budget_mutation_events(event_id)
);

CREATE TABLE budget_cumulative_approval_accounts (
    authority_id TEXT NOT NULL CHECK (authority_id <> ''),
    owner_id TEXT NOT NULL CHECK (owner_id <> ''),
    approval_budget_id TEXT NOT NULL CHECK (approval_budget_id <> ''),
    approval_budget_epoch INTEGER NOT NULL
        CHECK (approval_budget_epoch >= 0),
    root_grant_hash TEXT NOT NULL CHECK (root_grant_hash <> ''),
    delegation_root_id TEXT,
    root_binding_digest TEXT,
    currency TEXT NOT NULL CHECK (currency <> ''),
    authority_threshold_units INTEGER NOT NULL
        CHECK (authority_threshold_units >= 0),
    reserved_authorized_units INTEGER NOT NULL DEFAULT 0
        CHECK (reserved_authorized_units >= 0),
    captured_authorized_units INTEGER NOT NULL DEFAULT 0
        CHECK (captured_authorized_units >= 0),
    version INTEGER NOT NULL DEFAULT 0 CHECK (version >= 0),
    PRIMARY KEY (
        authority_id, owner_id, approval_budget_id, approval_budget_epoch
    ),
    CHECK (
        (delegation_root_id IS NULL AND root_binding_digest IS NULL)
        OR
        (
            delegation_root_id IS NOT NULL
            AND root_binding_digest IS NOT NULL
            AND delegation_root_id <> ''
            AND root_binding_digest <> ''
        )
    )
);

CREATE TABLE budget_cumulative_approval_operations (
    operation_id TEXT PRIMARY KEY CHECK (operation_id <> ''),
    hold_id TEXT UNIQUE NOT NULL,
    authority_id TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    approval_budget_id TEXT NOT NULL,
    approval_budget_epoch INTEGER NOT NULL,
    effective_threshold_units INTEGER NOT NULL,
    requested_authorized_units INTEGER NOT NULL,
    state TEXT NOT NULL,
    approval_set_digest TEXT CHECK (
        approval_set_digest IS NULL
        OR (
            length(approval_set_digest) = 64
            AND approval_set_digest NOT GLOB '*[^0-9a-f]*'
        )
    ),
    account_version INTEGER NOT NULL CHECK (account_version >= 0),
    FOREIGN KEY (hold_id)
        REFERENCES budget_authorization_holds(hold_id),
    FOREIGN KEY (operation_id, hold_id)
        REFERENCES budget_authorization_holds(operation_id, hold_id),
    FOREIGN KEY (
        authority_id, owner_id, approval_budget_id, approval_budget_epoch
    ) REFERENCES budget_cumulative_approval_accounts (
        authority_id, owner_id, approval_budget_id, approval_budget_epoch
    )
);

CREATE TABLE budget_event_cumulative_approval (
    event_id TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL,
    authority_id TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    approval_budget_id TEXT NOT NULL,
    approval_budget_epoch INTEGER NOT NULL,
    root_grant_hash TEXT NOT NULL,
    delegation_root_id TEXT,
    root_binding_digest TEXT,
    currency TEXT NOT NULL,
    authority_threshold_units INTEGER NOT NULL,
    effective_threshold_units INTEGER NOT NULL,
    requested_authorized_units INTEGER NOT NULL,
    state_before TEXT,
    state_after TEXT NOT NULL,
    reserved_authorized_before INTEGER NOT NULL,
    captured_authorized_before INTEGER NOT NULL,
    reserved_authorized_after INTEGER NOT NULL,
    captured_authorized_after INTEGER NOT NULL,
    version_before INTEGER NOT NULL,
    version_after INTEGER NOT NULL,
    FOREIGN KEY (event_id) REFERENCES budget_mutation_events(event_id)
);

CREATE TABLE budget_usage_history_anchors (
    capability_id TEXT NOT NULL,
    grant_index INTEGER NOT NULL,
    invocation_count INTEGER NOT NULL CHECK (invocation_count >= 0),
    updated_at INTEGER NOT NULL,
    seq INTEGER NOT NULL CHECK (seq > 0),
    total_cost_exposed INTEGER NOT NULL CHECK (total_cost_exposed >= 0),
    total_cost_realized_spend INTEGER NOT NULL
        CHECK (total_cost_realized_spend >= 0),
    anchored_schema_version INTEGER NOT NULL CHECK (anchored_schema_version = 1),
    PRIMARY KEY (capability_id, grant_index)
);

CREATE TABLE budget_usage_anchor_write_gate (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1)
);

CREATE TABLE budget_snapshot_coverage (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    covered_head INTEGER NOT NULL DEFAULT 0 CHECK (covered_head >= 0)
);

INSERT INTO budget_snapshot_coverage(singleton, covered_head)
VALUES (1, 0);

CREATE TABLE budget_snapshot_anchor_provenance (
    leader_url TEXT PRIMARY KEY CHECK (leader_url <> ''),
    commit_sequence INTEGER NOT NULL CHECK (commit_sequence > 0),
    chain_digest TEXT NOT NULL CHECK (
        length(chain_digest) = 64
        AND chain_digest NOT GLOB '*[^0-9a-f]*'
    ),
    anchor_set_digest TEXT NOT NULL CHECK (
        length(anchor_set_digest) = 64
        AND anchor_set_digest NOT GLOB '*[^0-9a-f]*'
    ),
    election_term INTEGER NOT NULL CHECK (election_term > 0),
    signer_public_key TEXT NOT NULL CHECK (signer_public_key <> ''),
    committed_at INTEGER NOT NULL CHECK (committed_at >= 0)
);

CREATE TRIGGER budget_usage_history_anchor_insert_fenced
BEFORE INSERT ON budget_usage_history_anchors
WHEN NOT EXISTS (
    SELECT 1 FROM budget_usage_anchor_write_gate WHERE singleton = 1
)
BEGIN
    SELECT RAISE(ABORT, 'budget usage history anchor insertion is fenced');
END;

CREATE TRIGGER budget_usage_history_anchor_immutable_update
BEFORE UPDATE ON budget_usage_history_anchors
BEGIN
    SELECT RAISE(ABORT, 'budget usage history anchor is immutable');
END;

CREATE TRIGGER budget_usage_history_anchor_immutable_delete
BEFORE DELETE ON budget_usage_history_anchors
BEGIN
    SELECT RAISE(ABORT, 'budget usage history anchor is immutable');
END;

CREATE TRIGGER budget_cumulative_account_identity_immutable
BEFORE UPDATE OF root_grant_hash, delegation_root_id,
                 root_binding_digest, currency,
                 authority_threshold_units
ON budget_cumulative_approval_accounts
WHEN OLD.root_grant_hash IS NOT NEW.root_grant_hash
  OR OLD.delegation_root_id IS NOT NEW.delegation_root_id
  OR OLD.root_binding_digest IS NOT NEW.root_binding_digest
  OR OLD.currency IS NOT NEW.currency
  OR OLD.authority_threshold_units IS NOT NEW.authority_threshold_units
BEGIN
    SELECT RAISE(ABORT, 'cumulative approval account identity is immutable');
END;

CREATE TRIGGER budget_quota_maximum_immutable
BEFORE UPDATE OF max_invocations ON budget_invocation_quotas
WHEN OLD.max_invocations IS NOT NEW.max_invocations
BEGIN
    SELECT RAISE(ABORT, 'budget quota maximum is immutable');
END;

CREATE TRIGGER budget_quota_bounds_insert
BEFORE INSERT ON budget_invocation_quotas
WHEN NEW.max_invocations <= 0
  OR NEW.reserved_invocations < 0
  OR NEW.captured_invocations < 0
  OR NEW.reserved_invocations > NEW.max_invocations
  OR NEW.captured_invocations > NEW.max_invocations - NEW.reserved_invocations
  OR NEW.owner_id = ''
  OR NOT (
      (NEW.profile = 'chio.grant-invocation.v1' AND NEW.grant_index >= 0)
      OR (NEW.profile IN (
          'chio.aggregate-capability-invocation.v1',
          'chio.aggregate-family-invocation.v1',
          'chio.broker-capability-execution.v1'
      ) AND NEW.grant_index = -1)
  )
BEGIN
    SELECT RAISE(ABORT, 'budget quota is outside durable bounds');
END;

CREATE TRIGGER budget_quota_bounds_update
BEFORE UPDATE ON budget_invocation_quotas
WHEN NEW.max_invocations <= 0
  OR NEW.reserved_invocations < 0
  OR NEW.captured_invocations < 0
  OR NEW.reserved_invocations > NEW.max_invocations
  OR NEW.captured_invocations > NEW.max_invocations - NEW.reserved_invocations
  OR NEW.owner_id = ''
  OR NOT (
      (NEW.profile = 'chio.grant-invocation.v1' AND NEW.grant_index >= 0)
      OR (NEW.profile IN (
          'chio.aggregate-capability-invocation.v1',
          'chio.aggregate-family-invocation.v1',
          'chio.broker-capability-execution.v1'
      ) AND NEW.grant_index = -1)
  )
BEGIN
    SELECT RAISE(ABORT, 'budget quota is outside durable bounds');
END;

CREATE TRIGGER budget_event_quota_bounds_insert
BEFORE INSERT ON budget_event_quota_members
WHEN NEW.max_invocations < 0
  OR (
      NEW.max_invocations = 0
      AND NOT EXISTS (
          SELECT 1 FROM budget_mutation_events
          WHERE event_id = NEW.event_id
            AND authorization_outcome = 'denied'
      )
  )
  OR NEW.reserved_before < 0 OR NEW.captured_before < 0
  OR NEW.reserved_after < 0 OR NEW.captured_after < 0
  OR NEW.reserved_before > NEW.max_invocations
  OR NEW.captured_before > NEW.max_invocations - NEW.reserved_before
  OR NEW.reserved_after > NEW.max_invocations
  OR NEW.captured_after > NEW.max_invocations - NEW.reserved_after
  OR NEW.owner_id = ''
  OR NOT (
      (NEW.profile = 'chio.grant-invocation.v1' AND NEW.grant_index >= 0)
      OR (NEW.profile IN (
          'chio.aggregate-capability-invocation.v1',
          'chio.aggregate-family-invocation.v1',
          'chio.broker-capability-execution.v1'
      ) AND NEW.grant_index = -1)
  )
BEGIN
    SELECT RAISE(ABORT, 'budget event quota is outside durable bounds');
END;

CREATE TRIGGER budget_hold_projection_immutable
BEFORE UPDATE OF projection_kind, operation_id, revocation_set_digest,
                 expected_revocation_count, expected_quota_count,
                 expected_artifact_count,
                 has_cumulative_approval, has_revocation_commit
ON budget_authorization_holds
WHEN OLD.projection_kind = 'composite_v1'
  AND OLD.expected_revocation_count IS NOT NULL AND (
    OLD.projection_kind IS NOT NEW.projection_kind
    OR OLD.operation_id IS NOT NEW.operation_id
    OR OLD.revocation_set_digest IS NOT NEW.revocation_set_digest
    OR OLD.expected_revocation_count IS NOT NEW.expected_revocation_count
    OR OLD.expected_quota_count IS NOT NEW.expected_quota_count
    OR OLD.expected_artifact_count IS NOT NEW.expected_artifact_count
    OR OLD.has_cumulative_approval IS NOT NEW.has_cumulative_approval
    OR OLD.has_revocation_commit IS NOT NEW.has_revocation_commit
)
BEGIN
    SELECT RAISE(ABORT, 'composite hold projection contract is immutable');
END;

CREATE TRIGGER budget_event_projection_immutable
BEFORE UPDATE OF projection_kind, operation_id, revocation_set_digest,
                 expected_revocation_count, expected_quota_count,
                 expected_artifact_count,
                 has_cumulative_approval, has_revocation_commit
ON budget_mutation_events
WHEN OLD.projection_kind = 'composite_v1'
  AND OLD.expected_revocation_count IS NOT NULL AND (
    OLD.projection_kind IS NOT NEW.projection_kind
    OR OLD.operation_id IS NOT NEW.operation_id
    OR OLD.revocation_set_digest IS NOT NEW.revocation_set_digest
    OR OLD.expected_revocation_count IS NOT NEW.expected_revocation_count
    OR OLD.expected_quota_count IS NOT NEW.expected_quota_count
    OR OLD.expected_artifact_count IS NOT NEW.expected_artifact_count
    OR OLD.has_cumulative_approval IS NOT NEW.has_cumulative_approval
    OR OLD.has_revocation_commit IS NOT NEW.has_revocation_commit
)
BEGIN
    SELECT RAISE(ABORT, 'composite event projection contract is immutable');
END;

CREATE TRIGGER budget_hold_capture_time_immutable
BEFORE UPDATE OF trusted_capture_time ON budget_authorization_holds
WHEN OLD.trusted_capture_time IS NOT NULL
  AND OLD.trusted_capture_time IS NOT NEW.trusted_capture_time
BEGIN
    SELECT RAISE(ABORT, 'composite hold capture time is immutable');
END;

CREATE TRIGGER budget_mutation_events_reset_ack_head_watermark
AFTER DELETE ON budget_mutation_events
BEGIN
    UPDATE budget_ack_head_watermark SET head_seq = 0 WHERE singleton = 1;
    DELETE FROM budget_origin_ack_heads;
END;

CREATE INDEX idx_capability_grant_budgets_seq ON capability_grant_budgets(seq);
CREATE UNIQUE INDEX idx_budget_events_operation_authorize
    ON budget_mutation_events(operation_id)
    WHERE operation_id IS NOT NULL
      AND kind IN ('reserve_invocation', 'authorize_exposure')
      AND authorization_outcome IS NOT 'denied';
INSERT INTO budget_replication_meta (singleton, next_seq) VALUES (1, 0);
INSERT INTO budget_ack_head_watermark (singleton, head_seq) VALUES (1, 0);

CREATE INDEX idx_budget_authorization_holds_reserved_until
    ON budget_authorization_holds(disposition, reserved_until);
