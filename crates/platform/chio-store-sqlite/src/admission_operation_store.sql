CREATE TABLE IF NOT EXISTS admission_operations (
    operation_id TEXT NOT NULL PRIMARY KEY
        CHECK (length(operation_id) = 64 AND operation_id NOT GLOB '*[^0-9a-f]*'),
    request_namespace_digest TEXT NOT NULL
        CHECK (length(request_namespace_digest) = 64
               AND request_namespace_digest NOT GLOB '*[^0-9a-f]*'),
    request_id TEXT NOT NULL CHECK (length(request_id) BETWEEN 1 AND 512),
    operation_json BLOB NOT NULL CHECK (length(operation_json) BETWEEN 1 AND 262144),
    state TEXT NOT NULL CHECK (state IN (
        'prepared', 'broker_attempt_registered', 'budget_authorized',
        'approval_reserved', 'ready_to_dispatch', 'capture_pending',
        'dispatch_committed', 'finalizing', 'completed',
        'compensated_before_dispatch', 'not_accepted_after_dispatch_commit',
        'outcome_unknown_after_dispatch', 'mutation_ready', 'mutation_submitted',
        'economic_mutation_applied', 'economic_mutation_not_applied'
    )),
    terminal INTEGER NOT NULL CHECK (terminal IN (0, 1)),
    coordinator_lease_epoch INTEGER NOT NULL CHECK (coordinator_lease_epoch > 0),
    version INTEGER NOT NULL CHECK (version > 0),
    created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms > 0),
    updated_at_unix_ms INTEGER NOT NULL
        CHECK (updated_at_unix_ms >= created_at_unix_ms),
    recovery_claimant_id TEXT,
    recovery_coordinator_lease_id TEXT,
    recovery_coordinator_lease_epoch INTEGER,
    recovery_claimed_version INTEGER,
    recovery_expires_at_unix_ms INTEGER,
    recovery_store_uuid TEXT,
    recovery_store_lease_id TEXT,
    recovery_store_owner_epoch INTEGER,
    CHECK (
        (recovery_claimant_id IS NULL
         AND recovery_coordinator_lease_id IS NULL
         AND recovery_coordinator_lease_epoch IS NULL
         AND recovery_claimed_version IS NULL
         AND recovery_expires_at_unix_ms IS NULL
         AND recovery_store_uuid IS NULL
         AND recovery_store_lease_id IS NULL
         AND recovery_store_owner_epoch IS NULL)
        OR
        (length(recovery_claimant_id) BETWEEN 1 AND 512
         AND length(recovery_coordinator_lease_id) BETWEEN 1 AND 512
         AND recovery_coordinator_lease_epoch > 0
         AND recovery_claimed_version > 0
         AND recovery_expires_at_unix_ms > 0
         AND recovery_store_uuid <> ''
         AND recovery_store_lease_id <> ''
         AND recovery_store_owner_epoch > 0)
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS admission_operations_replay_key
    ON admission_operations(request_namespace_digest, request_id);

CREATE INDEX IF NOT EXISTS admission_operations_recovery
    ON admission_operations(
        terminal, recovery_expires_at_unix_ms, updated_at_unix_ms, operation_id
    );

CREATE TABLE IF NOT EXISTS admission_operation_commit_meta (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    head_sequence INTEGER NOT NULL CHECK (head_sequence >= 0),
    head_chain_digest TEXT NOT NULL CHECK (
        length(head_chain_digest) = 64
        AND head_chain_digest NOT GLOB '*[^0-9a-f]*'
    ),
    trusted_time_high_water_unix_ms INTEGER NOT NULL
        CHECK (trusted_time_high_water_unix_ms >= 0)
);

INSERT INTO admission_operation_commit_meta (
    singleton, head_sequence, head_chain_digest,
    trusted_time_high_water_unix_ms
)
VALUES (
    1, 0,
    '0000000000000000000000000000000000000000000000000000000000000000',
    0
)
ON CONFLICT(singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS admission_operation_commits (
    commit_sequence INTEGER PRIMARY KEY CHECK (commit_sequence > 0),
    operation_id TEXT NOT NULL,
    operation_version INTEGER NOT NULL CHECK (operation_version > 0),
    mutation_kind TEXT NOT NULL CHECK (
        mutation_kind IN ('begin', 'compare_and_swap', 'recovery_claim')
    ),
    operation_digest TEXT NOT NULL
        CHECK (length(operation_digest) = 64
               AND operation_digest NOT GLOB '*[^0-9a-f]*'),
    recovery_claim_digest TEXT CHECK (
        recovery_claim_digest IS NULL
        OR (length(recovery_claim_digest) = 64
            AND recovery_claim_digest NOT GLOB '*[^0-9a-f]*')
    ),
    previous_chain_digest TEXT NOT NULL CHECK (
        length(previous_chain_digest) = 64
        AND previous_chain_digest NOT GLOB '*[^0-9a-f]*'
    ),
    chain_digest TEXT NOT NULL CHECK (
        length(chain_digest) = 64
        AND chain_digest NOT GLOB '*[^0-9a-f]*'
    ),
    store_uuid TEXT NOT NULL CHECK (store_uuid <> ''),
    store_lease_id TEXT NOT NULL CHECK (store_lease_id <> ''),
    store_owner_epoch INTEGER NOT NULL CHECK (store_owner_epoch > 0),
    recorded_at_unix_ms INTEGER NOT NULL CHECK (recorded_at_unix_ms > 0),
    FOREIGN KEY (operation_id) REFERENCES admission_operations(operation_id),
    FOREIGN KEY (store_uuid, store_owner_epoch)
        REFERENCES chio_serving_leases(store_uuid, owner_epoch),
    CHECK ((mutation_kind = 'begin' AND recovery_claim_digest IS NULL)
           OR (mutation_kind <> 'begin' AND recovery_claim_digest IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS admission_operation_commits_operation
    ON admission_operation_commits(operation_id, commit_sequence);

CREATE TRIGGER IF NOT EXISTS admission_operation_commits_exact_lease
BEFORE INSERT ON admission_operation_commits
WHEN NOT EXISTS (
    SELECT 1 FROM chio_serving_leases
    WHERE store_uuid = NEW.store_uuid
      AND owner_epoch = NEW.store_owner_epoch
      AND lease_id = NEW.store_lease_id
      AND end_head_index IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'admission operation commit has no exact serving lease');
END;

CREATE TRIGGER IF NOT EXISTS admission_operation_commits_immutable
BEFORE UPDATE ON admission_operation_commits
BEGIN
    SELECT RAISE(ABORT, 'admission operation commit is immutable');
END;

CREATE TRIGGER IF NOT EXISTS admission_operation_commits_no_delete
BEFORE DELETE ON admission_operation_commits
BEGIN
    SELECT RAISE(ABORT, 'admission operation commit is immutable');
END;

CREATE TRIGGER IF NOT EXISTS admission_operations_immutable_identity
BEFORE UPDATE OF operation_id, request_namespace_digest, request_id, created_at_unix_ms
ON admission_operations
BEGIN
    SELECT RAISE(ABORT, 'admission operation identity is immutable');
END;

CREATE TRIGGER IF NOT EXISTS admission_operations_versioned_body
BEFORE UPDATE ON admission_operations
WHEN (NEW.operation_json <> OLD.operation_json
      OR NEW.state <> OLD.state
      OR NEW.terminal <> OLD.terminal
      OR NEW.coordinator_lease_epoch <> OLD.coordinator_lease_epoch)
     AND NEW.version <> OLD.version + 1
BEGIN
    SELECT RAISE(ABORT, 'admission operation body requires one version increment');
END;

CREATE TRIGGER IF NOT EXISTS admission_operations_terminal_immutable
BEFORE UPDATE ON admission_operations
WHEN OLD.terminal = 1
     AND (NEW.operation_json <> OLD.operation_json
          OR NEW.state <> OLD.state
          OR NEW.terminal <> OLD.terminal
          OR NEW.coordinator_lease_epoch <> OLD.coordinator_lease_epoch
          OR NEW.version <> OLD.version)
BEGIN
    SELECT RAISE(ABORT, 'terminal admission operation is immutable');
END;

CREATE TRIGGER IF NOT EXISTS admission_operations_no_delete
BEFORE DELETE ON admission_operations
BEGIN
    SELECT RAISE(ABORT, 'admission operation must be retained');
END;

CREATE TRIGGER IF NOT EXISTS admission_operations_terminal_no_claim
BEFORE UPDATE ON admission_operations
WHEN OLD.terminal = 1
     AND (NEW.recovery_claimant_id IS NOT OLD.recovery_claimant_id
          OR NEW.recovery_coordinator_lease_id IS NOT OLD.recovery_coordinator_lease_id
          OR NEW.recovery_coordinator_lease_epoch IS NOT OLD.recovery_coordinator_lease_epoch
          OR NEW.recovery_claimed_version IS NOT OLD.recovery_claimed_version
          OR NEW.recovery_expires_at_unix_ms IS NOT OLD.recovery_expires_at_unix_ms
          OR NEW.recovery_store_uuid IS NOT OLD.recovery_store_uuid
          OR NEW.recovery_store_lease_id IS NOT OLD.recovery_store_lease_id
          OR NEW.recovery_store_owner_epoch IS NOT OLD.recovery_store_owner_epoch)
BEGIN
    SELECT RAISE(ABORT, 'terminal admission operation cannot be recovery-claimed');
END;

CREATE TABLE IF NOT EXISTS admission_operation_terminal_projections (
    operation_id TEXT NOT NULL PRIMARY KEY,
    source_operation_version INTEGER NOT NULL CHECK (source_operation_version > 0),
    terminal_operation_version INTEGER NOT NULL CHECK (
        terminal_operation_version = source_operation_version + 1
    ),
    terminal_state TEXT NOT NULL CHECK (terminal_state IN (
        'completed', 'compensated_before_dispatch',
        'not_accepted_after_dispatch_commit', 'outcome_unknown_after_dispatch',
        'economic_mutation_applied', 'economic_mutation_not_applied'
    )),
    projection_body_digest TEXT NOT NULL CHECK (
        length(projection_body_digest) = 64
        AND projection_body_digest NOT GLOB '*[^0-9a-f]*'
    ),
    projection_digest TEXT NOT NULL CHECK (
        length(projection_digest) = 64
        AND projection_digest NOT GLOB '*[^0-9a-f]*'
    ),
    projection_json BLOB NOT NULL CHECK (
        length(projection_json) BETWEEN 1 AND 4194304
    ),
    manifest_json BLOB NOT NULL CHECK (
        length(manifest_json) BETWEEN 1 AND 262144
    ),
    record_count INTEGER NOT NULL CHECK (record_count BETWEEN 1 AND 32),
    committed_at_unix_ms INTEGER NOT NULL CHECK (committed_at_unix_ms > 0),
    store_uuid TEXT NOT NULL CHECK (store_uuid <> ''),
    store_lease_id TEXT NOT NULL CHECK (store_lease_id <> ''),
    store_owner_epoch INTEGER NOT NULL CHECK (store_owner_epoch > 0),
    FOREIGN KEY (operation_id) REFERENCES admission_operations(operation_id),
    FOREIGN KEY (store_uuid, store_owner_epoch)
        REFERENCES chio_serving_leases(store_uuid, owner_epoch)
);

CREATE TRIGGER IF NOT EXISTS admission_operation_terminal_projections_exact_lease
BEFORE INSERT ON admission_operation_terminal_projections
WHEN NOT EXISTS (
    SELECT 1 FROM chio_serving_leases
    WHERE store_uuid = NEW.store_uuid
      AND owner_epoch = NEW.store_owner_epoch
      AND lease_id = NEW.store_lease_id
      AND end_head_index IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'admission terminal projection has no exact serving lease');
END;

CREATE TRIGGER IF NOT EXISTS admission_operation_terminal_projections_immutable
BEFORE UPDATE ON admission_operation_terminal_projections
BEGIN
    SELECT RAISE(ABORT, 'admission terminal projection is immutable');
END;

CREATE TRIGGER IF NOT EXISTS admission_operation_terminal_projections_no_delete
BEFORE DELETE ON admission_operation_terminal_projections
BEGIN
    SELECT RAISE(ABORT, 'admission terminal projection is immutable');
END;

CREATE TABLE IF NOT EXISTS admission_operation_terminal_records (
    operation_id TEXT NOT NULL,
    record_kind TEXT NOT NULL CHECK (record_kind IN (
        'receipt', 'incident', 'tool_outcome', 'payment_terminal',
        'authorization_consumption', 'outcome_eligibility',
        'observation_attempt_zero', 'obligation', 'release_proof',
        'economic_mutation_result', 'mutation_audit'
    )),
    record_id TEXT NOT NULL CHECK (length(record_id) BETWEEN 1 AND 512),
    record_digest TEXT NOT NULL CHECK (
        length(record_digest) = 64
        AND record_digest NOT GLOB '*[^0-9a-f]*'
    ),
    record_json BLOB NOT NULL CHECK (length(record_json) BETWEEN 1 AND 1048576),
    PRIMARY KEY (operation_id, record_kind, record_id),
    UNIQUE (record_kind, record_id),
    FOREIGN KEY (operation_id)
        REFERENCES admission_operation_terminal_projections(operation_id)
);

CREATE INDEX IF NOT EXISTS admission_operation_terminal_records_kind
    ON admission_operation_terminal_records(record_kind, operation_id);

CREATE TRIGGER IF NOT EXISTS admission_operation_terminal_records_immutable
BEFORE UPDATE ON admission_operation_terminal_records
BEGIN
    SELECT RAISE(ABORT, 'admission terminal record is immutable');
END;

CREATE TRIGGER IF NOT EXISTS admission_operation_terminal_records_no_delete
BEFORE DELETE ON admission_operation_terminal_records
BEGIN
    SELECT RAISE(ABORT, 'admission terminal record is immutable');
END;

CREATE TABLE IF NOT EXISTS admission_operation_authorization_consumptions (
    operation_id TEXT NOT NULL PRIMARY KEY,
    authorization_receipt_id TEXT NOT NULL UNIQUE
        CHECK (length(authorization_receipt_id) BETWEEN 1 AND 512),
    consumer_receipt_id TEXT NOT NULL
        CHECK (length(consumer_receipt_id) BETWEEN 1 AND 512),
    request_id TEXT NOT NULL CHECK (length(request_id) BETWEEN 1 AND 512),
    session_id TEXT NOT NULL CHECK (length(session_id) BETWEEN 1 AND 512),
    tool_call_id TEXT NOT NULL CHECK (length(tool_call_id) BETWEEN 1 AND 512),
    tenant_id TEXT CHECK (tenant_id IS NULL OR length(tenant_id) BETWEEN 1 AND 512),
    parameter_hash TEXT NOT NULL CHECK (
        length(parameter_hash) = 64
        AND parameter_hash NOT GLOB '*[^0-9a-f]*'
    ),
    consumed_at_unix_ms INTEGER NOT NULL CHECK (consumed_at_unix_ms > 0),
    record_digest TEXT NOT NULL CHECK (
        length(record_digest) = 64
        AND record_digest NOT GLOB '*[^0-9a-f]*'
    ),
    record_json BLOB NOT NULL CHECK (length(record_json) BETWEEN 1 AND 1048576),
    FOREIGN KEY (operation_id)
        REFERENCES admission_operation_terminal_projections(operation_id)
);

CREATE INDEX IF NOT EXISTS admission_operation_authorization_consumer
    ON admission_operation_authorization_consumptions(consumer_receipt_id);

CREATE TRIGGER IF NOT EXISTS admission_operation_authorization_consumptions_immutable
BEFORE UPDATE ON admission_operation_authorization_consumptions
BEGIN
    SELECT RAISE(ABORT, 'admission authorization consumption is immutable');
END;

CREATE TRIGGER IF NOT EXISTS admission_operation_authorization_consumptions_no_delete
BEFORE DELETE ON admission_operation_authorization_consumptions
BEGIN
    SELECT RAISE(ABORT, 'admission authorization consumption is immutable');
END;

CREATE TABLE IF NOT EXISTS admission_operation_observer_attempts (
    operation_id TEXT NOT NULL PRIMARY KEY,
    receipt_id TEXT NOT NULL UNIQUE CHECK (length(receipt_id) BETWEEN 1 AND 512),
    work_state TEXT NOT NULL CHECK (work_state IN (
        'pending', 'claimed', 'completed', 'failed'
    )),
    attempts INTEGER NOT NULL CHECK (attempts >= 0),
    next_visible_at_unix_ms INTEGER NOT NULL CHECK (next_visible_at_unix_ms > 0),
    row_version INTEGER NOT NULL CHECK (row_version >= 0),
    last_error TEXT CHECK (last_error IS NULL OR length(last_error) BETWEEN 1 AND 2048),
    record_digest TEXT NOT NULL CHECK (
        length(record_digest) = 64
        AND record_digest NOT GLOB '*[^0-9a-f]*'
    ),
    record_json BLOB NOT NULL CHECK (length(record_json) BETWEEN 1 AND 1048576),
    created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms > 0),
    updated_at_unix_ms INTEGER NOT NULL CHECK (
        updated_at_unix_ms >= created_at_unix_ms
    ),
    store_uuid TEXT NOT NULL CHECK (store_uuid <> ''),
    store_lease_id TEXT NOT NULL CHECK (store_lease_id <> ''),
    store_owner_epoch INTEGER NOT NULL CHECK (store_owner_epoch > 0),
    FOREIGN KEY (operation_id)
        REFERENCES admission_operation_terminal_projections(operation_id),
    FOREIGN KEY (store_uuid, store_owner_epoch)
        REFERENCES chio_serving_leases(store_uuid, owner_epoch)
);

CREATE INDEX IF NOT EXISTS admission_operation_observer_attempts_ready
    ON admission_operation_observer_attempts(
        work_state, next_visible_at_unix_ms, operation_id
    );

CREATE TRIGGER IF NOT EXISTS admission_operation_observer_attempts_exact_lease_insert
BEFORE INSERT ON admission_operation_observer_attempts
WHEN NOT EXISTS (
    SELECT 1 FROM chio_serving_leases
    WHERE store_uuid = NEW.store_uuid
      AND owner_epoch = NEW.store_owner_epoch
      AND lease_id = NEW.store_lease_id
      AND end_head_index IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'admission observer attempt has no exact serving lease');
END;

CREATE TRIGGER IF NOT EXISTS admission_operation_observer_attempts_exact_lease_update
BEFORE UPDATE ON admission_operation_observer_attempts
WHEN NOT EXISTS (
    SELECT 1 FROM chio_serving_leases
    WHERE store_uuid = NEW.store_uuid
      AND owner_epoch = NEW.store_owner_epoch
      AND lease_id = NEW.store_lease_id
      AND end_head_index IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'admission observer attempt has no exact serving lease');
END;

CREATE TRIGGER IF NOT EXISTS admission_operation_observer_attempts_immutable_evidence
BEFORE UPDATE OF operation_id, receipt_id, record_digest, record_json, created_at_unix_ms
ON admission_operation_observer_attempts
BEGIN
    SELECT RAISE(ABORT, 'admission observer evidence is immutable');
END;

CREATE TRIGGER IF NOT EXISTS admission_operation_observer_attempts_versioned
BEFORE UPDATE ON admission_operation_observer_attempts
WHEN NEW.row_version <> OLD.row_version + 1
BEGIN
    SELECT RAISE(ABORT, 'admission observer attempt requires one version increment');
END;

CREATE TRIGGER IF NOT EXISTS admission_operation_observer_attempts_no_delete
BEFORE DELETE ON admission_operation_observer_attempts
BEGIN
    SELECT RAISE(ABORT, 'admission observer attempt must be retained');
END;
