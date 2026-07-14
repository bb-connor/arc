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
