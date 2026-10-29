CREATE TABLE runtime_admission_bundles (
    admission_id TEXT PRIMARY KEY NOT NULL,
    bundle_sha256 TEXT NOT NULL,
    raw_json TEXT NOT NULL,
    created_at_unix_ms INTEGER NOT NULL
);
CREATE TABLE runtime_trust_floors (
    verifier_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    highest_version INTEGER NOT NULL,
    latest_bundle_sha256 TEXT NOT NULL,
    latest_revocation_checkpoint_sha256 TEXT NOT NULL,
    PRIMARY KEY (verifier_id, key_id)
);
CREATE TABLE runtime_runs (
    run_id TEXT PRIMARY KEY NOT NULL,
    status TEXT NOT NULL,
    started_at_unix_ms INTEGER NOT NULL,
    updated_at_unix_ms INTEGER NOT NULL,
    failure_code TEXT,
    workflow_report_sha256 TEXT,
    proof_regeneration_report_sha256 TEXT
);
CREATE TABLE runtime_step_states (
    run_id TEXT NOT NULL,
    step_index INTEGER NOT NULL,
    admission_id TEXT NOT NULL,
    state TEXT NOT NULL,
    destructive INTEGER NOT NULL,
    tool_receipt_sha256 TEXT,
    lease_id TEXT,
    PRIMARY KEY (run_id, step_index)
);
CREATE TABLE runtime_evidence_artifacts (
    run_id TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    role TEXT NOT NULL,
    relative_path TEXT NOT NULL,
    byte_count INTEGER NOT NULL,
    recorded_at_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (run_id, artifact_sha256)
);
CREATE TABLE runtime_treaty_artifacts (
    evidence_kind TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    raw_json TEXT NOT NULL,
    created_at_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (evidence_kind, evidence_id)
);
CREATE TABLE runtime_run_leases (
    run_id TEXT PRIMARY KEY NOT NULL,
    lease_id TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    acquired_at_unix_ms INTEGER NOT NULL,
    expires_at_unix_ms INTEGER NOT NULL,
    heartbeat_at_unix_ms INTEGER NOT NULL,
    fencing_token INTEGER NOT NULL,
    state TEXT NOT NULL,
    reason_code TEXT
);
CREATE TABLE runtime_scheduler_ticks (
    tick_id TEXT PRIMARY KEY NOT NULL,
    owner_id TEXT NOT NULL,
    generated_at_unix_ms INTEGER NOT NULL,
    claimed_count INTEGER NOT NULL,
    blocked_count INTEGER NOT NULL
);
CREATE TABLE runtime_recovery_drills (
    run_id TEXT NOT NULL,
    generated_at_unix_ms INTEGER NOT NULL,
    accepted INTEGER NOT NULL,
    failure_code TEXT,
    PRIMARY KEY (run_id, generated_at_unix_ms)
);
CREATE TABLE runtime_provider_health (
    provider_id TEXT PRIMARY KEY NOT NULL,
    generated_at_unix_ms INTEGER NOT NULL,
    healthy INTEGER NOT NULL,
    failure_code TEXT
);
CREATE TABLE runtime_evidence_sink_health (
    run_id TEXT PRIMARY KEY NOT NULL,
    generated_at_unix_ms INTEGER NOT NULL,
    healthy INTEGER NOT NULL,
    failure_code TEXT
);
CREATE TABLE runtime_source_qualification (
    singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
    canonical_bytes BLOB NOT NULL CHECK (
        typeof(canonical_bytes) = 'blob' AND length(canonical_bytes) BETWEEN 1 AND 4096
    )
);
CREATE TRIGGER runtime_source_qualification_no_replace
BEFORE INSERT ON runtime_source_qualification
WHEN EXISTS (SELECT 1 FROM runtime_source_qualification)
BEGIN SELECT RAISE(ABORT, 'runtime source qualification is immutable'); END;
CREATE TRIGGER runtime_source_qualification_no_update
BEFORE UPDATE ON runtime_source_qualification
BEGIN SELECT RAISE(ABORT, 'runtime source qualification is immutable'); END;
CREATE TRIGGER runtime_source_qualification_no_delete
BEFORE DELETE ON runtime_source_qualification
BEGIN SELECT RAISE(ABORT, 'runtime source qualification is immutable'); END;

CREATE TABLE runtime_treaty_epoch_pins (
    authority_id TEXT PRIMARY KEY NOT NULL,
    canonical_bytes BLOB NOT NULL CHECK (typeof(canonical_bytes) = 'blob' AND length(canonical_bytes) BETWEEN 1 AND 1048576)
);
CREATE TABLE runtime_treaty_epoch_records (
    authority_id TEXT NOT NULL,
    record_digest TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (typeof(sequence) = 'integer' AND sequence BETWEEN 1 AND 9007199254740991),
    canonical_bytes BLOB NOT NULL CHECK (typeof(canonical_bytes) = 'blob' AND length(canonical_bytes) BETWEEN 1 AND 1048576),
    PRIMARY KEY (authority_id, record_digest),
    UNIQUE (authority_id, sequence)
);
CREATE TABLE runtime_treaty_epoch_heads (
    authority_id TEXT PRIMARY KEY NOT NULL,
    record_digest TEXT NOT NULL
);
CREATE TABLE runtime_treaty_authorizations (
    claim_id TEXT PRIMARY KEY NOT NULL,
    canonical_bytes BLOB NOT NULL CHECK (typeof(canonical_bytes) = 'blob' AND length(canonical_bytes) BETWEEN 1 AND 1048576)
);
CREATE TRIGGER runtime_treaty_epoch_pins_no_update BEFORE UPDATE ON runtime_treaty_epoch_pins
BEGIN SELECT RAISE(ABORT, 'treaty epoch authority pin is immutable'); END;
CREATE TRIGGER runtime_treaty_epoch_pins_no_delete BEFORE DELETE ON runtime_treaty_epoch_pins
BEGIN SELECT RAISE(ABORT, 'treaty epoch authority pin is immutable'); END;
CREATE TRIGGER runtime_treaty_epoch_records_no_update BEFORE UPDATE ON runtime_treaty_epoch_records
BEGIN SELECT RAISE(ABORT, 'treaty epoch history is immutable'); END;
CREATE TRIGGER runtime_treaty_epoch_records_no_delete BEFORE DELETE ON runtime_treaty_epoch_records
BEGIN SELECT RAISE(ABORT, 'treaty epoch history is immutable'); END;
CREATE TRIGGER runtime_treaty_authorizations_no_update BEFORE UPDATE ON runtime_treaty_authorizations
BEGIN SELECT RAISE(ABORT, 'treaty authorization is immutable'); END;
CREATE TRIGGER runtime_treaty_authorizations_no_delete BEFORE DELETE ON runtime_treaty_authorizations
BEGIN SELECT RAISE(ABORT, 'treaty authorization is immutable'); END;
CREATE TRIGGER runtime_treaty_epoch_pins_no_replace BEFORE INSERT ON runtime_treaty_epoch_pins
WHEN EXISTS (SELECT 1 FROM runtime_treaty_epoch_pins WHERE authority_id = NEW.authority_id)
BEGIN SELECT RAISE(ABORT, 'treaty epoch authority pin is immutable'); END;
CREATE TRIGGER runtime_treaty_epoch_records_no_replace BEFORE INSERT ON runtime_treaty_epoch_records
WHEN EXISTS (SELECT 1 FROM runtime_treaty_epoch_records WHERE authority_id = NEW.authority_id AND (record_digest = NEW.record_digest OR sequence = NEW.sequence))
BEGIN SELECT RAISE(ABORT, 'treaty epoch history is immutable'); END;
CREATE TRIGGER runtime_treaty_authorizations_no_replace BEFORE INSERT ON runtime_treaty_authorizations
WHEN EXISTS (SELECT 1 FROM runtime_treaty_authorizations WHERE claim_id = NEW.claim_id)
BEGIN SELECT RAISE(ABORT, 'treaty authorization is immutable'); END;
