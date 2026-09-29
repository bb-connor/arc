use super::PortResult;
use super::Connection;
# [cfg (target_os = "macos")]
use super::security_state_lifecycle_lock_path;
use super::sqlite_error;
use super::schema_version_error;
use super::ensure_attested_finding_batch_tenant_keys;
use super::validate_correlation_durable_schema;
use super::upgrade_correlation_ingress_pending_index;
use super::prepare_declassification_schema_migration;
use super::ensure_lineage_fence_binding_columns;
use super::ensure_response_effect_generation_column;
use super::ensure_scheduler_lease_body_hash_column;
use super::ensure_scheduler_retry_health_columns;
use super::ensure_response_dispatch_commit_mode_column;
use super::ensure_attested_finding_response_outbox_schema;


const SECURITY_STATE_STORE_SCHEMA_KEY: &str = "security_state";
pub(super) const SECURITY_STATE_STORE_SUPPORTED_SCHEMA_VERSION: i32 = 0;
const SECURITY_STATE_STORE_LEGACY_ANCHOR_TABLES: &[&str] = &[
    "security_transitions",
    "security_flow_contexts",
    "security_response_effects",
    "security_scheduler_retries",
    "chio_tool_receipts",
];

// tenant-read-contract: security_advisory_events; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_attested_finding_batch_items; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_attested_finding_batches; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_capability_set_suspension_commands; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_capability_set_suspension_effects; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_capability_set_suspension_members; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_capability_set_suspension_state; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_containment_overlay_commands; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_correlation_events; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_correlation_ingress; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_correlation_outcomes; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_correlation_partials; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_correlation_partition_heads; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_declassification_evidence_identity; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_declassification_receipt_outbox; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_declassification_tombstones; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_declassification_uses; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_effect_contributions; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_egress_fences; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_egress_restriction_commands; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_egress_restriction_destinations; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_egress_restriction_effects; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_egress_restriction_state; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_event_ids; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_flow_contexts; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_flow_sequences; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_isolation_epochs; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_issuance_freeze_commands; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_issuance_freeze_effects; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_issuance_freeze_state; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_lineage_fences; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_lineage_flow_state; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_overlay_state; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_principal_flow_state; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_response_dispatch_fences; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_response_dispatch_recoveries; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_response_dispatches; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_response_effects; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_response_plans; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_response_receipt_cursors; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_scheduler_claims; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_scheduler_fence_sequences; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_scheduler_leases; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_scheduler_retries; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_session_flow_state; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_session_memberships; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_session_throttle_commands; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_session_throttle_effects; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_session_throttle_invocations; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_session_throttle_state; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_session_throttle_windows; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_transitions; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_verified_events; class=tenant-predicate; principal=security-runtime
// Contracts: docs/security/trust-boundary-inventory.json
pub(super) fn migrate(connection: &Connection) -> PortResult<()> {
    connection
        .execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;
            PRAGMA foreign_keys = ON;
            BEGIN IMMEDIATE;
            "#,
        )
        .map_err(sqlite_error)?;
    let migration = (|| {
        crate::check_schema_version(
            connection,
            SECURITY_STATE_STORE_SCHEMA_KEY,
            SECURITY_STATE_STORE_SUPPORTED_SCHEMA_VERSION,
            SECURITY_STATE_STORE_LEGACY_ANCHOR_TABLES,
        )
        .map_err(schema_version_error)?;
        prepare_declassification_schema_migration(connection)?;
        connection
            .execute_batch(
                r#"

            CREATE TABLE IF NOT EXISTS security_isolation_epochs (
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
                PRIMARY KEY (tenant_id, principal_id, lineage_id, isolation_epoch_id),
                UNIQUE (tenant_id, transition_id)
            );

            CREATE TABLE IF NOT EXISTS security_principal_flow_state (
                tenant_id TEXT NOT NULL,
                principal_id TEXT NOT NULL,
                isolation_epoch_id TEXT NOT NULL,
                label_json BLOB NOT NULL CHECK (length(label_json) <= 1048576),
                label_hash BLOB NOT NULL CHECK (length(label_hash) = 32),
                generation INTEGER NOT NULL,
                PRIMARY KEY (tenant_id, principal_id, isolation_epoch_id)
            );

            CREATE TABLE IF NOT EXISTS security_lineage_flow_state (
                tenant_id TEXT NOT NULL,
                lineage_id TEXT NOT NULL,
                label_json BLOB NOT NULL CHECK (length(label_json) <= 1048576),
                label_hash BLOB NOT NULL CHECK (length(label_hash) = 32),
                generation INTEGER NOT NULL,
                PRIMARY KEY (tenant_id, lineage_id)
            );

            CREATE TABLE IF NOT EXISTS security_session_flow_state (
                tenant_id TEXT NOT NULL,
                principal_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                isolation_epoch_id TEXT NOT NULL,
                label_json BLOB NOT NULL CHECK (length(label_json) <= 1048576),
                label_hash BLOB NOT NULL CHECK (length(label_hash) = 32),
                generation INTEGER NOT NULL,
                PRIMARY KEY (tenant_id, principal_id, session_id, isolation_epoch_id)
            );

            CREATE TABLE IF NOT EXISTS security_session_memberships (
                tenant_id TEXT NOT NULL,
                principal_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                isolation_epoch_id TEXT NOT NULL,
                PRIMARY KEY (tenant_id, principal_id, session_id, isolation_epoch_id)
            );

            CREATE TABLE IF NOT EXISTS security_flow_contexts (
                tenant_id TEXT NOT NULL,
                principal_id TEXT NOT NULL,
                lineage_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                isolation_epoch_id TEXT NOT NULL,
                generation INTEGER NOT NULL,
                PRIMARY KEY (
                    tenant_id, principal_id, lineage_id, session_id, isolation_epoch_id
                )
            );

            CREATE TABLE IF NOT EXISTS security_flow_sequences (
                tenant_id TEXT NOT NULL,
                last_generation INTEGER NOT NULL,
                PRIMARY KEY (tenant_id)
            );

            CREATE TABLE IF NOT EXISTS security_egress_fences (
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
                PRIMARY KEY (tenant_id, fence_id),
                UNIQUE (tenant_id, request_id)
            );

            CREATE TABLE IF NOT EXISTS security_declassification_lifecycle (
                singleton INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
                schema_version INTEGER NOT NULL CHECK (schema_version = 2),
                readiness_cursor TEXT NOT NULL,
                reconciliation_active INTEGER NOT NULL DEFAULT 0
                    CHECK (reconciliation_active IN (0, 1)),
                live_dispatch_sealed INTEGER NOT NULL DEFAULT 0
                    CHECK (live_dispatch_sealed IN (0, 1)),
                compaction_active INTEGER NOT NULL DEFAULT 0
                    CHECK (compaction_active IN (0, 1)),
                CHECK (reconciliation_active = 0 OR live_dispatch_sealed = 0)
            );

            INSERT OR IGNORE INTO security_declassification_lifecycle (
                singleton, schema_version, readiness_cursor
            ) VALUES (1, 2, 'declassification-evidence-schema-v2');

            CREATE TABLE IF NOT EXISTS security_declassification_uses (
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
                PRIMARY KEY (tenant_id, grant_id)
            );

            CREATE TABLE IF NOT EXISTS security_declassification_evidence_identity (
                evidence_id TEXT NOT NULL,
                transition_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                grant_id TEXT NOT NULL,
                phase TEXT NOT NULL CHECK (phase IN ('consumption', 'outcome')),
                body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
                PRIMARY KEY (tenant_id, evidence_id),
                UNIQUE (tenant_id, transition_id)
            );

            CREATE TABLE IF NOT EXISTS security_declassification_receipt_outbox (
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
                PRIMARY KEY (tenant_id, grant_id, phase_ordinal),
                FOREIGN KEY (tenant_id, evidence_id)
                    REFERENCES security_declassification_evidence_identity (
                        tenant_id, evidence_id
                    ),
                FOREIGN KEY (tenant_id, grant_id)
                    REFERENCES security_declassification_uses (tenant_id, grant_id)
            );

            CREATE TABLE IF NOT EXISTS security_declassification_tombstones (
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
                PRIMARY KEY (tenant_id, grant_id),
                FOREIGN KEY (tenant_id, consumption_evidence_id)
                    REFERENCES security_declassification_evidence_identity (
                        tenant_id, evidence_id
                    ),
                FOREIGN KEY (tenant_id, outcome_evidence_id)
                    REFERENCES security_declassification_evidence_identity (
                        tenant_id, evidence_id
                    )
            );

            CREATE INDEX IF NOT EXISTS security_declassification_receipt_pending
                ON security_declassification_receipt_outbox (
                    acknowledged, next_attempt_at, tenant_id, grant_id, phase_ordinal
                );

            CREATE TRIGGER IF NOT EXISTS security_declassification_tombstone_replay_rejected
            BEFORE INSERT ON security_declassification_uses
            WHEN EXISTS (
                SELECT 1
                FROM security_declassification_tombstones AS tombstone
                WHERE tombstone.tenant_id = NEW.tenant_id
                  AND tombstone.grant_id = NEW.grant_id
            )
            BEGIN
                SELECT RAISE(ABORT, 'declassification tombstone replay is rejected');
            END;

            CREATE TRIGGER IF NOT EXISTS security_declassification_use_immutable
            BEFORE UPDATE ON security_declassification_uses
            WHEN NEW.tenant_id != OLD.tenant_id
              OR NEW.grant_id != OLD.grant_id
              OR NEW.request_hash != OLD.request_hash
              OR NEW.consumed_at != OLD.consumed_at
              OR NEW.grant_expires_at != OLD.grant_expires_at
              OR NEW.retain_until != OLD.retain_until
              OR NEW.consumption_binding != OLD.consumption_binding
              OR OLD.state != 'consumed_pending_dispatch'
              OR NEW.state NOT IN ('released', 'dispatch_failed', 'outcome_unknown')
              OR OLD.transition_id IS NOT NULL
              OR NEW.transition_id IS NULL
              OR OLD.outcome_binding IS NOT NULL
              OR NEW.outcome_binding IS NULL
            BEGIN
                SELECT RAISE(ABORT, 'declassification use mapping is immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS security_declassification_use_delete_rejected
            BEFORE DELETE ON security_declassification_uses
            WHEN (SELECT compaction_active FROM security_declassification_lifecycle
                  WHERE singleton = 1) != 1
            BEGIN
                SELECT RAISE(ABORT, 'declassification use deletion is rejected');
            END;

            CREATE TRIGGER IF NOT EXISTS security_declassification_outcome_predecessor_insert
            BEFORE INSERT ON security_declassification_receipt_outbox
            WHEN NEW.phase = 'outcome' AND NOT EXISTS (
                SELECT 1
                FROM security_declassification_receipt_outbox AS predecessor
                WHERE predecessor.tenant_id = NEW.tenant_id
                  AND predecessor.grant_id = NEW.grant_id
                  AND predecessor.phase = 'consumption'
                  AND predecessor.phase_ordinal = 0
                  AND predecessor.evidence_id = NEW.predecessor_evidence_id
            )
            BEGIN
                SELECT RAISE(ABORT, 'declassification outcome predecessor is missing');
            END;

            CREATE TRIGGER IF NOT EXISTS security_declassification_evidence_use_binding_insert
            BEFORE INSERT ON security_declassification_receipt_outbox
            WHEN NOT EXISTS (
                SELECT 1
                FROM security_declassification_uses AS use_record
                WHERE use_record.tenant_id = NEW.tenant_id
                  AND use_record.grant_id = NEW.grant_id
                  AND use_record.request_hash = NEW.request_hash
                  AND use_record.state = NEW.state
            )
            BEGIN
                SELECT RAISE(ABORT, 'declassification evidence use binding is invalid');
            END;

            CREATE TRIGGER IF NOT EXISTS security_declassification_outcome_ack_order
            BEFORE UPDATE OF acknowledged ON security_declassification_receipt_outbox
            WHEN NEW.phase = 'outcome' AND NEW.acknowledged = 1 AND NOT EXISTS (
                SELECT 1
                FROM security_declassification_receipt_outbox AS predecessor
                WHERE predecessor.tenant_id = NEW.tenant_id
                  AND predecessor.grant_id = NEW.grant_id
                  AND predecessor.phase = 'consumption'
                  AND predecessor.phase_ordinal = 0
                  AND predecessor.evidence_id = NEW.predecessor_evidence_id
                  AND predecessor.acknowledged = 1
            )
            BEGIN
                SELECT RAISE(ABORT, 'declassification outcome predecessor is not acknowledged');
            END;

            CREATE TRIGGER IF NOT EXISTS security_declassification_evidence_immutable
            BEFORE UPDATE ON security_declassification_receipt_outbox
            WHEN NEW.tenant_id != OLD.tenant_id
              OR NEW.grant_id != OLD.grant_id
              OR NEW.phase != OLD.phase
              OR NEW.phase_ordinal != OLD.phase_ordinal
              OR NEW.request_hash != OLD.request_hash
              OR NEW.state != OLD.state
              OR NEW.transition_binding != OLD.transition_binding
              OR NEW.evidence_type != OLD.evidence_type
              OR NEW.evidence_id != OLD.evidence_id
              OR NEW.canonical_body != OLD.canonical_body
              OR NEW.body_hash != OLD.body_hash
              OR NEW.transition_id != OLD.transition_id
              OR NEW.occurred_at != OLD.occurred_at
              OR NEW.predecessor_evidence_id IS NOT OLD.predecessor_evidence_id
              OR (OLD.acknowledged_at IS NOT NULL AND NEW.acknowledged_at != OLD.acknowledged_at)
              OR (OLD.durable_sink_record_hash IS NOT NULL
                  AND NEW.durable_sink_record_hash != OLD.durable_sink_record_hash)
              OR NEW.attempts < OLD.attempts
              OR NEW.next_attempt_at < OLD.next_attempt_at
              OR NEW.acknowledged < OLD.acknowledged
            BEGIN
                SELECT RAISE(ABORT, 'declassification evidence mapping is immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS security_declassification_evidence_delete_rejected
            BEFORE DELETE ON security_declassification_receipt_outbox
            WHEN (SELECT compaction_active FROM security_declassification_lifecycle
                  WHERE singleton = 1) != 1
            BEGIN
                SELECT RAISE(ABORT, 'declassification evidence deletion is rejected');
            END;

            CREATE TRIGGER IF NOT EXISTS security_declassification_identity_immutable
            BEFORE UPDATE ON security_declassification_evidence_identity
            BEGIN
                SELECT RAISE(ABORT, 'declassification evidence identity is immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS security_declassification_identity_delete_rejected
            BEFORE DELETE ON security_declassification_evidence_identity
            BEGIN
                SELECT RAISE(ABORT, 'declassification evidence identity deletion is rejected');
            END;

            CREATE TRIGGER IF NOT EXISTS security_declassification_tombstone_immutable
            BEFORE UPDATE ON security_declassification_tombstones
            BEGIN
                SELECT RAISE(ABORT, 'declassification tombstone is immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS security_declassification_tombstone_delete_rejected
            BEFORE DELETE ON security_declassification_tombstones
            BEGIN
                SELECT RAISE(ABORT, 'declassification tombstone deletion is rejected');
            END;

            CREATE TABLE IF NOT EXISTS security_event_ids (
                event_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                event_class TEXT NOT NULL,
                body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
                PRIMARY KEY (tenant_id, event_id)
            );

            CREATE TABLE IF NOT EXISTS security_verified_events (
                tenant_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                producer_id TEXT NOT NULL,
                trust_class TEXT NOT NULL,
                event_time INTEGER NOT NULL,
                received_at INTEGER NOT NULL,
                body BLOB NOT NULL CHECK (length(body) <= 1048576),
                body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
                evidence_hash BLOB NOT NULL CHECK (length(evidence_hash) = 32),
                PRIMARY KEY (tenant_id, event_id)
            );

            CREATE INDEX IF NOT EXISTS security_verified_event_partition
                ON security_verified_events (tenant_id, event_time, event_id);

            CREATE TABLE IF NOT EXISTS security_correlation_ingress (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                producer_id TEXT NOT NULL,
                event_time INTEGER NOT NULL,
                received_at INTEGER NOT NULL,
                body BLOB NOT NULL CHECK (length(body) <= 1048576),
                body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
                source_evidence BLOB NOT NULL CHECK (length(source_evidence) <= 1048576),
                evidence_hash BLOB NOT NULL CHECK (length(evidence_hash) = 32),
                acknowledged INTEGER NOT NULL DEFAULT 0 CHECK (acknowledged IN (0, 1)),
                UNIQUE (tenant_id, event_id),
                FOREIGN KEY (tenant_id, event_id)
                    REFERENCES security_verified_events (tenant_id, event_id)
            );

            CREATE INDEX IF NOT EXISTS security_correlation_ingress_pending
                ON security_correlation_ingress (acknowledged, event_time, sequence);

            CREATE TRIGGER IF NOT EXISTS security_correlation_ingress_immutable
            BEFORE UPDATE ON security_correlation_ingress
            WHEN OLD.sequence != NEW.sequence
                OR OLD.tenant_id != NEW.tenant_id
                OR OLD.event_id != NEW.event_id
                OR OLD.producer_id != NEW.producer_id
                OR OLD.event_time != NEW.event_time
                OR OLD.received_at != NEW.received_at
                OR OLD.body != NEW.body
                OR OLD.body_hash != NEW.body_hash
                OR OLD.source_evidence != NEW.source_evidence
                OR OLD.evidence_hash != NEW.evidence_hash
                OR OLD.acknowledged = 1
                OR NEW.acknowledged != 1
            BEGIN
                SELECT RAISE(ABORT, 'correlation ingress mutation is rejected');
            END;

            CREATE TRIGGER IF NOT EXISTS security_correlation_ingress_delete_rejected
            BEFORE DELETE ON security_correlation_ingress
            BEGIN
                SELECT RAISE(ABORT, 'correlation ingress deletion is rejected');
            END;

            CREATE TABLE IF NOT EXISTS security_advisory_events (
                tenant_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                producer_id TEXT NOT NULL,
                event_time INTEGER NOT NULL,
                body BLOB NOT NULL CHECK (length(body) <= 1048576),
                body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
                PRIMARY KEY (tenant_id, event_id)
            );

            CREATE TABLE IF NOT EXISTS security_correlation_events (
                tenant_id TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                partition_hash BLOB NOT NULL CHECK (length(partition_hash) = 32),
                event_id TEXT NOT NULL,
                transition_id TEXT NOT NULL,
                PRIMARY KEY (tenant_id, rule_id, partition_hash, event_id),
                UNIQUE (tenant_id, rule_id, event_id),
                UNIQUE (tenant_id, transition_id),
                FOREIGN KEY (tenant_id, event_id)
                    REFERENCES security_verified_events (tenant_id, event_id)
            );

            CREATE TABLE IF NOT EXISTS security_correlation_partition_heads (
                tenant_id TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                partition_hash BLOB NOT NULL CHECK (length(partition_hash) = 32),
                generation INTEGER NOT NULL,
                PRIMARY KEY (tenant_id, rule_id, partition_hash)
            );

            CREATE TABLE IF NOT EXISTS security_correlation_partials (
                tenant_id TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                partition_hash BLOB NOT NULL CHECK (length(partition_hash) = 32),
                generation INTEGER NOT NULL,
                watermark INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                body BLOB NOT NULL CHECK (length(body) <= 1048576),
                body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
                transition_id TEXT NOT NULL,
                PRIMARY KEY (tenant_id, rule_id, partition_hash),
                UNIQUE (tenant_id, transition_id)
            );

            CREATE TABLE IF NOT EXISTS security_correlation_outcomes (
                tenant_id TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                partition_hash BLOB NOT NULL CHECK (length(partition_hash) = 32),
                status TEXT NOT NULL CHECK (status IN (
                    'accepted', 'advisory_only', 'duplicate', 'irrelevant', 'matched',
                    'suppressed', 'too_late'
                )),
                watermark INTEGER NOT NULL CHECK (watermark >= 0),
                rule_version_hash BLOB NOT NULL CHECK (length(rule_version_hash) = 32),
                event_body_hash BLOB NOT NULL CHECK (length(event_body_hash) = 32),
                event_evidence_hash BLOB NOT NULL CHECK (length(event_evidence_hash) = 32),
                body BLOB NOT NULL CHECK (length(body) <= 1048576),
                body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
                PRIMARY KEY (tenant_id, rule_id, event_id),
                FOREIGN KEY (tenant_id, event_id)
                    REFERENCES security_verified_events (tenant_id, event_id)
            );

            CREATE TRIGGER IF NOT EXISTS security_correlation_outcomes_immutable
            BEFORE UPDATE ON security_correlation_outcomes
            BEGIN
                SELECT RAISE(ABORT, 'correlation outcome mutation is rejected');
            END;

            CREATE TRIGGER IF NOT EXISTS security_correlation_outcomes_delete_rejected
            BEFORE DELETE ON security_correlation_outcomes
            BEGIN
                SELECT RAISE(ABORT, 'correlation outcome deletion is rejected');
            END;

            CREATE TABLE IF NOT EXISTS security_attested_finding_batches (
                batch_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                item_count INTEGER NOT NULL CHECK (item_count > 0 AND item_count <= 4096),
                body BLOB NOT NULL CHECK (length(body) <= 1048576),
                body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
                PRIMARY KEY (tenant_id, batch_id)
            );

            CREATE TABLE IF NOT EXISTS security_attested_finding_batch_items (
                batch_id TEXT NOT NULL,
                ordinal INTEGER NOT NULL CHECK (ordinal >= 0 AND ordinal < 4096),
                tenant_id TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                finding_hash BLOB NOT NULL CHECK (
                    length(finding_hash) = 32 AND finding_hash != zeroblob(32)
                ),
                action_id TEXT NOT NULL,
                reservation_id TEXT NOT NULL,
                PRIMARY KEY (tenant_id, batch_id, ordinal),
                UNIQUE (tenant_id, evidence_id),
                UNIQUE (tenant_id, finding_id),
                UNIQUE (tenant_id, action_id),
                UNIQUE (tenant_id, reservation_id),
                FOREIGN KEY (tenant_id, batch_id)
                    REFERENCES security_attested_finding_batches (tenant_id, batch_id)
            );

            CREATE TABLE IF NOT EXISTS security_response_plans (
                action_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                generation INTEGER NOT NULL,
                state TEXT NOT NULL,
                body BLOB NOT NULL CHECK (length(body) <= 1048576),
                body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
                due_at INTEGER,
                PRIMARY KEY (tenant_id, action_id)
            );

            CREATE TABLE IF NOT EXISTS security_response_receipt_cursors (
                tenant_id TEXT NOT NULL,
                action_id TEXT NOT NULL,
                plan_hash BLOB NOT NULL CHECK (length(plan_hash) = 32),
                generation INTEGER NOT NULL CHECK (generation >= 0),
                current_evidence_id TEXT NOT NULL,
                PRIMARY KEY (tenant_id, action_id),
                FOREIGN KEY (tenant_id, action_id)
                    REFERENCES security_response_plans (tenant_id, action_id)
            );

            CREATE TABLE IF NOT EXISTS security_response_dispatches (
                dispatch_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                action_id TEXT NOT NULL,
                commit_mode TEXT NOT NULL DEFAULT 'fresh'
                    CHECK (commit_mode IN ('fresh', 'governed_committed_resume', 'governed_committed_expired_resume')),
                authorization_body BLOB NOT NULL CHECK (length(authorization_body) <= 1048576),
                authorization_body_hash BLOB NOT NULL CHECK (length(authorization_body_hash) = 32),
                response_generation INTEGER NOT NULL CHECK (response_generation IN (1, 2)),
                response_state TEXT NOT NULL CHECK (response_state = 'applying'),
                response_body BLOB NOT NULL CHECK (length(response_body) <= 1048576),
                response_body_hash BLOB NOT NULL CHECK (length(response_body_hash) = 32),
                response_due_at INTEGER NOT NULL,
                initial_lease_owner_id TEXT NOT NULL,
                initial_lease_expires_at INTEGER NOT NULL,
                initial_fencing_token INTEGER NOT NULL CHECK (initial_fencing_token > 0),
                PRIMARY KEY (tenant_id, dispatch_id),
                UNIQUE (tenant_id, action_id),
                FOREIGN KEY (tenant_id, action_id)
                    REFERENCES security_response_plans (tenant_id, action_id)
            );

            CREATE TABLE IF NOT EXISTS security_response_dispatch_fences (
                dispatch_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                action_id TEXT NOT NULL,
                prepared_binding_body BLOB NOT NULL
                    CHECK (length(prepared_binding_body) <= 1048576),
                prepared_binding_hash BLOB NOT NULL
                    CHECK (length(prepared_binding_hash) = 32),
                fenced_at INTEGER NOT NULL CHECK (fenced_at > 0),
                PRIMARY KEY (tenant_id, action_id),
                UNIQUE (tenant_id, dispatch_id)
            );

            CREATE TABLE IF NOT EXISTS security_response_effects (
                effect_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                action_id TEXT NOT NULL,
                generation INTEGER NOT NULL DEFAULT 0,
                scheduler_lease_owner_id TEXT NOT NULL,
                scheduler_fencing_token INTEGER NOT NULL,
                state TEXT NOT NULL,
                body BLOB NOT NULL CHECK (length(body) <= 1048576),
                body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
                encrypted_rollback_ref TEXT,
                PRIMARY KEY (tenant_id, effect_id),
                FOREIGN KEY (encrypted_rollback_ref) REFERENCES chio_encrypted_blobs (blob_id)
            );

            CREATE TABLE IF NOT EXISTS security_effect_contributions (
                tenant_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                effect_id TEXT NOT NULL,
                action_id TEXT NOT NULL,
                posture_rank INTEGER NOT NULL,
                contribution_hash BLOB NOT NULL CHECK (length(contribution_hash) = 32),
                expires_at INTEGER,
                PRIMARY KEY (tenant_id, target_id, effect_id),
                UNIQUE (tenant_id, effect_id)
            );

            CREATE TABLE IF NOT EXISTS security_overlay_state (
                tenant_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                generation INTEGER NOT NULL,
                effective_posture_rank INTEGER NOT NULL,
                highest_fencing_token INTEGER NOT NULL,
                PRIMARY KEY (tenant_id, target_id)
            );

            CREATE TABLE IF NOT EXISTS security_containment_overlay_commands (
                tenant_id TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                request_body BLOB NOT NULL CHECK (length(request_body) <= 2097152),
                request_body_hash BLOB NOT NULL CHECK (length(request_body_hash) = 32),
                result_body BLOB NOT NULL CHECK (length(result_body) <= 1048576),
                result_body_hash BLOB NOT NULL CHECK (length(result_body_hash) = 32),
                resulting_snapshot_body BLOB NOT NULL CHECK (length(resulting_snapshot_body) <= 2097152),
                resulting_snapshot_body_hash BLOB NOT NULL CHECK (length(resulting_snapshot_body_hash) = 32),
                PRIMARY KEY (tenant_id, idempotency_key)
            );

            CREATE TABLE IF NOT EXISTS security_session_throttle_state (
                tenant_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                generation INTEGER NOT NULL CHECK (generation >= 0),
                highest_fencing_token INTEGER NOT NULL CHECK (highest_fencing_token >= 0),
                PRIMARY KEY (tenant_id, session_id)
            );

            CREATE TABLE IF NOT EXISTS security_session_throttle_effects (
                tenant_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                effect_id TEXT NOT NULL,
                action_id TEXT NOT NULL,
                window_ms INTEGER NOT NULL CHECK (window_ms > 0),
                max_invocations INTEGER NOT NULL CHECK (max_invocations > 0),
                contribution_hash BLOB NOT NULL CHECK (length(contribution_hash) = 32),
                expires_at INTEGER NOT NULL CHECK (expires_at > 0),
                installed_fencing_token INTEGER NOT NULL CHECK (installed_fencing_token > 0),
                PRIMARY KEY (tenant_id, session_id, effect_id),
                UNIQUE (tenant_id, effect_id),
                FOREIGN KEY (tenant_id, session_id)
                    REFERENCES security_session_throttle_state (tenant_id, session_id)
            );

            CREATE TABLE IF NOT EXISTS security_session_throttle_windows (
                tenant_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                effect_id TEXT NOT NULL,
                window_start INTEGER NOT NULL CHECK (window_start >= 0),
                window_end INTEGER NOT NULL CHECK (window_end > window_start),
                window_id TEXT NOT NULL,
                consumed INTEGER NOT NULL CHECK (consumed >= 0),
                PRIMARY KEY (tenant_id, session_id, effect_id, window_start),
                UNIQUE (tenant_id, window_id),
                FOREIGN KEY (tenant_id, session_id, effect_id)
                    REFERENCES security_session_throttle_effects (
                        tenant_id, session_id, effect_id
                    ) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS security_session_throttle_invocations (
                tenant_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                effect_id TEXT NOT NULL,
                window_start INTEGER NOT NULL,
                invocation_id TEXT NOT NULL,
                PRIMARY KEY (
                    tenant_id, session_id, effect_id, window_start, invocation_id
                ),
                FOREIGN KEY (tenant_id, session_id, effect_id, window_start)
                    REFERENCES security_session_throttle_windows (
                        tenant_id, session_id, effect_id, window_start
                    ) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS security_session_throttle_commands (
                tenant_id TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                request_body BLOB NOT NULL CHECK (length(request_body) <= 2097152),
                request_body_hash BLOB NOT NULL CHECK (length(request_body_hash) = 32),
                result_body BLOB NOT NULL CHECK (length(result_body) <= 1048576),
                result_body_hash BLOB NOT NULL CHECK (length(result_body_hash) = 32),
                resulting_snapshot_body BLOB NOT NULL CHECK (length(resulting_snapshot_body) <= 2097152),
                resulting_snapshot_body_hash BLOB NOT NULL CHECK (length(resulting_snapshot_body_hash) = 32),
                PRIMARY KEY (tenant_id, idempotency_key)
            );

            CREATE INDEX IF NOT EXISTS security_session_throttle_window_lookup
                ON security_session_throttle_windows (
                    tenant_id, session_id, effect_id, window_start
                );

            CREATE TABLE IF NOT EXISTS security_capability_set_suspension_state (
                tenant_id TEXT NOT NULL,
                affected_set_hash BLOB NOT NULL CHECK (length(affected_set_hash) = 32),
                generation INTEGER NOT NULL CHECK (generation >= 0),
                highest_fencing_token INTEGER NOT NULL CHECK (highest_fencing_token >= 0),
                PRIMARY KEY (tenant_id, affected_set_hash)
            );

            CREATE TABLE IF NOT EXISTS security_capability_set_suspension_effects (
                tenant_id TEXT NOT NULL,
                affected_set_hash BLOB NOT NULL CHECK (length(affected_set_hash) = 32),
                action_id TEXT NOT NULL,
                effect_id TEXT NOT NULL,
                affected_ids_body BLOB NOT NULL CHECK (length(affected_ids_body) <= 1048576),
                contribution_hash BLOB NOT NULL CHECK (length(contribution_hash) = 32),
                expires_at INTEGER NOT NULL CHECK (expires_at > 0),
                installed_fencing_token INTEGER NOT NULL CHECK (installed_fencing_token > 0),
                PRIMARY KEY (tenant_id, affected_set_hash, action_id, effect_id),
                UNIQUE (tenant_id, effect_id),
                FOREIGN KEY (tenant_id, affected_set_hash)
                    REFERENCES security_capability_set_suspension_state (
                        tenant_id, affected_set_hash
                    )
            );

            CREATE TABLE IF NOT EXISTS security_capability_set_suspension_members (
                tenant_id TEXT NOT NULL,
                affected_set_hash BLOB NOT NULL CHECK (length(affected_set_hash) = 32),
                action_id TEXT NOT NULL,
                effect_id TEXT NOT NULL,
                capability_id TEXT NOT NULL,
                PRIMARY KEY (
                    tenant_id, affected_set_hash, action_id, effect_id, capability_id
                ),
                FOREIGN KEY (tenant_id, affected_set_hash, action_id, effect_id)
                    REFERENCES security_capability_set_suspension_effects (
                        tenant_id, affected_set_hash, action_id, effect_id
                    ) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS security_capability_set_suspension_member_lookup
                ON security_capability_set_suspension_members (
                    tenant_id, capability_id, action_id, effect_id
                );

            CREATE TABLE IF NOT EXISTS security_capability_set_suspension_commands (
                tenant_id TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                request_body BLOB NOT NULL CHECK (length(request_body) <= 2097152),
                request_body_hash BLOB NOT NULL CHECK (length(request_body_hash) = 32),
                result_body BLOB NOT NULL CHECK (length(result_body) <= 1048576),
                result_body_hash BLOB NOT NULL CHECK (length(result_body_hash) = 32),
                resulting_snapshot_body BLOB NOT NULL CHECK (length(resulting_snapshot_body) <= 2097152),
                resulting_snapshot_body_hash BLOB NOT NULL CHECK (length(resulting_snapshot_body_hash) = 32),
                PRIMARY KEY (tenant_id, idempotency_key)
            );

            CREATE TABLE IF NOT EXISTS security_issuance_freeze_state (
                tenant_id TEXT NOT NULL,
                lineage_id TEXT NOT NULL,
                generation INTEGER NOT NULL CHECK (generation >= 0),
                highest_scheduler_fencing_token INTEGER NOT NULL CHECK (
                    highest_scheduler_fencing_token >= 0
                ),
                PRIMARY KEY (tenant_id, lineage_id)
            );

            CREATE TABLE IF NOT EXISTS security_issuance_freeze_effects (
                tenant_id TEXT NOT NULL,
                lineage_id TEXT NOT NULL,
                action_id TEXT NOT NULL,
                effect_id TEXT NOT NULL,
                commit_index INTEGER NOT NULL CHECK (commit_index > 0),
                affected_set_hash BLOB NOT NULL CHECK (length(affected_set_hash) = 32),
                frozen_affected_ids_body BLOB NOT NULL CHECK (
                    length(frozen_affected_ids_body) <= 1048576
                ),
                graph_slice_hash BLOB NOT NULL CHECK (length(graph_slice_hash) = 32),
                external_fencing_token INTEGER NOT NULL CHECK (external_fencing_token > 0),
                external_scheduler_lease_owner_id TEXT NOT NULL,
                external_scheduler_fencing_token INTEGER NOT NULL CHECK (
                    external_scheduler_fencing_token > 0
                ),
                external_fence_expires_at INTEGER NOT NULL CHECK (
                    external_fence_expires_at > 0
                ),
                contribution_hash BLOB NOT NULL CHECK (length(contribution_hash) = 32),
                expires_at INTEGER NOT NULL CHECK (expires_at > 0),
                installed_scheduler_fencing_token INTEGER NOT NULL CHECK (
                    installed_scheduler_fencing_token > 0
                ),
                PRIMARY KEY (tenant_id, lineage_id, action_id, effect_id),
                UNIQUE (tenant_id, effect_id),
                FOREIGN KEY (tenant_id, lineage_id)
                    REFERENCES security_issuance_freeze_state (tenant_id, lineage_id)
            );

            CREATE INDEX IF NOT EXISTS security_issuance_freeze_lineage_lookup
                ON security_issuance_freeze_effects (
                    tenant_id, lineage_id, action_id, effect_id
                );

            CREATE TABLE IF NOT EXISTS security_issuance_freeze_commands (
                tenant_id TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                lineage_id TEXT NOT NULL,
                action_id TEXT NOT NULL,
                effect_id TEXT NOT NULL,
                command_state TEXT NOT NULL CHECK (
                    command_state IN ('release_pending', 'completed')
                ),
                request_body BLOB NOT NULL CHECK (length(request_body) <= 2097152),
                request_body_hash BLOB NOT NULL CHECK (length(request_body_hash) = 32),
                result_body BLOB NOT NULL CHECK (length(result_body) <= 1048576),
                result_body_hash BLOB NOT NULL CHECK (length(result_body_hash) = 32),
                resulting_snapshot_body BLOB NOT NULL CHECK (
                    length(resulting_snapshot_body) <= 2097152
                ),
                resulting_snapshot_body_hash BLOB NOT NULL CHECK (
                    length(resulting_snapshot_body_hash) = 32
                ),
                pending_contribution_body BLOB CHECK (
                    pending_contribution_body IS NULL
                    OR length(pending_contribution_body) <= 2097152
                ),
                pending_contribution_body_hash BLOB CHECK (
                    pending_contribution_body_hash IS NULL
                    OR length(pending_contribution_body_hash) = 32
                ),
                CHECK (
                    (command_state = 'release_pending'
                     AND pending_contribution_body IS NOT NULL
                     AND pending_contribution_body_hash IS NOT NULL)
                    OR
                    (command_state = 'completed'
                     AND pending_contribution_body IS NULL
                     AND pending_contribution_body_hash IS NULL)
                ),
                PRIMARY KEY (tenant_id, idempotency_key)
            );

            CREATE INDEX IF NOT EXISTS security_issuance_freeze_pending_lookup
                ON security_issuance_freeze_commands (
                    tenant_id, lineage_id, command_state, action_id, effect_id
                );

            CREATE TABLE IF NOT EXISTS security_egress_restriction_state (
                tenant_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                generation INTEGER NOT NULL CHECK (generation >= 0),
                highest_fencing_token INTEGER NOT NULL CHECK (highest_fencing_token >= 0),
                PRIMARY KEY (tenant_id, session_id)
            );

            CREATE TABLE IF NOT EXISTS security_egress_restriction_effects (
                tenant_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                effect_id TEXT NOT NULL,
                action_id TEXT NOT NULL,
                contribution_hash BLOB NOT NULL CHECK (length(contribution_hash) = 32),
                expires_at INTEGER NOT NULL CHECK (expires_at > 0),
                installed_fencing_token INTEGER NOT NULL CHECK (installed_fencing_token > 0),
                PRIMARY KEY (tenant_id, session_id, effect_id),
                UNIQUE (tenant_id, effect_id),
                FOREIGN KEY (tenant_id, session_id)
                    REFERENCES security_egress_restriction_state (tenant_id, session_id)
            );

            CREATE TABLE IF NOT EXISTS security_egress_restriction_destinations (
                tenant_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                effect_id TEXT NOT NULL,
                destination_id TEXT NOT NULL,
                PRIMARY KEY (tenant_id, session_id, effect_id, destination_id),
                FOREIGN KEY (tenant_id, session_id, effect_id)
                    REFERENCES security_egress_restriction_effects (
                        tenant_id, session_id, effect_id
                    ) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS security_egress_restriction_destination_lookup
                ON security_egress_restriction_destinations (
                    tenant_id, session_id, destination_id, effect_id
                );

            CREATE TABLE IF NOT EXISTS security_egress_restriction_commands (
                tenant_id TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                request_body BLOB NOT NULL CHECK (length(request_body) <= 2097152),
                request_body_hash BLOB NOT NULL CHECK (length(request_body_hash) = 32),
                result_body BLOB NOT NULL CHECK (length(result_body) <= 1048576),
                result_body_hash BLOB NOT NULL CHECK (length(result_body_hash) = 32),
                PRIMARY KEY (tenant_id, idempotency_key)
            );

            CREATE TABLE IF NOT EXISTS security_lineage_fences (
                action_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                commit_index INTEGER NOT NULL,
                affected_set_hash BLOB NOT NULL CHECK (length(affected_set_hash) = 32),
                fencing_token INTEGER NOT NULL,
                scheduler_lease_owner_id TEXT NOT NULL,
                scheduler_fencing_token INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                state TEXT NOT NULL,
                PRIMARY KEY (tenant_id, action_id)
            );

            CREATE TABLE IF NOT EXISTS security_scheduler_claims (
                tenant_id TEXT NOT NULL,
                claim_id TEXT NOT NULL,
                request_hash BLOB NOT NULL CHECK (length(request_hash) = 32),
                lease_owner_id TEXT NOT NULL,
                lease_expires_at INTEGER NOT NULL,
                result_count INTEGER NOT NULL,
                committed_at INTEGER NOT NULL,
                PRIMARY KEY (tenant_id, claim_id)
            );

            CREATE TABLE IF NOT EXISTS security_scheduler_leases (
                action_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                claim_id TEXT NOT NULL,
                claim_ordinal INTEGER NOT NULL,
                lease_owner_id TEXT NOT NULL,
                lease_expires_at INTEGER NOT NULL,
                fencing_token INTEGER NOT NULL,
                lease_body_hash BLOB NOT NULL CHECK (length(lease_body_hash) = 32),
                PRIMARY KEY (tenant_id, action_id)
            );

            CREATE INDEX IF NOT EXISTS security_scheduler_leases_claim
                ON security_scheduler_leases (tenant_id, claim_id, action_id);

            CREATE INDEX IF NOT EXISTS security_scheduler_leases_expiry_order
                ON security_scheduler_leases (
                    tenant_id, lease_expires_at, claim_id, claim_ordinal, action_id
                );

            CREATE TABLE IF NOT EXISTS security_scheduler_fence_sequences (
                tenant_id TEXT NOT NULL,
                last_fencing_token INTEGER NOT NULL,
                PRIMARY KEY (tenant_id)
            );

            CREATE TABLE IF NOT EXISTS security_scheduler_retries (
                tenant_id TEXT NOT NULL,
                action_id TEXT NOT NULL,
                attempts INTEGER NOT NULL,
                last_error TEXT NOT NULL,
                first_failure_at INTEGER NOT NULL,
                not_before INTEGER NOT NULL,
                health_event_id TEXT,
                health_event_delivered INTEGER NOT NULL CHECK (health_event_delivered IN (0, 1)),
                PRIMARY KEY (tenant_id, action_id)
            );

            CREATE TABLE IF NOT EXISTS security_response_dispatch_recoveries (
                recovery_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                dispatch_id TEXT NOT NULL,
                action_id TEXT NOT NULL,
                request_hash BLOB NOT NULL CHECK (length(request_hash) = 32),
                outcome TEXT NOT NULL CHECK (outcome IN ('live_lease', 'takeover')),
                lease_owner_id TEXT NOT NULL,
                lease_expires_at INTEGER NOT NULL,
                fencing_token INTEGER NOT NULL CHECK (fencing_token > 0),
                PRIMARY KEY (tenant_id, recovery_id),
                FOREIGN KEY (tenant_id, dispatch_id)
                    REFERENCES security_response_dispatches (tenant_id, dispatch_id)
            );

            CREATE TABLE IF NOT EXISTS security_transitions (
                transition_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                transition_kind TEXT NOT NULL,
                request_hash BLOB NOT NULL CHECK (length(request_hash) = 32),
                PRIMARY KEY (tenant_id, transition_id)
            );
                "#,
            )
            .map_err(sqlite_error)?;
        ensure_attested_finding_batch_tenant_keys(connection)?;
        ensure_attested_finding_response_outbox_schema(connection)?;
        upgrade_correlation_ingress_pending_index(connection)?;
        validate_correlation_durable_schema(connection)?;
        ensure_response_effect_generation_column(connection)?;
        ensure_response_dispatch_commit_mode_column(connection)?;
        ensure_scheduler_lease_body_hash_column(connection)?;
        ensure_scheduler_retry_health_columns(connection)?;
        ensure_lineage_fence_binding_columns(connection)?;
        crate::stamp_schema_version(
            connection,
            SECURITY_STATE_STORE_SCHEMA_KEY,
            SECURITY_STATE_STORE_SUPPORTED_SCHEMA_VERSION,
        )
        .map_err(schema_version_error)?;
        Ok(())
    })();
    match migration {
        Ok(()) => connection.execute_batch("COMMIT;").map_err(sqlite_error),
        Err(error) => {
            let _ = connection.execute_batch("ROLLBACK;");
            Err(error)
        }
    }
}
