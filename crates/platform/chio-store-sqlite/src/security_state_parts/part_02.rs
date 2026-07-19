fn migrate(connection: &Connection) -> PortResult<()> {
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

            CREATE TABLE IF NOT EXISTS security_attested_finding_response_outbox (
                tenant_id TEXT NOT NULL,
                batch_id TEXT NOT NULL,
                ordinal INTEGER NOT NULL CHECK (ordinal >= 0 AND ordinal < 4096),
                evidence_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                finding_hash BLOB NOT NULL CHECK (
                    length(finding_hash) = 32 AND finding_hash != zeroblob(32)
                ),
                action_id TEXT NOT NULL,
                reservation_id TEXT NOT NULL,
                planning_state TEXT NOT NULL CHECK (planning_state IN ('pending', 'planned', 'failed')),
                admission_state TEXT NOT NULL CHECK (
                    admission_state IN ('pending', 'prepared', 'rejected', 'expired')
                ),
                completion_state TEXT NOT NULL CHECK (
                    completion_state IN ('not_started', 'pending', 'outcome_unknown_after_dispatch', 'completed')
                ),
                execution_dispatch_id TEXT CHECK (
                    execution_dispatch_id IS NULL
                        OR trim(execution_dispatch_id, '0') != ''
                ),
                prepared_dispatch_binding BLOB CHECK (
                    prepared_dispatch_binding IS NULL
                        OR length(prepared_dispatch_binding) <= 1048576
                ),
                prepared_dispatch_binding_hash BLOB CHECK (
                    prepared_dispatch_binding_hash IS NULL
                        OR (length(prepared_dispatch_binding_hash) = 32
                            AND prepared_dispatch_binding_hash != zeroblob(32))
                ),
                completion_outcome TEXT CHECK (
                    completion_outcome IS NULL OR completion_outcome IN (
                        'activated', 'failed_before_effect', 'rolled_back_after_partial'
                    )
                ),
                completion_evidence_id TEXT CHECK (
                    completion_evidence_id IS NULL
                        OR trim(completion_evidence_id, '0') != ''
                ),
                completion_evidence_body_hash BLOB CHECK (
                    completion_evidence_body_hash IS NULL
                        OR (length(completion_evidence_body_hash) = 32
                            AND completion_evidence_body_hash != zeroblob(32))
                ),
                plan_body BLOB CHECK (plan_body IS NULL OR length(plan_body) <= 1048576),
                plan_body_hash BLOB CHECK (
                    plan_body_hash IS NULL
                        OR (length(plan_body_hash) = 32
                            AND plan_body_hash != zeroblob(32))
                ),
                admission_artifact_ref TEXT CHECK (
                    admission_artifact_ref IS NULL
                        OR trim(admission_artifact_ref, '0') != ''
                ),
                admission_artifact_digest BLOB CHECK (
                    admission_artifact_digest IS NULL
                        OR (length(admission_artifact_digest) = 32
                            AND admission_artifact_digest != zeroblob(32))
                ),
                attempts INTEGER NOT NULL DEFAULT 0
                    CHECK (attempts >= 0 AND attempts <= 1000000),
                next_attempt_at INTEGER NOT NULL DEFAULT 0 CHECK (next_attempt_at >= 0),
                last_error_code TEXT,
                CHECK (
                    (planning_state = 'pending' AND plan_body IS NULL
                        AND plan_body_hash IS NULL AND admission_artifact_ref IS NULL
                        AND admission_artifact_digest IS NULL)
                    OR (planning_state = 'planned' AND plan_body IS NOT NULL
                        AND plan_body_hash IS NOT NULL AND admission_artifact_ref IS NOT NULL)
                    OR (planning_state = 'failed' AND plan_body IS NULL
                        AND plan_body_hash IS NULL AND admission_artifact_ref IS NULL
                        AND admission_artifact_digest IS NULL)
                ),
                CHECK (
                    (admission_state = 'pending' AND execution_dispatch_id IS NULL
                        AND prepared_dispatch_binding IS NULL
                        AND completion_state = 'not_started')
                    OR (admission_state = 'prepared' AND execution_dispatch_id IS NOT NULL
                        AND prepared_dispatch_binding IS NOT NULL
                        AND admission_artifact_digest IS NOT NULL
                        AND completion_state IN ('pending', 'outcome_unknown_after_dispatch', 'completed'))
                    OR (admission_state IN ('rejected', 'expired')
                        AND execution_dispatch_id IS NULL
                        AND prepared_dispatch_binding IS NULL
                        AND completion_state = 'not_started')
                    OR (admission_state = 'expired'
                        AND execution_dispatch_id IS NOT NULL
                        AND prepared_dispatch_binding IS NOT NULL
                        AND admission_artifact_digest IS NOT NULL
                        AND completion_state = 'not_started')
                ),
                CHECK (
                    (prepared_dispatch_binding IS NULL
                        AND prepared_dispatch_binding_hash IS NULL)
                    OR (prepared_dispatch_binding IS NOT NULL
                        AND prepared_dispatch_binding_hash IS NOT NULL)
                ),
                CHECK (planning_state = 'planned' OR admission_state != 'prepared'),
                CHECK (
                    (completion_state = 'completed' AND completion_outcome IS NOT NULL
                        AND completion_evidence_id IS NOT NULL
                        AND completion_evidence_body_hash IS NOT NULL)
                    OR (completion_state != 'completed' AND completion_outcome IS NULL
                        AND completion_evidence_id IS NULL
                        AND completion_evidence_body_hash IS NULL)
                ),
                PRIMARY KEY (tenant_id, action_id),
                UNIQUE (tenant_id, batch_id, ordinal),
                UNIQUE (tenant_id, reservation_id),
                UNIQUE (tenant_id, execution_dispatch_id),
                FOREIGN KEY (tenant_id, batch_id, ordinal)
                    REFERENCES security_attested_finding_batch_items (tenant_id, batch_id, ordinal)
            );

            CREATE INDEX IF NOT EXISTS security_attested_finding_response_outbox_due
                ON security_attested_finding_response_outbox (
                    planning_state, admission_state, completion_state,
                    next_attempt_at, attempts, tenant_id, action_id
                );

            CREATE TRIGGER IF NOT EXISTS security_attested_finding_response_outbox_immutable
            BEFORE UPDATE ON security_attested_finding_response_outbox
            WHEN NEW.tenant_id IS NOT OLD.tenant_id
              OR NEW.batch_id IS NOT OLD.batch_id
              OR NEW.ordinal IS NOT OLD.ordinal
              OR NEW.evidence_id IS NOT OLD.evidence_id
              OR NEW.finding_id IS NOT OLD.finding_id
              OR NEW.finding_hash IS NOT OLD.finding_hash
              OR NEW.action_id IS NOT OLD.action_id
              OR NEW.reservation_id IS NOT OLD.reservation_id
              OR (OLD.plan_body IS NOT NULL
                  AND NEW.plan_body IS NOT OLD.plan_body)
              OR (OLD.plan_body_hash IS NOT NULL
                  AND NEW.plan_body_hash IS NOT OLD.plan_body_hash)
              OR (OLD.admission_artifact_ref IS NOT NULL
                  AND NEW.admission_artifact_ref IS NOT OLD.admission_artifact_ref)
              OR (OLD.admission_artifact_digest IS NOT NULL
                  AND NEW.admission_artifact_digest IS NOT OLD.admission_artifact_digest)
              OR (OLD.execution_dispatch_id IS NOT NULL
                  AND NEW.execution_dispatch_id IS NOT OLD.execution_dispatch_id)
              OR (OLD.prepared_dispatch_binding IS NOT NULL
                  AND NEW.prepared_dispatch_binding IS NOT OLD.prepared_dispatch_binding)
              OR (OLD.prepared_dispatch_binding_hash IS NOT NULL
                  AND NEW.prepared_dispatch_binding_hash IS NOT OLD.prepared_dispatch_binding_hash)
              OR (OLD.completion_outcome IS NOT NULL
                  AND NEW.completion_outcome IS NOT OLD.completion_outcome)
              OR (OLD.completion_evidence_id IS NOT NULL
                  AND NEW.completion_evidence_id IS NOT OLD.completion_evidence_id)
              OR (OLD.completion_evidence_body_hash IS NOT NULL
                  AND NEW.completion_evidence_body_hash IS NOT OLD.completion_evidence_body_hash)
              OR NEW.attempts < OLD.attempts
              OR (OLD.planning_state IN ('planned', 'failed')
                  AND NEW.planning_state IS NOT OLD.planning_state)
              OR (OLD.admission_state = 'prepared'
                  AND NEW.admission_state NOT IN ('prepared', 'expired'))
              OR (OLD.admission_state IN ('rejected', 'expired')
                  AND NEW.admission_state IS NOT OLD.admission_state)
              OR (OLD.completion_state = 'pending'
                  AND NEW.completion_state NOT IN ('pending', 'outcome_unknown_after_dispatch', 'completed')
                  AND NOT (NEW.admission_state = 'expired'
                      AND NEW.completion_state = 'not_started'))
              OR (OLD.completion_state = 'outcome_unknown_after_dispatch'
                  AND NEW.completion_state NOT IN ('outcome_unknown_after_dispatch', 'completed')
                  AND NOT (NEW.admission_state = 'expired'
                      AND NEW.completion_state = 'not_started'))
              OR (OLD.completion_state = 'completed'
                  AND NEW.completion_state != 'completed')
            BEGIN
                SELECT RAISE(ABORT,
                    'attested finding response outbox state is immutable or monotonic');
            END;

            CREATE TRIGGER IF NOT EXISTS security_attested_finding_response_outbox_delete_rejected
            BEFORE DELETE ON security_attested_finding_response_outbox
            BEGIN
                SELECT RAISE(ABORT, 'attested finding response outbox deletion is rejected');
            END;

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
                PRIMARY KEY (tenant_id, action_id)
            );

            CREATE INDEX IF NOT EXISTS security_scheduler_leases_claim
                ON security_scheduler_leases (tenant_id, claim_id, action_id);

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
        ensure_scheduler_retry_health_columns(connection)?;
        ensure_lineage_fence_binding_columns(connection)?;
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

fn validate_no_attested_finding_batch_schema_extensions(connection: &Connection) -> PortResult<()> {
    let extension_count: i64 = connection
        .query_row(
            r#"
            SELECT COUNT(*)
            FROM sqlite_master
            WHERE type IN ('index', 'trigger')
              AND (
                  tbl_name IN (
                      'security_attested_finding_batches',
                      'security_attested_finding_batch_items'
                  )
                  OR (
                      type = 'trigger'
                      AND (
                          instr(lower(sql), 'security_attested_finding_batches') > 0
                          OR instr(lower(sql), 'security_attested_finding_batch_items') > 0
                      )
                  )
              )
              AND sql IS NOT NULL
            "#,
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if extension_count != 0 {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

fn validate_attested_finding_batch_records(connection: &Connection) -> PortResult<()> {
    let quick_check: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    if quick_check != "ok" {
        return Err(PortError::integrity_failure());
    }
    let mut foreign_key_check = connection
        .prepare("PRAGMA foreign_key_check(\"security_attested_finding_batch_items\")")
        .map_err(sqlite_error)?;
    if foreign_key_check
        .query([])
        .map_err(sqlite_error)?
        .next()
        .map_err(sqlite_error)?
        .is_some()
    {
        return Err(PortError::integrity_failure());
    }
    drop(foreign_key_check);

    let mut cursor: Option<(String, String)> = None;
    loop {
        let (cursor_tenant, cursor_batch) =
            cursor.as_ref().map_or((None, None), |(tenant, batch)| {
                (Some(tenant.as_str()), Some(batch.as_str()))
            });
        let mut statement = connection
            .prepare(
                r#"
                SELECT tenant_id, batch_id
                FROM security_attested_finding_batches
                WHERE ?1 IS NULL
                   OR tenant_id > ?1
                   OR (tenant_id = ?1 AND batch_id > ?2)
                ORDER BY tenant_id, batch_id
                LIMIT 256
                "#,
            )
            .map_err(sqlite_error)?;
        let page = statement
            .query_map(params![cursor_tenant, cursor_batch], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error)?;
        if page.is_empty() {
            break;
        }
        for (tenant, batch) in &page {
            let key = AttestedFindingBatchKey {
                tenant_id: TenantId::new(tenant.clone())
                    .map_err(|_| PortError::integrity_failure())?,
                batch_id: RecordId::new(batch.clone())
                    .map_err(|_| PortError::integrity_failure())?,
            };
            if load_attested_finding_batch_record(connection, &key)?.is_none() {
                return Err(PortError::integrity_failure());
            }
        }
        cursor = page.last().cloned();
    }
    Ok(())
}

fn validate_attested_finding_batch_tenant_keys(connection: &Connection) -> PortResult<()> {
    if !table_definition_is_exact(
        connection,
        "security_attested_finding_batches",
        ATTESTED_FINDING_BATCH_CANONICAL_DDL,
    )? || !table_definition_is_exact(
        connection,
        "security_attested_finding_batch_items",
        ATTESTED_FINDING_BATCH_ITEM_CANONICAL_DDL,
    )? {
        return Err(PortError::integrity_failure());
    }
    validate_no_attested_finding_batch_schema_extensions(connection)?;
    validate_attested_finding_batch_records(connection)
}

fn attested_finding_batch_legacy_schema_is_exact(connection: &Connection) -> PortResult<bool> {
    Ok(table_definition_is_exact(
        connection,
        "security_attested_finding_batches",
        ATTESTED_FINDING_BATCH_LEGACY_DDL,
    )? && table_definition_is_exact(
        connection,
        "security_attested_finding_batch_items",
        ATTESTED_FINDING_BATCH_ITEM_LEGACY_DDL,
    )?)
}

fn count_rows(connection: &Connection, table: &str) -> PortResult<i64> {
    connection
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .map_err(sqlite_error)
}

fn table_has_foreign_key_violation(connection: &Connection, table: &str) -> PortResult<bool> {
    let mut statement = connection
        .prepare(&format!("PRAGMA foreign_key_check(\"{table}\")"))
        .map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    rows.next().map(|row| row.is_some()).map_err(sqlite_error)
}

fn ensure_attested_finding_batch_tenant_keys(connection: &Connection) -> PortResult<()> {
    if table_definition_is_exact(
        connection,
        "security_attested_finding_batches",
        ATTESTED_FINDING_BATCH_CANONICAL_DDL,
    )? && table_definition_is_exact(
        connection,
        "security_attested_finding_batch_items",
        ATTESTED_FINDING_BATCH_ITEM_CANONICAL_DDL,
    )? {
        return validate_attested_finding_batch_tenant_keys(connection);
    }
    if !attested_finding_batch_legacy_schema_is_exact(connection)? {
        return Err(PortError::integrity_failure());
    }
    validate_no_attested_finding_batch_schema_extensions(connection)?;
    validate_attested_finding_batch_records(connection)?;

    connection
        .execute_batch(
            r#"
            DROP TRIGGER IF EXISTS security_attested_finding_response_outbox_delete_rejected;
            DROP TRIGGER IF EXISTS security_attested_finding_response_outbox_immutable;
            DROP INDEX IF EXISTS security_attested_finding_response_outbox_due;
            DROP TABLE IF EXISTS security_attested_finding_response_outbox;
            "#,
        )
        .map_err(|_| PortError::integrity_failure())?;

    const BATCH_STAGING: &str = "security_attested_finding_batches_tenant_migration";
    const ITEM_STAGING: &str = "security_attested_finding_batch_items_tenant_migration";
    let batch_staging_ddl = ATTESTED_FINDING_BATCH_CANONICAL_DDL
        .replace("security_attested_finding_batches", BATCH_STAGING);
    let item_staging_ddl = ATTESTED_FINDING_BATCH_ITEM_CANONICAL_DDL
        .replace("security_attested_finding_batch_items", ITEM_STAGING)
        .replace("security_attested_finding_batches", BATCH_STAGING);
    connection
        .execute_batch(&format!("{batch_staging_ddl};{item_staging_ddl};"))
        .map_err(|_| PortError::integrity_failure())?;
    connection
        .execute_batch(&format!(
            r#"
            INSERT INTO {BATCH_STAGING} (
                batch_id, tenant_id, item_count, body, body_hash
            )
            SELECT batch_id, tenant_id, item_count, body, body_hash
            FROM security_attested_finding_batches;
            INSERT INTO {ITEM_STAGING} (
                batch_id, ordinal, tenant_id, evidence_id, finding_id,
                finding_hash, action_id, reservation_id
            )
            SELECT batch_id, ordinal, tenant_id, evidence_id, finding_id,
                   finding_hash, action_id, reservation_id
            FROM security_attested_finding_batch_items;
            "#,
        ))
        .map_err(|_| PortError::integrity_failure())?;
    let original_batch_count = count_rows(connection, "security_attested_finding_batches")?;
    let original_item_count = count_rows(connection, "security_attested_finding_batch_items")?;
    if count_rows(connection, BATCH_STAGING)? != original_batch_count
        || count_rows(connection, ITEM_STAGING)? != original_item_count
        || table_has_foreign_key_violation(connection, ITEM_STAGING)?
    {
        return Err(PortError::integrity_failure());
    }

    connection
        .execute_batch(
            r#"
            DROP TABLE security_attested_finding_batch_items;
            DROP TABLE security_attested_finding_batches;
            "#,
        )
        .map_err(|_| PortError::integrity_failure())?;
    connection
        .execute_batch(&format!(
            "{ATTESTED_FINDING_BATCH_CANONICAL_DDL};{ATTESTED_FINDING_BATCH_ITEM_CANONICAL_DDL};"
        ))
        .map_err(|_| PortError::integrity_failure())?;
    connection
        .execute_batch(&format!(
            r#"
            INSERT INTO security_attested_finding_batches (
                batch_id, tenant_id, item_count, body, body_hash
            )
            SELECT batch_id, tenant_id, item_count, body, body_hash
            FROM {BATCH_STAGING};
            INSERT INTO security_attested_finding_batch_items (
                batch_id, ordinal, tenant_id, evidence_id, finding_id,
                finding_hash, action_id, reservation_id
            )
            SELECT batch_id, ordinal, tenant_id, evidence_id, finding_id,
                   finding_hash, action_id, reservation_id
            FROM {ITEM_STAGING};
            "#,
        ))
        .map_err(|_| PortError::integrity_failure())?;
    if count_rows(connection, "security_attested_finding_batches")? != original_batch_count
        || count_rows(connection, "security_attested_finding_batch_items")? != original_item_count
        || table_has_foreign_key_violation(connection, "security_attested_finding_batch_items")?
    {
        return Err(PortError::integrity_failure());
    }
    connection
        .execute_batch(&format!(
            "DROP TABLE {ITEM_STAGING};DROP TABLE {BATCH_STAGING};"
        ))
        .map_err(|_| PortError::integrity_failure())?;
    validate_attested_finding_batch_tenant_keys(connection)
}

fn ensure_lineage_fence_binding_columns(connection: &Connection) -> PortResult<()> {
    let mut statement = connection
        .prepare("PRAGMA table_info(security_lineage_fences)")
        .map_err(sqlite_error)?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(sqlite_error)?
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(sqlite_error)?;
    drop(statement);
    if !columns.contains("scheduler_lease_owner_id") {
        connection
            .execute(
                "ALTER TABLE security_lineage_fences ADD COLUMN scheduler_lease_owner_id TEXT NOT NULL DEFAULT ''",
                [],
            )
            .map_err(sqlite_error)?;
    }
    if !columns.contains("scheduler_fencing_token") {
        connection
            .execute(
                "ALTER TABLE security_lineage_fences ADD COLUMN scheduler_fencing_token INTEGER NOT NULL DEFAULT 0",
                [],
            )
            .map_err(sqlite_error)?;
    }
    let mut statement = connection
        .prepare("PRAGMA table_info(security_issuance_freeze_effects)")
        .map_err(sqlite_error)?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(sqlite_error)?
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(sqlite_error)?;
    drop(statement);
    if !columns.contains("external_scheduler_lease_owner_id") {
        connection
            .execute(
                "ALTER TABLE security_issuance_freeze_effects ADD COLUMN external_scheduler_lease_owner_id TEXT NOT NULL DEFAULT ''",
                [],
            )
            .map_err(sqlite_error)?;
    }
    if !columns.contains("external_scheduler_fencing_token") {
        connection
            .execute(
                "ALTER TABLE security_issuance_freeze_effects ADD COLUMN external_scheduler_fencing_token INTEGER NOT NULL DEFAULT 0",
                [],
            )
            .map_err(sqlite_error)?;
    }
    Ok(())
}

fn ensure_response_effect_generation_column(connection: &Connection) -> PortResult<()> {
    let mut statement = connection
        .prepare("PRAGMA table_info(security_response_effects)")
        .map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    let mut generation_exists = false;
    let mut scheduler_lease_owner_id_exists = false;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let name: String = row.get(1).map_err(sqlite_error)?;
        if name == "generation" {
            generation_exists = true;
        } else if name == "scheduler_lease_owner_id" {
            scheduler_lease_owner_id_exists = true;
        }
    }
    drop(rows);
    drop(statement);
    if !generation_exists {
        connection
            .execute(
                "ALTER TABLE security_response_effects ADD COLUMN generation INTEGER NOT NULL DEFAULT 0",
                [],
            )
            .map_err(sqlite_error)?;
    }
    if !scheduler_lease_owner_id_exists {
        connection
            .execute(
                "ALTER TABLE security_response_effects ADD COLUMN scheduler_lease_owner_id TEXT NOT NULL DEFAULT ''",
                [],
            )
            .map_err(sqlite_error)?;
        connection
            .execute(
                r#"
                UPDATE security_response_effects AS effects
                SET scheduler_lease_owner_id = (
                    SELECT leases.lease_owner_id
                    FROM security_scheduler_leases AS leases
                    WHERE leases.tenant_id = effects.tenant_id
                      AND leases.action_id = effects.action_id
                      AND leases.fencing_token = effects.scheduler_fencing_token
                )
                WHERE scheduler_lease_owner_id = ''
                  AND EXISTS (
                    SELECT 1
                    FROM security_scheduler_leases AS leases
                    WHERE leases.tenant_id = effects.tenant_id
                      AND leases.action_id = effects.action_id
                      AND leases.fencing_token = effects.scheduler_fencing_token
                  )
                "#,
                [],
            )
            .map_err(sqlite_error)?;
    }
    let unresolved_owner: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM security_response_effects WHERE scheduler_lease_owner_id IS NULL OR scheduler_lease_owner_id = '')",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if unresolved_owner {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

fn ensure_scheduler_retry_health_columns(connection: &Connection) -> PortResult<()> {
    let mut statement = connection
        .prepare("PRAGMA table_info(security_scheduler_retries)")
        .map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    let mut first_failure_exists = false;
    let mut health_event_id_exists = false;
    let mut health_event_delivered_exists = false;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let name: String = row.get(1).map_err(sqlite_error)?;
        match name.as_str() {
            "first_failure_at" => first_failure_exists = true,
            "health_event_id" => health_event_id_exists = true,
            "health_event_delivered" => health_event_delivered_exists = true,
            _ => {}
        }
    }
    drop(rows);
    drop(statement);
    if !first_failure_exists {
        connection
            .execute(
                "ALTER TABLE security_scheduler_retries ADD COLUMN first_failure_at INTEGER NOT NULL DEFAULT 0",
                [],
            )
            .map_err(sqlite_error)?;
    }
    if !health_event_id_exists {
        connection
            .execute(
                "ALTER TABLE security_scheduler_retries ADD COLUMN health_event_id TEXT",
                [],
            )
            .map_err(sqlite_error)?;
    }
    if !health_event_delivered_exists {
        connection
            .execute(
                "ALTER TABLE security_scheduler_retries ADD COLUMN health_event_delivered INTEGER NOT NULL DEFAULT 0 CHECK (health_event_delivered IN (0, 1))",
                [],
            )
            .map_err(sqlite_error)?;
    }
    Ok(())
}

fn sqlite_error(error: rusqlite::Error) -> PortError {
    match error {
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            PortError::conflict()
        }
        rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::IntegralValueOutOfRange(..)
        | rusqlite::Error::InvalidColumnType(..) => PortError::integrity_failure(),
        rusqlite::Error::ToSqlConversionFailure(_) => PortError::invalid_data(),
        _ => PortError::unavailable(),
    }
}

fn to_i64(value: u64) -> PortResult<i64> {
    i64::try_from(value).map_err(|_| PortError::invalid_data())
}

fn from_i64(value: i64) -> PortResult<u64> {
    u64::try_from(value).map_err(|_| PortError::integrity_failure())
}

fn body_hash(body: &[u8]) -> [u8; 32] {
    let hash = sha256(body);
    let mut result = [0_u8; 32];
    result.copy_from_slice(hash.as_ref());
    result
}

fn validate_body(body: &CanonicalBody, expected: &Digest32) -> PortResult<()> {
    if body_hash(body.as_bytes()).as_slice() != expected.as_bytes() {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

fn validate_canonical_json_body(body: &CanonicalBody, expected: &Digest32) -> PortResult<()> {
    validate_body(body, expected)?;
    let value: serde_json::Value =
        serde_json::from_slice(body.as_bytes()).map_err(|_| PortError::invalid_data())?;
    let canonical = canonical_json_bytes(&value).map_err(|_| PortError::invalid_data())?;
    if canonical.as_slice() != body.as_bytes() {
        return Err(PortError::invalid_data());
    }
    Ok(())
}

fn decode_digest(bytes: Vec<u8>) -> PortResult<Digest32> {
    let value: [u8; 32] = bytes
        .try_into()
        .map_err(|_| PortError::integrity_failure())?;
    Ok(Digest32::new(value))
}

fn canonical_request_hash<T: serde::Serialize>(value: &T) -> PortResult<[u8; 32]> {
    let canonical = canonical_json_bytes(value).map_err(|_| PortError::invalid_data())?;
    Ok(body_hash(canonical.as_ref()))
}

fn validate_encrypted_blob_reference(
    connection: &Connection,
    tenant_id: &str,
    reference: &RecordId,
) -> PortResult<()> {
    let lengths: Option<(i64, i64)> = connection
        .query_row(
            r#"
            SELECT length(nonce), length(ciphertext) FROM chio_encrypted_blobs
            WHERE blob_id = ?1 AND tenant_id = ?2
            "#,
            params![reference.as_str(), tenant_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((nonce_length, ciphertext_length)) = lengths else {
        return Err(PortError::invalid_data());
    };
    if nonce_length != 12 || ciphertext_length < 16 {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

fn encode_label(label: &InformationLabel) -> PortResult<(Vec<u8>, [u8; 32])> {
    let body = canonical_json_bytes(label).map_err(|_| PortError::invalid_data())?;
    let hash = body_hash(body.as_ref());
    Ok((body, hash))
}

fn decode_label(body: Vec<u8>, stored_hash: Vec<u8>) -> PortResult<InformationLabel> {
    let hash = decode_digest(stored_hash)?;
    if body_hash(&body).as_slice() != hash.as_bytes() {
        return Err(PortError::integrity_failure());
    }
    let label: InformationLabel =
        serde_json::from_slice(&body).map_err(|_| PortError::integrity_failure())?;
    let canonical = canonical_json_bytes(&label).map_err(|_| PortError::integrity_failure())?;
    if canonical.as_slice() != body.as_slice() {
        return Err(PortError::integrity_failure());
    }
    Ok(label)
}

fn transition_status(
    connection: &Connection,
    tenant_id: &str,
    transition_id: &str,
    kind: &str,
    request_hash: &[u8; 32],
) -> PortResult<bool> {
    let existing: Option<(String, String, Vec<u8>)> = connection
        .query_row(
            "SELECT tenant_id, transition_kind, request_hash FROM security_transitions WHERE tenant_id = ?1 AND transition_id = ?2",
            params![tenant_id, transition_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    if let Some((existing_tenant, existing_kind, existing_hash)) = existing {
        if existing_tenant == tenant_id
            && existing_kind == kind
            && existing_hash.as_slice() == request_hash
        {
            return Ok(true);
        }
        return Err(PortError::conflict());
    }
    Ok(false)
}

fn record_transition(
    connection: &Connection,
    tenant_id: &str,
    transition_id: &str,
    kind: &str,
    request_hash: &[u8; 32],
) -> PortResult<()> {
    connection
        .execute(
            "INSERT INTO security_transitions (transition_id, tenant_id, transition_kind, request_hash) VALUES (?1, ?2, ?3, ?4)",
            params![transition_id, tenant_id, kind, request_hash.as_slice()],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

type StoredLabel = (Vec<u8>, Vec<u8>, i64);

fn load_principal_label(
    connection: &Connection,
    key: &FlowStateKey,
) -> PortResult<Option<(InformationLabel, u64)>> {
    let stored: Option<StoredLabel> = connection
        .query_row(
            r#"
            SELECT label_json, label_hash, generation
            FROM security_principal_flow_state
            WHERE tenant_id = ?1 AND principal_id = ?2 AND isolation_epoch_id = ?3
            "#,
            params![
                key.tenant_id.as_str(),
                key.principal_id.as_str(),
                key.isolation_epoch_id.as_str()
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    stored
        .map(|(body, hash, generation)| Ok((decode_label(body, hash)?, from_i64(generation)?)))
        .transpose()
}

fn load_lineage_label(
    connection: &Connection,
    key: &FlowStateKey,
) -> PortResult<Option<(InformationLabel, u64)>> {
    let stored: Option<StoredLabel> = connection
        .query_row(
            r#"
            SELECT label_json, label_hash, generation
            FROM security_lineage_flow_state
            WHERE tenant_id = ?1 AND lineage_id = ?2
            "#,
            params![key.tenant_id.as_str(), key.lineage_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    stored
        .map(|(body, hash, generation)| Ok((decode_label(body, hash)?, from_i64(generation)?)))
        .transpose()
}

fn load_session_label(
    connection: &Connection,
    key: &FlowStateKey,
) -> PortResult<Option<(InformationLabel, u64)>> {
    let stored: Option<StoredLabel> = connection
        .query_row(
            r#"
            SELECT label_json, label_hash, generation
            FROM security_session_flow_state
            WHERE tenant_id = ?1 AND principal_id = ?2
              AND session_id = ?3 AND isolation_epoch_id = ?4
            "#,
            params![
                key.tenant_id.as_str(),
                key.principal_id.as_str(),
                key.session_id.as_str(),
                key.isolation_epoch_id.as_str()
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    stored
        .map(|(body, hash, generation)| Ok((decode_label(body, hash)?, from_i64(generation)?)))
        .transpose()
}

fn load_context_generation(connection: &Connection, key: &FlowStateKey) -> PortResult<Option<u64>> {
    let generation: Option<i64> = connection
        .query_row(
            r#"
            SELECT generation FROM security_flow_contexts
            WHERE tenant_id = ?1 AND principal_id = ?2 AND lineage_id = ?3
              AND session_id = ?4 AND isolation_epoch_id = ?5
            "#,
            params![
                key.tenant_id.as_str(),
                key.principal_id.as_str(),
                key.lineage_id.as_str(),
                key.session_id.as_str(),
                key.isolation_epoch_id.as_str()
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    generation.map(from_i64).transpose()
}

fn session_membership_exists(connection: &Connection, key: &FlowStateKey) -> PortResult<bool> {
    connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM security_session_memberships
                WHERE tenant_id = ?1 AND principal_id = ?2
                  AND session_id = ?3 AND isolation_epoch_id = ?4
            )
            "#,
            params![
                key.tenant_id.as_str(),
                key.principal_id.as_str(),
                key.session_id.as_str(),
                key.isolation_epoch_id.as_str()
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}

fn isolation_epoch_exists(connection: &Connection, key: &FlowStateKey) -> PortResult<bool> {
    connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM security_isolation_epochs
                WHERE tenant_id = ?1 AND principal_id = ?2 AND lineage_id = ?3
                  AND isolation_epoch_id = ?4
            )
            "#,
            params![
                key.tenant_id.as_str(),
                key.principal_id.as_str(),
                key.lineage_id.as_str(),
                key.isolation_epoch_id.as_str()
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}
