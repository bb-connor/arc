// tenant-read-contract: security_attested_finding_response_outbox; class=tenant-predicate; principal=security-runtime
#[cfg(target_os = "macos")]
use super::security_state_lifecycle_lock_path;
use super::{
    from_i64, params, scheduler_lease_body_hash, schema_object_definition_is_exact, sqlite_error,
    table_definition_is_exact, table_has_foreign_key_violation, ActionId, BTreeSet, Connection,
    LeaseOwnerId, PortError, PortResult, RecordId, TenantId,
};

pub(super) const ATTESTED_FINDING_RESPONSE_OUTBOX_CANONICAL_DDL: &str = r#"
CREATE TABLE security_attested_finding_response_outbox (
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
        completion_state IN ('not_started', 'pending', 'outcome_unknown_after_dispatch', 'completed', 'simulated')
    ),
    execution_dispatch_id TEXT CHECK (
        execution_dispatch_id IS NULL OR trim(execution_dispatch_id, '0') != ''
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
        completion_evidence_id IS NULL OR trim(completion_evidence_id, '0') != ''
    ),
    completion_evidence_body_hash BLOB CHECK (
        completion_evidence_body_hash IS NULL
        OR (length(completion_evidence_body_hash) = 32
            AND completion_evidence_body_hash != zeroblob(32))
    ),
    plan_body BLOB CHECK (plan_body IS NULL OR length(plan_body) <= 1048576),
    plan_body_hash BLOB CHECK (
        plan_body_hash IS NULL
        OR (length(plan_body_hash) = 32 AND plan_body_hash != zeroblob(32))
    ),
    admission_artifact_ref TEXT CHECK (
        admission_artifact_ref IS NULL OR trim(admission_artifact_ref, '0') != ''
    ),
    admission_artifact_digest BLOB CHECK (
        admission_artifact_digest IS NULL
        OR (length(admission_artifact_digest) = 32
            AND admission_artifact_digest != zeroblob(32))
    ),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0 AND attempts <= 1000000),
    next_attempt_at INTEGER NOT NULL DEFAULT 0 CHECK (next_attempt_at >= 0),
    last_error_code TEXT,
    CHECK (
        (planning_state = 'pending' AND plan_body IS NULL AND plan_body_hash IS NULL
            AND admission_artifact_ref IS NULL AND admission_artifact_digest IS NULL)
        OR (planning_state = 'planned' AND plan_body IS NOT NULL AND plan_body_hash IS NOT NULL
            AND admission_artifact_ref IS NOT NULL)
        OR (planning_state = 'failed' AND plan_body IS NULL AND plan_body_hash IS NULL
            AND admission_artifact_ref IS NULL AND admission_artifact_digest IS NULL)
    ),
    CHECK (
        (admission_state = 'pending' AND execution_dispatch_id IS NULL
            AND prepared_dispatch_binding IS NULL AND completion_state IN ('not_started', 'simulated'))
        OR (admission_state = 'prepared' AND execution_dispatch_id IS NOT NULL
            AND prepared_dispatch_binding IS NOT NULL AND admission_artifact_digest IS NOT NULL
            AND completion_state IN ('pending', 'outcome_unknown_after_dispatch', 'completed'))
        OR (admission_state IN ('rejected', 'expired') AND execution_dispatch_id IS NULL
            AND prepared_dispatch_binding IS NULL AND completion_state = 'not_started')
        OR (admission_state = 'expired' AND execution_dispatch_id IS NOT NULL
            AND prepared_dispatch_binding IS NOT NULL AND admission_artifact_digest IS NOT NULL
            AND completion_state = 'not_started')
    ),
    CHECK (
        (prepared_dispatch_binding IS NULL AND prepared_dispatch_binding_hash IS NULL)
        OR (prepared_dispatch_binding IS NOT NULL
            AND prepared_dispatch_binding_hash IS NOT NULL)
    ),
    CHECK (planning_state = 'planned' OR admission_state != 'prepared'),
    CHECK (
        (completion_state = 'completed' AND completion_outcome IS NOT NULL
            AND completion_evidence_id IS NOT NULL
            AND completion_evidence_body_hash IS NOT NULL)
        OR (completion_state = 'simulated' AND completion_outcome IS NULL
            AND completion_evidence_id IS NOT NULL AND completion_evidence_body_hash IS NOT NULL
            AND admission_artifact_digest IS NOT NULL AND planning_state = 'planned')
        OR (completion_state NOT IN ('completed', 'simulated') AND completion_outcome IS NULL
            AND completion_evidence_id IS NULL
            AND completion_evidence_body_hash IS NULL)
    ),
    PRIMARY KEY (tenant_id, action_id),
    UNIQUE (tenant_id, batch_id, ordinal),
    UNIQUE (tenant_id, reservation_id),
    UNIQUE (tenant_id, execution_dispatch_id),
    FOREIGN KEY (tenant_id, batch_id, ordinal)
        REFERENCES security_attested_finding_batch_items (tenant_id, batch_id, ordinal)
)
"#;
pub(super) const ATTESTED_FINDING_RESPONSE_OUTBOX_DUE_INDEX_DDL: &str = r#"
CREATE INDEX security_attested_finding_response_outbox_due
ON security_attested_finding_response_outbox (
    planning_state, admission_state, completion_state,
    next_attempt_at, attempts, tenant_id, action_id
)
"#;
pub(super) const ATTESTED_FINDING_RESPONSE_OUTBOX_IMMUTABLE_TRIGGER_DDL: &str = r#"
CREATE TRIGGER security_attested_finding_response_outbox_immutable
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
      AND NOT (NEW.admission_state = 'expired' AND NEW.completion_state = 'not_started'))
  OR (OLD.completion_state = 'outcome_unknown_after_dispatch'
      AND NEW.completion_state NOT IN ('outcome_unknown_after_dispatch', 'completed')
      AND NOT (NEW.admission_state = 'expired' AND NEW.completion_state = 'not_started'))
  OR (OLD.completion_state = 'simulated' AND NEW.completion_state != 'simulated')
  OR (OLD.completion_state = 'completed'
      AND NEW.completion_state != 'completed')
BEGIN
    SELECT RAISE(ABORT, 'attested finding response outbox state is immutable or monotonic');
END
"#;
pub(super) const ATTESTED_FINDING_RESPONSE_OUTBOX_DELETE_TRIGGER_DDL: &str = r#"
CREATE TRIGGER security_attested_finding_response_outbox_delete_rejected
BEFORE DELETE ON security_attested_finding_response_outbox
BEGIN
    SELECT RAISE(ABORT, 'attested finding response outbox deletion is rejected');
END
"#;

pub(super) fn ensure_lineage_fence_binding_columns(connection: &Connection) -> PortResult<()> {
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

pub(super) fn ensure_response_effect_generation_column(connection: &Connection) -> PortResult<()> {
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

pub(super) fn ensure_scheduler_lease_body_hash_column(connection: &Connection) -> PortResult<()> {
    let mut statement = connection
        .prepare("PRAGMA table_info(security_scheduler_leases)")
        .map_err(sqlite_error)?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(sqlite_error)?
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(sqlite_error)?;
    drop(statement);
    let body_hash_exists = columns.contains("lease_body_hash");
    if !body_hash_exists {
        connection
            .execute(
                "ALTER TABLE security_scheduler_leases ADD COLUMN lease_body_hash BLOB",
                [],
            )
            .map_err(sqlite_error)?;
    }

    type StoredLeaseBody = (
        String,
        String,
        String,
        i64,
        String,
        i64,
        i64,
        Option<Vec<u8>>,
    );
    let mut statement = connection
        .prepare(
            r#"
            SELECT tenant_id, action_id, claim_id, claim_ordinal,
                   lease_owner_id, lease_expires_at, fencing_token,
                   lease_body_hash
            FROM security_scheduler_leases
            ORDER BY tenant_id, action_id
            "#,
        )
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
            ))
        })
        .map_err(sqlite_error)?;
    let mut leases = Vec::<StoredLeaseBody>::new();
    for row in rows {
        leases.push(row.map_err(sqlite_error)?);
    }
    drop(statement);

    for (
        tenant_id,
        action_id,
        claim_id,
        claim_ordinal,
        lease_owner_id,
        lease_expires_at,
        fencing_token,
        stored_hash,
    ) in leases
    {
        TenantId::new(tenant_id.clone()).map_err(|_| PortError::integrity_failure())?;
        ActionId::new(action_id.clone()).map_err(|_| PortError::integrity_failure())?;
        RecordId::new(claim_id.clone()).map_err(|_| PortError::integrity_failure())?;
        LeaseOwnerId::new(lease_owner_id.clone()).map_err(|_| PortError::integrity_failure())?;
        let claim_ordinal = from_i64(claim_ordinal)?;
        let lease_expires_at = from_i64(lease_expires_at)?;
        let fencing_token = from_i64(fencing_token)?;
        if lease_expires_at == 0 || fencing_token == 0 {
            return Err(PortError::integrity_failure());
        }
        let expected_hash = scheduler_lease_body_hash(
            &tenant_id,
            &action_id,
            &claim_id,
            claim_ordinal,
            &lease_owner_id,
            lease_expires_at,
            fencing_token,
        )?;
        if body_hash_exists {
            let stored_hash = stored_hash.ok_or_else(PortError::integrity_failure)?;
            if stored_hash.as_slice() != expected_hash.as_slice() {
                return Err(PortError::integrity_failure());
            }
        } else {
            let updated = connection
                .execute(
                    r#"
                    UPDATE security_scheduler_leases
                    SET lease_body_hash = ?3
                    WHERE tenant_id = ?1 AND action_id = ?2
                      AND lease_body_hash IS NULL
                    "#,
                    params![tenant_id, action_id, expected_hash.as_slice()],
                )
                .map_err(sqlite_error)?;
            if updated != 1 {
                return Err(PortError::integrity_failure());
            }
        }
    }
    let invalid_hash_exists = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM security_scheduler_leases
                WHERE lease_body_hash IS NULL OR length(lease_body_hash) != 32
            )
            "#,
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(sqlite_error)?;
    if invalid_hash_exists {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

pub(super) fn ensure_scheduler_retry_health_columns(connection: &Connection) -> PortResult<()> {
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

pub(super) fn ensure_response_dispatch_commit_mode_column(
    connection: &Connection,
) -> PortResult<()> {
    let mut statement = connection
        .prepare("PRAGMA table_info(security_response_dispatches)")
        .map_err(sqlite_error)?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    drop(statement);
    if !columns.iter().any(|column| column == "commit_mode") {
        connection
            .execute(
                "ALTER TABLE security_response_dispatches ADD COLUMN commit_mode TEXT NOT NULL DEFAULT 'fresh' CHECK (commit_mode IN ('fresh', 'governed_committed_resume', 'governed_committed_expired_resume'))",
                [],
            )
            .map_err(sqlite_error)?;
    }
    let invalid: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM security_response_dispatches WHERE commit_mode NOT IN ('fresh', 'governed_committed_resume', 'governed_committed_expired_resume')",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if invalid != 0 {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

pub(super) fn ensure_attested_finding_response_outbox_schema(
    connection: &Connection,
) -> PortResult<()> {
    let table_ddl = ATTESTED_FINDING_RESPONSE_OUTBOX_CANONICAL_DDL.replacen(
        "CREATE TABLE ",
        "CREATE TABLE IF NOT EXISTS ",
        1,
    );
    let index_ddl = ATTESTED_FINDING_RESPONSE_OUTBOX_DUE_INDEX_DDL.replacen(
        "CREATE INDEX ",
        "CREATE INDEX IF NOT EXISTS ",
        1,
    );
    let immutable_trigger_ddl = ATTESTED_FINDING_RESPONSE_OUTBOX_IMMUTABLE_TRIGGER_DDL.replacen(
        "CREATE TRIGGER ",
        "CREATE TRIGGER IF NOT EXISTS ",
        1,
    );
    let delete_trigger_ddl = ATTESTED_FINDING_RESPONSE_OUTBOX_DELETE_TRIGGER_DDL.replacen(
        "CREATE TRIGGER ",
        "CREATE TRIGGER IF NOT EXISTS ",
        1,
    );
    connection
        .execute_batch(&format!(
            "{};{};{};{};",
            table_ddl, index_ddl, immutable_trigger_ddl, delete_trigger_ddl,
        ))
        .map_err(sqlite_error)?;
    if connection
        .execute(
            r#"
            INSERT INTO security_attested_finding_response_outbox (
                tenant_id, batch_id, ordinal, evidence_id, finding_id,
                finding_hash, action_id, reservation_id, planning_state,
                admission_state, completion_state
            )
            SELECT item.tenant_id, item.batch_id, item.ordinal, item.evidence_id,
                   item.finding_id, item.finding_hash, item.action_id,
                   item.reservation_id, 'pending', 'pending', 'not_started'
            FROM security_attested_finding_batch_items AS item
            WHERE NOT EXISTS (
                SELECT 1
                FROM security_attested_finding_response_outbox AS outbox
                WHERE outbox.tenant_id = item.tenant_id
                  AND outbox.action_id = item.action_id
            )
            "#,
            [],
        )
        .is_err()
    {
        return Err(PortError::integrity_failure());
    }
    if !table_definition_is_exact(
        connection,
        "security_attested_finding_response_outbox",
        ATTESTED_FINDING_RESPONSE_OUTBOX_CANONICAL_DDL,
    )? || !schema_object_definition_is_exact(
        connection,
        "index",
        "security_attested_finding_response_outbox_due",
        ATTESTED_FINDING_RESPONSE_OUTBOX_DUE_INDEX_DDL,
    )? || !schema_object_definition_is_exact(
        connection,
        "trigger",
        "security_attested_finding_response_outbox_immutable",
        ATTESTED_FINDING_RESPONSE_OUTBOX_IMMUTABLE_TRIGGER_DDL,
    )? || !schema_object_definition_is_exact(
        connection,
        "trigger",
        "security_attested_finding_response_outbox_delete_rejected",
        ATTESTED_FINDING_RESPONSE_OUTBOX_DELETE_TRIGGER_DDL,
    )? || table_has_foreign_key_violation(
        connection,
        "security_attested_finding_response_outbox",
    )? || !attested_finding_response_outbox_is_one_to_one(connection)?
    {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

pub(super) fn attested_finding_response_outbox_is_one_to_one(
    connection: &Connection,
) -> PortResult<bool> {
    let (batch_items, outbox_rows, exact_matches): (i64, i64, i64) = connection
        .query_row(
            r#"
            SELECT
                (SELECT COUNT(*) FROM security_attested_finding_batch_items),
                (SELECT COUNT(*) FROM security_attested_finding_response_outbox),
                (
                    SELECT COUNT(*)
                    FROM security_attested_finding_batch_items AS item
                    JOIN security_attested_finding_response_outbox AS outbox
                      ON outbox.tenant_id = item.tenant_id
                     AND outbox.batch_id = item.batch_id
                     AND outbox.ordinal = item.ordinal
                     AND outbox.evidence_id = item.evidence_id
                     AND outbox.finding_id = item.finding_id
                     AND outbox.finding_hash = item.finding_hash
                     AND outbox.action_id = item.action_id
                     AND outbox.reservation_id = item.reservation_id
                )
            "#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(sqlite_error)?;
    Ok(batch_items == outbox_rows && batch_items == exact_matches)
}
