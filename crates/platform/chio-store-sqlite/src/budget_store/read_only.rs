use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use chio_kernel::budget_store::PartitionEscrowCommitEvidence;
use chio_kernel::{BudgetStoreError, BudgetStoreProfile};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use super::SqliteBudgetStore;

const READ_ONLY_BUDGET_SCHEMA_VERSION: i32 = 1;
const READ_ONLY_BUDGET_SCHEMA_KEY: &str = "budget";
const CURRENT_PARTITION_ESCROW_INSERT_GUARD: &str = r#"
CREATE TRIGGER budget_partition_escrow_evidence_insert_guard
BEFORE INSERT ON budget_composite_partition_escrow_evidence
WHEN NOT EXISTS (
    SELECT 1 FROM budget_composite_authorizations
    WHERE hold_id = NEW.hold_id
) OR NOT EXISTS (
    SELECT 1 FROM budget_composite_authorization_artifacts
    WHERE hold_id = NEW.hold_id AND artifact_digest = NEW.evidence_digest
)
BEGIN
    SELECT RAISE(ABORT, 'partition escrow evidence lacks authorization binding');
END
"#;

const REQUIRED_REPLAY_TRIGGERS: &[(&str, &str)] = &[
    (
        "budget_composite_managed_grant_insert_guard",
        r#"
        CREATE TRIGGER budget_composite_managed_grant_insert_guard
        BEFORE INSERT ON budget_composite_managed_grants
        WHEN NOT EXISTS (
            SELECT 1 FROM budget_composite_authorizations
            WHERE hold_id = NEW.first_hold_id
              AND capability_id = NEW.capability_id
              AND grant_index = NEW.grant_index
        )
        BEGIN
            SELECT RAISE(ABORT, 'managed grant requires its composite authorization');
        END
        "#,
    ),
    (
        "budget_composite_managed_grant_update_forbidden",
        r#"
        CREATE TRIGGER budget_composite_managed_grant_update_forbidden
        BEFORE UPDATE ON budget_composite_managed_grants
        BEGIN
            SELECT RAISE(ABORT, 'immutable composite grant authority');
        END
        "#,
    ),
    (
        "budget_composite_managed_grant_delete_forbidden",
        r#"
        CREATE TRIGGER budget_composite_managed_grant_delete_forbidden
        BEFORE DELETE ON budget_composite_managed_grants
        BEGIN
            SELECT RAISE(ABORT, 'immutable composite grant authority');
        END
        "#,
    ),
    (
        "budget_composite_authorization_immutable",
        r#"
        CREATE TRIGGER budget_composite_authorization_immutable
        BEFORE UPDATE ON budget_composite_authorizations
        BEGIN
            SELECT RAISE(ABORT, 'immutable composite authorization');
        END
        "#,
    ),
    (
        "budget_composite_authorization_delete_forbidden",
        r#"
        CREATE TRIGGER budget_composite_authorization_delete_forbidden
        BEFORE DELETE ON budget_composite_authorizations
        BEGIN
            SELECT RAISE(ABORT, 'immutable composite authorization');
        END
        "#,
    ),
    (
        "budget_composite_authorization_quota_immutable",
        r#"
        CREATE TRIGGER budget_composite_authorization_quota_immutable
        BEFORE UPDATE ON budget_composite_authorization_quotas
        BEGIN
            SELECT RAISE(ABORT, 'immutable composite authorization quota snapshot');
        END
        "#,
    ),
    (
        "budget_composite_authorization_quota_delete_forbidden",
        r#"
        CREATE TRIGGER budget_composite_authorization_quota_delete_forbidden
        BEFORE DELETE ON budget_composite_authorization_quotas
        BEGIN
            SELECT RAISE(ABORT, 'immutable composite authorization quota snapshot');
        END
        "#,
    ),
    (
        "budget_composite_authorization_artifact_immutable",
        r#"
        CREATE TRIGGER budget_composite_authorization_artifact_immutable
        BEFORE UPDATE ON budget_composite_authorization_artifacts
        BEGIN
            SELECT RAISE(ABORT, 'immutable composite authorization artifact');
        END
        "#,
    ),
    (
        "budget_composite_authorization_artifact_delete_forbidden",
        r#"
        CREATE TRIGGER budget_composite_authorization_artifact_delete_forbidden
        BEFORE DELETE ON budget_composite_authorization_artifacts
        BEGIN
            SELECT RAISE(ABORT, 'immutable composite authorization artifact');
        END
        "#,
    ),
    (
        "budget_partition_escrow_evidence_update_forbidden",
        r#"
        CREATE TRIGGER budget_partition_escrow_evidence_update_forbidden
        BEFORE UPDATE ON budget_composite_partition_escrow_evidence
        BEGIN
            SELECT RAISE(ABORT, 'immutable partition escrow authorization evidence');
        END
        "#,
    ),
    (
        "budget_partition_escrow_evidence_delete_forbidden",
        r#"
        CREATE TRIGGER budget_partition_escrow_evidence_delete_forbidden
        BEFORE DELETE ON budget_composite_partition_escrow_evidence
        BEGIN
            SELECT RAISE(ABORT, 'immutable partition escrow authorization evidence');
        END
        "#,
    ),
    (
        "budget_authorization_hold_admission_owner_immutable",
        r#"
        CREATE TRIGGER budget_authorization_hold_admission_owner_immutable
        BEFORE UPDATE OF operation_id, request_binding_hash
        ON budget_authorization_holds
        WHEN OLD.operation_id IS NOT NEW.operation_id
          OR OLD.request_binding_hash IS NOT NEW.request_binding_hash
        BEGIN
            SELECT RAISE(ABORT, 'immutable budget hold admission owner');
        END
        "#,
    ),
    (
        "budget_mutation_event_admission_owner_immutable",
        r#"
        CREATE TRIGGER budget_mutation_event_admission_owner_immutable
        BEFORE UPDATE OF operation_id, request_binding_hash
        ON budget_mutation_events
        WHEN OLD.operation_id IS NOT NEW.operation_id
          OR OLD.request_binding_hash IS NOT NEW.request_binding_hash
        BEGIN
            SELECT RAISE(ABORT, 'immutable budget mutation admission owner');
        END
        "#,
    ),
    (
        "budget_composite_hold_admission_owner_immutable",
        r#"
        CREATE TRIGGER budget_composite_hold_admission_owner_immutable
        BEFORE UPDATE OF operation_id, request_binding_hash
        ON budget_composite_holds
        WHEN OLD.operation_id IS NOT NEW.operation_id
          OR OLD.request_binding_hash IS NOT NEW.request_binding_hash
        BEGIN
            SELECT RAISE(ABORT, 'immutable composite hold admission owner');
        END
        "#,
    ),
    (
        "budget_composite_mutation_owner_immutable",
        r#"
        CREATE TRIGGER budget_composite_mutation_owner_immutable
        BEFORE UPDATE OF operation_id, request_binding_hash
        ON budget_composite_mutation_snapshots
        WHEN OLD.operation_id IS NOT NEW.operation_id
          OR OLD.request_binding_hash IS NOT NEW.request_binding_hash
        BEGIN
            SELECT RAISE(ABORT, 'immutable composite mutation admission owner');
        END
        "#,
    ),
    (
        "payment_journal_recovery_binding_immutable",
        r#"
        CREATE TRIGGER payment_journal_recovery_binding_immutable
        BEFORE UPDATE OF operation_id, request_binding_hash, authority_id, lease_id, lease_epoch,
                         budget_exposure_units
        ON payment_journal
        WHEN OLD.operation_id IS NOT NEW.operation_id
          OR OLD.request_binding_hash IS NOT NEW.request_binding_hash
          OR OLD.authority_id IS NOT NEW.authority_id
          OR OLD.lease_id IS NOT NEW.lease_id
          OR OLD.lease_epoch IS NOT NEW.lease_epoch
          OR OLD.budget_exposure_units IS NOT NEW.budget_exposure_units
        BEGIN
            SELECT RAISE(ABORT, 'immutable payment journal recovery binding');
        END
        "#,
    ),
];

const REQUIRED_REPLAY_TABLES: &[&str] = &[
    "admission_capture_events",
    "budget_authorization_claims",
    "budget_authorization_holds",
    "budget_composite_authorization_artifacts",
    "budget_composite_authorization_quotas",
    "budget_composite_authorizations",
    "budget_composite_holds",
    "budget_composite_managed_grants",
    "budget_composite_mutation_quota_snapshots",
    "budget_composite_mutation_snapshots",
    "budget_composite_partition_escrow_evidence",
    "budget_mutation_events",
    "chio_store_schema_versions",
    "payment_journal",
];

const REPLAY_SCHEMA_PROBES: &[&str] = &[
    r#"
    SELECT event_id, hold_id, operation_id, request_binding_hash,
           capability_id, grant_index, kind, allowed, recorded_at,
           event_seq, usage_seq, exposure_units, realized_spend_units,
           max_invocations, max_exposure_per_invocation,
           max_total_exposure_units, invocation_count_after,
           total_cost_exposed_after, total_cost_realized_spend_after,
           authority_id, lease_id, lease_epoch
    FROM budget_mutation_events WHERE 0
    "#,
    r#"
    SELECT hold_id, event_id, operation_id, request_binding_hash,
           capability_id, grant_index, requested_exposure_units,
           max_cost_per_invocation, max_total_cost_units,
           authority_id, lease_id, lease_epoch, allowed,
           invocation_state, monetary_state, revocation_set_digest,
           revocation_ids_json, aggregate_root_capability_id,
           aggregate_root_binding_digest, committed_cost_units_after,
           invocation_count_after, event_seq
    FROM budget_composite_authorizations WHERE 0
    "#,
    r#"
    SELECT hold_id, position, profile, owner_id, grant_index_key,
           max_invocations, reserved_invocations_after,
           captured_invocations_after
    FROM budget_composite_authorization_quotas WHERE 0
    "#,
    r#"
    SELECT hold_id, position, artifact_digest
    FROM budget_composite_authorization_artifacts WHERE 0
    "#,
    r#"
    SELECT hold_id, evidence_digest, canonical_evidence
    FROM budget_composite_partition_escrow_evidence WHERE 0
    "#,
    r#"
    SELECT event_id, operation_id, request_binding_hash,
           invocation_state, monetary_state, revocation_set_digest,
           revocation_ids_json
    FROM budget_composite_mutation_snapshots WHERE 0
    "#,
    r#"
    SELECT event_id, position, profile, owner_id, grant_index_key,
           max_invocations, reserved_invocations_after,
           captured_invocations_after
    FROM budget_composite_mutation_quota_snapshots WHERE 0
    "#,
    r#"
    SELECT hold_id, operation_id, request_binding_hash, invocation_state,
           monetary_state, revocation_set_digest, revocation_ids_json,
           remaining_exposure_units, updated_at
    FROM budget_composite_holds WHERE 0
    "#,
    "SELECT capability_id, grant_index, first_hold_id FROM budget_composite_managed_grants WHERE 0",
    "SELECT hold_id, event_id FROM budget_authorization_claims WHERE 0",
    "SELECT hold_id, operation_id FROM budget_authorization_holds WHERE 0",
    r#"
    SELECT operation_id, request_binding_hash, capture_event_id, hold_id,
           capability_id, grant_index, authority_id, lease_id, lease_epoch,
           revocation_set_digest, revocation_ids_json, artifact_digests_json,
           aggregate_root_capability_id, aggregate_root_binding_digest,
           last_observed_revocation_index, outcome, revoked_ids_json,
           revocation_commit_index, authority_commit_index,
           budget_commit_index, recorded_at
    FROM admission_capture_events WHERE 0
    "#,
    "SELECT request_id, operation_id, hold_id FROM payment_journal WHERE 0",
];

impl SqliteBudgetStore {
    /// Open an existing budget database for committed replay queries only.
    ///
    /// This path cannot create, migrate, repair, or change the journal mode of
    /// the database. Schema v0 is deliberately rejected so replay never turns
    /// into an implicit authority migration.
    pub fn open_existing_read_only(path: impl AsRef<Path>) -> Result<Self, BudgetStoreError> {
        let path = path.as_ref();
        validate_existing_budget_file(path)?;
        let directory = crate::durable_sqlite::TrustedSqliteDirectory::open_for_database(path)
            .map_err(|error| BudgetStoreError::Invariant(error.to_string()))?;
        let database_identity_file = directory
            .open_existing_database_read_only(path)
            .map_err(|error| BudgetStoreError::Invariant(error.to_string()))?;
        let connection = database_identity_file
            .open_read_only_connection()
            .map_err(|error| BudgetStoreError::Invariant(error.to_string()))?;
        configure_read_only_budget_connection(&connection)?;
        validate_read_only_budget_schema(&connection)?;
        validate_read_only_budget_integrity(&connection)?;

        Ok(Self {
            connection: Mutex::new(connection),
            authority_profile: BudgetStoreProfile::SingleNodeDurable,
            database_identity_file: Some(database_identity_file),
        })
    }

    /// Check every durable namespace that can collide with a composite replay.
    pub fn composite_replay_namespace_exists(
        &self,
        hold_id: &str,
        event_id: &str,
        operation_id: &str,
    ) -> Result<bool, BudgetStoreError> {
        if hold_id.is_empty() || event_id.is_empty() || operation_id.is_empty() {
            return Err(BudgetStoreError::Invariant(
                "composite replay namespace query requires non-empty identifiers".to_string(),
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let exists = transaction.query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM budget_authorization_claims WHERE hold_id = ?1
                    OR event_id = ?2
                UNION ALL
                SELECT 1 FROM budget_authorization_holds
                WHERE hold_id = ?1 OR operation_id = ?3
                UNION ALL
                SELECT 1 FROM budget_composite_authorizations
                WHERE hold_id = ?1 OR event_id = ?2 OR operation_id = ?3
                UNION ALL
                SELECT 1 FROM budget_composite_authorization_quotas WHERE hold_id = ?1
                UNION ALL
                SELECT 1 FROM budget_composite_authorization_artifacts WHERE hold_id = ?1
                UNION ALL
                SELECT 1 FROM budget_composite_partition_escrow_evidence WHERE hold_id = ?1
                UNION ALL
                SELECT 1 FROM budget_composite_holds
                WHERE hold_id = ?1 OR operation_id = ?3
                UNION ALL
                SELECT 1 FROM budget_composite_managed_grants WHERE first_hold_id = ?1
                UNION ALL
                SELECT 1 FROM budget_composite_mutation_snapshots
                WHERE event_id = ?2 OR operation_id = ?3
                UNION ALL
                SELECT 1 FROM budget_composite_mutation_quota_snapshots WHERE event_id = ?2
                UNION ALL
                SELECT 1 FROM budget_mutation_events
                WHERE event_id = ?2 OR hold_id = ?1 OR operation_id = ?3
                UNION ALL
                SELECT 1 FROM admission_capture_events
                WHERE capture_event_id = ?2 OR hold_id = ?1 OR operation_id = ?3
                UNION ALL
                SELECT 1 FROM payment_journal
                WHERE request_id = ?2 OR hold_id = ?1 OR operation_id = ?3
            )
            "#,
            params![hold_id, event_id, operation_id],
            |row| row.get::<_, bool>(0),
        )?;
        transaction.rollback()?;
        Ok(exists)
    }

    /// Load the exact immutable partition evidence bound to a composite hold.
    /// The read-only opener has already validated schema, triggers, integrity,
    /// and WAL/query-only posture before this method can execute.
    pub fn query_partition_escrow_evidence_for_hold(
        &self,
        hold_id: &str,
    ) -> Result<Option<PartitionEscrowCommitEvidence>, BudgetStoreError> {
        if hold_id.is_empty() {
            return Err(BudgetStoreError::Invariant(
                "partition escrow replay query requires a non-empty hold id".to_string(),
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let row = transaction
            .query_row(
                r#"
                SELECT evidence_digest, canonical_evidence
                FROM budget_composite_partition_escrow_evidence
                WHERE hold_id = ?1
                "#,
                [hold_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?;
        transaction.rollback()?;
        row.map(|(digest, canonical)| {
            let canonical = String::from_utf8(canonical).map_err(|error| {
                BudgetStoreError::Invariant(format!(
                    "persisted partition escrow evidence is not UTF-8 JSON: {error}"
                ))
            })?;
            PartitionEscrowCommitEvidence::from_canonical_json(canonical, digest)
        })
        .transpose()
    }
}

fn validate_existing_budget_file(path: &Path) -> Result<(), BudgetStoreError> {
    let path_text = path.to_string_lossy();
    let lower = path_text.to_ascii_lowercase();
    let memory_uri = lower.starts_with("file:")
        && (lower.contains("?mode=memory") || lower.contains("&mode=memory"));
    if path_text.is_empty()
        || path_text == ":memory:"
        || memory_uri
        || lower.starts_with("file::memory:")
    {
        return Err(BudgetStoreError::Invariant(
            "committed replay requires an existing durable SQLite budget file".to_string(),
        ));
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(BudgetStoreError::Invariant(
            "committed replay budget path is not an existing regular file".to_string(),
        ));
    }
    Ok(())
}

fn configure_read_only_budget_connection(connection: &Connection) -> Result<(), BudgetStoreError> {
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.execute_batch(
        "PRAGMA query_only = ON; PRAGMA foreign_keys = ON; PRAGMA trusted_schema = OFF;",
    )?;
    let query_only: i64 = connection.query_row("PRAGMA query_only", [], |row| row.get(0))?;
    let foreign_keys: i64 = connection.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
    let trusted_schema: i64 =
        connection.query_row("PRAGMA trusted_schema", [], |row| row.get(0))?;
    let journal_mode: String = connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    if query_only != 1
        || foreign_keys != 1
        || trusted_schema != 0
        || !journal_mode.eq_ignore_ascii_case("wal")
    {
        return Err(BudgetStoreError::Invariant(
            "committed replay budget connection is not an exact query-only WAL reader".to_string(),
        ));
    }
    Ok(())
}

fn validate_read_only_budget_schema(connection: &Connection) -> Result<(), BudgetStoreError> {
    let application_id: i32 =
        connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    if application_id != crate::CHIO_SQLITE_APPLICATION_ID {
        return Err(BudgetStoreError::Invariant(format!(
            "committed replay database has application_id {application_id:#x}, expected {:#x}",
            crate::CHIO_SQLITE_APPLICATION_ID
        )));
    }
    let schema_versions_sql = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'chio_store_schema_versions'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let schema_versions_sql = schema_versions_sql
        .as_deref()
        .map(normalize_schema_sql)
        .ok_or_else(|| {
            BudgetStoreError::Invariant(
                "committed replay budget schema is missing exact version metadata".to_string(),
            )
        })?;
    if !schema_versions_sql.contains(&normalize_schema_sql("store_key TEXT PRIMARY KEY"))
        || !schema_versions_sql.contains(&normalize_schema_sql("version INTEGER NOT NULL"))
    {
        return Err(BudgetStoreError::Invariant(
            "committed replay budget version metadata does not match the v1 schema contract"
                .to_string(),
        ));
    }
    let (schema_version_rows, minimum_version, maximum_version): (i64, Option<i32>, Option<i32>) =
        connection.query_row(
            r#"
        SELECT COUNT(*), MIN(version), MAX(version)
        FROM chio_store_schema_versions WHERE store_key = ?1
        "#,
            [READ_ONLY_BUDGET_SCHEMA_KEY],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
    if schema_version_rows != 1
        || minimum_version != Some(READ_ONLY_BUDGET_SCHEMA_VERSION)
        || maximum_version != Some(READ_ONLY_BUDGET_SCHEMA_VERSION)
    {
        return Err(BudgetStoreError::Invariant(format!(
            "committed replay requires exactly one budget schema version {READ_ONLY_BUDGET_SCHEMA_VERSION} row"
        )));
    }
    for table in REQUIRED_REPLAY_TABLES {
        let object_type = connection
            .query_row(
                "SELECT type FROM sqlite_master WHERE name = ?1",
                [table],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if object_type.as_deref() != Some("table") {
            return Err(BudgetStoreError::Invariant(format!(
                "committed replay budget schema is missing table `{table}`"
            )));
        }
    }
    for probe in REPLAY_SCHEMA_PROBES {
        let _statement = connection.prepare(probe)?;
    }

    let obsolete_table_exists = connection.query_row(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM sqlite_master
            WHERE type = 'table' AND name = 'partition_escrow_budget_store_config'
        )
        "#,
        [],
        |row| row.get::<_, bool>(0),
    )?;
    let trigger_sql = connection
        .query_row(
            r#"
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger'
              AND name = 'budget_partition_escrow_evidence_insert_guard'
            "#,
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if obsolete_table_exists
        || trigger_sql.as_deref().map(normalize_schema_sql)
            != Some(normalize_schema_sql(CURRENT_PARTITION_ESCROW_INSERT_GUARD))
    {
        return Err(BudgetStoreError::Invariant(
            "committed replay budget schema lacks the exact v1 partition escrow guard".to_string(),
        ));
    }
    for (name, expected) in REQUIRED_REPLAY_TRIGGERS {
        let sql = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
                [name],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if sql.as_deref().map(normalize_schema_sql) != Some(normalize_schema_sql(expected)) {
            return Err(BudgetStoreError::Invariant(format!(
                "committed replay budget schema lacks exact authority guard `{name}`"
            )));
        }
    }
    Ok(())
}

fn validate_read_only_budget_integrity(connection: &Connection) -> Result<(), BudgetStoreError> {
    let integrity_check: String =
        connection.query_row("PRAGMA integrity_check(1)", [], |row| row.get(0))?;
    if integrity_check != "ok" {
        return Err(BudgetStoreError::Invariant(
            "committed replay budget database failed SQLite integrity_check".to_string(),
        ));
    }
    let mut foreign_key_check = connection.prepare("PRAGMA foreign_key_check")?;
    if foreign_key_check.query([])?.next()?.is_some() {
        return Err(BudgetStoreError::Invariant(
            "committed replay budget database failed SQLite foreign_key_check".to_string(),
        ));
    }
    drop(foreign_key_check);
    super::schema::validate_read_only_budget_semantics(connection)
}

fn normalize_schema_sql(sql: &str) -> String {
    sql.trim()
        .trim_end_matches(';')
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_read_only_budget_database_is_not_created() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("missing.db");
        let opened = SqliteBudgetStore::open_existing_read_only(&path);
        assert!(opened.is_err());
        assert!(!path.exists());
        Ok(())
    }

    #[test]
    fn exact_budget_database_opens_as_query_only() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("budget.db");
        let authority = crate::SqliteAdmissionCaptureAuthority::open(&path)?;
        let writer = SqliteBudgetStore::open(&path)?;

        let store = SqliteBudgetStore::open_existing_read_only(&path)?;
        let connection = store.connection.lock().map_err(|_| {
            BudgetStoreError::Invariant("sqlite budget store lock poisoned".to_string())
        })?;
        let query_only: i64 = connection.query_row("PRAGMA query_only", [], |row| row.get(0))?;
        assert_eq!(query_only, 1);
        assert!(connection
            .execute("CREATE TABLE forbidden_replay_write (value INTEGER)", [])
            .is_err());
        drop(writer);
        drop(authority);
        Ok(())
    }

    #[test]
    fn read_only_open_rejects_v0_without_migrating() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("budget-v0.db");
        let authority = crate::SqliteAdmissionCaptureAuthority::open(&path)?;
        let connection = Connection::open(&path)?;
        connection.execute(
            "UPDATE chio_store_schema_versions SET version = 0 WHERE store_key = 'budget'",
            [],
        )?;

        assert!(SqliteBudgetStore::open_existing_read_only(&path).is_err());
        let version: i32 = connection.query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key = 'budget'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(version, 0);
        drop(authority);
        Ok(())
    }

    #[test]
    fn read_only_open_rejects_missing_trigger_without_repairing(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("budget-missing-trigger.db");
        let authority = crate::SqliteAdmissionCaptureAuthority::open(&path)?;
        let connection = Connection::open(&path)?;
        connection.execute_batch("DROP TRIGGER budget_partition_escrow_evidence_insert_guard;")?;

        assert!(SqliteBudgetStore::open_existing_read_only(&path).is_err());
        let trigger_exists: bool = connection.query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM sqlite_master
                WHERE type = 'trigger'
                  AND name = 'budget_partition_escrow_evidence_insert_guard'
            )
            "#,
            [],
            |row| row.get(0),
        )?;
        assert!(!trigger_exists);
        drop(authority);
        Ok(())
    }
}
