// tenant-read-contract: security_declassification_tombstones; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_declassification_receipt_outbox; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_declassification_evidence_identity; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_declassification_uses; class=tenant-predicate; principal=security-runtime
use super::declassification;
use super::sha256;


use super::PortError;
use super::PortResult;
use super::params;
use super::Connection;
use super::OptionalExtension;
# [cfg (target_os = "macos")]
use super::security_state_lifecycle_lock_path;
use super::sqlite_error;
use super::normalize_sql;

pub(super) const DECLASSIFICATION_READINESS_CURSOR: &str = "declassification-evidence-schema-v2";
const DECLASSIFICATION_LIFECYCLE_CANONICAL_DDL: &str = r#"
CREATE TABLE security_declassification_lifecycle (
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
)
"#;
const DECLASSIFICATION_USES_CANONICAL_DDL: &str = r#"
CREATE TABLE security_declassification_uses (
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
)
"#;
const DECLASSIFICATION_IDENTITY_CANONICAL_DDL: &str = r#"
CREATE TABLE security_declassification_evidence_identity (
    evidence_id TEXT NOT NULL,
    transition_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('consumption', 'outcome')),
    body_hash BLOB NOT NULL CHECK (length(body_hash) = 32),
    PRIMARY KEY (tenant_id, evidence_id),
    UNIQUE (tenant_id, transition_id)
)
"#;
const DECLASSIFICATION_OUTBOX_CANONICAL_DDL: &str = r#"
CREATE TABLE security_declassification_receipt_outbox (
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
)
"#;
const DECLASSIFICATION_TOMBSTONE_CANONICAL_DDL: &str = r#"
CREATE TABLE security_declassification_tombstones (
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
)
"#;
const DECLASSIFICATION_IDENTITY_LEGACY_DDL: &str = r#"
CREATE TABLE security_declassification_evidence_identity (
    evidence_id TEXT NOT NULL PRIMARY KEY,
    transition_id TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('consumption', 'outcome')),
    body_hash BLOB NOT NULL CHECK (length(body_hash) = 32)
)
"#;
const DECLASSIFICATION_OUTBOX_LEGACY_DDL: &str = r#"
CREATE TABLE security_declassification_receipt_outbox (
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
    FOREIGN KEY (evidence_id)
        REFERENCES security_declassification_evidence_identity (evidence_id),
    FOREIGN KEY (tenant_id, grant_id)
        REFERENCES security_declassification_uses (tenant_id, grant_id)
)
"#;
const DECLASSIFICATION_TOMBSTONE_LEGACY_DDL: &str = r#"
CREATE TABLE security_declassification_tombstones (
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
    FOREIGN KEY (consumption_evidence_id)
        REFERENCES security_declassification_evidence_identity (evidence_id),
    FOREIGN KEY (outcome_evidence_id)
        REFERENCES security_declassification_evidence_identity (evidence_id)
)
"#;

pub(super) fn prepare_declassification_schema_migration(connection: &Connection) -> PortResult<()> {
    let current_tables = [
        (
            "security_declassification_lifecycle",
            DECLASSIFICATION_LIFECYCLE_CANONICAL_DDL,
        ),
        (
            "security_declassification_uses",
            DECLASSIFICATION_USES_CANONICAL_DDL,
        ),
        (
            "security_declassification_evidence_identity",
            DECLASSIFICATION_IDENTITY_CANONICAL_DDL,
        ),
        (
            "security_declassification_receipt_outbox",
            DECLASSIFICATION_OUTBOX_CANONICAL_DDL,
        ),
        (
            "security_declassification_tombstones",
            DECLASSIFICATION_TOMBSTONE_CANONICAL_DDL,
        ),
    ];
    let legacy_tables = [
        (
            "security_declassification_lifecycle",
            DECLASSIFICATION_LIFECYCLE_CANONICAL_DDL,
        ),
        (
            "security_declassification_uses",
            DECLASSIFICATION_USES_CANONICAL_DDL,
        ),
        (
            "security_declassification_evidence_identity",
            DECLASSIFICATION_IDENTITY_LEGACY_DDL,
        ),
        (
            "security_declassification_receipt_outbox",
            DECLASSIFICATION_OUTBOX_LEGACY_DDL,
        ),
        (
            "security_declassification_tombstones",
            DECLASSIFICATION_TOMBSTONE_LEGACY_DDL,
        ),
    ];
    let mut present_tables = 0_usize;
    let mut current_exact_tables = 0_usize;
    let mut legacy_exact_tables = 0_usize;
    for ((table, current_sql), (legacy_table, legacy_sql)) in
        current_tables.iter().zip(legacy_tables.iter())
    {
        if table != legacy_table {
            return Err(PortError::integrity_failure());
        }
        let existing: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
                params![table],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        if let Some(existing_sql) = existing {
            present_tables = present_tables
                .checked_add(1)
                .ok_or_else(PortError::integrity_failure)?;
            let normalized = normalize_sql(&existing_sql);
            if normalized == normalize_sql(current_sql) {
                current_exact_tables = current_exact_tables
                    .checked_add(1)
                    .ok_or_else(PortError::integrity_failure)?;
            }
            if normalized == normalize_sql(legacy_sql) {
                legacy_exact_tables = legacy_exact_tables
                    .checked_add(1)
                    .ok_or_else(PortError::integrity_failure)?;
            }
        }
    }
    if present_tables == 0 {
        return Ok(());
    }
    if current_exact_tables == current_tables.len() {
        return Ok(());
    }
    if legacy_exact_tables == legacy_tables.len() {
        return migrate_declassification_tenant_keys(connection);
    }
    for table in [
        "security_declassification_uses",
        "security_declassification_evidence_identity",
        "security_declassification_receipt_outbox",
        "security_declassification_tombstones",
    ] {
        let exists: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                params![table],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if exists != 0 {
            let count_sql = format!("SELECT COUNT(*) FROM {table}");
            let count = connection
                .query_row(&count_sql, [], |row| row.get::<_, i64>(0))
                .map_err(|_| PortError::integrity_failure())?;
            if count != 0 {
                return Err(PortError::integrity_failure());
            }
        }
    }
    connection
        .execute_batch(
            r#"
            DROP TRIGGER IF EXISTS security_declassification_use_immutable;
            DROP TRIGGER IF EXISTS security_declassification_use_delete_rejected;
            DROP TRIGGER IF EXISTS security_declassification_outcome_predecessor_insert;
            DROP TRIGGER IF EXISTS security_declassification_evidence_use_binding_insert;
            DROP TRIGGER IF EXISTS security_declassification_outcome_ack_order;
            DROP TRIGGER IF EXISTS security_declassification_evidence_immutable;
            DROP TRIGGER IF EXISTS security_declassification_evidence_delete_rejected;
            DROP TRIGGER IF EXISTS security_declassification_identity_immutable;
            DROP TRIGGER IF EXISTS security_declassification_identity_delete_rejected;
            DROP TRIGGER IF EXISTS security_declassification_tombstone_immutable;
            DROP TRIGGER IF EXISTS security_declassification_tombstone_delete_rejected;
            DROP TRIGGER IF EXISTS security_declassification_tombstone_replay_rejected;
            DROP INDEX IF EXISTS security_declassification_receipt_pending;
            DROP TABLE IF EXISTS security_declassification_tombstones;
            DROP TABLE IF EXISTS security_declassification_receipt_outbox;
            DROP TABLE IF EXISTS security_declassification_evidence_identity;
            DROP TABLE IF EXISTS security_declassification_uses;
            DROP TABLE IF EXISTS security_declassification_lifecycle;
            "#,
        )
        .map_err(sqlite_error)
}

fn migrate_declassification_tenant_keys(connection: &Connection) -> PortResult<()> {
    validate_declassification_evidence_integrity(connection)?;
    const IDENTITY_STAGING: &str = "security_declassification_evidence_identity_tenant_migration";
    const OUTBOX_STAGING: &str = "security_declassification_receipt_outbox_tenant_migration";
    const TOMBSTONE_STAGING: &str = "security_declassification_tombstones_tenant_migration";
    let identity_staging_ddl = DECLASSIFICATION_IDENTITY_CANONICAL_DDL.replace(
        "security_declassification_evidence_identity",
        IDENTITY_STAGING,
    );
    let outbox_staging_ddl = DECLASSIFICATION_OUTBOX_CANONICAL_DDL
        .replace("security_declassification_receipt_outbox", OUTBOX_STAGING)
        .replace(
            "security_declassification_evidence_identity",
            IDENTITY_STAGING,
        );
    let tombstone_staging_ddl = DECLASSIFICATION_TOMBSTONE_CANONICAL_DDL
        .replace("security_declassification_tombstones", TOMBSTONE_STAGING)
        .replace(
            "security_declassification_evidence_identity",
            IDENTITY_STAGING,
        );
    connection
        .execute_batch(&format!(
            "{identity_staging_ddl};\n{outbox_staging_ddl};\n{tombstone_staging_ddl};"
        ))
        .map_err(sqlite_error)?;
    connection
        .execute_batch(
            r#"
            INSERT INTO security_declassification_evidence_identity_tenant_migration (
                evidence_id, transition_id, tenant_id, grant_id, phase, body_hash
            )
            SELECT evidence_id, transition_id, tenant_id, grant_id, phase, body_hash
            FROM security_declassification_evidence_identity;

            INSERT INTO security_declassification_receipt_outbox_tenant_migration (
                tenant_id, grant_id, phase, phase_ordinal, request_hash, state,
                transition_binding, evidence_type, evidence_id, canonical_body,
                body_hash, transition_id, occurred_at, predecessor_evidence_id,
                acknowledged, acknowledged_at, durable_sink_record_hash, attempts,
                next_attempt_at, last_error_code
            )
            SELECT tenant_id, grant_id, phase, phase_ordinal, request_hash, state,
                   transition_binding, evidence_type, evidence_id, canonical_body,
                   body_hash, transition_id, occurred_at, predecessor_evidence_id,
                   acknowledged, acknowledged_at, durable_sink_record_hash, attempts,
                   next_attempt_at, last_error_code
            FROM security_declassification_receipt_outbox;

            INSERT INTO security_declassification_tombstones_tenant_migration (
                tenant_id, grant_id, request_hash, terminal_state,
                consumption_evidence_id, consumption_body_hash,
                consumption_transition_id, consumption_occurred_at,
                consumption_sink_record_hash, outcome_evidence_id,
                outcome_body_hash, outcome_transition_id, outcome_occurred_at,
                outcome_sink_record_hash, policy_hash, compacted_at
            )
            SELECT tenant_id, grant_id, request_hash, terminal_state,
                   consumption_evidence_id, consumption_body_hash,
                   consumption_transition_id, consumption_occurred_at,
                   consumption_sink_record_hash, outcome_evidence_id,
                   outcome_body_hash, outcome_transition_id, outcome_occurred_at,
                   outcome_sink_record_hash, policy_hash, compacted_at
            FROM security_declassification_tombstones;
            "#,
        )
        .map_err(sqlite_error)?;
    let staged_counts = (
        connection
            .query_row(
                "SELECT COUNT(*) FROM security_declassification_evidence_identity_tenant_migration",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(sqlite_error)?,
        connection
            .query_row(
                "SELECT COUNT(*) FROM security_declassification_receipt_outbox_tenant_migration",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(sqlite_error)?,
        connection
            .query_row(
                "SELECT COUNT(*) FROM security_declassification_tombstones_tenant_migration",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(sqlite_error)?,
    );
    for table in [OUTBOX_STAGING, TOMBSTONE_STAGING] {
        let mut statement = connection
            .prepare(&format!("PRAGMA foreign_key_check(\"{table}\")"))
            .map_err(sqlite_error)?;
        let mut rows = statement.query([]).map_err(sqlite_error)?;
        if rows.next().map_err(sqlite_error)?.is_some() {
            return Err(PortError::integrity_failure());
        }
    }
    connection
        .execute_batch(
            r#"
            DROP TABLE security_declassification_tombstones;
            DROP TABLE security_declassification_receipt_outbox;
            DROP TABLE security_declassification_evidence_identity;
            "#,
        )
        .map_err(sqlite_error)?;
    connection
        .execute_batch(&format!(
            "{};\n{};\n{};",
            DECLASSIFICATION_IDENTITY_CANONICAL_DDL,
            DECLASSIFICATION_OUTBOX_CANONICAL_DDL,
            DECLASSIFICATION_TOMBSTONE_CANONICAL_DDL,
        ))
        .map_err(sqlite_error)?;
    connection
        .execute_batch(
            r#"
            INSERT INTO security_declassification_evidence_identity (
                evidence_id, transition_id, tenant_id, grant_id, phase, body_hash
            )
            SELECT evidence_id, transition_id, tenant_id, grant_id, phase, body_hash
            FROM security_declassification_evidence_identity_tenant_migration;

            INSERT INTO security_declassification_receipt_outbox (
                tenant_id, grant_id, phase, phase_ordinal, request_hash, state,
                transition_binding, evidence_type, evidence_id, canonical_body,
                body_hash, transition_id, occurred_at, predecessor_evidence_id,
                acknowledged, acknowledged_at, durable_sink_record_hash, attempts,
                next_attempt_at, last_error_code
            )
            SELECT tenant_id, grant_id, phase, phase_ordinal, request_hash, state,
                   transition_binding, evidence_type, evidence_id, canonical_body,
                   body_hash, transition_id, occurred_at, predecessor_evidence_id,
                   acknowledged, acknowledged_at, durable_sink_record_hash, attempts,
                   next_attempt_at, last_error_code
            FROM security_declassification_receipt_outbox_tenant_migration;

            INSERT INTO security_declassification_tombstones (
                tenant_id, grant_id, request_hash, terminal_state,
                consumption_evidence_id, consumption_body_hash,
                consumption_transition_id, consumption_occurred_at,
                consumption_sink_record_hash, outcome_evidence_id,
                outcome_body_hash, outcome_transition_id, outcome_occurred_at,
                outcome_sink_record_hash, policy_hash, compacted_at
            )
            SELECT tenant_id, grant_id, request_hash, terminal_state,
                   consumption_evidence_id, consumption_body_hash,
                   consumption_transition_id, consumption_occurred_at,
                   consumption_sink_record_hash, outcome_evidence_id,
                   outcome_body_hash, outcome_transition_id, outcome_occurred_at,
                   outcome_sink_record_hash, policy_hash, compacted_at
            FROM security_declassification_tombstones_tenant_migration;
            "#,
        )
        .map_err(sqlite_error)?;
    let migrated_counts = (
        connection
            .query_row(
                "SELECT COUNT(*) FROM security_declassification_evidence_identity",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(sqlite_error)?,
        connection
            .query_row(
                "SELECT COUNT(*) FROM security_declassification_receipt_outbox",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(sqlite_error)?,
        connection
            .query_row(
                "SELECT COUNT(*) FROM security_declassification_tombstones",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(sqlite_error)?,
    );
    if migrated_counts != staged_counts {
        return Err(PortError::integrity_failure());
    }
    for table in [
        "security_declassification_receipt_outbox",
        "security_declassification_tombstones",
    ] {
        let mut statement = connection
            .prepare(&format!("PRAGMA foreign_key_check(\"{table}\")"))
            .map_err(sqlite_error)?;
        let mut rows = statement.query([]).map_err(sqlite_error)?;
        if rows.next().map_err(sqlite_error)?.is_some() {
            return Err(PortError::integrity_failure());
        }
    }
    for (table, expected_sql) in [
        (
            "security_declassification_evidence_identity",
            DECLASSIFICATION_IDENTITY_CANONICAL_DDL,
        ),
        (
            "security_declassification_receipt_outbox",
            DECLASSIFICATION_OUTBOX_CANONICAL_DDL,
        ),
        (
            "security_declassification_tombstones",
            DECLASSIFICATION_TOMBSTONE_CANONICAL_DDL,
        ),
    ] {
        let actual: String = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
                params![table],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if normalize_sql(&actual) != normalize_sql(expected_sql) {
            return Err(PortError::integrity_failure());
        }
    }
    validate_declassification_evidence_integrity(connection)?;
    connection
        .execute_batch(
            r#"
            DROP TABLE security_declassification_tombstones_tenant_migration;
            DROP TABLE security_declassification_receipt_outbox_tenant_migration;
            DROP TABLE security_declassification_evidence_identity_tenant_migration;
            "#,
        )
        .map_err(sqlite_error)
}

pub(super) fn validate_declassification_evidence_schema(connection: &Connection) -> PortResult<()> {
    const EXPECTED_SCHEMA_DIGEST_HEX: &str =
        "83c3175ea1984bf501f554ac29bf7d279b858b06a8cc343cedc8571a681c867f";
    let quick_check: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    if quick_check != "ok" {
        return Err(PortError::integrity_failure());
    }
    let mut foreign_key_check = connection
        .prepare("PRAGMA foreign_key_check")
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

    for (table, expected_sql) in [
        (
            "security_declassification_lifecycle",
            DECLASSIFICATION_LIFECYCLE_CANONICAL_DDL,
        ),
        (
            "security_declassification_uses",
            DECLASSIFICATION_USES_CANONICAL_DDL,
        ),
        (
            "security_declassification_evidence_identity",
            DECLASSIFICATION_IDENTITY_CANONICAL_DDL,
        ),
        (
            "security_declassification_receipt_outbox",
            DECLASSIFICATION_OUTBOX_CANONICAL_DDL,
        ),
        (
            "security_declassification_tombstones",
            DECLASSIFICATION_TOMBSTONE_CANONICAL_DDL,
        ),
    ] {
        let actual: String = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
                params![table],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if normalize_sql(&actual) != normalize_sql(expected_sql) {
            return Err(PortError::integrity_failure());
        }
    }

    let mut statement = connection
        .prepare(
            r#"
            SELECT type, name, sql
            FROM sqlite_master
            WHERE sql IS NOT NULL AND (
                name LIKE 'security_declassification_%'
                OR tbl_name IN (
                    'security_declassification_lifecycle',
                    'security_declassification_uses',
                    'security_declassification_evidence_identity',
                    'security_declassification_receipt_outbox',
                    'security_declassification_tombstones'
                )
                OR (
                    type = 'trigger'
                    AND instr(lower(sql), 'security_declassification_') > 0
                )
            )
            ORDER BY type, name
            "#,
        )
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    let canonical = rows
        .into_iter()
        .map(|(object_type, name, sql)| format!("{object_type}|{name}|{}", normalize_sql(&sql)))
        .collect::<Vec<_>>()
        .join("\n");
    if hex::encode(sha256(canonical.as_bytes()).as_bytes()) != EXPECTED_SCHEMA_DIGEST_HEX {
        return Err(PortError::integrity_failure());
    }

    declassification::verify_legacy_lifecycle(connection)
}

pub(super) fn validate_declassification_evidence_integrity(connection: &Connection) -> PortResult<()> {
    declassification::verify_legacy_integrity(connection)
}
