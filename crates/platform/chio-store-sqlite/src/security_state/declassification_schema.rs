// tenant-read-contract: security_declassification_tombstones; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_declassification_receipt_outbox; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_declassification_evidence_identity; class=tenant-predicate; principal=security-runtime
// tenant-read-contract: security_declassification_uses; class=tenant-predicate; principal=security-runtime
use super::{
    declassification, normalize_sql, params, sha256, sqlite_error, Connection, PortError,
    PortResult,
};

pub(super) const DECLASSIFICATION_READINESS_CURSOR: &str = "declassification-evidence-schema-v1";
const DECLASSIFICATION_LIFECYCLE_CANONICAL_DDL: &str = r#"
CREATE TABLE security_declassification_lifecycle (
    singleton INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
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
pub(super) fn validate_declassification_evidence_schema(connection: &Connection) -> PortResult<()> {
    const EXPECTED_SCHEMA_DIGEST_HEX: &str =
        "9f13e522900395adaaab0b9287a9101b24621c5443e5e0848e760a8b8bd03fa9";
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

pub(super) fn validate_declassification_evidence_integrity(
    connection: &Connection,
) -> PortResult<()> {
    declassification::verify_legacy_integrity(connection)
}
