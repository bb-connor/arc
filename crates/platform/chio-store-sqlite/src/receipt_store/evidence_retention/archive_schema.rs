use super::*;
use crate::receipt_store::support;

const ARCHIVE_SCHEMA: &str = r#"
        CREATE TABLE IF NOT EXISTS archive.chio_tool_receipts (
            seq INTEGER PRIMARY KEY,
            receipt_id TEXT NOT NULL UNIQUE, timestamp INTEGER NOT NULL,
            capability_id TEXT NOT NULL, subject_key TEXT, issuer_key TEXT,
            grant_index INTEGER, tool_server TEXT NOT NULL, tool_name TEXT NOT NULL,
            decision_kind TEXT NOT NULL, policy_hash TEXT NOT NULL,
            content_hash TEXT NOT NULL, raw_json TEXT NOT NULL, tenant_id TEXT,
            cost_currency TEXT CHECK (
                cost_currency IS NULL OR (
                    typeof(cost_currency) = 'text' AND
                    length(cost_currency) = 3 AND instr(cost_currency, char(0)) = 0 AND octet_length(cost_currency) <= 12 AND
                    cost_currency NOT GLOB '*[^A-Z]*'
                )
            ),
            cost_charged_be BLOB CHECK (
                (cost_currency IS NULL AND cost_charged_be IS NULL) OR
                (
                    cost_currency IS NOT NULL AND
                    typeof(cost_charged_be) = 'blob' AND
                    length(cost_charged_be) = 8
                )
            ),
            attempted_cost_be BLOB CHECK (
                attempted_cost_be IS NULL OR (
                    typeof(attempted_cost_be) = 'blob' AND length(attempted_cost_be) = 8
                )
            )
        );
        CREATE TABLE IF NOT EXISTS archive.chio_child_receipts (
            seq INTEGER PRIMARY KEY,
            receipt_id TEXT NOT NULL UNIQUE, timestamp INTEGER NOT NULL,
            session_id TEXT NOT NULL, parent_request_id TEXT NOT NULL,
            request_id TEXT NOT NULL, operation_kind TEXT NOT NULL,
            terminal_state TEXT NOT NULL, policy_hash TEXT NOT NULL,
            outcome_hash TEXT NOT NULL, raw_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS archive.kernel_checkpoints (
            id INTEGER PRIMARY KEY, checkpoint_seq INTEGER NOT NULL UNIQUE,
            batch_start_seq INTEGER NOT NULL, batch_end_seq INTEGER NOT NULL,
            tree_size INTEGER NOT NULL, merkle_root TEXT NOT NULL,
            issued_at INTEGER NOT NULL, statement_json TEXT NOT NULL,
            signature TEXT NOT NULL, kernel_key TEXT NOT NULL,
            previous_checkpoint_sha256 TEXT CHECK (previous_checkpoint_sha256 IS NULL OR (typeof(previous_checkpoint_sha256) = 'text' AND length(previous_checkpoint_sha256) = 64 AND instr(previous_checkpoint_sha256, char(0)) = 0 AND octet_length(previous_checkpoint_sha256) <= 256 AND previous_checkpoint_sha256 NOT GLOB '*[^0-9a-f]*'))
        );
        CREATE TABLE IF NOT EXISTS archive.capability_lineage (
            capability_id TEXT PRIMARY KEY, subject_key TEXT NOT NULL,
            issuer_key TEXT NOT NULL, issued_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL, grants_json TEXT NOT NULL,
            delegation_depth INTEGER NOT NULL DEFAULT 0, parent_capability_id TEXT,
            federated_parent_capability_id TEXT,
            provenance TEXT NOT NULL
                CHECK (provenance IN ('signed_token', 'synthetic_anchor')),
            signed_capability_json TEXT
        );
        CREATE TABLE IF NOT EXISTS archive.claim_receipt_log_entries (
            entry_seq INTEGER PRIMARY KEY,
            receipt_id TEXT NOT NULL UNIQUE, receipt_kind TEXT NOT NULL,
            source_seq INTEGER NOT NULL, timestamp INTEGER NOT NULL,
            capability_id TEXT, session_id TEXT, parent_request_id TEXT,
            request_id TEXT, subject_key TEXT, issuer_key TEXT,
            tool_server TEXT, tool_name TEXT, raw_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS archive.settlement_reconciliations (
            receipt_id TEXT PRIMARY KEY, reconciliation_state TEXT NOT NULL,
            note TEXT, updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS archive.metered_billing_reconciliations (
            receipt_id TEXT PRIMARY KEY, adapter_kind TEXT NOT NULL,
            evidence_id TEXT NOT NULL, observed_units INTEGER NOT NULL,
            billed_cost_units INTEGER NOT NULL, billed_cost_currency TEXT NOT NULL,
            evidence_sha256 TEXT, recorded_at INTEGER NOT NULL,
            reconciliation_state TEXT NOT NULL, note TEXT, updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS archive.chio_authorization_receipt_consumptions (
            authorization_receipt_id TEXT PRIMARY KEY, consumer_receipt_id TEXT NOT NULL,
            request_id TEXT NOT NULL, session_id TEXT NOT NULL, tool_call_id TEXT NOT NULL,
            tenant_id TEXT, parameter_hash TEXT NOT NULL, consumed_at_unix_ms INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS archive.receipt_lineage_statements (
            receipt_id TEXT PRIMARY KEY, statement_id TEXT, request_id TEXT,
            session_id TEXT, session_anchor_id TEXT, chain_id TEXT,
            parent_request_id TEXT, parent_receipt_id TEXT, evidence_class TEXT,
            evidence_sources_json TEXT,
            verified_session_anchor INTEGER NOT NULL DEFAULT 0,
            verified_parent_request INTEGER NOT NULL DEFAULT 0,
            verified_parent_receipt INTEGER NOT NULL DEFAULT 0,
            replay_protected INTEGER NOT NULL DEFAULT 0,
            recorded_at INTEGER NOT NULL, source_kind TEXT NOT NULL,
            json_sha256 TEXT NOT NULL, raw_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS archive.checkpoint_tree_heads (
            checkpoint_seq INTEGER PRIMARY KEY, batch_start_seq INTEGER NOT NULL,
            batch_end_seq INTEGER NOT NULL, tree_size INTEGER NOT NULL,
            merkle_root TEXT NOT NULL, issued_at INTEGER NOT NULL, kernel_key TEXT NOT NULL,
            previous_checkpoint_sha256 TEXT CHECK (previous_checkpoint_sha256 IS NULL OR (typeof(previous_checkpoint_sha256) = 'text' AND length(previous_checkpoint_sha256) = 64 AND instr(previous_checkpoint_sha256, char(0)) = 0 AND octet_length(previous_checkpoint_sha256) <= 256 AND previous_checkpoint_sha256 NOT GLOB '*[^0-9a-f]*')), statement_json TEXT NOT NULL, signature TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS archive.checkpoint_predecessor_witnesses (
            predecessor_checkpoint_seq INTEGER NOT NULL, witness_checkpoint_seq INTEGER PRIMARY KEY,
            previous_checkpoint_sha256 TEXT NOT NULL CHECK (previous_checkpoint_sha256 IS NULL OR (typeof(previous_checkpoint_sha256) = 'text' AND length(previous_checkpoint_sha256) = 64 AND instr(previous_checkpoint_sha256, char(0)) = 0 AND octet_length(previous_checkpoint_sha256) <= 256 AND previous_checkpoint_sha256 NOT GLOB '*[^0-9a-f]*')), witnessed_at INTEGER NOT NULL,
            witness_statement_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS archive.checkpoint_publication_metadata (
            checkpoint_seq INTEGER PRIMARY KEY, publication_schema TEXT NOT NULL,
            merkle_root TEXT NOT NULL, published_at INTEGER NOT NULL, kernel_key TEXT NOT NULL,
            log_tree_size INTEGER NOT NULL, entry_start_seq INTEGER NOT NULL,
            entry_end_seq INTEGER NOT NULL, previous_checkpoint_sha256 TEXT CHECK (previous_checkpoint_sha256 IS NULL OR (typeof(previous_checkpoint_sha256) = 'text' AND length(previous_checkpoint_sha256) = 64 AND instr(previous_checkpoint_sha256, char(0)) = 0 AND octet_length(previous_checkpoint_sha256) <= 256 AND previous_checkpoint_sha256 NOT GLOB '*[^0-9a-f]*'))
        );
        CREATE TABLE IF NOT EXISTS archive.checkpoint_publication_trust_anchor_bindings (
            checkpoint_seq INTEGER PRIMARY KEY, binding_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS archive.chio_receipt_sink_identity (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            sink_id TEXT NOT NULL UNIQUE
        ) STRICT;
"#;

pub(in crate::receipt_store) fn create_archive_schema(
    connection: &mut rusqlite::Connection,
) -> Result<(), ReceiptStoreError> {
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let application_id: i32 =
        transaction.query_row("PRAGMA archive.application_id", [], |row| row.get(0))?;
    let empty: bool = transaction.query_row(
        "SELECT NOT EXISTS(SELECT 1 FROM archive.sqlite_schema)",
        [],
        |row| row.get(0),
    )?;
    if application_id == 0 && empty {
        create_fresh_archive(&transaction)?;
    } else {
        if application_id == 0 {
            return Err(ReceiptStoreError::Conflict(
                "retention archive is not an empty new database".into(),
            ));
        }
        if application_id != crate::CHIO_SQLITE_APPLICATION_ID {
            return Err(ReceiptStoreError::Conflict(format!(
                "retention archive application_id {application_id:#x} is not a Chio store"
            )));
        }
        validate_metadata(&transaction)?;
    }
    validate_catalog(&transaction)?;
    validate_sink_identity(&transaction)?;
    support::verify_archive_receipt_cost_projection(&transaction)?;
    transaction.commit()?;
    Ok(())
}

fn create_fresh_archive(connection: &rusqlite::Connection) -> Result<(), ReceiptStoreError> {
    connection.execute_batch(ARCHIVE_SCHEMA)?;
    support::ensure_archive_security_evidence_schema(connection)?;
    support::create_archive_transparency_projection_guards(connection)?;
    connection.execute(
        "INSERT INTO archive.chio_receipt_sink_identity(singleton, sink_id) VALUES(1, ?1)",
        [uuid::Uuid::now_v7().to_string()],
    )?;
    support::install_archive_receipt_cost_indexes(connection)?;
    connection.execute_batch(&crate::schema_version::METADATA_SCHEMA.replacen(
        "CREATE TABLE ",
        "CREATE TABLE archive.",
        1,
    ))?;
    connection.execute_batch(&format!(
        "PRAGMA archive.application_id = {}",
        crate::CHIO_SQLITE_APPLICATION_ID
    ))?;
    connection.execute(
        "INSERT INTO archive.chio_store_schema_versions(store_key, version) VALUES(?1, ?2)",
        params![RECEIPT_STORE_SCHEMA_KEY, RECEIPT_STORE_SCHEMA_VERSION],
    )?;
    Ok(())
}

fn validate_metadata(connection: &rusqlite::Connection) -> Result<(), ReceiptStoreError> {
    let sql: Option<String> = connection.query_row(
        "SELECT sql FROM archive.sqlite_schema WHERE type = 'table' AND name = 'chio_store_schema_versions'",
        [], |row| row.get(0),
    ).optional()?;
    if sql.is_none() {
        return Err(ReceiptStoreError::Conflict(
            "retention archive carries tables but no receipt schema version".into(),
        ));
    }
    if sql.as_deref() != Some(crate::schema_version::METADATA_SCHEMA) {
        return Err(ReceiptStoreError::Conflict(
            "retention archive schema is not canonical".into(),
        ));
    }
    let version: Option<i32> = connection
        .query_row(
            "SELECT version FROM archive.chio_store_schema_versions WHERE store_key = ?1",
            [RECEIPT_STORE_SCHEMA_KEY],
            |row| row.get(0),
        )
        .optional()?;
    let version = version.ok_or_else(|| {
        ReceiptStoreError::Conflict("retention archive carries no receipt schema version".into())
    })?;
    if version != RECEIPT_STORE_SCHEMA_VERSION {
        return Err(ReceiptStoreError::Conflict(format!(
            "retention archive schema version {version} is not the current receipt schema version {RECEIPT_STORE_SCHEMA_VERSION}"
        )));
    }
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM archive.chio_store_schema_versions",
        [],
        |row| row.get(0),
    )?;
    if count != 1 {
        return Err(ReceiptStoreError::Conflict(
            "retention archive schema namespaces are not canonical".into(),
        ));
    }
    Ok(())
}

fn validate_catalog(connection: &rusqlite::Connection) -> Result<(), ReceiptStoreError> {
    let canonical = rusqlite::Connection::open_in_memory()?;
    canonical.execute_batch("ATTACH DATABASE ':memory:' AS archive")?;
    let transaction =
        rusqlite::Transaction::new_unchecked(&canonical, rusqlite::TransactionBehavior::Immediate)?;
    create_fresh_archive(&transaction)?;
    crate::schema_catalog::validate_archive_against(connection, &transaction).map_err(|_| {
        ReceiptStoreError::Conflict("retention archive schema is not canonical".into())
    })
}

fn validate_sink_identity(connection: &rusqlite::Connection) -> Result<(), ReceiptStoreError> {
    let sink_id: Option<String> = connection
        .query_row(
            "SELECT sink_id FROM archive.chio_receipt_sink_identity WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let sink_id = sink_id.ok_or_else(|| {
        ReceiptStoreError::Conflict("retention archive sink identity is missing".into())
    })?;
    let parsed = uuid::Uuid::parse_str(&sink_id).map_err(|_| {
        ReceiptStoreError::Conflict("retention archive sink identity is invalid".into())
    })?;
    if parsed.to_string() != sink_id {
        return Err(ReceiptStoreError::Conflict(
            "retention archive sink identity is not canonical".into(),
        ));
    }
    Ok(())
}
