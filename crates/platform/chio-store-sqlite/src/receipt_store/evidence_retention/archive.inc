/// Co-archive-and-delete the checkpoint-aligned prefix [1, W]. All deletes plus
/// the trigger drop/recreate plus the watermark insert run in ONE BEGIN
/// IMMEDIATE transaction on the writer connection; the copy is idempotent and
/// completes first, so a crash between copy and delete leaves the live store
/// intact and the rotation re-runnable.
fn archive_range(
    connection: &mut rusqlite::Connection,
    cutoff_unix_secs: u64,
    archive_path: &str,
    verified_checkpoint_ceiling: Option<u64>,
) -> Result<u64, ReceiptStoreError> {
    // Never archive past the checkpoint boundary the caller has verified. The
    // ceiling is itself a checkpoint `batch_end_seq`, and `compute_archival_watermark`
    // returns one too, so the minimum still lands on a real boundary.
    let watermark = compute_archival_watermark(connection, cutoff_unix_secs)?
        .min(verified_checkpoint_ceiling.unwrap_or(u64::MAX));
    if watermark == 0 {
        return Ok(0); // fail-safe: nothing checkpointed has fully aged.
    }
    // Idempotency / monotonicity: a rotation only ever advances the prefix.
    // When the recomputed watermark does not exceed what is already archived
    // (a re-run at the same or an earlier cutoff), there is nothing new to
    // archive. Returning early keeps the DB-level monotonic watermark trigger
    // (strictly-increasing) from rejecting a redundant re-insert and makes a
    // repeated rotation a clean no-op rather than an error.
    let previous_watermark = super::support::retention_watermark(connection)?.unwrap_or(0);
    if watermark <= previous_watermark {
        return Ok(0);
    }
    let previous_w = sqlite_i64(previous_watermark, "previous archival watermark")?;
    let w = sqlite_i64(watermark, "archival watermark")?;
    let previous_archive_identity = super::support::latest_watermark_archive_sha256(connection)?;
    let previous_archive_content_sha256 =
        super::support::latest_watermark_archive_content_sha256(connection)?;
    if previous_watermark > 0
        && (previous_archive_identity.is_none() || previous_archive_content_sha256.is_none())
    {
        return Err(ReceiptStoreError::Conflict(
            "retention cannot advance a legacy watermark without committed archive identity and \
             canonical content digests; signed checkpoint roots do not prove completeness of \
             the previously archived auxiliary evidence"
                .to_string(),
        ));
    }

    // Rotation may be the first receipt-backed consumer of the bootstrap-created
    // IOU table. Establish and exact-SQL-validate its ownership/immutability
    // triggers, then reject any pre-existing orphan under a live IMMEDIATE
    // transaction before creating, attaching, or mutating the archive. The
    // authoritative delete transaction repeats this check to fence interleaved
    // trigger tampering or inserts.
    preflight_retention_iou_ownership(connection)?;
    ensure_durable_distinct_archive_path(connection, archive_path)?;
    ensure_archive_file_exists(archive_path)?;
    // Dial and record the archive by its absolute, symlink-free path so a later
    // reader (a restart, a CLI health check) resolves the same file regardless
    // of its working directory.
    let archive_path = absolute_archive_path(archive_path)?;
    // Pre-lock fast fail: reject a path split or a moved/emptied backing archive
    // before doing any copy work. Both reads are re-run under the write lock in
    // `delete_archived_prefix_in_tx`, which is the authoritative check: a
    // concurrent rotation can still commit between here and that locked delete.
    ensure_archive_path_matches_ledger(connection, &archive_path)?;
    let previous_archive_uses_legacy_content_digest =
        ensure_committed_prefix_still_backed(connection).map_err(|error| {
            ReceiptStoreError::Conflict(format!(
                "retention archive committed-prefix validation failed: {error}"
            ))
        })?;
    let (archive_identity, archive_content_sha256) =
        with_attached_retention_archive_transaction(connection, &archive_path, |connection| {
            create_archive_schema(connection).map_err(|error| {
                ReceiptStoreError::Conflict(format!(
                    "retention archive schema migration failed: {error}"
                ))
            })?;
            let archive_identity = super::support::ensure_attached_retention_archive_identity(
                connection,
                previous_archive_identity.as_deref(),
            )?;
            if !previous_archive_uses_legacy_content_digest {
                if let Some(previous_content) = previous_archive_content_sha256.as_deref() {
                    validate_retention_archive_prefix_content_sha256(
                        connection,
                        "archive",
                        previous_w,
                        previous_content,
                    )?;
                }
            }
            copy_archived_prefix_after_watermark(connection, previous_w, w)?;
            verify_co_archival_complete(connection, w)?;
            if !previous_archive_uses_legacy_content_digest {
                if let Some(previous_content) = previous_archive_content_sha256.as_deref() {
                    validate_retention_archive_prefix_content_sha256(
                        connection,
                        "archive",
                        previous_w,
                        previous_content,
                    )?;
                }
            }
            let archive_content_sha256 =
                retention_archive_prefix_content_sha256(connection, "archive", w)?;
            Ok((archive_identity, archive_content_sha256))
        })
        .map_err(|error| {
            ReceiptStoreError::Conflict(format!(
                "retention archive copy transaction failed: {error}"
            ))
        })?;
    // The final delete deliberately runs with no archive attached. Its archive
    // ownership guard checkpoints and locks the exact durable file first, then
    // the live IMMEDIATE transaction re-verifies the copied suffix and stages
    // deletion while that archive writer lock remains held.
    let archived = delete_archived_prefix_in_tx(
        connection,
        previous_w,
        w,
        cutoff_unix_secs,
        &archive_path,
        &archive_identity,
        previous_archive_content_sha256.as_deref(),
        &archive_content_sha256,
    )
    .map_err(|error| {
        ReceiptStoreError::Conflict(format!(
            "retention archive live-prefix commit failed: {error}"
        ))
    })?;

    // Reclaim freelist pages produced by the delete and shrink the WAL.
    connection.execute_batch("PRAGMA incremental_vacuum")?;
    require_complete_wal_checkpoint(connection, "live retention database")?;
    Ok(archived)
}

pub(super) fn with_attached_retention_archive_transaction<T, F>(
    connection: &mut rusqlite::Connection,
    archive_path: &str,
    body: F,
) -> Result<T, ReceiptStoreError>
where
    F: FnOnce(&mut rusqlite::Connection) -> Result<T, ReceiptStoreError>,
{
    if !connection.is_autocommit() {
        return Err(ReceiptStoreError::Conflict(
            "retention archive attachment requires an autocommit connection".to_string(),
        ));
    }
    super::bootstrap::open::validate_no_temp_schema_objects(connection)?;
    let archive_already_attached = retention_archive_schema_is_attached(connection)?;
    if archive_already_attached {
        return Err(ReceiptStoreError::Conflict(
            "retention archive schema is already attached".to_string(),
        ));
    }

    let mut attached = false;
    let primary_result = (|| -> Result<T, ReceiptStoreError> {
        let escaped_path = archive_path.replace('\'', "''");
        connection.execute_batch(&format!(
            "ATTACH DATABASE '{escaped_path}' AS archive"
        ))?;
        attached = true;
        connection.execute_batch("BEGIN IMMEDIATE")?;
        let result = body(connection)?;
        connection.execute_batch("COMMIT")?;
        Ok(result)
    })();

    let mut cleanup_failures = Vec::new();
    if !connection.is_autocommit() {
        match connection.execute_batch("ROLLBACK") {
            Ok(()) => {}
            Err(error) => cleanup_failures.push(format!("rollback failed: {error}")),
        }
    }
    let archive_is_attached = match retention_archive_schema_is_attached(connection) {
        Ok(is_attached) => is_attached,
        Err(error) => {
            cleanup_failures.push(format!("attachment inspection failed: {error}"));
            attached
        }
    };
    if archive_is_attached {
        connection.flush_prepared_statement_cache();
        if let Err(error) = connection.execute_batch("DETACH DATABASE archive") {
            cleanup_failures.push(format!("detach failed: {error}"));
        }
    }
    match retention_archive_schema_is_attached(connection) {
        Ok(false) => {}
        Ok(true) => cleanup_failures.push("archive schema remains attached".to_string()),
        Err(error) => cleanup_failures.push(format!("attachment check failed: {error}")),
    }
    if let Err(error) = super::bootstrap::open::validate_no_temp_schema_objects(connection) {
        cleanup_failures.push(format!("TEMP schema cleanup check failed: {error}"));
    }

    if cleanup_failures.is_empty() {
        return primary_result;
    }
    let cleanup = cleanup_failures.join("; ");
    match primary_result {
        Ok(_) => Err(ReceiptStoreError::Conflict(format!(
            "retention archive attachment cleanup failed: {cleanup}"
        ))),
        Err(primary) => Err(ReceiptStoreError::Conflict(format!(
            "{primary}; retention archive attachment cleanup also failed: {cleanup}"
        ))),
    }
}

fn retention_archive_schema_is_attached(
    connection: &rusqlite::Connection,
) -> Result<bool, ReceiptStoreError> {
    Ok(super::bootstrap::open::sqlite_database_list(connection)?
        .into_iter()
        .any(|(_, schema, _)| schema == "archive"))
}

/// Create the archive schema. The archive gains the receipt tables, the
/// checkpoint rows, capability lineage, the claim-log projection (with
/// `entry_seq` preserved: `INTEGER PRIMARY KEY`, no `AUTOINCREMENT`, so copied
/// values insert verbatim), settlement/metered reconciliations,
/// authorization consumptions, and the governed-receipt lineage statements
/// (keyed by `receipt_id`) that carry each archived receipt's call-chain
/// provenance. The archive-only identity table carries the random nonce whose
/// domain-separated SHA-256 commitment is pinned into every watermark row; the
/// final live lock proves the recorded path is an independently writable file
/// before any source row is deleted. A separate canonical logical digest binds
/// this complete table contract and every typed row without depending on SQLite
/// file pages or WAL bytes. The archive `chio_tool_receipts` mirrors the live
/// column layout exactly, including the `tenant_id` column added to the
/// live table by the attribution migration (`ensure_tool_receipt_attribution_columns`),
/// so a global rotation over a mixed-tenant store preserves tenant attribution
/// in the archive. Every copy names its columns explicitly (except the tables
/// copied with `SELECT *`, whose column order is asserted to match the live
/// DDL) so a future column added to one side cannot silently produce a
/// positional or column-count mismatch at runtime.
///
/// The checkpoint projections (`checkpoint_tree_heads`,
/// `checkpoint_predecessor_witnesses`, `checkpoint_publication_metadata`, and
/// `checkpoint_publication_trust_anchor_bindings`) are copied with their
/// checkpoint rows before the archive digest is computed. The first three are
/// deterministic projections of `kernel_checkpoints`; trust-anchor bindings
/// are independent append-only evidence and cannot be reconstructed. All four
/// remain complete within each committed prefix. An archive is a write-once
/// evidence copy, not a live receipt store: adding live-store tables, triggers,
/// views, or unique indexes invalidates its catalog. Unlike the live schema, the
/// archive versions carry no `REFERENCES` clauses and never enforce live
/// FK-cascade behavior.
const ARCHIVE_SCHEMA_SQL: &str = r#"
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
                    length(cost_currency) = 3 AND
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
            signature TEXT NOT NULL, kernel_key TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS archive.capability_lineage (
            capability_id TEXT PRIMARY KEY, subject_key TEXT NOT NULL,
            issuer_key TEXT NOT NULL, issued_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL, grants_json TEXT NOT NULL,
            delegation_depth INTEGER NOT NULL DEFAULT 0, parent_capability_id TEXT,
            federated_parent_capability_id TEXT,
            provenance TEXT NOT NULL DEFAULT 'legacy_projection'
                CHECK (provenance IN ('signed_token', 'synthetic_anchor', 'legacy_projection')),
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
        CREATE TABLE IF NOT EXISTS archive.iou_envelope (
            receipt_id TEXT PRIMARY KEY, iou_id TEXT NOT NULL,
            receipt_timestamp INTEGER NOT NULL, tenant_id TEXT,
            amount_units INTEGER NOT NULL, currency TEXT NOT NULL,
            issuer_key TEXT NOT NULL, canonical_json TEXT NOT NULL
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
            previous_checkpoint_sha256 TEXT, statement_json TEXT NOT NULL, signature TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS archive.checkpoint_predecessor_witnesses (
            predecessor_checkpoint_seq INTEGER NOT NULL, witness_checkpoint_seq INTEGER PRIMARY KEY,
            previous_checkpoint_sha256 TEXT NOT NULL, witnessed_at INTEGER NOT NULL,
            witness_statement_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS archive.checkpoint_publication_metadata (
            checkpoint_seq INTEGER PRIMARY KEY, publication_schema TEXT NOT NULL,
            merkle_root TEXT NOT NULL, published_at INTEGER NOT NULL, kernel_key TEXT NOT NULL,
            log_tree_size INTEGER NOT NULL, entry_start_seq INTEGER NOT NULL,
            entry_end_seq INTEGER NOT NULL, previous_checkpoint_sha256 TEXT
        );
        CREATE TABLE IF NOT EXISTS archive.checkpoint_publication_trust_anchor_bindings (
            checkpoint_seq INTEGER PRIMARY KEY, binding_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS archive.chio_retention_archive_identity (
            identity_slot     INTEGER PRIMARY KEY CHECK (identity_slot = 1),
            nonce             TEXT NOT NULL UNIQUE,
            commitment_sha256 TEXT NOT NULL UNIQUE
        );
        CREATE TABLE IF NOT EXISTS archive.chio_store_schema_versions (
            store_key TEXT PRIMARY KEY,
            version INTEGER NOT NULL
        );
        "#;

pub(super) fn create_archive_schema(
    connection: &rusqlite::Connection,
) -> Result<(), ReceiptStoreError> {
    let application_id: i32 =
        connection.query_row("PRAGMA archive.application_id", [], |row| row.get(0))?;
    if application_id != 0 && application_id != crate::CHIO_SQLITE_APPLICATION_ID {
        return Err(ReceiptStoreError::Conflict(format!(
            "retention archive application_id {application_id:#x} is not a Chio store"
        )));
    }
    let version_table_exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM archive.sqlite_master WHERE type = 'table' AND name = 'chio_store_schema_versions')",
        [],
        |row| row.get(0),
    )?;
    let archive_schema_version = if version_table_exists {
        connection
            .query_row(
                "SELECT version FROM archive.chio_store_schema_versions WHERE store_key = ?1",
                [super::RECEIPT_STORE_SCHEMA_KEY],
                |row| row.get::<_, i32>(0),
            )
            .optional()?
            .unwrap_or(0)
    } else {
        0
    };
    if archive_schema_version > super::RECEIPT_STORE_SUPPORTED_SCHEMA_VERSION {
        return Err(ReceiptStoreError::Conflict(format!(
            "retention archive schema version {archive_schema_version} is newer than this binary supports ({})",
            super::RECEIPT_STORE_SUPPORTED_SCHEMA_VERSION
        )));
    }

    connection.execute_batch(ARCHIVE_SCHEMA_SQL)?;
    super::support::migrate_archive_receipt_cost_projection(connection)?;
    super::support::verify_archive_receipt_cost_projection(connection)?;
    ensure_archive_capability_lineage_provenance_columns(connection, "archive")?;
    connection.execute_batch(&format!(
        "PRAGMA archive.application_id = {}",
        crate::CHIO_SQLITE_APPLICATION_ID
    ))?;
    connection.execute(
        "INSERT INTO archive.chio_store_schema_versions (store_key, version) VALUES (?1, ?2) \
         ON CONFLICT(store_key) DO UPDATE SET version = excluded.version",
        rusqlite::params![
            super::RECEIPT_STORE_SCHEMA_KEY,
            super::RECEIPT_STORE_SUPPORTED_SCHEMA_VERSION
        ],
    )?;
    validate_archive_schema_contract(connection)
}

#[cfg(test)]
pub(super) fn create_archive_schema_in_schema_for_test(
    connection: &rusqlite::Connection,
    schema: &str,
) -> Result<(), ReceiptStoreError> {
    let schema = validated_sqlite_schema_name(schema)?;
    let schema_sql = ARCHIVE_SCHEMA_SQL.replace("archive.", &format!("{schema}."));
    connection.execute_batch(&schema_sql)?;
    ensure_archive_capability_lineage_provenance_columns(connection, schema)?;
    validate_archive_schema_contract_in_schema(connection, schema)
}

fn ensure_archive_capability_lineage_provenance_columns(
    connection: &rusqlite::Connection,
    schema: &str,
) -> Result<(), ReceiptStoreError> {
    let schema = validated_sqlite_schema_name(schema)?;
    for (column, definition) in [
        ("federated_parent_capability_id", "TEXT"),
        (
            "provenance",
            "TEXT NOT NULL DEFAULT 'legacy_projection' CHECK (provenance IN ('signed_token', 'synthetic_anchor', 'legacy_projection'))",
        ),
        ("signed_capability_json", "TEXT"),
    ] {
        let pragma = format!("PRAGMA {schema}.table_info(capability_lineage)");
        let mut statement = connection.prepare(&pragma)?;
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<Result<Vec<_>, _>>()?;
        if !columns.iter().any(|existing| existing == column) {
            connection.execute(
                &format!(
                    "ALTER TABLE {schema}.capability_lineage ADD COLUMN {column} {definition}"
                ),
                [],
            )?;
        }
    }
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
struct ArchiveColumnContract {
    position: i64,
    name: String,
    data_type: String,
    not_null: i64,
    default_value: Option<String>,
    primary_key_position: i64,
    hidden: i64,
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ArchiveIndexColumnContract {
    position: i64,
    table_column_position: i64,
    name: Option<String>,
    descending: i64,
    collation: Option<String>,
    key_column: i64,
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ArchiveUniqueConstraintContract {
    origin: String,
    unique: i64,
    partial: i64,
    columns: Vec<ArchiveIndexColumnContract>,
}

#[derive(Debug, Eq, PartialEq)]
struct ArchiveTableContract {
    create_sql: String,
    columns: Vec<ArchiveColumnContract>,
    unique_constraints: Vec<ArchiveUniqueConstraintContract>,
}

/// Require every archive evidence table to have the structural schema Chio
/// creates. `CREATE TABLE IF NOT EXISTS` alone accepts a reused table with
/// missing primary-key or unique constraints. Such a table can retain a
/// divergent row, accept a second matching row, pass an existence-only copy
/// check, and become ambiguous after the live source is deleted. Build the
/// expected catalog in a private in-memory attachment from the same DDL and
/// compare columns plus SQLite-owned primary/unique indexes before any evidence
/// copy runs. Explicit non-unique operational indexes are inert and permitted.
/// Explicit unique indexes, triggers, views, and unexpected tables are rejected
/// because they can change copy semantics or mutate committed evidence.
fn validate_archive_schema_contract(
    connection: &rusqlite::Connection,
) -> Result<(), ReceiptStoreError> {
    validate_archive_schema_contract_in_schema(connection, "archive")
}

pub(in crate::receipt_store) fn validate_archive_schema_contract_in_schema(
    connection: &rusqlite::Connection,
    actual_schema: &str,
) -> Result<(), ReceiptStoreError> {
    let expected = expected_archive_catalog()?;
    validate_archive_schema_contract_against(
        connection,
        actual_schema,
        &expected,
        false,
    )
}

fn validate_archive_schema_contract_against(
    connection: &rusqlite::Connection,
    actual_schema: &str,
    expected: &rusqlite::Connection,
    allow_current_schema_version_table: bool,
) -> Result<(), ReceiptStoreError> {
    let actual_schema = validated_sqlite_schema_name(actual_schema)?;

    let mut expected_statement = expected.prepare(
        "SELECT name FROM archive.sqlite_master \
         WHERE type = 'table' AND name NOT GLOB 'sqlite_*' ORDER BY name",
    )?;
    let expected_rows = expected_statement.query_map([], |row| row.get::<_, String>(0))?;
    let mut expected_tables = Vec::new();
    for expected_row in expected_rows {
        expected_tables.push(expected_row?);
    }
    let mut actual_statement = connection.prepare(&format!(
        "SELECT name FROM {actual_schema}.sqlite_master \
         WHERE type = 'table' AND name NOT GLOB 'sqlite_*' ORDER BY name"
    ))?;
    let actual_rows = actual_statement.query_map([], |row| row.get::<_, String>(0))?;
    let mut actual_tables = Vec::new();
    for actual_row in actual_rows {
        actual_tables.push(actual_row?);
    }
    if allow_current_schema_version_table {
        if actual_tables
            .iter()
            .any(|table| table == "chio_store_schema_versions")
        {
            let current_expected = expected_archive_catalog()?;
            let expected_contract = load_archive_table_contract(
                &current_expected,
                "archive",
                "chio_store_schema_versions",
            )?;
            let actual_contract = load_archive_table_contract(
                connection,
                actual_schema,
                "chio_store_schema_versions",
            )?;
            if actual_contract != expected_contract {
                return Err(ReceiptStoreError::Conflict(
                    "archive table chio_store_schema_versions does not match the required \
                     evidence schema"
                        .to_string(),
                ));
            }
            let version_rows: i64 = connection.query_row(
                &format!(
                    "SELECT COUNT(*) FROM {actual_schema}.chio_store_schema_versions \
                     WHERE store_key = ?1 AND version = ?2"
                ),
                rusqlite::params![
                    super::RECEIPT_STORE_SCHEMA_KEY,
                    super::RECEIPT_STORE_SUPPORTED_SCHEMA_VERSION
                ],
                |row| row.get(0),
            )?;
            let total_rows: i64 = connection.query_row(
                &format!(
                    "SELECT COUNT(*) FROM {actual_schema}.chio_store_schema_versions"
                ),
                [],
                |row| row.get(0),
            )?;
            if version_rows != 1 || total_rows != 1 {
                return Err(ReceiptStoreError::Conflict(
                    "legacy archive compatibility accepts only the current singleton receipt \
                     schema-version row"
                        .to_string(),
                ));
            }
        }
        actual_tables.retain(|table| table != "chio_store_schema_versions");
    }
    if actual_tables != expected_tables {
        return Err(ReceiptStoreError::Conflict(format!(
            "archive table catalog does not match the required evidence schema: expected \
             {expected_tables:?}, found {actual_tables:?}"
        )));
    }
    let active_schema_object = connection
        .query_row(
            &format!(
                "SELECT type, name FROM {actual_schema}.sqlite_master \
                 WHERE type IN ('trigger', 'view') ORDER BY type, name LIMIT 1"
            ),
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    if let Some((object_type, name)) = active_schema_object {
        return Err(ReceiptStoreError::Conflict(format!(
            "archive schema contains forbidden {object_type} {name:?}"
        )));
    }
    for table in expected_tables {
        let expected_contract = load_archive_table_contract(expected, "archive", &table)?;
        let actual_contract = load_archive_table_contract(connection, actual_schema, &table)?;
        let contract_matches = if table == "chio_tool_receipts" {
            actual_contract.columns == expected_contract.columns
                && actual_contract.unique_constraints == expected_contract.unique_constraints
        } else {
            actual_contract == expected_contract
        };
        if !contract_matches {
            return Err(ReceiptStoreError::Conflict(format!(
                "archive table {table} does not match the required evidence schema"
            )));
        }
    }
    Ok(())
}

fn expected_archive_catalog() -> Result<rusqlite::Connection, ReceiptStoreError> {
    let expected = rusqlite::Connection::open_in_memory()?;
    expected.execute_batch("ATTACH DATABASE ':memory:' AS archive")?;
    expected.execute_batch(ARCHIVE_SCHEMA_SQL)?;
    Ok(expected)
}

fn expected_legacy_archive_catalog() -> Result<rusqlite::Connection, ReceiptStoreError> {
    let expected = expected_archive_catalog()?;
    expected.execute_batch("DROP TABLE archive.chio_store_schema_versions")?;
    Ok(expected)
}

fn load_archive_table_contract(
    connection: &rusqlite::Connection,
    schema: &str,
    table: &str,
) -> Result<ArchiveTableContract, ReceiptStoreError> {
    let schema = validated_sqlite_schema_name(schema)?;
    let escaped_table = table.replace('\'', "''");
    let create_sql = connection
        .query_row(
            &format!("SELECT sql FROM {schema}.sqlite_master WHERE type = 'table' AND name = ?1"),
            params![table],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| {
            ReceiptStoreError::Conflict(format!(
                "archive table {table} is missing from schema {schema}"
            ))
        })?;
    let create_sql = normalize_archive_create_sql(&create_sql);
    let mut column_statement =
        connection.prepare(&format!("PRAGMA {schema}.table_xinfo('{escaped_table}')"))?;
    let column_rows = column_statement.query_map([], |row| {
        Ok(ArchiveColumnContract {
            position: row.get(0)?,
            name: row.get(1)?,
            data_type: row.get(2)?,
            not_null: row.get(3)?,
            default_value: row.get(4)?,
            primary_key_position: row.get(5)?,
            hidden: row.get(6)?,
        })
    })?;
    let mut columns = Vec::new();
    for column in column_rows {
        columns.push(column?);
    }

    let mut index_statement =
        connection.prepare(&format!("PRAGMA {schema}.index_list('{escaped_table}')"))?;
    let index_rows = index_statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, i64>(4)?,
        ))
    })?;
    let mut unique_constraints = Vec::new();
    for index in index_rows {
        let (index_name, unique, origin, partial) = index?;
        if origin == "c" && unique != 0 {
            return Err(ReceiptStoreError::Conflict(format!(
                "archive schema table {table} contains forbidden explicit unique index \
                 {index_name:?}"
            )));
        }
        if origin != "u" && origin != "pk" {
            continue;
        }
        let escaped_index = index_name.replace('\'', "''");
        let mut index_column_statement =
            connection.prepare(&format!("PRAGMA {schema}.index_xinfo('{escaped_index}')"))?;
        let index_column_rows = index_column_statement.query_map([], |row| {
            Ok(ArchiveIndexColumnContract {
                position: row.get(0)?,
                table_column_position: row.get(1)?,
                name: row.get(2)?,
                descending: row.get(3)?,
                collation: row.get(4)?,
                key_column: row.get(5)?,
            })
        })?;
        let mut index_columns = Vec::new();
        for index_column in index_column_rows {
            index_columns.push(index_column?);
        }
        unique_constraints.push(ArchiveUniqueConstraintContract {
            origin,
            unique,
            partial,
            columns: index_columns,
        });
    }
    unique_constraints.sort();
    Ok(ArchiveTableContract {
        create_sql,
        columns,
        unique_constraints,
    })
}

fn normalize_archive_create_sql(sql: &str) -> String {
    sql.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim_end_matches(';')
        .to_string()
}

fn validated_sqlite_schema_name(schema: &str) -> Result<&str, ReceiptStoreError> {
    let mut characters = schema.chars();
    let valid_start = characters
        .next()
        .is_some_and(|character| character.is_ascii_alphabetic() || character == '_');
    if !valid_start
        || !characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        return Err(ReceiptStoreError::Conflict(format!(
            "invalid SQLite schema name {schema:?} in archive verification"
        )));
    }
    Ok(schema)
}

const RETENTION_ARCHIVE_PREFIX_CONTENT_DOMAIN: &[u8] =
    b"chio.retention-archive.prefix-content.v1";

/// Compute a canonical logical commitment over the Chio evidence reachable
/// through one archival watermark. The digest is independent of SQLite page
/// layout, WAL state, vacuuming, and file metadata. It binds every expected
/// table's exact structural contract and every reachable typed cell, ordered
/// first by table name and then by the table's declared primary key. A copied
/// but uncommitted later suffix cannot change an earlier watermark commitment.
pub(crate) fn retention_archive_prefix_content_sha256(
    connection: &rusqlite::Connection,
    schema: &str,
    watermark: i64,
) -> Result<String, ReceiptStoreError> {
    let expected = expected_archive_catalog()?;
    retention_archive_prefix_content_sha256_against(
        connection,
        schema,
        watermark,
        &expected,
        false,
    )
}

pub(crate) fn legacy_retention_archive_prefix_content_sha256(
    connection: &rusqlite::Connection,
    schema: &str,
    watermark: i64,
) -> Result<String, ReceiptStoreError> {
    let expected = expected_legacy_archive_catalog()?;
    retention_archive_prefix_content_sha256_against(
        connection,
        schema,
        watermark,
        &expected,
        true,
    )
}

pub(in crate::receipt_store) fn validate_legacy_retention_archive_prefix_content_sha256(
    connection: &rusqlite::Connection,
    schema: &str,
    watermark: i64,
    expected_sha256: &str,
) -> Result<(), ReceiptStoreError> {
    let actual = legacy_retention_archive_prefix_content_sha256(connection, schema, watermark)?;
    if actual != expected_sha256 {
        return Err(ReceiptStoreError::Conflict(format!(
            "legacy retention archive canonical content digest {actual:?} for prefix watermark \
             {watermark} does not match the committed watermark digest {expected_sha256:?}"
        )));
    }
    Ok(())
}

fn retention_archive_prefix_content_sha256_against(
    connection: &rusqlite::Connection,
    schema: &str,
    watermark: i64,
    expected: &rusqlite::Connection,
    allow_current_schema_version_table: bool,
) -> Result<String, ReceiptStoreError> {
    if watermark <= 0 {
        return Err(ReceiptStoreError::Conflict(
            "retention archive prefix digest requires a positive watermark".to_string(),
        ));
    }
    let schema = validated_sqlite_schema_name(schema)?;
    validate_archive_schema_contract_against(
        connection,
        schema,
        expected,
        allow_current_schema_version_table,
    )?;

    let mut table_statement = expected.prepare(
        "SELECT name FROM archive.sqlite_master \
         WHERE type = 'table' AND name NOT GLOB 'sqlite_*' ORDER BY name",
    )?;
    let table_rows = table_statement.query_map([], |row| row.get::<_, String>(0))?;
    let mut table_names = Vec::new();
    for table in table_rows {
        table_names.push(table?);
    }

    let mut hasher = Sha256::new();
    archive_digest_frame(
        &mut hasher,
        b'D',
        RETENTION_ARCHIVE_PREFIX_CONTENT_DOMAIN,
    )?;
    archive_digest_i64(&mut hasher, b'W', watermark)?;
    archive_digest_u64(
        &mut hasher,
        b'T',
        u64::try_from(table_names.len()).map_err(|_| {
            ReceiptStoreError::Conflict(
                "retention archive table count cannot be represented canonically".to_string(),
            )
        })?,
    )?;
    for table in table_names {
        let contract = load_archive_table_contract(connection, schema, &table)?;
        archive_digest_table(
            &mut hasher,
            connection,
            schema,
            &table,
            &contract,
            watermark,
        )?;
    }
    Ok(hex::encode(hasher.finalize()))
}

pub(crate) fn validate_retention_archive_prefix_content_sha256(
    connection: &rusqlite::Connection,
    schema: &str,
    watermark: i64,
    expected_sha256: &str,
) -> Result<(), ReceiptStoreError> {
    let actual = retention_archive_prefix_content_sha256(connection, schema, watermark)?;
    if actual != expected_sha256 {
        return Err(ReceiptStoreError::Conflict(format!(
            "retention archive canonical content digest {actual:?} for prefix watermark \
             {watermark} does not match the committed watermark digest {expected_sha256:?}"
        )));
    }
    Ok(())
}

pub(in crate::receipt_store) fn legacy_archive_path_backs_prefix(
    connection: &rusqlite::Connection,
    archive_path: &str,
    watermark: u64,
    expected_archive_identity: &str,
    expected_archive_content_sha256: &str,
) -> Result<bool, ReceiptStoreError> {
    if watermark == 0 {
        return Ok(false);
    }
    let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
        | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
        | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let Ok(archive) = rusqlite::Connection::open_with_flags(archive_path, flags) else {
        return Ok(false);
    };
    archive.execute_batch("PRAGMA query_only = ON; BEGIN DEFERRED")?;
    archive.query_row("SELECT COUNT(*) FROM main.sqlite_master", [], |row| {
        row.get::<_, i64>(0)
    })?;
    super::support::validate_retention_archive_identity(&archive, expected_archive_identity)?;
    validate_legacy_retention_archive_prefix_content_sha256(
        &archive,
        "main",
        sqlite_i64(watermark, "legacy archive prefix watermark")?,
        expected_archive_content_sha256,
    )?;
    if !super::support::archive_connection_backs_prefix(connection, &archive, watermark)? {
        return Err(ReceiptStoreError::Conflict(format!(
            "legacy retention archive does not re-derive the signed checkpoint prefix through \
             watermark {watermark}"
        )));
    }
    Ok(true)
}

fn archive_digest_table(
    hasher: &mut Sha256,
    connection: &rusqlite::Connection,
    schema: &str,
    table: &str,
    contract: &ArchiveTableContract,
    watermark: i64,
) -> Result<(), ReceiptStoreError> {
    archive_digest_frame(hasher, b't', table.as_bytes())?;
    archive_digest_frame(hasher, b's', contract.create_sql.as_bytes())?;
    archive_digest_u64(
        hasher,
        b'c',
        u64::try_from(contract.columns.len()).map_err(|_| {
            ReceiptStoreError::Conflict(format!(
                "archive table {table} column count cannot be represented canonically"
            ))
        })?,
    )?;
    for column in &contract.columns {
        archive_digest_i64(hasher, b'p', column.position)?;
        archive_digest_frame(hasher, b'n', column.name.as_bytes())?;
        archive_digest_frame(hasher, b'y', column.data_type.as_bytes())?;
        archive_digest_i64(hasher, b'r', column.not_null)?;
        archive_digest_optional_text(hasher, column.default_value.as_deref())?;
        archive_digest_i64(hasher, b'k', column.primary_key_position)?;
        archive_digest_i64(hasher, b'h', column.hidden)?;
    }
    archive_digest_u64(
        hasher,
        b'u',
        u64::try_from(contract.unique_constraints.len()).map_err(|_| {
            ReceiptStoreError::Conflict(format!(
                "archive table {table} unique constraint count cannot be represented canonically"
            ))
        })?,
    )?;
    for unique in &contract.unique_constraints {
        archive_digest_frame(hasher, b'o', unique.origin.as_bytes())?;
        archive_digest_i64(hasher, b'q', unique.unique)?;
        archive_digest_i64(hasher, b'a', unique.partial)?;
        archive_digest_u64(
            hasher,
            b'i',
            u64::try_from(unique.columns.len()).map_err(|_| {
                ReceiptStoreError::Conflict(format!(
                    "archive table {table} index width cannot be represented canonically"
                ))
            })?,
        )?;
        for index_column in &unique.columns {
            archive_digest_i64(hasher, b'p', index_column.position)?;
            archive_digest_i64(hasher, b'c', index_column.table_column_position)?;
            archive_digest_optional_text(hasher, index_column.name.as_deref())?;
            archive_digest_i64(hasher, b'd', index_column.descending)?;
            archive_digest_optional_text(hasher, index_column.collation.as_deref())?;
            archive_digest_i64(hasher, b'k', index_column.key_column)?;
        }
    }

    let mut primary_key_columns: Vec<&ArchiveColumnContract> = contract
        .columns
        .iter()
        .filter(|column| column.primary_key_position > 0)
        .collect();
    primary_key_columns.sort_by_key(|column| column.primary_key_position);
    if primary_key_columns.is_empty() {
        return Err(ReceiptStoreError::Conflict(format!(
            "archive table {table} has no primary key for canonical row ordering"
        )));
    }
    let order_by = primary_key_columns
        .iter()
        .map(|column| quote_sqlite_identifier(&column.name))
        .collect::<Vec<_>>()
        .join(", ");
    let qualified_table = format!("{schema}.{}", quote_sqlite_identifier(table));
    let predicate = archive_prefix_predicate(schema, table)?;
    let mut statement = connection.prepare(&format!(
        "SELECT * FROM {qualified_table} AS evidence WHERE {predicate} ORDER BY {order_by}"
    ))?;
    if statement.column_count() != contract.columns.len() {
        return Err(ReceiptStoreError::Conflict(format!(
            "archive table {table} exposes {} columns but its schema binds {}",
            statement.column_count(),
            contract.columns.len()
        )));
    }
    let mut rows = statement.query(params![watermark])?;
    let mut row_count = 0_u64;
    while let Some(row) = rows.next()? {
        archive_digest_u64(hasher, b'R', row_count)?;
        for primary_key_column in &primary_key_columns {
            let position = usize::try_from(primary_key_column.position).map_err(|_| {
                ReceiptStoreError::Conflict(format!(
                    "archive table {table} has an invalid primary-key column position"
                ))
            })?;
            if matches!(row.get_ref(position)?, rusqlite::types::ValueRef::Null) {
                return Err(ReceiptStoreError::Conflict(format!(
                    "archive table {table} contains a NULL primary key and cannot be ordered \
                     canonically"
                )));
            }
        }
        for column in 0..contract.columns.len() {
            archive_digest_sqlite_value(hasher, row.get_ref(column)?)?;
        }
        row_count = row_count.checked_add(1).ok_or_else(|| {
            ReceiptStoreError::Conflict(format!(
                "archive table {table} row count overflowed canonical encoding"
            ))
        })?;
    }
    archive_digest_u64(hasher, b'N', row_count)
}

fn archive_prefix_predicate(schema: &str, table: &str) -> Result<String, ReceiptStoreError> {
    let schema = validated_sqlite_schema_name(schema)?;
    let claims = format!("{schema}.claim_receipt_log_entries");
    let checkpoints = format!("{schema}.kernel_checkpoints");
    let tool_receipts = format!("{schema}.chio_tool_receipts");
    let predicate = match table {
        "chio_retention_archive_identity" | "chio_store_schema_versions" => {
            "?1 > 0".to_string()
        }
        "claim_receipt_log_entries" => "evidence.entry_seq <= ?1".to_string(),
        "chio_tool_receipts" => format!(
            "EXISTS (SELECT 1 FROM {claims} AS claim \
             WHERE claim.entry_seq <= ?1 AND claim.receipt_kind = 'tool_receipt' \
               AND claim.source_seq = evidence.seq AND claim.receipt_id = evidence.receipt_id)"
        ),
        "chio_child_receipts" => format!(
            "EXISTS (SELECT 1 FROM {claims} AS claim \
             WHERE claim.entry_seq <= ?1 AND claim.receipt_kind = 'child_receipt' \
               AND claim.source_seq = evidence.seq AND claim.receipt_id = evidence.receipt_id)"
        ),
        "kernel_checkpoints" => "evidence.batch_end_seq <= ?1".to_string(),
        "checkpoint_tree_heads"
        | "checkpoint_publication_metadata"
        | "checkpoint_publication_trust_anchor_bindings" => format!(
            "EXISTS (SELECT 1 FROM {checkpoints} AS checkpoint \
             WHERE checkpoint.batch_end_seq <= ?1 \
               AND checkpoint.checkpoint_seq = evidence.checkpoint_seq)"
        ),
        "checkpoint_predecessor_witnesses" => format!(
            "EXISTS (SELECT 1 FROM {checkpoints} AS checkpoint \
             WHERE checkpoint.batch_end_seq <= ?1 \
               AND checkpoint.checkpoint_seq = evidence.witness_checkpoint_seq)"
        ),
        "capability_lineage" => format!(
            "EXISTS (SELECT 1 FROM {claims} AS claim \
             INNER JOIN {tool_receipts} AS receipt \
               ON receipt.seq = claim.source_seq AND receipt.receipt_id = claim.receipt_id \
             WHERE claim.entry_seq <= ?1 AND claim.receipt_kind = 'tool_receipt' \
               AND receipt.capability_id = evidence.capability_id)"
        ),
        "settlement_reconciliations" | "iou_envelope" | "metered_billing_reconciliations" => {
            format!(
                "EXISTS (SELECT 1 FROM {claims} AS claim \
                 WHERE claim.entry_seq <= ?1 AND claim.receipt_kind = 'tool_receipt' \
                   AND claim.receipt_id = evidence.receipt_id)"
            )
        }
        "chio_authorization_receipt_consumptions" => format!(
            "EXISTS (SELECT 1 FROM {claims} AS claim \
             WHERE claim.entry_seq <= ?1 AND claim.receipt_kind = 'tool_receipt' \
               AND claim.receipt_id = evidence.authorization_receipt_id)"
        ),
        "receipt_lineage_statements" => format!(
            "EXISTS (SELECT 1 FROM {claims} AS claim \
             WHERE claim.entry_seq <= ?1 AND claim.receipt_id = evidence.receipt_id)"
        ),
        other => {
            return Err(ReceiptStoreError::Conflict(format!(
                "archive prefix digest has no reachability rule for table {other}"
            )))
        }
    };
    Ok(predicate)
}

fn archive_digest_sqlite_value(
    hasher: &mut Sha256,
    value: rusqlite::types::ValueRef<'_>,
) -> Result<(), ReceiptStoreError> {
    match value {
        rusqlite::types::ValueRef::Null => archive_digest_frame(hasher, b'0', &[]),
        rusqlite::types::ValueRef::Integer(value) => {
            archive_digest_frame(hasher, b'I', &value.to_be_bytes())
        }
        rusqlite::types::ValueRef::Real(value) => {
            archive_digest_frame(hasher, b'F', &value.to_bits().to_be_bytes())
        }
        rusqlite::types::ValueRef::Text(value) => archive_digest_frame(hasher, b'X', value),
        rusqlite::types::ValueRef::Blob(value) => archive_digest_frame(hasher, b'B', value),
    }
}

fn archive_digest_optional_text(
    hasher: &mut Sha256,
    value: Option<&str>,
) -> Result<(), ReceiptStoreError> {
    match value {
        Some(value) => archive_digest_frame(hasher, b'V', value.as_bytes()),
        None => archive_digest_frame(hasher, b'0', &[]),
    }
}

fn archive_digest_i64(hasher: &mut Sha256, tag: u8, value: i64) -> Result<(), ReceiptStoreError> {
    archive_digest_frame(hasher, tag, &value.to_be_bytes())
}

fn archive_digest_u64(hasher: &mut Sha256, tag: u8, value: u64) -> Result<(), ReceiptStoreError> {
    archive_digest_frame(hasher, tag, &value.to_be_bytes())
}

fn archive_digest_frame(
    hasher: &mut Sha256,
    tag: u8,
    value: &[u8],
) -> Result<(), ReceiptStoreError> {
    let length = u64::try_from(value.len()).map_err(|_| {
        ReceiptStoreError::Conflict(
            "retention archive digest field length cannot be represented canonically".to_string(),
        )
    })?;
    hasher.update([tag]);
    hasher.update(length.to_be_bytes());
    hasher.update(value);
    Ok(())
}

fn quote_sqlite_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

/// Idempotent copy of the [1, W] prefix into the archive. Returns the number of
/// newly archived tool-receipt rows.
///
/// Append-only evidence (the receipt tables, the claim-log projection, the
/// signed checkpoints, the write-once authorization consumptions) copies with
/// `INSERT OR IGNORE`: those rows never change once written, so a pre-existing
/// archive row that diverges from the live row signals a reused or corrupt
/// archive and must be caught fail-closed by `verify_co_archival_complete`, not
/// silently overwritten.
///
/// The settlement and metered reconciliation rows, by contrast, are mutated in
/// place by ongoing reconciliation upserts, including for a receipt already in
/// the archival prefix. A rotation copies the reconciliation row, a later
/// reconciliation update changes it, and the write-locked co-archival re-verify
/// then aborts because the archive holds the pre-update bytes. An `INSERT OR
/// IGNORE` retry would keep the stale archive row on every rotation and leave
/// the prefix permanently unrotatable. These two tables therefore refresh their
/// archived copy from the current live row (`INSERT OR REPLACE`) so a retry
/// converges on the latest committed reconciliation state instead of stalling.
#[cfg(test)]
pub(super) fn copy_archived_prefix(
    connection: &rusqlite::Connection,
    w: i64,
) -> Result<u64, ReceiptStoreError> {
    copy_archived_prefix_after_watermark(connection, 0, w)
}

pub(super) fn copy_archived_prefix_after_watermark(
    connection: &rusqlite::Connection,
    previous_watermark: i64,
    w: i64,
) -> Result<u64, ReceiptStoreError> {
    let before: i64 = connection.query_row(
        "SELECT COUNT(*) FROM archive.chio_tool_receipts",
        [],
        |row| row.get(0),
    )?;
    connection.execute_batch(&format!(
        r#"
        INSERT OR IGNORE INTO archive.claim_receipt_log_entries
            SELECT * FROM main.claim_receipt_log_entries WHERE entry_seq <= {w};
        INSERT OR IGNORE INTO archive.chio_tool_receipts
            (seq, receipt_id, timestamp, capability_id, subject_key, issuer_key,
             grant_index, tool_server, tool_name, decision_kind, policy_hash,
             content_hash, raw_json, tenant_id, cost_currency, cost_charged_be)
            SELECT seq, receipt_id, timestamp, capability_id, subject_key, issuer_key,
                   grant_index, tool_server, tool_name, decision_kind, policy_hash,
                   content_hash, raw_json, tenant_id, cost_currency, cost_charged_be
            FROM main.chio_tool_receipts WHERE seq IN (
                SELECT source_seq FROM main.claim_receipt_log_entries
                WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt');
        INSERT OR IGNORE INTO archive.chio_child_receipts
            (seq, receipt_id, timestamp, session_id, parent_request_id, request_id,
             operation_kind, terminal_state, policy_hash, outcome_hash, raw_json)
            SELECT seq, receipt_id, timestamp, session_id, parent_request_id, request_id,
                   operation_kind, terminal_state, policy_hash, outcome_hash, raw_json
            FROM main.chio_child_receipts WHERE seq IN (
                SELECT source_seq FROM main.claim_receipt_log_entries
                WHERE entry_seq <= {w} AND receipt_kind = 'child_receipt');
        INSERT OR IGNORE INTO archive.kernel_checkpoints
            SELECT * FROM main.kernel_checkpoints WHERE batch_end_seq <= {w};
        INSERT OR IGNORE INTO archive.checkpoint_tree_heads
            (checkpoint_seq, batch_start_seq, batch_end_seq, tree_size, merkle_root,
             issued_at, kernel_key, previous_checkpoint_sha256, statement_json, signature)
            SELECT p.checkpoint_seq, p.batch_start_seq, p.batch_end_seq, p.tree_size,
                   p.merkle_root, p.issued_at, p.kernel_key, p.previous_checkpoint_sha256,
                   p.statement_json, p.signature
            FROM main.checkpoint_tree_heads p
            INNER JOIN main.kernel_checkpoints k ON k.checkpoint_seq = p.checkpoint_seq
            WHERE k.batch_end_seq <= {w};
        INSERT OR IGNORE INTO archive.checkpoint_predecessor_witnesses
            (predecessor_checkpoint_seq, witness_checkpoint_seq,
             previous_checkpoint_sha256, witnessed_at, witness_statement_json)
            SELECT p.predecessor_checkpoint_seq, p.witness_checkpoint_seq,
                   p.previous_checkpoint_sha256, p.witnessed_at, p.witness_statement_json
            FROM main.checkpoint_predecessor_witnesses p
            INNER JOIN main.kernel_checkpoints k
                ON k.checkpoint_seq = p.witness_checkpoint_seq
            WHERE k.batch_end_seq <= {w};
        INSERT OR IGNORE INTO archive.checkpoint_publication_metadata
            (checkpoint_seq, publication_schema, merkle_root, published_at, kernel_key,
             log_tree_size, entry_start_seq, entry_end_seq, previous_checkpoint_sha256)
            SELECT p.checkpoint_seq, p.publication_schema, p.merkle_root, p.published_at,
                   p.kernel_key, p.log_tree_size, p.entry_start_seq, p.entry_end_seq,
                   p.previous_checkpoint_sha256
            FROM main.checkpoint_publication_metadata p
            INNER JOIN main.kernel_checkpoints k ON k.checkpoint_seq = p.checkpoint_seq
            WHERE k.batch_end_seq <= {w};
        INSERT OR IGNORE INTO archive.checkpoint_publication_trust_anchor_bindings
            (checkpoint_seq, binding_json)
            SELECT p.checkpoint_seq, p.binding_json
            FROM main.checkpoint_publication_trust_anchor_bindings p
            INNER JOIN main.kernel_checkpoints k ON k.checkpoint_seq = p.checkpoint_seq
            WHERE k.batch_end_seq <= {w};
        -- A capability first observed in an already committed prefix has a
        -- frozen archive lineage state, including authoritative absence. Copy
        -- lineage only for capabilities whose first archived receipt enters in
        -- this suffix. This keeps D(previous_watermark) stable when a caller
        -- attempts to record a late snapshot for a reused capability.
        INSERT OR IGNORE INTO archive.capability_lineage
            SELECT DISTINCT cl.* FROM main.capability_lineage cl
            WHERE EXISTS (
                SELECT 1 FROM archive.claim_receipt_log_entries claim
                INNER JOIN archive.chio_tool_receipts receipt
                    ON receipt.seq = claim.source_seq
                   AND receipt.receipt_id = claim.receipt_id
                WHERE claim.entry_seq <= {w}
                  AND claim.receipt_kind = 'tool_receipt'
                  AND receipt.capability_id = cl.capability_id)
              AND NOT EXISTS (
                SELECT 1 FROM archive.claim_receipt_log_entries prior_claim
                INNER JOIN archive.chio_tool_receipts prior_receipt
                    ON prior_receipt.seq = prior_claim.source_seq
                   AND prior_receipt.receipt_id = prior_claim.receipt_id
                WHERE prior_claim.entry_seq <= {previous_watermark}
                  AND prior_claim.receipt_kind = 'tool_receipt'
                  AND prior_receipt.capability_id = cl.capability_id);
        -- Refresh (not IGNORE) the mutable reconciliation rows: an earlier copy
        -- may hold pre-update bytes for a receipt whose reconciliation state has
        -- since advanced, and only replacing it lets a retried rotation pass the
        -- write-locked co-archival re-verify instead of stalling on stale bytes.
        INSERT OR REPLACE INTO archive.settlement_reconciliations
            SELECT * FROM main.settlement_reconciliations WHERE receipt_id IN (
                SELECT receipt_id FROM main.claim_receipt_log_entries
                WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt');
        INSERT OR REPLACE INTO archive.metered_billing_reconciliations
            SELECT * FROM main.metered_billing_reconciliations WHERE receipt_id IN (
                SELECT receipt_id FROM main.claim_receipt_log_entries
                WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt');
        INSERT OR IGNORE INTO archive.chio_authorization_receipt_consumptions
            SELECT * FROM main.chio_authorization_receipt_consumptions WHERE authorization_receipt_id IN (
                SELECT receipt_id FROM main.claim_receipt_log_entries
                WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt');
        INSERT OR IGNORE INTO archive.receipt_lineage_statements
            (receipt_id, statement_id, request_id, session_id, session_anchor_id,
             chain_id, parent_request_id, parent_receipt_id, evidence_class,
             evidence_sources_json, verified_session_anchor, verified_parent_request,
             verified_parent_receipt, replay_protected, recorded_at, source_kind,
             json_sha256, raw_json)
            SELECT receipt_id, statement_id, request_id, session_id, session_anchor_id,
                   chain_id, parent_request_id, parent_receipt_id, evidence_class,
                   evidence_sources_json, verified_session_anchor, verified_parent_request,
                   verified_parent_receipt, replay_protected, recorded_at, source_kind,
                   json_sha256, raw_json
            FROM main.receipt_lineage_statements WHERE receipt_id IN (
                SELECT receipt_id FROM main.claim_receipt_log_entries WHERE entry_seq <= {w});
        "#
    ))?;
    let iou_envelope_exists = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.sqlite_master \
         WHERE type = 'table' AND name = 'iou_envelope')",
        [],
        |row| row.get::<_, i64>(0),
    )? != 0;
    if iou_envelope_exists {
        connection.execute_batch(&format!(
            r#"
            INSERT OR IGNORE INTO archive.iou_envelope
                (receipt_id, iou_id, receipt_timestamp, tenant_id, amount_units,
                 currency, issuer_key, canonical_json)
                SELECT receipt_id, iou_id, receipt_timestamp, tenant_id, amount_units,
                       currency, issuer_key, canonical_json
                FROM main.iou_envelope WHERE receipt_id IN (
                    SELECT receipt_id FROM main.claim_receipt_log_entries
                    WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt');
            "#
        ))?;
    }
    let after: i64 = connection.query_row(
        "SELECT COUNT(*) FROM archive.chio_tool_receipts",
        [],
        |row| row.get(0),
    )?;
    sqlite_u64((after - before).max(0), "archived tool receipt delta")
}
