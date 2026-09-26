use super::*;

pub(crate) fn validate_indexed_security_receipt(
    evidence_id: &OpaqueReceiptRef,
    receipt: &ChioReceipt,
) -> Result<(), ReceiptStoreError> {
    let metadata = receipt.metadata.as_ref().ok_or_else(|| {
        ReceiptStoreError::Conflict(
            "indexed active-defense receipt is missing security metadata".to_string(),
        )
    })?;
    let claimed_evidence_id = metadata
        .get("active_defense_evidence_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            ReceiptStoreError::Conflict(
                "indexed active-defense receipt is missing its logical evidence ID".to_string(),
            )
        })?;
    let body: ActiveDefenseReceiptBody = serde_json::from_value(
        metadata
            .get("active_defense_body")
            .cloned()
            .ok_or_else(|| {
                ReceiptStoreError::Conflict(
                    "indexed active-defense receipt is missing its closed body".to_string(),
                )
            })?,
    )
    .map_err(|error| {
        ReceiptStoreError::Conflict(format!(
            "indexed active-defense receipt body is invalid: {error}"
        ))
    })?;
    body.validate().map_err(|error| {
        ReceiptStoreError::Conflict(format!(
            "indexed active-defense receipt body is invalid: {error}"
        ))
    })?;
    let derived_evidence_id = body.evidence_id().map_err(|error| {
        ReceiptStoreError::Conflict(format!(
            "indexed active-defense evidence ID derivation failed: {error}"
        ))
    })?;
    let body_digest = body.body_digest().map_err(|error| {
        ReceiptStoreError::Conflict(format!(
            "indexed active-defense body digest failed: {error}"
        ))
    })?;
    if claimed_evidence_id != evidence_id.as_str()
        || &derived_evidence_id != evidence_id
        || receipt.tool_origin != chio_core::receipt::kinds::ToolOrigin::ChioInternal
        || receipt.tool_server != "chio.kernel"
        || receipt.tool_name != body.kind().as_str()
        || receipt.tenant_id.as_deref() != Some(body.header().tenant_id.as_str())
        || receipt.content_hash != hex::encode(body_digest.as_bytes())
    {
        return Err(ReceiptStoreError::Conflict(
            "indexed active-defense receipt binding is inconsistent".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn same_unsigned_receipt_and_bbs_binding(
    left: &ChioReceipt,
    right: &ChioReceipt,
) -> Result<bool, ReceiptStoreError> {
    let left_body = canonical_json_bytes(&left.body())
        .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
    let right_body = canonical_json_bytes(&right.body())
        .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
    let left_bbs = canonical_json_bytes(&left.bbs_signature)
        .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
    let right_bbs = canonical_json_bytes(&right.bbs_signature)
        .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
    Ok(left_body == right_body && left_bbs == right_bbs)
}

// Logical identities are permanent, just like retention tombstones. Receipt
// payloads move to the authenticated archive; keeping this small immutable
// index preserves exact retry identity without pinning the live payload.
const SECURITY_EVIDENCE_INDEX_SCHEMA: &str = r#"
        CREATE TABLE chio_security_evidence_index (
            evidence_id TEXT NOT NULL PRIMARY KEY,
            receipt_id TEXT NOT NULL UNIQUE
        );

        CREATE TRIGGER chio_security_evidence_index_reject_update
        BEFORE UPDATE ON chio_security_evidence_index
        BEGIN
            SELECT RAISE(ABORT, 'security evidence index entries are immutable');
        END;

        CREATE TRIGGER chio_security_evidence_index_reject_delete
        BEFORE DELETE ON chio_security_evidence_index
        BEGIN
            SELECT RAISE(ABORT, 'security evidence index entries are immutable');
        END;
        "#;

pub(crate) fn migrate_indexed_security_evidence_schema(
    connection: &Connection,
) -> Result<(), ReceiptStoreError> {
    let legacy = Connection::open_in_memory()?;
    legacy.execute_batch(&SECURITY_EVIDENCE_INDEX_SCHEMA.replace(
        "receipt_id TEXT NOT NULL UNIQUE",
        "receipt_id TEXT NOT NULL UNIQUE REFERENCES chio_tool_receipts(receipt_id) ON DELETE RESTRICT",
    ))?;
    let catalog = indexed_security_evidence_schema_catalog(connection)?;
    if catalog == indexed_security_evidence_schema_catalog(&legacy)? {
        // The caller owns the schema migration transaction. Both identities
        // and immutable guards survive a failed or interrupted migration.
        connection.execute_batch(
            "CREATE TABLE chio_security_evidence_index_v5 (
                evidence_id TEXT NOT NULL PRIMARY KEY, receipt_id TEXT NOT NULL UNIQUE
             );
             INSERT INTO chio_security_evidence_index_v5 SELECT * FROM chio_security_evidence_index;
             DROP TABLE chio_security_evidence_index;",
        )?;
        connection.execute_batch(SECURITY_EVIDENCE_INDEX_SCHEMA)?;
        connection.execute_batch(
            "INSERT INTO chio_security_evidence_index SELECT * FROM chio_security_evidence_index_v5;
             DROP TABLE chio_security_evidence_index_v5;"
        )?;
    }
    validate_indexed_security_evidence_schema(connection)
}

pub(crate) fn validate_indexed_security_evidence_schema(
    connection: &Connection,
) -> Result<(), ReceiptStoreError> {
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(SECURITY_EVIDENCE_INDEX_SCHEMA)?;
    if indexed_security_evidence_schema_catalog(connection)?
        != indexed_security_evidence_schema_catalog(&expected)?
    {
        return Err(ReceiptStoreError::Conflict(
            "security evidence index schema differs from the canonical definition".to_string(),
        ));
    }
    Ok(())
}

type SecurityEvidenceSchemaEntry = (String, String, String, Option<String>);

fn indexed_security_evidence_schema_catalog(
    connection: &Connection,
) -> Result<Vec<SecurityEvidenceSchemaEntry>, ReceiptStoreError> {
    let mut statement = connection.prepare(
        r#"
        SELECT type, name, tbl_name, sql
        FROM sqlite_schema
        WHERE name = 'chio_security_evidence_index'
           OR tbl_name = 'chio_security_evidence_index'
        ORDER BY type, name, tbl_name
        "#,
    )?;
    let entries = statement
        .query_map([], |row| {
            let sql = row
                .get::<_, Option<String>>(3)?
                .map(|value| value.split_whitespace().collect::<Vec<_>>().join(" "));
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, sql))
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(ReceiptStoreError::from)?;
    Ok(entries)
}

#[cfg(test)]
mod migration_tests {
    use super::*;

    #[test]
    fn legacy_index_migration_preserves_identity_and_allows_payload_retention(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
            CREATE TABLE chio_tool_receipts (receipt_id TEXT PRIMARY KEY);
            INSERT INTO chio_tool_receipts VALUES ('receipt');",
        )?;
        connection.execute_batch(&SECURITY_EVIDENCE_INDEX_SCHEMA.replace(
            "receipt_id TEXT NOT NULL UNIQUE",
            "receipt_id TEXT NOT NULL UNIQUE REFERENCES chio_tool_receipts(receipt_id) ON DELETE RESTRICT",
        ))?;
        connection.execute(
            "INSERT INTO chio_security_evidence_index VALUES ('evidence', 'receipt')",
            [],
        )?;
        assert!(connection
            .execute("DELETE FROM chio_tool_receipts", [])
            .is_err());
        let transaction = connection.transaction()?;
        migrate_indexed_security_evidence_schema(&transaction)?;
        transaction.commit()?;
        connection.execute("DELETE FROM chio_tool_receipts", [])?;
        let identity: String = connection.query_row(
            "SELECT receipt_id FROM chio_security_evidence_index WHERE evidence_id = 'evidence'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(identity, "receipt");
        assert!(connection
            .execute("DELETE FROM chio_security_evidence_index", [])
            .is_err());
        validate_indexed_security_evidence_schema(&connection)?;
        Ok(())
    }
}
