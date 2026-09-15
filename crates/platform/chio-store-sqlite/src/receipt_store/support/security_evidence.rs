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

pub(crate) fn validate_indexed_security_evidence_schema(
    connection: &Connection,
) -> Result<(), ReceiptStoreError> {
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(
        r#"
        CREATE TABLE chio_security_evidence_index (
            evidence_id TEXT NOT NULL PRIMARY KEY,
            receipt_id TEXT NOT NULL UNIQUE
                REFERENCES chio_tool_receipts(receipt_id) ON DELETE RESTRICT
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
        "#,
    )?;
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
