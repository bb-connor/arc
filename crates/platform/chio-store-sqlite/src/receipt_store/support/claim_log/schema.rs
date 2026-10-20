// tenant-read-contract: chio_tool_receipts; class=tenant-predicate; principal=receipt-read-adapter
// Contracts: docs/security/trust-boundary-inventory.json
use super::*;

const RECEIPT_COST_CURRENCY_COLUMN: &str = r#"cost_currency TEXT CHECK (
    cost_currency IS NULL OR (
        typeof(cost_currency) = 'text' AND
        length(cost_currency) = 3 AND instr(cost_currency, char(0)) = 0 AND octet_length(cost_currency) <= 12 AND
        cost_currency NOT GLOB '*[^A-Z]*'
    )
)"#;
const RECEIPT_COST_KEY_COLUMN: &str = r#"cost_charged_be BLOB CHECK (
    (cost_currency IS NULL AND cost_charged_be IS NULL) OR
    (
        cost_currency IS NOT NULL AND
        typeof(cost_charged_be) = 'blob' AND
        length(cost_charged_be) = 8
    )
)"#;
const RECEIPT_ATTEMPTED_COST_COLUMN: &str = r#"attempted_cost_be BLOB CHECK (
    attempted_cost_be IS NULL OR (
        typeof(attempted_cost_be) = 'blob' AND length(attempted_cost_be) = 8
    )
)"#;
const RECEIPT_COST_INDEX_SQL: &str = "CREATE INDEX IF NOT EXISTS \
    idx_chio_tool_receipts_cost ON \
    chio_tool_receipts(tenant_id, cost_currency, cost_charged_be, seq)";
const RECEIPT_GLOBAL_COST_INDEX_SQL: &str = "CREATE INDEX IF NOT EXISTS \
    idx_chio_tool_receipts_cost_global ON \
    chio_tool_receipts(cost_currency, cost_charged_be, seq)";
const ARCHIVE_RECEIPT_COST_INDEX_SQL: &str = "CREATE INDEX IF NOT EXISTS \
    archive.idx_chio_tool_receipts_cost ON \
    chio_tool_receipts(tenant_id, cost_currency, cost_charged_be, seq)";
const ARCHIVE_RECEIPT_GLOBAL_COST_INDEX_SQL: &str = "CREATE INDEX IF NOT EXISTS \
    archive.idx_chio_tool_receipts_cost_global ON \
    chio_tool_receipts(cost_currency, cost_charged_be, seq)";
const RECEIPT_COST_REFERENCE_SCHEMA: &str = r#"
CREATE TABLE chio_tool_receipts (
    seq INTEGER,
    tenant_id TEXT,
    cost_currency TEXT,
    cost_charged_be BLOB,
    attempted_cost_be BLOB
);
CREATE TABLE chio_child_receipts (id INTEGER);
CREATE TABLE claim_receipt_log_entries (id INTEGER);
CREATE TABLE checkpoint_tree_heads (id INTEGER);
CREATE TABLE checkpoint_predecessor_witnesses (id INTEGER);
CREATE TABLE checkpoint_publication_metadata (id INTEGER);
CREATE TABLE checkpoint_publication_trust_anchor_bindings (id INTEGER);
"#;

#[derive(Debug, PartialEq, Eq)]
struct ReceiptCostSchemaObject {
    object_type: String,
    name: String,
    table_name: String,
    sql: String,
}

#[derive(Default)]
pub(crate) struct ReceiptCostProjection {
    pub(crate) currency: Option<String>,
    pub(crate) charged: Option<Vec<u8>>,
    pub(crate) attempted: Option<Vec<u8>>,
}

pub(crate) fn receipt_cost_projection(
    receipt: &ChioReceipt,
) -> Result<ReceiptCostProjection, ReceiptStoreError> {
    let Some(financial) = receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("financial"))
    else {
        return Ok(ReceiptCostProjection::default());
    };
    if financial.is_null() {
        return Ok(ReceiptCostProjection::default());
    }
    let financial =
        serde_json::from_value::<FinancialReceiptMetadata>(financial.clone()).map_err(|error| {
            ReceiptStoreError::Conflict(format!(
                "tool receipt `{}` has invalid financial metadata: {error}",
                receipt.id
            ))
        })?;
    if financial.currency.len() != 3
        || !financial
            .currency
            .bytes()
            .all(|byte| byte.is_ascii_uppercase())
    {
        return Err(ReceiptStoreError::Conflict(format!(
            "tool receipt `{}` has invalid financial currency",
            receipt.id
        )));
    }
    Ok(ReceiptCostProjection {
        currency: Some(financial.currency),
        charged: Some(financial.cost_charged.to_be_bytes().to_vec()),
        attempted: financial
            .attempted_cost
            .map(|cost| cost.to_be_bytes().to_vec()),
    })
}

pub(crate) fn install_receipt_cost_indexes(
    connection: &Connection,
) -> Result<(), ReceiptStoreError> {
    connection.execute(RECEIPT_COST_INDEX_SQL, [])?;
    connection.execute(RECEIPT_GLOBAL_COST_INDEX_SQL, [])?;
    Ok(())
}

pub(crate) fn verify_receipt_cost_projection(
    connection: &Connection,
) -> Result<(), ReceiptStoreError> {
    verify_receipt_cost_projection_schema(
        connection,
        "sqlite_schema",
        "PRAGMA table_info(chio_tool_receipts)",
        "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'chio_tool_receipts'",
        true,
    )
}

pub(crate) fn audit_receipt_cost_projection(
    connection: &Connection,
) -> Result<(), ReceiptStoreError> {
    reconcile_receipt_cost_projection(connection, "persisted tool receipt cost projection")
}

pub(crate) fn install_archive_receipt_cost_indexes(
    connection: &Connection,
) -> Result<(), ReceiptStoreError> {
    connection.execute(ARCHIVE_RECEIPT_COST_INDEX_SQL, [])?;
    connection.execute(ARCHIVE_RECEIPT_GLOBAL_COST_INDEX_SQL, [])?;
    Ok(())
}

pub(crate) fn verify_archive_receipt_cost_projection(
    connection: &Connection,
) -> Result<(), ReceiptStoreError> {
    verify_receipt_cost_projection_schema(
        connection,
        "archive.sqlite_schema",
        "PRAGMA archive.table_info(chio_tool_receipts)",
        "SELECT sql FROM archive.sqlite_schema WHERE type = 'table' AND name = 'chio_tool_receipts'",
        true,
    )
}

fn verify_receipt_cost_projection_schema(
    connection: &Connection,
    schema_catalog: &str,
    table_info: &str,
    table_schema: &str,
    include_guards: bool,
) -> Result<(), ReceiptStoreError> {
    let mut columns = connection
        .prepare(table_info)?
        .query_map([], |row| {
            Ok((row.get::<_, String>(1)?, row.get::<_, String>(2)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    columns.retain(|(name, _)| {
        matches!(
            name.as_str(),
            "cost_currency" | "cost_charged_be" | "attempted_cost_be"
        )
    });
    columns.sort();
    if columns
        != [
            ("attempted_cost_be".to_string(), "BLOB".to_string()),
            ("cost_charged_be".to_string(), "BLOB".to_string()),
            ("cost_currency".to_string(), "TEXT".to_string()),
        ]
    {
        return Err(receipt_cost_schema_error());
    }

    let table_sql = connection
        .query_row(table_schema, [], |row| row.get::<_, String>(0))
        .optional()?
        .ok_or_else(receipt_cost_schema_error)?;
    let normalized_table_sql = normalize_schema_sql(&table_sql);
    if !normalized_table_sql.contains(&normalize_schema_sql(RECEIPT_COST_CURRENCY_COLUMN))
        || !normalized_table_sql.contains(&normalize_schema_sql(RECEIPT_COST_KEY_COLUMN))
        || !normalized_table_sql.contains(&normalize_schema_sql(RECEIPT_ATTEMPTED_COST_COLUMN))
    {
        return Err(receipt_cost_schema_error());
    }

    let reference = Connection::open_in_memory()?;
    reference.execute_batch(RECEIPT_COST_REFERENCE_SCHEMA)?;
    reference.execute(RECEIPT_COST_INDEX_SQL, [])?;
    reference.execute(RECEIPT_GLOBAL_COST_INDEX_SQL, [])?;
    if include_guards {
        ensure_transparency_projection_guards(&reference)?;
    }
    if receipt_cost_schema_catalog(connection, schema_catalog)?
        != receipt_cost_schema_catalog(&reference, "sqlite_schema")?
    {
        return Err(receipt_cost_schema_error());
    }
    Ok(())
}

fn receipt_cost_schema_catalog(
    connection: &Connection,
    schema_catalog: &str,
) -> Result<Vec<ReceiptCostSchemaObject>, ReceiptStoreError> {
    let sql = format!(
        "SELECT type, name, tbl_name, sql FROM {schema_catalog} \
         WHERE name IN (\
             'idx_chio_tool_receipts_cost', \
             'idx_chio_tool_receipts_cost_global', \
             'chio_tool_receipts_reject_update', \
             'chio_tool_receipts_reject_delete'\
         ) ORDER BY type ASC, name ASC"
    );
    connection
        .prepare(&sql)?
        .query_map([], |row| {
            Ok(ReceiptCostSchemaObject {
                object_type: row.get(0)?,
                name: row.get(1)?,
                table_name: row.get(2)?,
                sql: row.get(3)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(ReceiptStoreError::from)
}

fn normalize_schema_sql(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn receipt_cost_schema_error() -> ReceiptStoreError {
    ReceiptStoreError::Conflict(
        "receipt cost projection schema differs from the canonical definition".to_string(),
    )
}

fn reconcile_receipt_cost_projection(
    connection: &Connection,
    context: &str,
) -> Result<(), ReceiptStoreError> {
    let mut previous_seq = 0_i64;
    loop {
        let row = connection
            .query_row(
                "SELECT seq, raw_json, cost_currency, cost_charged_be, attempted_cost_be \
                 FROM chio_tool_receipts WHERE seq > ?1 ORDER BY seq ASC LIMIT 1",
                [previous_seq],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<Vec<u8>>>(3)?,
                        row.get::<_, Option<Vec<u8>>>(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((seq, raw_json, currency, charged, attempted)) = row else {
            break;
        };
        let receipt = decode_verified_chio_receipt(
            &raw_json,
            context,
            Some(sqlite_positive_u64(seq, "tool receipt source_seq")?),
        )?;
        let expected = receipt_cost_projection(&receipt)?;
        if currency != expected.currency
            || charged != expected.charged
            || attempted != expected.attempted
        {
            return Err(ReceiptStoreError::Conflict(format!(
                "tool receipt `{}` already exists with different cost projection",
                receipt.id
            )));
        }
        previous_seq = seq;
    }
    Ok(())
}
