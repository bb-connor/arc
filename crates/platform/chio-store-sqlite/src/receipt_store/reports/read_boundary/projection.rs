//! Compare the selected row with its signed body before trusting its dimensions.
use super::*;

fn text_matches(
    row: &rusqlite::Row<'_>,
    column: usize,
    expected: Option<&str>,
) -> Result<bool, ReceiptStoreError> {
    Ok(match (row.get_ref(column)?, expected) {
        (ValueRef::Null, None) => true,
        (ValueRef::Text(actual), Some(expected)) => actual == expected.as_bytes(),
        _ => false,
    })
}

fn blob_matches(
    row: &rusqlite::Row<'_>,
    column: usize,
    expected: Option<&[u8]>,
) -> Result<bool, ReceiptStoreError> {
    Ok(match (row.get_ref(column)?, expected) {
        (ValueRef::Null, None) => true,
        (ValueRef::Blob(actual), Some(expected)) => actual == expected,
        _ => false,
    })
}

fn attribution_matches(
    row: &rusqlite::Row<'_>,
    column: usize,
    signed: Option<&str>,
    fallback: Option<&str>,
) -> Result<bool, ReceiptStoreError> {
    // Old rows can precede their capability snapshot. NULL is the legitimate
    // stored representation in that case; grouping then reads the validated
    // local lineage through COALESCE in this same snapshot.
    if signed.is_none() && matches!(row.get_ref(column)?, ValueRef::Null) {
        return Ok(true);
    }
    text_matches(row, column, signed.or(fallback))
}

pub(super) fn verify(
    connection: &Connection,
    row: &rusqlite::Row<'_>,
    receipt: &ChioReceipt,
    budget: &mut ReportReadBudget,
) -> Result<(), ReceiptStoreError> {
    let cost = receipt_cost_projection(receipt)?;
    if !text_matches(row, 15, cost.currency.as_deref())?
        || !blob_matches(row, 16, cost.charged.as_deref())?
        || !blob_matches(row, 17, cost.attempted.as_deref())?
    {
        let surface = if budget.surface == "receipt analytics report" {
            "receipt analytics"
        } else {
            budget.surface
        };
        return Err(ReceiptStoreError::Conflict(format!(
            "{surface} cost projection differs from signed receipt {}",
            receipt.id,
        )));
    }
    let attribution = extract_receipt_attribution(receipt);
    let lineage = if attribution.subject_key.is_none() || attribution.issuer_key.is_none() {
        lineage::local(connection, &receipt.capability_id, budget)?
    } else {
        None
    };
    if !text_matches(row, 3, Some(&receipt.id))?
        || row.get::<_, i64>(4)? != sqlite_i64(receipt.timestamp, "report receipt timestamp")?
        || !text_matches(row, 5, Some(&receipt.capability_id))?
        || !text_matches(row, 6, Some(&receipt.tool_server))?
        || !text_matches(row, 7, Some(&receipt.tool_name))?
        || !text_matches(row, 8, Some(receipt_decision_kind(receipt)))?
        || !text_matches(row, 9, receipt.tenant_id.as_deref())?
        || !attribution_matches(
            row,
            10,
            attribution.subject_key.as_deref(),
            lineage.as_ref().map(|value| value.subject_key.as_str()),
        )?
        || !attribution_matches(
            row,
            11,
            attribution.issuer_key.as_deref(),
            lineage.as_ref().map(|value| value.issuer_key.as_str()),
        )?
        || row.get::<_, Option<i64>>(12)? != attribution.grant_index.map(i64::from)
        || !text_matches(row, 13, Some(&receipt.policy_hash))?
        || !text_matches(row, 14, Some(&receipt.content_hash))?
    {
        return Err(ReceiptStoreError::Conflict(format!(
            "selected report projection differs from signed receipt {}",
            receipt.id,
        )));
    }
    Ok(())
}
