//! Authenticate projected amounts against the signed receipts inside the
//! report's pinned snapshot. Schema guards alone cannot prove stored values.

use super::*;

pub(super) fn verify_report_costs(
    snapshot: &Connection,
    scope: &AnalyticsScope,
) -> Result<(), ReceiptStoreError> {
    let scan = scope.scan(SubjectDimension::Absent);
    let sql = format!(
        "SELECT r.seq, r.raw_json, r.cost_currency, r.cost_charged_be, \
         r.attempted_cost_be {}",
        scan.from_where,
    );
    let mut statement = snapshot.prepare(&sql)?;
    let mut rows = statement.query(scan.params())?;
    while let Some(row) = rows.next()? {
        let seq = sqlite_positive_u64(row.get(0)?, "analytics receipt sequence")?;
        let raw: String = row.get(1)?;
        let receipt = decode_verified_chio_receipt(&raw, "receipt analytics", Some(seq))?;
        let expected = receipt_cost_projection(&receipt)?;
        let currency: Option<String> = row.get(2)?;
        let charged: Option<Vec<u8>> = row.get(3)?;
        let attempted: Option<Vec<u8>> = row.get(4)?;
        if currency != expected.currency
            || charged != expected.charged
            || attempted != expected.attempted
        {
            return Err(ReceiptStoreError::Conflict(format!(
                "receipt analytics cost projection differs from signed receipt {}",
                receipt.id,
            )));
        }
    }
    Ok(())
}
