//! Check every selected projection before aggregation, without claiming corpus trust.
use super::super::read_boundary::ReportReadBudget;
use super::*;

pub(super) fn verify_report_costs(
    snapshot: &Connection,
    scope: &AnalyticsScope,
    budget: &mut ReportReadBudget,
) -> Result<(), ReceiptStoreError> {
    let row_bytes = sqlite_i64(budget.metadata_byte_limit()?, "report encoded row limit")?;
    let ceiling =
        sqlite_i64(
            budget.limits.rows.checked_add(1).ok_or_else(|| {
                ReceiptStoreError::ReadBoundary("invalid report row limit".into())
            })?,
            "report row limit",
        )?;
    let (sql, scan) = selected_query(scope, &row_bytes, &ceiling, false);
    let mut statement = snapshot.prepare(&sql)?;
    let mut rows = statement.query(scan.params())?;
    while let Some(row) = rows.next()? {
        budget.receipt(snapshot, row)?;
    }
    Ok(())
}
