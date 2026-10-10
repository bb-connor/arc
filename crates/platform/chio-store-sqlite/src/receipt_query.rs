#[path = "receipt_query/read.rs"]
mod read;
#[cfg(test)]
pub(crate) use read::receipt_query_sql;
pub(crate) use read::{query_receipts_on_connection, unrecorded_attribution_rows};

use chio_kernel::receipt_query::{ReceiptQuery, ReceiptQueryResult};
use chio_kernel::ReceiptStoreError;

use crate::receipt_store::SqliteReceiptStore;

impl SqliteReceiptStore {
    /// Query live and authenticated archived tool receipts with multi-filter support and cursor-based pagination.
    ///
    /// Filters are applied with AND semantics. The cursor parameter enables
    /// forward-only pagination using the seq column as a stable cursor.
    ///
    /// The limit is capped at MAX_QUERY_LIMIT. total_count reflects the full
    /// filtered set (no cursor applied), regardless of the page limit.
    pub fn query_receipts(
        &self,
        query: &ReceiptQuery,
    ) -> Result<ReceiptQueryResult, ReceiptStoreError> {
        self.with_retained_snapshot(|snapshot| snapshot.query_receipts(query))
    }

    /// Diagnostic query of the live store only. Ordinary reads should use
    /// `query_receipts`, which also authenticates retained archive history.
    pub fn query_live_receipts(
        &self,
        query: &ReceiptQuery,
    ) -> Result<ReceiptQueryResult, ReceiptStoreError> {
        self.query_receipts_impl(query)
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "Test and proof fixtures deliberately fail on violated setup invariants."
)]
mod tests;
