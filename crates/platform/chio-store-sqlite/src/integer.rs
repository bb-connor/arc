//! Checked integer crossings between Rust collections, wire counters and SQLite.

use std::any::type_name;
use std::error::Error;

/// A range failure carries type information, never the persisted value.
#[derive(Debug, thiserror::Error)]
#[error("integer cannot be represented as {target}")]
pub(crate) struct IntegerRangeError {
    target: &'static str,
    #[source]
    source: Box<dyn Error + Send + Sync>,
}

pub(crate) fn checked<T, U>(value: T) -> Result<U, IntegerRangeError>
where
    U: TryFrom<T>,
    U::Error: Error + Send + Sync + 'static,
{
    U::try_from(value).map_err(|source| IntegerRangeError {
        target: type_name::<U>(),
        source: Box::new(source),
    })
}

// Rust's supported address widths fit in a u64 wire counter. Reject a future
// wider target at compile time instead of silently narrowing a collection size.
#[cfg(not(any(
    target_pointer_width = "16",
    target_pointer_width = "32",
    target_pointer_width = "64"
)))]
compile_error!("SQLite storage requires collection lengths representable by u64");

#[allow(
    clippy::as_conversions,
    reason = "The compile-time target-width gate proves usize fits in u64."
)]
pub(crate) const fn count(value: usize) -> u64 {
    value as u64
}

impl From<IntegerRangeError> for rusqlite::Error {
    fn from(error: IntegerRangeError) -> Self {
        Self::ToSqlConversionFailure(Box::new(error))
    }
}

impl From<IntegerRangeError> for chio_kernel::ReceiptStoreError {
    fn from(error: IntegerRangeError) -> Self {
        Self::Sqlite(error.into())
    }
}

impl From<IntegerRangeError> for chio_kernel::BudgetStoreError {
    fn from(error: IntegerRangeError) -> Self {
        Self::Sqlite(error.into())
    }
}

impl From<IntegerRangeError> for chio_kernel::RevocationStoreError {
    fn from(error: IntegerRangeError) -> Self {
        Self::Sqlite(error.into())
    }
}

impl From<IntegerRangeError> for chio_kernel::ApprovalStoreError {
    fn from(error: IntegerRangeError) -> Self {
        Self::Invalid(error.to_string())
    }
}

impl From<IntegerRangeError> for chio_kernel::admission_operation::AdmissionOperationStoreError {
    fn from(error: IntegerRangeError) -> Self {
        Self::Invariant(error.to_string())
    }
}

impl From<IntegerRangeError> for chio_kernel::EvidenceExportError {
    fn from(error: IntegerRangeError) -> Self {
        Self::Sqlite(error.into())
    }
}

impl From<IntegerRangeError> for chio_security_types::ports::PortError {
    fn from(_: IntegerRangeError) -> Self {
        Self::integrity_failure()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn narrowing_and_signed_crossings_reject_both_edges() {
        assert!(matches!(
            checked::<_, i64>(u64::MAX),
            Err(IntegerRangeError { target: "i64", .. })
        ));
        assert!(matches!(
            checked::<_, u64>(-1_i64),
            Err(IntegerRangeError { target: "u64", .. })
        ));
        assert!(matches!(
            checked::<_, u32>(u64::from(u32::MAX) + 1),
            Err(IntegerRangeError { target: "u32", .. })
        ));
        assert_eq!(
            checked::<_, u64>(i64::MAX).ok(),
            Some(i64::MAX.unsigned_abs())
        );
        assert_eq!(checked::<_, u32>(u64::from(u32::MAX)).ok(), Some(u32::MAX));
    }
}
