#[path = "admission_operation_store/part_01.inc"]
mod store;
pub use store::SqliteAdmissionOperationStore;
use store::*;
#[cfg(test)]
mod connection_recovery;
#[cfg(test)]
mod foreign_schema_tests;
#[cfg(test)]
mod review_tests;
#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "Test and proof fixtures deliberately fail on violated setup invariants."
)]
#[path = "admission_operation_store/part_02.inc"]
mod tests;

#[path = "security_admission_operation_store/recovery_pages.rs"]
mod recovery_pages;
mod table_shape;
